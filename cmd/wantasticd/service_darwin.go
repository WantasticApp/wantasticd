//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/auth"
	"wantastic-agent/pkg/runner"
)

const (
	darwinDaemonTarget = "system/" + runner.DaemonLaunchdLabel
	darwinServiceLog   = darwinLogDir + "/wantasticd.log"
	darwinServiceWait  = 15 * time.Second
)

// runServiceCommand manages the launchd daemon install.sh sets up, so a Mac
// can be repaired, restarted or checked without re-running the installer.
// Removing everything (binary too) stays `wantasticd uninstall`.
func runServiceCommand(args []string) int {
	if len(args) == 0 {
		darwinServiceUsage()
		return 2
	}
	if args[0] != "status" && os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "wantasticd service %s: run it as root: sudo wantasticd service %s\n", args[0], args[0])
		return 1
	}
	var err error
	switch args[0] {
	case "install":
		err = darwinServiceInstall(args[1:])
	case "uninstall", "remove":
		err = darwinServiceUninstall()
	case "reinstall":
		// A clean slate for a broken install; the login and config stay.
		if err = darwinServiceUninstall(); err == nil {
			err = darwinServiceInstall(args[1:])
		}
	case "start":
		err = darwinServiceStart()
	case "stop":
		err = darwinServiceStop()
	case "restart":
		err = darwinServiceRestart()
	case "status":
		err = darwinServiceStatus()
	default:
		darwinServiceUsage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wantasticd service %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func darwinServiceUsage() {
	fmt.Fprintln(os.Stderr, "Usage: sudo wantasticd service <command>")
	fmt.Fprintln(os.Stderr, "  install [--config PATH] [--no-start] [--no-tray]")
	fmt.Fprintln(os.Stderr, "                       register (or repair) the launchd service and menu-bar app, then start it")
	fmt.Fprintln(os.Stderr, "  uninstall            stop and remove the service and menu-bar app; the program and login stay")
	fmt.Fprintln(os.Stderr, "  reinstall [install flags]  uninstall, then install again (login and config kept)")
	fmt.Fprintln(os.Stderr, "  start | stop | restart | status")
	fmt.Fprintln(os.Stderr, "To remove Wantastic completely: sudo wantasticd uninstall [--purge]")
}

func darwinServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	configPath := fs.String("config", auth.DefaultConfigPath(), "Configuration file the service connects with")
	noStart := fs.Bool("no-start", false, "Register the service without starting it")
	noTray := fs.Bool("no-tray", false, "Do not run the menu-bar app")
	fs.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if err := os.MkdirAll(darwinLogDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(darwinDaemonPlist), 0o755); err != nil {
		return err
	}
	tmp := darwinDaemonPlist + ".tmp"
	if err := os.WriteFile(tmp, []byte(runner.DaemonPlistContent(exe, *configPath, darwinServiceLog)), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("plutil", "-lint", tmp).CombinedOutput(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("invalid service plist: %s", strings.TrimSpace(string(out)))
	}
	launchdUnload(darwinDaemonTarget)
	if err := os.Rename(tmp, darwinDaemonPlist); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chown(darwinDaemonPlist, 0, 0)
	fmt.Printf("Service registered: %s\n", darwinDaemonPlist)

	if *noTray {
		if err := runner.RemoveTrayAgent(true); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: menu-bar app not removed: %v\n", err)
		} else {
			fmt.Println("Menu-bar app off (--no-tray).")
		}
	} else if started, err := runner.InstallTrayAgent(exe); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: menu-bar app not started: %v\n", err)
	} else if started {
		fmt.Println("Menu-bar app started; it also starts at every login.")
	} else {
		fmt.Println("Menu-bar app installed; it starts at the next login.")
	}

	if *noStart {
		return nil
	}
	return darwinServiceStart()
}

func darwinServiceUninstall() error {
	launchdUnload(darwinDaemonTarget)
	removeFiles(darwinDaemonPlist)
	fmt.Println("Service removed.")
	if err := runner.RemoveTrayAgent(false); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: menu-bar app not removed: %v\n", err)
	} else {
		fmt.Println("Menu-bar app removed.")
	}
	fmt.Println("The program and your login are kept: sudo wantasticd service install puts the service back.")
	return nil
}

func darwinServiceStart() error {
	if _, err := os.Stat(darwinDaemonPlist); err != nil {
		return errors.New("the service is not installed (run: sudo wantasticd service install)")
	}
	_ = exec.Command("launchctl", "enable", darwinDaemonTarget).Run()
	if _, loaded := launchdJob(darwinDaemonTarget); !loaded {
		if out, err := exec.Command("launchctl", "bootstrap", "system", darwinDaemonPlist).CombinedOutput(); err != nil {
			return fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	_ = exec.Command("launchctl", "kickstart", darwinDaemonTarget).Run()
	return waitDaemonRunning()
}

// darwinServiceStop unloads the daemon; it stays stopped until
// `service start` or the next boot.
func darwinServiceStop() error {
	if _, loaded := launchdJob(darwinDaemonTarget); !loaded {
		fmt.Println("Service not running.")
		return nil
	}
	launchdUnload(darwinDaemonTarget)
	fmt.Println("Service stopped; it starts again at boot or with: sudo wantasticd service start")
	return nil
}

func darwinServiceRestart() error {
	if _, loaded := launchdJob(darwinDaemonTarget); !loaded {
		return darwinServiceStart()
	}
	if out, err := exec.Command("launchctl", "kickstart", "-k", darwinDaemonTarget).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// kickstart -k returns once the new process is spawned; let it settle.
	time.Sleep(time.Second)
	return waitDaemonRunning()
}

// waitDaemonRunning requires a process that stays up: a crash loop also
// looks loaded.
func waitDaemonRunning() error {
	deadline := time.Now().Add(darwinServiceWait)
	for time.Now().Before(deadline) {
		if info, _ := launchdJob(darwinDaemonTarget); info.pid > 0 {
			time.Sleep(2 * time.Second)
			if again, _ := launchdJob(darwinDaemonTarget); again.pid == info.pid {
				fmt.Printf("Service running (pid %d).\n", info.pid)
				fmt.Println("Logs: " + darwinServiceLog)
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the service did not stay running\n%s", darwinLogTail(20))
}

func darwinServiceStatus() error {
	info, loaded := launchdJob(darwinDaemonTarget)
	_, statErr := os.Stat(darwinDaemonPlist)
	state := "not installed"
	switch {
	case loaded && info.pid > 0:
		state = "running"
	case loaded:
		state = firstNonEmptyDarwin(info.state, "loaded, not running")
	case statErr == nil:
		state = "stopped"
	}
	fmt.Printf("State:    %s\n", state)
	if info.pid > 0 {
		fmt.Printf("PID:      %d\n", info.pid)
	}
	if info.lastExit != "" && info.lastExit != "0" && info.lastExit != "(never exited)" {
		fmt.Printf("Last exit: %s\n", info.lastExit)
	}
	if statErr == nil {
		fmt.Printf("Plist:    %s\n", darwinDaemonPlist)
		if cmd := darwinPlistCommand(); cmd != "" {
			fmt.Printf("Command:  %s\n", cmd)
		}
	}
	fmt.Printf("Logs:     %s\n", darwinServiceLog)
	tray := "off"
	if _, err := os.Stat(runner.TrayAgentPlist); err == nil {
		tray = "installed"
		if uid, ok := runner.ConsoleUID(); ok {
			if t, loaded := launchdJob("gui/" + strconv.FormatUint(uint64(uid), 10) + "/" + runner.TrayAgentLabel); loaded && t.pid > 0 {
				tray = fmt.Sprintf("running (pid %d)", t.pid)
			}
		}
	}
	fmt.Printf("Menu bar: %s\n", tray)
	return nil
}

// darwinPlistCommand is the daemon's command line from its plist.
func darwinPlistCommand() string {
	var parts []string
	for i := 0; i < 16; i++ {
		out, err := exec.Command("plutil", "-extract", "ProgramArguments."+strconv.Itoa(i), "raw", "-o", "-", darwinDaemonPlist).Output()
		if err != nil {
			break
		}
		arg := strings.TrimRight(string(out), "\n")
		if strings.ContainsAny(arg, " \t\"'") {
			arg = strconv.Quote(arg)
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

type launchdInfo struct {
	pid      int
	state    string
	lastExit string
}

// launchdJob reads `launchctl print`; loaded is false when launchd does not
// know the job.
func launchdJob(target string) (launchdInfo, bool) {
	out, err := exec.Command("launchctl", "print", target).Output()
	if err != nil {
		return launchdInfo{}, false
	}
	return parseLaunchdPrint(string(out)), true
}

func parseLaunchdPrint(out string) launchdInfo {
	var info launchdInfo
	for _, line := range strings.Split(out, "\n") {
		// Nested blocks are indented deeper; only the job's own keys count.
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch key {
		case "pid":
			info.pid, _ = strconv.Atoi(value)
		case "state":
			info.state = value
		case "last exit code":
			info.lastExit = value
		}
	}
	return info
}

func darwinLogTail(lines int) string {
	data, err := os.ReadFile(darwinServiceLog)
	if err != nil {
		return "No service log at " + darwinServiceLog + "."
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return "Last lines of " + darwinServiceLog + ":\n  " + strings.Join(all, "\n  ")
}

func firstNonEmptyDarwin(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
