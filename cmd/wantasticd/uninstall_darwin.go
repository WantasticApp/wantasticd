//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"wantastic-agent/pkg/runner"
)

const (
	darwinDaemonPlist = "/Library/LaunchDaemons/" + runner.DaemonLaunchdLabel + ".plist"
	darwinSupportDir  = "/Library/Application Support/Wantastic"
	darwinLogDir      = "/Library/Logs/Wantastic"
)

// runUninstall removes what install.sh installs on a Mac: the launchd
// daemon, the menu-bar agent and the binary; --purge also the login.
func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "Also remove the login, claim key, settings and logs")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "wantasticd uninstall: run it as root: sudo wantasticd uninstall")
		return 1
	}
	// The menu-bar app may have started this; leave its process group so
	// unloading it at the end does not stop the uninstall halfway.
	_, _ = syscall.Setsid()
	signal.Ignore(syscall.SIGHUP, syscall.SIGTERM)

	fmt.Println("Uninstalling wantasticd...")
	launchdUnload("system/" + runner.DaemonLaunchdLabel)
	removeFiles(darwinDaemonPlist, runner.TrayAgentPlist)

	bins := []string{"/usr/local/bin/wantasticd", "/usr/bin/wantasticd", "/bin/wantasticd"}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil && filepath.Base(resolved) == "wantasticd" {
			bins = append(bins, resolved)
		}
	}
	for _, bin := range bins {
		removeFiles(bin, bin+".previous", bin+".new")
	}

	if *purge {
		for _, dir := range []string{darwinSupportDir, darwinLogDir} {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		}
		fmt.Println("Configuration removed.")
	} else {
		fmt.Printf("Configuration kept in %s (use --purge to remove it).\n", darwinSupportDir)
	}
	fmt.Println("wantasticd uninstalled.")

	// Last: when the menu-bar app started this, unloading it ends its session.
	if uid, ok := runner.ConsoleUID(); ok {
		launchdUnload("gui/" + strconv.FormatUint(uint64(uid), 10) + "/" + runner.TrayAgentLabel)
	}
	return 0
}

// launchdUnload boots a job out and waits until launchd forgets it.
func launchdUnload(target string) {
	_ = exec.Command("launchctl", "bootout", target).Run()
	for i := 0; i < 20; i++ {
		if exec.Command("launchctl", "print", target).Run() != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "Warning: %s is still loaded\n", target)
}

func removeFiles(paths ...string) {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}
}
