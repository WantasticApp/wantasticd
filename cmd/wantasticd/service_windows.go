//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/platform/firewall"
	"wantastic-agent/pkg/runner"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	winServiceName        = "wantasticd"
	winServiceDisplayName = "Wantastic Overlay Networking"
	winServiceDescription = "Wantastic secure overlay networking agent."
	winServiceWait        = 30 * time.Second
)

// runServiceCommand registers and controls the Windows service through the
// Service Control Manager API, so the service command line is quoted
// correctly whatever shell runs the installer.
func runServiceCommand(args []string) int {
	if len(args) == 0 {
		serviceUsage()
		return 2
	}
	var err error
	switch args[0] {
	case "install":
		err = serviceInstall(args[1:])
	case "uninstall", "remove":
		err = serviceUninstall()
	case "start":
		err = withService(func(s *mgr.Service) error { return startAndWait(s) })
	case "stop":
		err = withService(func(s *mgr.Service) error { return stopAndWait(s) })
	case "restart":
		err = withService(func(s *mgr.Service) error {
			if err := stopAndWait(s); err != nil {
				return err
			}
			return startAndWait(s)
		})
	case "status":
		err = withService(printServiceStatus)
	default:
		serviceUsage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wantasticd service %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func serviceUsage() {
	fmt.Fprintln(os.Stderr, "Usage: wantasticd service <command>")
	fmt.Fprintln(os.Stderr, "  install [--config PATH] [--no-start]   register (or repair) the service, firewall rules and recovery, then start it")
	fmt.Fprintln(os.Stderr, "  uninstall                              stop and remove the service and its firewall rules")
	fmt.Fprintln(os.Stderr, "  start | stop | restart | status")
}

func serviceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	configPath := fs.String("config", auth.DefaultConfigPath(), "Configuration file the service connects with")
	noStart := fs.Bool("no-start", false, "Register the service without starting it")
	fs.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// The service runs in session 0 with no desktop; the tray is a per-user app.
	svcArgs := []string{"connect", "--config", *configPath, "--tray=false"}

	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(winServiceName)
	if err == nil {
		// Reconfigure in place: delete + create fails with "marked for
		// deletion" while anything (services.msc) holds a handle.
		cfg, err := s.Config()
		if err != nil {
			s.Close()
			return fmt.Errorf("read service configuration: %w", err)
		}
		cfg.BinaryPathName = commandLine(exe, svcArgs)
		cfg.StartType = mgr.StartAutomatic
		cfg.DelayedAutoStart = false
		cfg.ErrorControl = mgr.ErrorNormal
		cfg.DisplayName = winServiceDisplayName
		cfg.Description = winServiceDescription
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("update service: %w", err)
		}
		fmt.Println("Service updated.")
	} else {
		s, err = m.CreateService(winServiceName, exe, mgr.Config{
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
			DisplayName:  winServiceDisplayName,
			Description:  winServiceDescription,
		}, svcArgs...)
		if err != nil {
			if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				return errors.New("the old service is still being removed; close the Services window and Task Manager, then try again")
			}
			return fmt.Errorf("create service: %w", err)
		}
		fmt.Println("Service created.")
	}
	defer s.Close()

	// Restart on failure (5 s, 10 s, then every 30 s), also when the agent
	// exits with an error rather than crashing.
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 86400); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set service recovery: %v\n", err)
	} else if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set service recovery: %v\n", err)
	}

	if err := firewall.AllowApp(exe); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Windows Firewall rule not added (peers may use the relay only): %v\n", err)
	} else {
		fmt.Println("Windows Firewall: inbound UDP allowed for wantasticd.")
	}

	if *noStart {
		return nil
	}
	if err := stopAndWait(s); err != nil {
		return err
	}
	return startAndWait(s)
}

func serviceUninstall() error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(winServiceName); err == nil {
		stopErr := stopAndWait(s)
		delErr := s.Delete()
		s.Close()
		if delErr != nil && !errors.Is(delErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("remove service: %w", delErr)
		}
		if stopErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", stopErr)
		}
		fmt.Println("Service removed.")
	} else {
		fmt.Println("Service not installed.")
	}
	if err := firewall.Remove(); err != nil {
		return err
	}
	fmt.Println("Firewall rules removed.")
	return nil
}

func connectSCM() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("access denied: run PowerShell as Administrator")
	}
	return m, err
}

func withService(fn func(*mgr.Service) error) error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(winServiceName)
	if err != nil {
		return errors.New("the service is not installed (run: wantasticd service install)")
	}
	defer s.Close()
	return fn(s)
}

func startAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Running {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return fmt.Errorf("start service: %w", err)
		}
	}
	if err := waitState(s, svc.Running); err != nil {
		return fmt.Errorf("%w\n%s", err, serviceLogTail(25))
	}
	fmt.Println("Service running.")
	return nil
}

// serviceLogTail is the end of the service log, for start failures.
func serviceLogTail(lines int) string {
	path := runner.ServiceLogPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return "No service log at " + path + "."
	}
	all := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return "Last lines of " + path + ":\n  " + strings.Join(all, "\n  ")
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	return waitState(s, svc.Stopped)
}

func waitState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(winServiceWait)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if want == svc.Running && st.State == svc.Stopped {
			return fmt.Errorf("the service stopped right after starting (exit code %d)", st.Win32ExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not reach %s within %s (now %s)", stateName(want), winServiceWait, stateName(st.State))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func printServiceStatus(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	start := map[uint32]string{mgr.StartAutomatic: "automatic", mgr.StartManual: "manual", mgr.StartDisabled: "disabled"}[cfg.StartType]
	fmt.Printf("State:   %s\n", stateName(st.State))
	fmt.Printf("Startup: %s\n", firstNonEmptyString(start, fmt.Sprint(cfg.StartType)))
	fmt.Printf("Command: %s\n", cfg.BinaryPathName)
	return nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	default:
		return fmt.Sprintf("state %d", s)
	}
}

// commandLine quotes the executable and arguments the way CreateService does.
func commandLine(exe string, args []string) string {
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

func firstNonEmptyString(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
