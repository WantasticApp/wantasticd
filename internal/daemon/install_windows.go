package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "wantasticd"
const serviceDesc = "Wantastic Overlay Networking Daemon"

// SetupService installs and starts the service on Windows
func SetupService(configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager (are you running as Administrator?): %w", err)
	}
	defer m.Disconnect()

	// If service already exists, delete/stop it first to update path/config.
	_ = uninstallService(m)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlink for executable: %w", err)
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config: %w", err)
	}

	c := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Dnscache", "iphlpsvc"},
		DisplayName:  serviceName,
		Description:  serviceDesc,
	}

	fmt.Println("Installing Windows service...")
	// The command-line path and arguments need to be provided together for Windows services.
	// Ensure paths are quoted correctly in case they contain spaces.
	execStr := fmt.Sprintf("\"%s\" connect -config \"%s\"", exePath, absConfigPath)

	srv, err := m.CreateService(serviceName, execStr, c)
	if err != nil {
		return fmt.Errorf("failed to create %q service: %w", serviceName, err)
	}
	defer srv.Close()

	// Configure Recovery Actions (restart service exponentially on crash)
	ra := []mgr.RecoveryAction{
		{mgr.ServiceRestart, 2 * time.Second},
		{mgr.ServiceRestart, 5 * time.Second},
		{mgr.ServiceRestart, 15 * time.Second},
	}
	if err := srv.SetRecoveryActions(ra, 60); err != nil {
		return fmt.Errorf("failed to set service recovery actions: %w", err)
	}

	fmt.Println("Starting Windows service...")
	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func uninstallService(m *mgr.Mgr) error {
	srv, err := m.OpenService(serviceName)
	if err != nil {
		return err // doesn't exist
	}
	defer srv.Close()

	st, err := srv.Query()
	if err == nil && st.State != svc.Stopped {
		_, _ = srv.Control(svc.Stop)
	}

	// Just in case, try to sleep slightly to let the service terminate cleanly before deleting, sometimes Windows locks it
	time.Sleep(500 * time.Millisecond)
	return srv.Delete()
}
