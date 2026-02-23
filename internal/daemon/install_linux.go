package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const systemdServiceTemplate = `[Unit]
Description=Wantastic Overlay Networking Daemon
After=network.target

[Service]
Type=simple
ExecStart=%s connect -config %s
Restart=on-failure
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
`

// SetupService installs and starts the service via systemd on Linux
func SetupService(configPath string) error {
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

	serviceContent := fmt.Sprintf(systemdServiceTemplate, exePath, absConfigPath)
	servicePath := "/etc/systemd/system/wantasticd.service"

	fmt.Println("Installing system service to", servicePath)
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file (do you have root privileges?): %w", err)
	}

	fmt.Println("Reloading systemd daemon...")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}

	fmt.Println("Enabling system service on boot...")
	if err := exec.Command("systemctl", "enable", "wantasticd.service").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	fmt.Println("Starting system service...")
	// We'll try to stop it first in case it's already running
	_ = exec.Command("systemctl", "stop", "wantasticd.service").Run()
	if err := exec.Command("systemctl", "start", "wantasticd.service").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}
