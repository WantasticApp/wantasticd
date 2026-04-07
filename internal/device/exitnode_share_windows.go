//go:build windows
// +build windows

package device

import (
	"fmt"
	"os/exec"
)

func enableExitNodeSharingOS(tunName string) (string, error) {
	_ = tunName
	if err := windowsSetIPForwarding(true); err != nil {
		return "", err
	}
	return "IP forwarding is enabled, but NAT still requires manual configuration on Windows", nil
}

func disableExitNodeSharingOS(tunName string) error {
	_ = tunName
	return windowsSetIPForwarding(false)
}

func windowsSetIPForwarding(enabled bool) error {
	state := "Disabled"
	if enabled {
		state = "Enabled"
	}

	cmd := exec.Command(
		"powershell",
		"-Command",
		fmt.Sprintf("Get-NetIPInterface | Where-Object {$_.AddressFamily -in @('IPv4','IPv6')} | Set-NetIPInterface -Forwarding %s", state),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set IP forwarding %s: %v, output: %s", state, err, out)
	}

	return nil
}
