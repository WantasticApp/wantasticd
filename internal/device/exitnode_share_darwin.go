//go:build darwin
// +build darwin

package device

import (
	"fmt"
	"os/exec"
)

func enableExitNodeSharingOS(tunName string) (string, error) {
	_ = tunName
	if err := darwinSetIPForwarding(true); err != nil {
		return "", err
	}
	return "IP forwarding is enabled, but NAT still requires manual PF or Internet Sharing setup on macOS", nil
}

func disableExitNodeSharingOS(tunName string) error {
	_ = tunName
	return darwinSetIPForwarding(false)
}

func darwinSetIPForwarding(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}

	if out, err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding="+value).CombinedOutput(); err != nil {
		return fmt.Errorf("set ipv4 forwarding=%s: %v, output: %s", value, err, out)
	}
	if out, err := exec.Command("sysctl", "-w", "net.inet6.ip6.forwarding="+value).CombinedOutput(); err != nil {
		return fmt.Errorf("set ipv6 forwarding=%s: %v, output: %s", value, err, out)
	}

	return nil
}
