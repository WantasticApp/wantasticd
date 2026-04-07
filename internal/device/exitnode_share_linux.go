//go:build linux
// +build linux

package device

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func enableExitNodeSharingOS(tunName string) (string, error) {
	_ = tunName
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return "", fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0644); err != nil {
		return "", fmt.Errorf("enable ipv6 forwarding: %w", err)
	}

	uplink, err := linuxDefaultRouteInterface()
	if err != nil {
		return "", err
	}

	if err := ensureLinuxMasqueradeRule("iptables", uplink); err != nil {
		return "", err
	}
	if err := ensureLinuxMasqueradeRule("ip6tables", uplink); err != nil {
		return "IPv6 masquerade could not be enabled automatically", nil
	}

	return "", nil
}

func disableExitNodeSharingOS(tunName string) error {
	_ = tunName
	var firstErr error

	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("disable ipv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("0\n"), 0644); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("disable ipv6 forwarding: %w", err)
	}

	uplink, err := linuxDefaultRouteInterface()
	if err != nil {
		return err
	}

	if err := deleteLinuxMasqueradeRule("iptables", uplink); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := deleteLinuxMasqueradeRule("ip6tables", uplink); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

func linuxDefaultRouteInterface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("detect default route interface: %v, output: %s", err, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1], nil
			}
		}
	}

	return "", fmt.Errorf("default route interface not found in: %s", strings.TrimSpace(string(out)))
}

func ensureLinuxMasqueradeRule(binary, uplink string) error {
	check := exec.Command(binary, "-t", "nat", "-C", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE")
	if err := check.Run(); err == nil {
		return nil
	}

	out, err := exec.Command(binary, "-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s add masquerade on %s: %v, output: %s", binary, uplink, err, out)
	}

	return nil
}

func deleteLinuxMasqueradeRule(binary, uplink string) error {
	check := exec.Command(binary, "-t", "nat", "-C", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE")
	if err := check.Run(); err != nil {
		return nil
	}

	out, err := exec.Command(binary, "-t", "nat", "-D", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s delete masquerade on %s: %v, output: %s", binary, uplink, err, out)
	}

	return nil
}
