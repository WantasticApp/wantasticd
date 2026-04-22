//go:build linux
// +build linux

package device

import (
	"fmt"

	"wantastic-agent/internal/netctl"
)

func enableExitNodeSharingOS(tunName string) (string, error) {
	if err := ctl.IPForwardingSet(true); err != nil {
		return "", fmt.Errorf("enable forwarding: %w", err)
	}

	uplink, _, err := ctl.RouteGetDefault()
	if err != nil {
		return "", fmt.Errorf("detect default route: %w", err)
	}

	masq := netctl.FirewallRule{
		Table: "nat", Chain: "POSTROUTING",
		Args: []string{"-o", uplink, "-j", "MASQUERADE"},
	}
	if err := ctl.FirewallEnsureRule(masq); err != nil {
		return "", fmt.Errorf("iptables masquerade on %s: %w", uplink, err)
	}

	// Try IPv6 masquerade (non-fatal)
	masq6 := netctl.FirewallRule{
		Table: "nat", Chain: "POSTROUTING",
		Args: []string{"-o", uplink, "-j", "MASQUERADE"},
	}
	if err := ctl.FirewallEnsureRule(masq6); err != nil {
		return "IPv6 masquerade could not be enabled automatically", nil
	}

	return "", nil
}

func disableExitNodeSharingOS(tunName string) error {
	var firstErr error

	if err := ctl.IPForwardingSet(false); err != nil {
		firstErr = err
	}

	uplink, _, err := ctl.RouteGetDefault()
	if err != nil {
		return fmt.Errorf("detect default route: %w", err)
	}

	masq := netctl.FirewallRule{
		Table: "nat", Chain: "POSTROUTING",
		Args: []string{"-o", uplink, "-j", "MASQUERADE"},
	}
	if err := ctl.FirewallDeleteRule(masq); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}
