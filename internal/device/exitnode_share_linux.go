//go:build linux
// +build linux

package device

import (
	"fmt"

	"wantastic-agent/internal/netctl"
)

const localAccessFirewallMark = "0x57540000/0xffff0000"

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

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	if err := ctl.IPForwardingSet(true); err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}

	added := make([]netctl.FirewallRule, 0, len(routes)*len(sources)*2)
	for _, source := range sources {
		for _, route := range routes {
			markRule := netctl.FirewallRule{
				Table: "mangle",
				Chain: "PREROUTING",
				Args: []string{
					"-i", tunName, "-s", source, "-d", route,
					"-j", "MARK", "--set-xmark", localAccessFirewallMark,
				},
			}
			if err := ctl.FirewallEnsureRule(markRule); err != nil {
				for i := len(added) - 1; i >= 0; i-- {
					_ = ctl.FirewallDeleteRule(added[i])
				}
				return fmt.Errorf("mark local-access traffic from %s to %s: %w", source, route, err)
			}
			added = append(added, markRule)

			masqueradeRule := netctl.FirewallRule{
				Table: "nat",
				Chain: "POSTROUTING",
				Args: []string{
					"-m", "mark", "--mark", localAccessFirewallMark,
					"-s", source, "-d", route, "-j", "MASQUERADE",
				},
			}
			if err := ctl.FirewallEnsureRule(masqueradeRule); err != nil {
				for i := len(added) - 1; i >= 0; i-- {
					_ = ctl.FirewallDeleteRule(added[i])
				}
				return fmt.Errorf("enable local-access SNAT from %s to %s: %w", source, route, err)
			}
			added = append(added, masqueradeRule)
		}
	}
	return nil
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	var firstErr error
	for _, source := range sources {
		for _, route := range routes {
			masqueradeRule := netctl.FirewallRule{
				Table: "nat",
				Chain: "POSTROUTING",
				Args: []string{
					"-m", "mark", "--mark", localAccessFirewallMark,
					"-s", source, "-d", route, "-j", "MASQUERADE",
				},
			}
			if err := ctl.FirewallDeleteRule(masqueradeRule); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("remove local-access SNAT from %s to %s: %w", source, route, err)
			}
			markRule := netctl.FirewallRule{
				Table: "mangle",
				Chain: "PREROUTING",
				Args: []string{
					"-i", tunName, "-s", source, "-d", route,
					"-j", "MARK", "--set-xmark", localAccessFirewallMark,
				},
			}
			if err := ctl.FirewallDeleteRule(markRule); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("remove local-access traffic mark from %s to %s: %w", source, route, err)
			}
		}
	}
	return firstErr
}
