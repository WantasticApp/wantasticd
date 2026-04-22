//go:build linux
// +build linux

package device

import (
	"fmt"
	"log"
	"net/netip"

	"wantastic-agent/internal/netctl"
)

var ctl = netctl.New()

func setupTUNInterface(tunName string, addrs []netip.Prefix) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses provided for tun interface")
	}

	if err := ctl.LinkSetUp(tunName); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	for _, addr := range addrs {
		log.Printf("[TUN] Assigning IP %s to interface %s", addr.String(), tunName)
		if err := ctl.AddrAdd(tunName, addr); err != nil {
			return fmt.Errorf("add addr %s: %w", addr, err)
		}
	}

	// Ensure the firewall allows traffic on the WireGuard TUN interface.
	// On OpenWrt/embedded Linux, the default fw3/fw4 drops traffic on interfaces
	// not assigned to a zone. These rules allow all tunnel traffic (ICMP, TCP, UDP).
	allowTUNFirewall(tunName)

	return nil
}

// allowTUNFirewall adds iptables INPUT/OUTPUT ACCEPT rules for the TUN interface.
// Idempotent — uses netctl.FirewallEnsureRule which checks before adding.
// Non-fatal: if iptables is unavailable (e.g. nftables-only system), we log and continue.
func allowTUNFirewall(tunName string) {
	rules := []netctl.FirewallRule{
		{Table: "filter", Chain: "INPUT", Args: []string{"-i", tunName, "-j", "ACCEPT"}},
		{Table: "filter", Chain: "OUTPUT", Args: []string{"-o", tunName, "-j", "ACCEPT"}},
		{Table: "filter", Chain: "FORWARD", Args: []string{"-i", tunName, "-j", "ACCEPT"}},
		{Table: "filter", Chain: "FORWARD", Args: []string{"-o", tunName, "-j", "ACCEPT"}},
	}
	for _, rule := range rules {
		if err := ctl.FirewallEnsureRule(rule); err != nil {
			log.Printf("[TUN] Warning: could not add firewall rule (%s %s %v): %v", rule.Table, rule.Chain, rule.Args, err)
		}
	}
}

func addRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid prefix %s: %w", network, err)
	}
	log.Printf("[TUN] Adding Linux route %s via %s", network, tunName)
	return ctl.RouteReplace(tunName, prefix)
}

func removeRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid prefix %s: %w", network, err)
	}
	log.Printf("[TUN] Removing Linux route %s via %s", network, tunName)
	return ctl.RouteDel(tunName, prefix)
}
