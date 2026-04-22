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
	return nil
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
