//go:build darwin
// +build darwin

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
	log.Printf("[TUN] Adding route %s via %s", network, tunName)
	return ctl.RouteReplace(tunName, prefix)
}

func removeRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid prefix %s: %w", network, err)
	}
	log.Printf("[TUN] Removing route %s via %s", network, tunName)
	return ctl.RouteDel(tunName, prefix)
}
