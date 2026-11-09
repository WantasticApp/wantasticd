//go:build windows
// +build windows

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

// setTUNMTUOS applies the tunnel MTU to the Windows IP interface. Wintun
// advertises a 65535-byte link MTU and wireguard-go's MTU is only reported
// internally, so without this Windows sends full 1500-byte segments (TCP
// MSS 65495) into a tunnel that carries ~1420: large transfers stall behind
// fragmentation or a PMTUD black hole, worst through an exit node.
func setTUNMTUOS(tunName string, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	log.Printf("[TUN] Setting MTU %d on interface %s", mtu, tunName)
	return ctl.LinkSetMTU(tunName, mtu)
}

func addRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid prefix %s: %w", network, err)
	}
	prefix = prefix.Masked()
	log.Printf("[TUN] Adding route %s via %s", prefix, tunName)
	return ctl.RouteReplace(tunName, prefix)
}

func removeRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid prefix %s: %w", network, err)
	}
	prefix = prefix.Masked()
	log.Printf("[TUN] Removing route %s via %s", prefix, tunName)
	return ctl.RouteDel(tunName, prefix)
}
