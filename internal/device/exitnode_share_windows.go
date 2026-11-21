//go:build windows
// +build windows

package device

import (
	"fmt"
	"log"
	"net/netip"
)

// Windows has no NAT the agent can drive, so local access works like the
// Windows exit node: peers' packets to this host's LANs land in a userspace
// stack whose TCP and UDP forwarders re-open each flow from this host's own
// sockets, and replies return to the peer through WireGuard. Only packets
// from the overlay to the shared LAN subnets are taken; everything else is
// untouched.
func (d *Device) enableLocalAccessOS(tunName string, routes, sources []string) error {
	lan, err := parsePrefixes(routes)
	if err != nil {
		return err
	}
	src, err := parsePrefixes(sources)
	if err != nil {
		return err
	}
	ux, err := newUserspaceExit(d.config.Interface.MTU, d.injectOutbound)
	if err != nil {
		return fmt.Errorf("local access forwarder: %w", err)
	}
	if old := d.exitGuard.setLAN(ux, lan, src); old != nil {
		old.close()
	}
	log.Printf("[LAN] Sharing %v with the network through this host's sockets", routes)
	return nil
}

func (d *Device) disableLocalAccessOS(tunName string, routes, sources []string) error {
	if old := d.exitGuard.setLAN(nil, nil, nil); old != nil {
		old.close()
	}
	return nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("local access route %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return fmt.Errorf("use Device.enableLocalAccessOS on Windows")
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return nil
}
