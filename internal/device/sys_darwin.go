//go:build darwin
// +build darwin

package device

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
)

// setupTUNInterface configures the TUN interface with the assigned IP address
func setupTUNInterface(tunName string, addrs []netip.Prefix) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses provided for tun interface")
	}

	for _, addr := range addrs {
		if addr.Addr().Is4() {
			ipStr := addr.Addr().String()
			log.Printf("[TUN] Assigning IPv4 %s to interface %s", ipStr, tunName)
			// macOS requires a point-to-point destination. We use the same IP for both sides.
			cmd := exec.Command("ifconfig", tunName, "inet", ipStr, ipStr, "netmask", "255.255.255.255", "up")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("ifconfig failed: %v, output: %s", err, out)
			}
		} else if addr.Addr().Is6() {
			ipStr := addr.Addr().String()
			prefixLen := fmt.Sprintf("prefixlen %d", addr.Bits())
			log.Printf("[TUN] Assigning IPv6 %s to interface %s", ipStr, tunName)
			cmd := exec.Command("ifconfig", tunName, "inet6", ipStr, prefixLen, "up")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("ifconfig ipv6 failed: %v, output: %s", err, out)
			}
		}
	}
	return nil
}

// addRouteOS adds a system route dynamically pointing to the TUN interface
func addRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid network prefix %s: %w", network, err)
	}

	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}

	log.Printf("[TUN] Adding macOS route %s via %s", network, tunName)
	cmd := exec.Command("route", "-q", "-n", "add", family, network, "-interface", tunName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add failed: %v, output: %s", err, out)
	}
	return nil
}

// removeRouteOS removes a system route dynamically
func removeRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid network prefix %s: %w", network, err)
	}

	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}

	log.Printf("[TUN] Removing macOS route %s via %s", network, tunName)
	cmd := exec.Command("route", "-q", "-n", "delete", family, network, "-interface", tunName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete failed: %v, output: %s", err, out)
	}
	return nil
}
