//go:build linux
// +build linux

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

	// Wait for the interface to properly show up (WireGuard creates it, but it might flutter)
	// Usually ip link set up does this
	cmd := exec.Command("ip", "link", "set", "dev", tunName, "up")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set up failed: %v, output: %s", err, out)
	}

	for _, addr := range addrs {
		addrStr := addr.String()
		log.Printf("[TUN] Assigning IP %s to interface %s", addrStr, tunName)
		cmd := exec.Command("ip", "addr", "add", addrStr, "dev", tunName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// ignore "File exists" if it was already assigned
			return fmt.Errorf("ip addr add failed: %v, output: %s", err, out)
		}
	}
	return nil
}

// addRouteOS adds a system route dynamically pointing to the TUN interface
func addRouteOS(tunName string, network string) error {
	log.Printf("[TUN] Adding Linux route %s via %s", network, tunName)
	cmd := exec.Command("ip", "route", "add", network, "dev", tunName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route add failed: %v, output: %s", err, out)
	}
	return nil
}

// removeRouteOS removes a system route dynamically
func removeRouteOS(tunName string, network string) error {
	log.Printf("[TUN] Removing Linux route %s via %s", network, tunName)
	cmd := exec.Command("ip", "route", "del", network, "dev", tunName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route del failed: %v, output: %s", err, out)
	}
	return nil
}
