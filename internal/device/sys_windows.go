//go:build windows
// +build windows

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
			log.Printf("[TUN] Assigning IPv4 %s to Windows interface %s", ipStr, tunName)
			// netsh interface ipv4 set address name="Wantastic" static 10.0.0.2 255.255.255.255
			cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
				fmt.Sprintf("name=\"%s\"", tunName),
				"static", ipStr, "255.255.255.255")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("netsh address add failed: %v, output: %s", err, out)
			}
		} else if addr.Addr().Is6() {
			ipStr := addr.Addr().String()
			log.Printf("[TUN] Assigning IPv6 %s to Windows interface %s", ipStr, tunName)
			cmd := exec.Command("netsh", "interface", "ipv6", "add", "address",
				fmt.Sprintf("interface=\"%s\"", tunName),
				fmt.Sprintf("address=%s", addr.String()))
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("netsh address ipv6 add failed: %v, output: %s", err, out)
			}
		}
	}
	return nil
}

// addRouteOS adds a system route dynamically pointing to the TUN interface
func addRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid network prefix: %v", err)
	}

	log.Printf("[TUN] Adding Windows route %s", network)

	// netsh interface ip add route prefix interface metric
	family := "ipv4"
	if prefix.Addr().Is6() {
		family = "ipv6"
	}

	cmd := exec.Command("netsh", "interface", family, "add", "route", network,
		fmt.Sprintf("\"%s\"", tunName), "metric=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Windows 'route add' could also be used: route add 10.0.0.0 mask 255.255.255.255 0.0.0.0 IF x
		return fmt.Errorf("netsh route add failed: %v, output: %s", err, out)
	}
	return nil
}

// removeRouteOS removes a system route dynamically
func removeRouteOS(tunName string, network string) error {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("invalid network prefix: %v", err)
	}

	family := "ipv4"
	if prefix.Addr().Is6() {
		family = "ipv6"
	}

	log.Printf("[TUN] Removing Windows route %s", network)
	cmd := exec.Command("netsh", "interface", family, "delete", "route", network,
		fmt.Sprintf("\"%s\"", tunName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh route delete failed: %v, output: %s", err, out)
	}
	return nil
}
