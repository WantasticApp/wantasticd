//go:build linux

package device

import "wantastic-agent/internal/device/wireguard-go/tun"

// openExternalTUN wraps a descriptor from the platform. Unmonitored: an
// Android app may not open the netlink route socket the monitored variant
// listens on.
func openExternalTUN(fd int) (tun.Device, string, error) {
	return tun.CreateUnmonitoredTUNFromFD(fd)
}
