package device

import (
	"net"
	"strconv"
	"time"
)

// WireGuard overhead on the outer path: IP header + UDP (8) + WireGuard
// transport header and tag (32).
const (
	wireGuardOverheadIPv4 = 20 + 8 + 32
	wireGuardOverheadIPv6 = 40 + 8 + 32
	minTunnelMTU          = 1280
)

// effectiveTunnelMTU lowers the configured tunnel MTU so tunnel packets fit
// the link that carries them to the hub. On PPPoE (1492), LTE (often
// 1400-1450) or nested tunnels, a fixed 1420 made every full-size packet
// fragment or vanish. It never raises the configured value and never goes
// below 1280 (the IPv6 minimum). linkMTU 0 means unknown.
func effectiveTunnelMTU(configured, linkMTU int, outerIPv6 bool) int {
	if configured <= 0 {
		configured = 1420
	}
	if linkMTU <= 0 {
		return configured
	}
	overhead := wireGuardOverheadIPv4
	if outerIPv6 {
		overhead = wireGuardOverheadIPv6
	}
	fit := linkMTU - overhead
	if fit < minTunnelMTU {
		fit = minTunnelMTU
	}
	if fit < configured {
		return fit
	}
	return configured
}

// hubLinkMTU returns the MTU of the interface the system would use to reach
// the hub, and whether that path is IPv6. Connecting a UDP socket only asks
// the kernel for a route; nothing is sent. It returns 0 when unknown.
func hubLinkMTU(endpoint string, port int) (int, bool) {
	if endpoint == "" {
		return 0, false
	}
	target := endpoint
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		if port <= 0 {
			port = 51820
		}
		target = net.JoinHostPort(endpoint, strconv.Itoa(port))
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("udp", target)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return 0, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(local.IP) {
				return iface.MTU, local.IP.To4() == nil
			}
		}
	}
	return 0, local.IP.To4() == nil
}
