package device

import (
	"net"
	"testing"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

func TestP2PObservedEndpoint(t *testing.T) {
	cases := []struct {
		addr net.UDPAddr
		want string
	}{
		{net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 41641}, "203.0.113.7:41641"},
		{net.UDPAddr{IP: net.IPv4zero, Port: 41641}, ""},
		{net.UDPAddr{IP: net.IPv4(203, 0, 113, 7)}, ""},
		{net.UDPAddr{}, ""},
	}
	for _, tc := range cases {
		if got := p2pObservedEndpoint(&wgdevice.DiscoveredPeer{ObservedAddr: tc.addr}); got != tc.want {
			t.Errorf("p2pObservedEndpoint(%v) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
