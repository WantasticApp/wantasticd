package device

import (
	"net/netip"
	"testing"

	"wantastic-agent/internal/device/wireguard-go/conn"
)

// A frozen endpoint ignores the packet source; after EnableRoaming it follows.
func TestEnableRoamingLetsEndpointFollowPackets(t *testing.T) {
	peer := &Peer{}
	first := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("198.51.100.7:40000")}
	moved := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("198.51.100.7:41234")}
	peer.endpoint.val = first
	peer.endpoint.disableRoaming = true

	peer.SetEndpointFromPacket(moved)
	if peer.endpoint.val != conn.Endpoint(first) {
		t.Fatal("frozen endpoint moved")
	}
	peer.EnableRoaming()
	peer.SetEndpointFromPacket(moved)
	if peer.endpoint.val != conn.Endpoint(moved) {
		t.Fatal("endpoint did not follow the rebound NAT mapping")
	}
}
