package device

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestEncodeLocalAccessAdvertisementRoundTrip(t *testing.T) {
	t.Parallel()

	payload, err := EncodeLocalAccessAdvertisement([]string{
		"192.168.50.7/24",
		"10.23.0.0/16",
		"192.168.50.0/24",
		"10.23.4.5/32",
	})
	if err != nil {
		t.Fatalf("EncodeLocalAccessAdvertisement() error = %v", err)
	}
	if got := TUNControlAction(payload[0]); got != TUNControlActionSetLocalAccessRoutes {
		t.Fatalf("action = %v, want %v", got, TUNControlActionSetLocalAccessRoutes)
	}
	prefixes, err := decodeLocalAccessRoutes(payload, 1)
	if err != nil {
		t.Fatalf("decodeLocalAccessRoutes() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.23.0.0/16"),
		netip.MustParsePrefix("10.23.4.5/32"),
		netip.MustParsePrefix("192.168.50.0/24"),
	}
	if !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("decoded routes = %v, want %v", prefixes, want)
	}
}

func TestEncodeLocalAccessAdvertisementRejectsUnsafeRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route string
	}{
		{name: "public network", route: "203.0.113.0/24"},
		{name: "default route", route: "0.0.0.0/0"},
		{name: "IPv6", route: "fd00::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := EncodeLocalAccessAdvertisement([]string{tt.route}); err == nil {
				t.Fatalf("EncodeLocalAccessAdvertisement(%q) unexpectedly succeeded", tt.route)
			}
		})
	}
}

func TestSelectPrivateLANRoutes(t *testing.T) {
	t.Parallel()

	candidates := []localNetworkCandidate{
		{InterfaceName: "br-lan", Flags: net.FlagUp, Prefix: netip.MustParsePrefix("192.168.8.7/24")},
		{InterfaceName: "eth1", Flags: net.FlagUp, Prefix: netip.MustParsePrefix("10.12.0.4/16")},
		{InterfaceName: "wantastic0", Flags: net.FlagUp, Prefix: netip.MustParsePrefix("10.200.0.5/24")},
		{InterfaceName: "lo", Flags: net.FlagUp | net.FlagLoopback, Prefix: netip.MustParsePrefix("127.0.0.1/8")},
		{InterfaceName: "eth2", Flags: net.FlagUp, Prefix: netip.MustParsePrefix("198.51.100.10/24")},
		{InterfaceName: "ppp0", Flags: net.FlagUp | net.FlagPointToPoint, Prefix: netip.MustParsePrefix("172.16.5.1/24")},
		{InterfaceName: "eth3", Flags: 0, Prefix: netip.MustParsePrefix("192.168.9.1/24")},
	}

	want := []string{"10.12.0.0/16", "192.168.8.0/24"}
	if got := selectPrivateLANRoutes(candidates, "wantastic0"); !reflect.DeepEqual(got, want) {
		t.Fatalf("selectPrivateLANRoutes() = %v, want %v", got, want)
	}
}

func TestLocalAccessRouteUpdateRoundTrip(t *testing.T) {
	t.Parallel()

	var owner [32]byte
	owner[0] = 0x12
	owner[31] = 0x34
	routes := []netip.Prefix{netip.MustParsePrefix("192.168.44.0/24")}
	payload, err := encodeLocalAccessRouteUpdate(owner, routes)
	if err != nil {
		t.Fatalf("encodeLocalAccessRouteUpdate() error = %v", err)
	}
	gotOwner, gotRoutes, err := decodeLocalAccessRouteUpdate(payload)
	if err != nil {
		t.Fatalf("decodeLocalAccessRouteUpdate() error = %v", err)
	}
	if gotOwner != owner || !reflect.DeepEqual(gotRoutes, routes) {
		t.Fatalf("decoded update = (%x, %v), want (%x, %v)", gotOwner, gotRoutes, owner, routes)
	}

	removal := encodeLocalAccessRouteRemoval(owner)
	gotOwner, err = decodeLocalAccessRouteRemoval(removal)
	if err != nil || gotOwner != owner {
		t.Fatalf("decoded removal = (%x, %v), want (%x, nil)", gotOwner, err, owner)
	}
}

func TestDecodeLocalAccessSnapshot(t *testing.T) {
	t.Parallel()

	var owner [32]byte
	owner[0] = 0x42
	payload := make([]byte, 40)
	payload[0] = byte(TUNControlActionSyncLocalAccessRoutes)
	payload[1] = 1
	copy(payload[2:34], owner[:])
	payload[34] = 1
	payload[35] = 24
	copy(payload[36:40], []byte{192, 168, 80, 9})

	got, err := decodeLocalAccessSnapshot(payload)
	if err != nil {
		t.Fatalf("decodeLocalAccessSnapshot() error = %v", err)
	}
	want := map[[32]byte][]string{owner: {"192.168.80.0/24"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %v, want %v", got, want)
	}

	empty, err := decodeLocalAccessSnapshot([]byte{byte(TUNControlActionSyncLocalAccessRoutes), 0})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty snapshot = (%v, %v), want empty map", empty, err)
	}
}

func TestLocalAccessSourceRoutes(t *testing.T) {
	t.Parallel()

	want := []string{"10.0.0.0/8", "172.20.0.0/16"}
	got := localAccessSourceRoutes([]string{
		"0.0.0.0/0",
		"10.0.0.0/8",
		"172.20.1.1/16",
		"203.0.113.0/24",
		"fd00::/64",
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localAccessSourceRoutes() = %v, want %v", got, want)
	}
}

func TestRouteOverlapsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		route      string
		candidates []string
		want       bool
	}{
		{name: "same LAN", route: "192.168.1.0/24", candidates: []string{"192.168.1.0/24"}, want: true},
		{name: "broader local LAN", route: "10.20.0.0/16", candidates: []string{"10.0.0.0/8"}, want: true},
		{name: "different LAN", route: "192.168.2.0/24", candidates: []string{"192.168.1.0/24"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := routeOverlapsAny(tt.route, tt.candidates); got != tt.want {
				t.Fatalf("routeOverlapsAny(%q, %v) = %v, want %v", tt.route, tt.candidates, got, tt.want)
			}
		})
	}
}
