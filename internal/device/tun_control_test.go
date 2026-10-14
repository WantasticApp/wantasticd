package device

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestEncodeExitNodeSelectionTUNControlDisable(t *testing.T) {
	data, err := EncodeExitNodeSelectionTUNControl("none")
	if err != nil {
		t.Fatalf("EncodeExitNodeSelectionTUNControl returned error: %v", err)
	}
	if len(data) != tunControlPeerPayloadSize {
		t.Fatalf("got payload length %d, want %d", len(data), tunControlPeerPayloadSize)
	}
	if got := TUNControlAction(data[0]); got != TUNControlActionRequestExitNodeRouting {
		t.Fatalf("got action %v, want %v", got, TUNControlActionRequestExitNodeRouting)
	}
	if !bytes.Equal(data[1:], make([]byte, 32)) {
		t.Fatalf("expected zeroed peer payload for disable request, got %x", data[1:])
	}
}

func TestEncodeExitNodeSelectionTUNControlPeer(t *testing.T) {
	const peerPubKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	data, err := EncodeExitNodeSelectionTUNControl(peerPubKeyHex)
	if err != nil {
		t.Fatalf("EncodeExitNodeSelectionTUNControl returned error: %v", err)
	}
	if len(data) != tunControlPeerPayloadSize {
		t.Fatalf("got payload length %d, want %d", len(data), tunControlPeerPayloadSize)
	}
	if got := TUNControlAction(data[0]); got != TUNControlActionRequestExitNodeRouting {
		t.Fatalf("got action %v, want %v", got, TUNControlActionRequestExitNodeRouting)
	}

	decoded, err := decodeTUNControlPeerKey(data)
	if err != nil {
		t.Fatalf("decodeTUNControlPeerKey returned error: %v", err)
	}
	if got := decoded[0]; got != 0x00 || decoded[31] != 0xff {
		t.Fatalf("unexpected decoded key boundaries: %x ... %x", decoded[0], decoded[31])
	}
}

func TestEncodeExitNodeSelectionTUNControlInvalidPeer(t *testing.T) {
	if _, err := EncodeExitNodeSelectionTUNControl("not-hex"); err == nil {
		t.Fatal("expected invalid peer key error")
	}
}

func TestEffectiveExitRoutesDefaultsByAddressFamily(t *testing.T) {
	v4Routes, err := effectiveExitRoutes([]netip.Prefix{netip.MustParsePrefix("172.16.0.6/32")}, nil)
	if err != nil {
		t.Fatalf("effectiveExitRoutes(v4) returned error: %v", err)
	}
	if len(v4Routes) != 1 || v4Routes[0] != "0.0.0.0/0" {
		t.Fatalf("unexpected v4-only routes: %v", v4Routes)
	}

	dualRoutes, err := effectiveExitRoutes([]netip.Prefix{
		netip.MustParsePrefix("172.16.0.6/32"),
		netip.MustParsePrefix("fd7a:115c:a1e0::901:5582/48"),
	}, nil)
	if err != nil {
		t.Fatalf("effectiveExitRoutes(dual) returned error: %v", err)
	}
	if len(dualRoutes) != 2 || dualRoutes[0] != "0.0.0.0/0" || dualRoutes[1] != "::/0" {
		t.Fatalf("unexpected dual-stack routes: %v", dualRoutes)
	}
}

func TestCanonicalizeExitRoutesDeduplicatesAndMasks(t *testing.T) {
	routes, err := canonicalizeExitRoutes([]string{
		"10.0.0.1/24",
		"10.0.0.0/24",
		"  ::/0  ",
	})
	if err != nil {
		t.Fatalf("canonicalizeExitRoutes returned error: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("unexpected canonical route count: %v", routes)
	}
	if routes[0] != "10.0.0.0/24" || routes[1] != "::/0" {
		t.Fatalf("unexpected canonical routes: %v", routes)
	}
}
