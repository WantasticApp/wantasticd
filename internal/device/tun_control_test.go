package device

import (
	"bytes"
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
