package device

import (
	"bytes"
	"testing"
	"time"
)

func TestTUNControlNoiseTransportRoundTrip(t *testing.T) {
	goroutineLeakCheck(t)

	pair := genTestPair(t, false)
	received := make(chan []byte, 1)
	pair[1].dev.SetTUNControlHandler(func(_ *Peer, payload []byte) {
		received <- payload
	})

	// Establish a session before sending the custom encrypted transport type.
	pair.Send(t, Ping, nil)

	want := []byte{1, 0xde, 0xad, 0xbe, 0xef}
	mustSinglePeer(t, pair[0].dev).SendTUNControl(want)

	select {
	case got := <-received:
		if !bytes.Equal(got, want) {
			t.Fatalf("TUN control payload = %x, want %x", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for authenticated TUN control payload")
	}

	select {
	case packet := <-pair[1].tun.Inbound:
		t.Fatalf("TUN control payload leaked into network TUN: %x", packet)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestConsumeTUNControlPayloadRejectsInvalidLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{name: "missing header", plaintext: []byte{1}},
		{name: "truncated payload", plaintext: []byte{4, 0, 1, 2}},
		{name: "over limit", plaintext: []byte{0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := consumeTUNControlPayload(tt.plaintext); err == nil {
				t.Fatal("consumeTUNControlPayload() unexpectedly succeeded")
			}
		})
	}
}
