package device

import (
	"testing"
	"time"
)

func TestP2PControlNoiseTransportRoundTrip(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[1].dev, mustSinglePeer(t, pair[1].dev).handshake.remoteStatic)
	pair[1].dev.p2pClient.Store(client)
	pair.Send(t, Ping, nil)

	want := &P2PMessage{Subtype: P2PSubtypePeerList, TargetID: 42, Payload: []byte{1, 2, 3}}
	mustSinglePeer(t, pair[0].dev).SendP2PControl(want.Encode())
	select {
	case event := <-client.controlQueue:
		if event.message == nil || event.message.Subtype != want.Subtype || event.message.TargetID != want.TargetID {
			t.Fatalf("P2P control message = %+v, want subtype %d target %d", event.message, want.Subtype, want.TargetID)
		}
		if len(event.message.Payload) != len(want.Payload) {
			t.Fatalf("P2P payload length = %d, want %d", len(event.message.Payload), len(want.Payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for authenticated P2P control payload")
	}
}
