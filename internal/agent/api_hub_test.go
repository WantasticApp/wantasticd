package agent

import (
	"testing"
	"time"

	"wantastic-agent/internal/device"
)

func TestHubHandshake(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p2p := device.PeerInfo{IsP2P: true, LastHandshake: now.Unix()}
	cases := []struct {
		name      string
		peers     []device.PeerInfo
		wantLast  int64
		wantAge   int64
		reachable bool
	}{
		{"no server peer", []device.PeerInfo{p2p}, 0, -1, false},
		{"never handshaked", []device.PeerInfo{p2p, {}}, 0, -1, false},
		{"fresh", []device.PeerInfo{p2p, {LastHandshake: now.Unix() - 30}}, now.Unix() - 30, 30, true},
		{"just before stale", []device.PeerInfo{{LastHandshake: now.Unix() - 179}}, now.Unix() - 179, 179, true},
		{"stale", []device.PeerInfo{{LastHandshake: now.Unix() - 180}}, now.Unix() - 180, 180, false},
		// A P2P peer's fresh handshake says nothing about the hub.
		{"stale hub, fresh p2p", []device.PeerInfo{p2p, {LastHandshake: now.Unix() - 600}}, now.Unix() - 600, 600, false},
		{"clock skew", []device.PeerInfo{{LastHandshake: now.Unix() + 5}}, now.Unix() + 5, 0, true},
	}
	for _, c := range cases {
		last, age, ok := hubHandshake(c.peers, now)
		if last != c.wantLast || age != c.wantAge || ok != c.reachable {
			t.Errorf("%s: got (%d, %d, %v), want (%d, %d, %v)", c.name, last, age, ok, c.wantLast, c.wantAge, c.reachable)
		}
	}
}
