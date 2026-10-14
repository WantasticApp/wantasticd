package main

import (
	"runtime"
	"testing"

	"wantastic-agent/internal/device"
)

func TestPeerConnection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		peer device.PeerInfo
		want string
	}{
		{name: "direct", peer: device.PeerInfo{IsP2P: true, P2PState: "established"}, want: "direct"},
		{name: "trying", peer: device.PeerInfo{IsP2P: true, P2PState: "trying"}, want: "trying"},
		{name: "relay fallback", peer: device.PeerInfo{IsP2P: false, P2PState: "failed"}, want: "relay"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := peerConnection(tt.peer); got != tt.want {
				t.Fatalf("peerConnection() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMagicName(t *testing.T) {
	t.Parallel()
	if got := magicName(device.PeerInfo{Hostname: "Office AP #1", AssignedIP: "10.8.0.7"}); got != "office-ap-1.wantastic" {
		t.Fatalf("magicName(hostname) = %q", got)
	}
	if got := magicName(device.PeerInfo{AssignedIP: "10.8.0.7"}); got != "node-10-8-0-7.wantastic" {
		t.Fatalf("magicName(ip) = %q", got)
	}
}

func TestPingArgsKeepsTargetAsOneArgument(t *testing.T) {
	t.Parallel()
	args := pingArgs("10.8.0.7")
	if got := args[len(args)-1]; got != "10.8.0.7" {
		t.Fatalf("last ping argument = %q", got)
	}
	if runtime.GOOS != "windows" && len(args) < 5 {
		t.Fatalf("pingArgs() = %v", args)
	}
}
