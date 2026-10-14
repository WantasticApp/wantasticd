package main

import (
	"errors"
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

func TestMakeTrayPresentation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     *StatusData
		err        error
		wantStatus string
		wantIP     string
		wantToggle string
		wantTip    string
	}{
		{
			name: "connected",
			status: &StatusData{
				Configured: true,
				Running:    true,
				IPs:        []string{"10.20.0.7"},
			},
			wantStatus: "Status: Connected",
			wantIP:     "IP: 10.20.0.7",
			wantToggle: "Disconnect",
			wantTip:    "Wantastic VPN — Connected — 10.20.0.7",
		},
		{
			name:       "disconnected",
			status:     &StatusData{Configured: true},
			wantStatus: "Status: Disconnected",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic VPN — Disconnected",
		},
		{
			name:       "not configured",
			status:     &StatusData{},
			wantStatus: "Status: Not configured",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic VPN — Not configured",
		},
		{
			name:       "unavailable",
			err:        errors.New("status failed"),
			wantStatus: "Status: Unavailable",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic VPN — Unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := makeTrayPresentation(tt.status, tt.err)
			if got.statusTitle != tt.wantStatus || got.ipTitle != tt.wantIP ||
				got.toggleTitle != tt.wantToggle || got.tooltip != tt.wantTip {
				t.Fatalf("makeTrayPresentation() = %#v", got)
			}
		})
	}
}
