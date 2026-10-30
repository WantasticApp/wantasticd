package runner

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

func TestDeriveTrayViewStates(t *testing.T) {
	if v := deriveTrayView(nil, trafficSample{}, trafficSample{}); v.State != trayDaemonDown || v.ToggleEnabled {
		t.Fatalf("daemon down: %+v", v)
	}
	down := &agent.StatusResponse{Running: true, DeviceRunning: false}
	if v := deriveTrayView(down, trafficSample{}, trafficSample{}); v.State != trayDisconnected || v.ToggleTitle != "Connect" || !v.ToggleEnabled {
		t.Fatalf("disconnected: %+v", v)
	}
	up := &agent.StatusResponse{
		Running: true, DeviceRunning: true, IPs: []string{"10.255.255.44/32"},
		RxBytes: 3 << 20, TxBytes: 1 << 20, UptimeSec: 3700, ServerEndpoint: "172.239.44.171:51820",
		Peers: []device.PeerInfo{
			{PublicKey: "srv"},
			{IsP2P: true, P2PState: "established", Endpoint: "1.2.3.4:5", AssignedIP: "10.255.255.36"},
			{IsP2P: true, P2PState: "failed", AssignedIP: "10.255.255.38"},
		},
	}
	t0 := time.Unix(1000, 0)
	v := deriveTrayView(up, trafficSample{rx: 1 << 20, tx: 1 << 20, at: t0}, trafficSample{rx: 3 << 20, tx: 1 << 20, at: t0.Add(2 * time.Second)})
	if v.State != trayConnected || v.ToggleTitle != "Disconnect" || v.Address != "IP: 10.255.255.44" {
		t.Fatalf("connected: %+v", v)
	}
	if v.Rate != "Speed: ↓ 1.0 MiB/s  ↑ 0 B/s" || v.PeersTitle != "Peers: 1 direct, 1 relay" || v.Details != "Up 1h01m · server 172.239.44.171:51820" {
		t.Fatalf("details: %+v", v)
	}
	up.ExitNodeState = &device.ExitNodeStatus{Using: &device.ExitUse{IP: "10.255.255.36", Hostname: "mini", State: "active"}}
	if v := deriveTrayView(up, trafficSample{}, trafficSample{}); v.State != trayExitActive || !strings.Contains(v.Header, "mini") || v.Rate != "Speed: —" {
		t.Fatalf("exit active: %+v", v)
	}
}

func TestTrafficRateCounterReset(t *testing.T) {
	t0 := time.Unix(1000, 0)
	if got := trafficRate(trafficSample{rx: 500, at: t0}, trafficSample{rx: 10, at: t0.Add(time.Second)}); got != "—" {
		t.Fatalf("reset counters: %q", got)
	}
}

func TestPeerEntriesDirectFirstWithLatency(t *testing.T) {
	now := time.Unix(10_000, 0)
	peers := []device.PeerInfo{
		{PublicKey: "server"},
		{IsP2P: true, P2PState: "failed", AssignedIP: "10.0.0.2", Hostname: "relay-box"},
		{IsP2P: true, P2PState: "established", Endpoint: "1.2.3.4:5", AssignedIP: "10.0.0.3", LastHandshake: now.Unix() - 21},
	}
	got := buildPeerMenuEntries(peers, map[string]agent.PingResult{
		"10.0.0.3": {IP: "10.0.0.3", Received: 3, AvgMs: 171.4},
		"10.0.0.2": {IP: "10.0.0.2"},
	}, now)
	if len(got) != 2 {
		t.Fatalf("server must not be listed: %+v", got)
	}
	if got[0].Title != "● 10.0.0.3 · direct · 171 ms" || got[0].CopyText != "10.0.0.3" || !strings.Contains(got[0].Tooltip, "Handshake: 21s ago") {
		t.Fatalf("direct: %+v", got[0])
	}
	if got[1].Title != "◌ relay-box (10.0.0.2) · relay · no reply" {
		t.Fatalf("relay: %+v", got[1])
	}
}

func TestPingSummary(t *testing.T) {
	pr := &agent.PingResponse{Results: []agent.PingResult{{Received: 3, AvgMs: 100}, {Received: 3, AvgMs: 200}, {}}}
	if got := pingSummary(pr, nil); got != "Ping: 2/3 peers answered · avg 150 ms" {
		t.Fatal(got)
	}
	if got := pingSummary(&agent.PingResponse{}, nil); got != "Ping: no peers to ping" {
		t.Fatal(got)
	}
}

func TestTrayIcons(t *testing.T) {
	for s := range trayStateColors {
		data := trayIconPNG(s, 32)
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("state %d: %v", s, err)
		}
		// Centre of the disc is opaque, the corner transparent.
		if _, _, _, a := img.At(16, 8).RGBA(); a == 0 {
			t.Fatalf("state %d: disc missing", s)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Fatalf("state %d: corner not transparent", s)
		}
		ico := pngToICO(data, 32)
		if !bytes.Equal(ico[:6], []byte{0, 0, 1, 0, 1, 0}) || ico[6] != 32 || !bytes.Equal(ico[22:], data) {
			t.Fatalf("state %d: bad ico header % x", s, ico[:22])
		}
	}
}
