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
	if v := deriveTrayView(nil, gatewayLatency{}); v.State != trayDaemonDown || v.ToggleEnabled || v.Latency != "Latency: —" {
		t.Fatalf("daemon down: %+v", v)
	}
	down := &agent.StatusResponse{Running: true, DeviceRunning: false}
	// A stale measurement never shows while the tunnel is down.
	if v := deriveTrayView(down, gatewayLatency{Measured: true, Replied: true, Ms: 12}); v.State != trayDisconnected || v.ToggleTitle != "Connect" || !v.ToggleEnabled || v.Latency != "Latency: —" {
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
	v := deriveTrayView(up, gatewayLatency{Measured: true, Replied: true, Ms: 23.4})
	if v.State != trayConnected || v.ToggleTitle != "Disconnect" || v.Address != "IP: 10.255.255.44" {
		t.Fatalf("connected: %+v", v)
	}
	wantTraffic := "Traffic: ↓ " + trayBytes(3<<20) + "  ↑ " + trayBytes(1<<20)
	if v.Latency != "Latency: 23 ms" || v.Traffic != wantTraffic || v.PeersTitle != "Peers: 1 direct, 1 relay" || v.Details != "Up 1h01m · server 172.239.44.171:51820" {
		t.Fatalf("details: %+v", v)
	}
	if v := deriveTrayView(up, gatewayLatency{}); v.Latency != "Latency: —" {
		t.Fatalf("not measured yet: %q", v.Latency)
	}
	if v := deriveTrayView(up, gatewayLatency{Measured: true}); v.Latency != "Latency: no reply" {
		t.Fatalf("no reply: %q", v.Latency)
	}
	up.ExitNodeState = &device.ExitNodeStatus{Using: &device.ExitUse{IP: "10.255.255.36", Hostname: "mini", State: "active"}}
	if v := deriveTrayView(up, gatewayLatency{Measured: true, Replied: true, Ms: 40}); v.State != trayExitActive || !strings.Contains(v.Header, "mini") || v.Latency != "Latency: 40 ms" {
		t.Fatalf("exit active: %+v", v)
	}
}

func TestTrayBytesFormat(t *testing.T) {
	fs := string(figureSpace)
	cases := map[uint64]string{
		0:             fs + fs + fs + fs + "0 B", // mantissa right-aligned in a 5-wide field
		512:           fs + fs + "512 B",         // exact bytes, no decimal
		1023:          fs + "1023 B",             // last byte value before KiB (binary boundary)
		1024:          fs + fs + "1.0 KiB",       // 1024-based: exactly 1.0 KiB, not "1.0 KB"
		1536:          fs + fs + "1.5 KiB",       // 1.5 * 1024
		1 << 20:       fs + fs + "1.0 MiB",       // 1 MiB
		1 << 30:       fs + fs + "1.0 GiB",       // 1 GiB
		3<<30 + 1<<29: fs + fs + "3.5 GiB",       // large, multi-GiB
	}
	for n, want := range cases {
		if got := trayBytes(n); got != want {
			t.Errorf("trayBytes(%d) = %q, want %q", n, got, want)
		}
	}
	// Every result ends in a binary unit with the "iB" suffix (never a decimal
	// "KB"/"MB"), and a rate simply appends "/s" — bytes per second, not bps.
	for _, n := range []uint64{0, 1024, 1 << 40} {
		if s := trayBytes(n); !strings.HasSuffix(s, " B") && !strings.Contains(s, "iB") {
			t.Errorf("trayBytes(%d) = %q: not a binary unit", n, s)
		}
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
	if got[0].Title != "( ● 10.0.0.3 · direct · 171 ms )" || got[0].VPNIP != "10.0.0.3" || got[0].PublicIP != "1.2.3.4" || !strings.Contains(got[0].Detail, "Handshake 21s ago") || got[0].Tooltip != T("peer.tooltip") {
		t.Fatalf("direct: %+v", got[0])
	}
	if got[1].Title != "( ◌ relay-box · relay · no reply )" || got[1].VPNIP != "10.0.0.2" || got[1].PublicIP != "" {
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
		// The logo's top is opaque, the corner transparent.
		if _, _, _, a := img.At(16, 8).RGBA(); a == 0 {
			t.Fatalf("state %d: logo missing", s)
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

func TestTrayViewNotSignedIn(t *testing.T) {
	st := &agent.StatusResponse{Claim: &agent.ClaimStatus{URL: "https://wantastic.app/claim?key=abc", PublicKey: "abc"}}
	v := deriveTrayView(st, gatewayLatency{})
	if v.State != trayNotSignedIn || v.LoginURL != st.Claim.URL || v.ToggleEnabled {
		t.Fatalf("not signed in: %+v", v)
	}
	if m := deriveExitMenu(st); m.OfferTooltip != "Log in first" {
		t.Errorf("exit menu while not signed in: %+v", m)
	}
	if v := deriveTrayView(&agent.StatusResponse{Running: true, DeviceRunning: true}, gatewayLatency{}); v.LoginURL != "" {
		t.Errorf("signed-in device offers Log in: %+v", v)
	}
}

// TestTrayViewHubReachability covers the tunnel-up-but-offline state: it is
// driven by the daemon's hub handshake facts (menu open or not) and by
// consecutive unanswered gateway probes while the menu is open.
func TestTrayViewHubReachability(t *testing.T) {
	yes, no := true, false
	status := func(reachable *bool, last, age int64, exit bool) *agent.StatusResponse {
		st := &agent.StatusResponse{
			Running: true, DeviceRunning: true, IPs: []string{"10.255.255.44/32"},
			UptimeSec: 3700, ServerEndpoint: "172.239.44.171:51820",
			HubReachable: reachable, HubLastHandshake: last, HubHandshakeAgeSec: age,
		}
		if exit {
			st.ExitNodeState = &device.ExitNodeStatus{Using: &device.ExitUse{IP: "10.255.255.36", Hostname: "mini", State: "active"}}
		}
		return st
	}
	replied := gatewayLatency{Measured: true, Replied: true, Ms: 23}
	cases := []struct {
		name       string
		st         *agent.StatusResponse
		lat        gatewayLatency
		want       trayState
		header     string
		details    string
		latencyRow string
	}{
		{"fresh handshake", status(&yes, 1000, 30, false), gatewayLatency{}, trayConnected,
			"● Connected", "Up 1h01m · server 172.239.44.171:51820", "Latency: —"},
		{"fresh handshake, gateway replies", status(&yes, 1000, 30, false), replied, trayConnected,
			"● Connected", "Up 1h01m · server 172.239.44.171:51820", "Latency: 23 ms"},
		{"stale handshake", status(&no, 1000, 250, false), gatewayLatency{}, trayNoInternet,
			"○ No internet · reconnecting…", "No answer from the server for 4m10s · server 172.239.44.171:51820", "Latency: —"},
		{"stale handshake beats exit node", status(&no, 1000, 250, true), gatewayLatency{}, trayNoInternet,
			"○ No internet · reconnecting…", "No answer from the server for 4m10s · server 172.239.44.171:51820", "Latency: —"},
		{"never handshaked", status(&no, 0, -1, false), gatewayLatency{}, trayNoInternet,
			"○ Connecting…", "Waiting for the server to answer · server 172.239.44.171:51820", "Latency: —"},
		// One lost echo is not enough to downgrade.
		{"gateway one miss", status(&yes, 1000, 30, false), gatewayLatency{Measured: true, Misses: 1}, trayConnected,
			"● Connected", "Up 1h01m · server 172.239.44.171:51820", "Latency: no reply"},
		{"gateway no reply twice", status(&yes, 1000, 30, false), gatewayLatency{Measured: true, Misses: 2}, trayNoInternet,
			"○ No internet · reconnecting…", "Up 1h01m · server 172.239.44.171:51820", "Latency: no reply"},
		// Recovery is immediate: one reply (Misses reset) and a fresh handshake.
		{"recovered", status(&yes, 1100, 2, false), replied, trayConnected,
			"● Connected", "Up 1h01m · server 172.239.44.171:51820", "Latency: 23 ms"},
		{"recovered via exit", status(&yes, 1100, 2, true), replied, trayExitActive,
			"● Connected via exit mini", "Up 1h01m · server 172.239.44.171:51820", "Latency: 23 ms"},
		// An older daemon does not report reachability: never downgrade on it.
		{"old daemon", status(nil, 0, 0, false), gatewayLatency{}, trayConnected,
			"● Connected", "Up 1h01m · server 172.239.44.171:51820", "Latency: —"},
	}
	for _, c := range cases {
		v := deriveTrayView(c.st, c.lat)
		if v.State != c.want || v.Header != c.header || v.Details != c.details || v.Latency != c.latencyRow {
			t.Errorf("%s: got state %d header %q details %q latency %q; want %d %q %q %q",
				c.name, v.State, v.Header, v.Details, v.Latency, c.want, c.header, c.details, c.latencyRow)
		}
		if !v.ToggleEnabled || v.ToggleTitle != "Disconnect" || !tunnelUp(v.State) {
			t.Errorf("%s: an up tunnel must offer Disconnect: %+v", c.name, v)
		}
		if v.State == trayNoInternet && !strings.Contains(v.Tooltip, "no internet") {
			t.Errorf("%s: tooltip %q", c.name, v.Tooltip)
		}
	}
}
