package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

func TestHumanBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: got %s want %s", n, got, want)
		}
	}
}

func TestHumanDurationAndAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		12 * time.Second: "12s", 192 * time.Second: "3m12s",
		2*time.Hour + 5*time.Minute: "2h05m", 76 * time.Hour: "3d04h", -time.Second: "0s",
	} {
		if got := humanDuration(d); got != want {
			t.Errorf("%s: got %s want %s", d, got, want)
		}
	}
	now := time.Unix(1700000100, 0)
	if got := handshakeAge(1700000088, now); got != "12s ago" {
		t.Errorf("age: %s", got)
	}
	if got := handshakeAge(0, now); got != "never" {
		t.Errorf("zero age: %s", got)
	}
}

func TestDisplayKey(t *testing.T) {
	if got := displayKey(strings.Repeat("00", 32)); got != "AAAAAAAA…" {
		t.Errorf("hex key: %s", got)
	}
	if got := displayKey("short"); got != "short" {
		t.Errorf("short: %s", got)
	}
}

func TestReorderFlags(t *testing.T) {
	got := reorderFlags([]string{"laptop", "-c", "2", "router", "--json", "-W=2s"})
	want := []string{"-c", "2", "--json", "-W=2s", "laptop", "router"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func samplePeers() []device.PeerInfo {
	return []device.PeerInfo{
		{PublicKey: strings.Repeat("cd", 32), AssignedIP: "10.0.0.5", Hostname: "router", IsP2P: true, P2PState: "trying", RxBytes: 2048},
		{PublicKey: strings.Repeat("ef", 32), Endpoint: "203.0.113.1:51820", LastHandshake: 1700000090, RxBytes: 5 << 20, TxBytes: 1 << 20},
		{PublicKey: strings.Repeat("ab", 32), AssignedIP: "10.0.0.4", Hostname: "laptop", IsP2P: true, P2PState: "established", Endpoint: "198.51.100.7:4000", LastHandshake: 1700000088},
	}
}

func TestPrintPeers(t *testing.T) {
	var buf bytes.Buffer
	lat := map[string]agent.PingResult{"10.0.0.4": {Received: 1, AvgMs: 3.25}, "10.0.0.5": {}}
	printPeers(&buf, samplePeers(), lat, time.Unix(1700000100, 0))
	out := buf.String()
	t.Log("\n" + out)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "(server)") {
		t.Fatalf("server row not first:\n%s", out)
	}
	for _, want := range []string{"LATENCY", "direct", "relay", "12s ago", "3.2 ms", "timeout", "5.0 MiB", "never"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestPrintStatusAndPing(t *testing.T) {
	var buf bytes.Buffer
	printStatus(&buf, agent.StatusResponse{
		Running: true, DeviceRunning: true, TUNMode: true, TUNName: "utun7",
		IPs: []string{"10.0.0.2/32"}, PubKey: "AAAA", RxBytes: 3 << 20, TxBytes: 1024,
		Peers: samplePeers(), Version: "v1.0.50", ServerEndpoint: "wg.example:51820", UptimeSec: 3725,
	})
	t.Log("\n" + buf.String())
	for _, want := range []string{"Connected", "TUN (utun7)", "v1.0.50", "wg.example:51820", "direct 1, relay 1", "1h02m", "3.0 MiB"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("status missing %q", want)
		}
	}

	buf.Reset()
	printPing(&buf, agent.PingResponse{Results: []agent.PingResult{
		{Target: "laptop", Hostname: "laptop", IP: "10.0.0.4", Path: "direct", Endpoint: "198.51.100.7:4000", Sent: 4, Received: 4, MinMs: 1.1, AvgMs: 2.2, MaxMs: 3.3, JitterMs: 0.4},
		{Target: "router", Hostname: "router", IP: "10.0.0.5", Path: "relay", P2PState: "trying", Sent: 4, LossPct: 100},
	}})
	t.Log("\n" + buf.String())
	for _, want := range []string{"laptop (10.0.0.4) direct via 198.51.100.7:4000", "1.10/2.20/3.30/0.40 ms", "100% loss", "p2p: trying"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("ping missing %q", want)
		}
	}
}

func TestDaemonGetFrom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(agent.StatusResponse{Running: true})
	}))
	defer srv.Close()
	var st agent.StatusResponse
	if err := daemonGetFrom(srv.URL, "/api/status", time.Second, &st); err != nil || !st.Running {
		t.Fatalf("get: %v %+v", err, st)
	}
	srv.Close()
	if err := daemonGetFrom(srv.URL, "/api/status", time.Second, &st); err != errDaemonDown {
		t.Errorf("closed server: %v", err)
	}
}
