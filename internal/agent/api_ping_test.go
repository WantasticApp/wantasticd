package agent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/internal/wifiprobe"
)

var (
	keyA = strings.Repeat("ab", 32)
	keyB = strings.Repeat("cd", 32)
	keyS = strings.Repeat("ef", 32)
)

func testPeers() []device.PeerInfo {
	return []device.PeerInfo{
		{PublicKey: keyS, Endpoint: "203.0.113.1:51820"},
		{PublicKey: keyA, AssignedIP: "10.0.0.4", Hostname: "Laptop", IsP2P: true, P2PState: "established", Endpoint: "198.51.100.7:4000", LastHandshake: 1700000000},
		{PublicKey: keyB, AssignedIP: "10.0.0.5", Hostname: "router", IsP2P: true, P2PState: "trying"},
	}
}

func TestPeerPath(t *testing.T) {
	p := testPeers()
	for i, want := range []string{PathServer, PathDirect, PathRelay} {
		if got := PeerPath(p[i]); got != want {
			t.Errorf("peer %d: got %s want %s", i, got, want)
		}
	}
	// Established without an endpoint is still relayed.
	if got := PeerPath(device.PeerInfo{IsP2P: true, P2PState: "established"}); got != PathRelay {
		t.Errorf("established without endpoint: got %s", got)
	}
}

func TestResolvePingTargets(t *testing.T) {
	peers := testPeers()
	raw, _ := hex.DecodeString(keyB)
	b64 := base64.StdEncoding.EncodeToString(raw)

	cases := []struct {
		q, ip string
		peer  bool
	}{
		{"10.0.0.4", "10.0.0.4", true},
		{"laptop", "10.0.0.4", true},
		{"ROUTER", "10.0.0.5", true},
		{keyA[:6], "10.0.0.4", true},
		{b64[:6], "10.0.0.5", true},
		{"192.0.2.9", "192.0.2.9", false},
	}
	for _, c := range cases {
		got, err := resolvePingTargets([]string{c.q}, peers)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		if got[0].addr.String() != c.ip || (got[0].peer != nil) != c.peer {
			t.Errorf("%s: got %s peer=%v", c.q, got[0].addr, got[0].peer != nil)
		}
	}

	all, err := resolvePingTargets(nil, peers)
	if err != nil || len(all) != 2 {
		t.Fatalf("all peers: %v %v", all, err)
	}
	dup, _ := resolvePingTargets([]string{"laptop", "10.0.0.4"}, peers)
	if len(dup) != 1 {
		t.Errorf("duplicates not merged: %d", len(dup))
	}
	for _, bad := range []string{"nosuchhost", "fe80::1", "ab"} {
		if _, err := resolvePingTargets([]string{bad}, peers); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
	if _, err := resolvePingTargets(nil, nil); err == nil {
		t.Error("no peers: expected error")
	}
}

func TestHandlePing(t *testing.T) {
	var gotOpts wifiprobe.Options
	orig := probeFunc
	probeFunc = func(_ context.Context, targets []netip.Addr, o wifiprobe.Options) (map[netip.Addr]wifiprobe.Result, error) {
		gotOpts = o
		out := map[netip.Addr]wifiprobe.Result{}
		for _, a := range targets {
			if a.String() == "10.0.0.4" {
				out[a] = wifiprobe.Result{Sent: o.Count, Received: o.Count, Min: time.Millisecond, Avg: 2 * time.Millisecond, Max: 3 * time.Millisecond}
			} else {
				out[a] = wifiprobe.Result{Sent: o.Count}
			}
		}
		return out, nil
	}
	defer func() { probeFunc = orig }()

	s := &APIServer{peers: testPeers}
	do := func(method, query string) (int, PingResponse) {
		rec := httptest.NewRecorder()
		s.handlePing(rec, httptest.NewRequest(method, "/api/ping?"+query, nil))
		var pr PingResponse
		json.Unmarshal(rec.Body.Bytes(), &pr)
		return rec.Code, pr
	}

	for _, q := range []string{"count=0", "count=x", "interval=-5", "timeout=abc", "target=nosuch"} {
		if code, pr := do(http.MethodGet, q); code != http.StatusBadRequest || pr.Error == "" {
			t.Errorf("%s: code %d err %q", q, code, pr.Error)
		}
	}
	if code, _ := do(http.MethodPost, ""); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", code)
	}

	code, pr := do(http.MethodGet, "count=99&interval=1&target=laptop,router")
	if code != http.StatusOK {
		t.Fatalf("code %d: %s", code, pr.Error)
	}
	if gotOpts.Count != pingMaxCount || gotOpts.Interval != pingMinInterval {
		t.Errorf("bounds not applied: %+v", gotOpts)
	}
	if len(pr.Results) != 2 {
		t.Fatalf("results: %+v", pr.Results)
	}
	a, b := pr.Results[0], pr.Results[1]
	if a.Path != PathDirect || a.Hostname != "Laptop" || a.LossPct != 0 || a.AvgMs != 2 || a.Endpoint == "" {
		t.Errorf("laptop: %+v", a)
	}
	if b.Path != PathRelay || b.LossPct != 100 || b.Received != 0 || b.P2PState != "trying" {
		t.Errorf("router: %+v", b)
	}

	// Total time stays within pingMaxDuration.
	do(http.MethodGet, "count=20&interval=5000&timeout=10000&target=10.0.0.4")
	if d := time.Duration(gotOpts.Count-1)*gotOpts.Interval + gotOpts.Timeout; d > pingMaxDuration {
		t.Errorf("run of %s exceeds cap", d)
	}
}

func TestIPCPortFile(t *testing.T) {
	if f := ipcPortFile(); f == "" {
		t.Fatal("empty port file path")
	}
	t.Setenv("WTC_IPC_PORT", "9999")
	if GetIPCPort() != "9999" {
		t.Error("env override ignored")
	}
}
