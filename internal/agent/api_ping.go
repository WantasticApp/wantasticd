package agent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/internal/wifiprobe"
)

const (
	pingMaxCount       = 20
	pingDefaultCount   = 4
	pingMinInterval    = 50 * time.Millisecond
	pingMaxInterval    = 5 * time.Second
	pingDefaultTimeout = time.Second
	pingMaxTimeout     = 10 * time.Second
	// pingMaxDuration caps one /api/ping request end to end.
	pingMaxDuration = 60 * time.Second
)

// Peer path classes reported by status, peers and ping.
const (
	PathDirect  = "direct"
	PathRelay   = "relay"
	PathServer  = "server"
	PathUnknown = "unknown"
)

// probeFunc sends the ICMP echoes; replaced in tests.
var probeFunc = wifiprobe.Probe

// pingSlot lets one probe run at a time: each opens a raw ICMP socket as the
// daemon's (usually root) user, and the IPC API is open to every local user.
var pingSlot = make(chan struct{}, 1)

// PingResult is one target's summary in the /api/ping response.
type PingResult struct {
	Target        string  `json:"target"`
	Hostname      string  `json:"hostname,omitempty"`
	IP            string  `json:"ip"`
	PublicKey     string  `json:"public_key,omitempty"`
	Path          string  `json:"path"`
	Endpoint      string  `json:"endpoint,omitempty"`
	P2PState      string  `json:"p2p_state,omitempty"`
	LastHandshake int64   `json:"last_handshake,omitempty"`
	Sent          int     `json:"sent"`
	Received      int     `json:"received"`
	LossPct       float64 `json:"loss_pct"`
	MinMs         float64 `json:"min_ms"`
	AvgMs         float64 `json:"avg_ms"`
	MaxMs         float64 `json:"max_ms"`
	JitterMs      float64 `json:"jitter_ms"`
}

// PingResponse is the /api/ping body.
type PingResponse struct {
	Count      int          `json:"count"`
	IntervalMs int64        `json:"interval_ms"`
	TimeoutMs  int64        `json:"timeout_ms"`
	Results    []PingResult `json:"results"`
	Error      string       `json:"error,omitempty"`
}

// PeerPath classifies how traffic to a peer travels.
func PeerPath(p device.PeerInfo) string {
	switch {
	case !p.IsP2P:
		return PathServer
	case p.P2PState == "established" && p.Endpoint != "":
		return PathDirect
	default:
		return PathRelay
	}
}

type pingTarget struct {
	query string
	addr  netip.Addr
	peer  *device.PeerInfo
}

// resolvePingTargets maps user queries (IP, hostname, public key prefix in
// hex or base64) onto peers. No queries means every peer with a VPN IP.
func resolvePingTargets(queries []string, peers []device.PeerInfo) ([]pingTarget, error) {
	var out []pingTarget
	seen := map[netip.Addr]bool{}
	add := func(t pingTarget) {
		if seen[t.addr] {
			return
		}
		seen[t.addr] = true
		out = append(out, t)
	}
	if len(queries) == 0 {
		for i := range peers {
			if a, err := netip.ParseAddr(peers[i].AssignedIP); err == nil && a.Is4() {
				add(pingTarget{query: peers[i].AssignedIP, addr: a, peer: &peers[i]})
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no peers with a VPN IP to ping")
		}
		return capTargets(out), nil
	}
	for _, q := range queries {
		t, err := resolvePingTarget(q, peers)
		if err != nil {
			return nil, err
		}
		add(t)
	}
	return capTargets(out), nil
}

func capTargets(t []pingTarget) []pingTarget {
	if len(t) > wifiprobe.MaxTargets {
		return t[:wifiprobe.MaxTargets]
	}
	return t
}

func resolvePingTarget(q string, peers []device.PeerInfo) (pingTarget, error) {
	if a, err := netip.ParseAddr(q); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return pingTarget{}, fmt.Errorf("%s: only IPv4 targets are supported", q)
		}
		t := pingTarget{query: q, addr: a}
		for i := range peers {
			if peers[i].AssignedIP == a.String() {
				t.peer = &peers[i]
				break
			}
		}
		return t, nil
	}
	var match *device.PeerInfo
	for i := range peers {
		if peerMatches(q, peers[i]) {
			if match != nil {
				return pingTarget{}, fmt.Errorf("%s: matches more than one peer", q)
			}
			match = &peers[i]
		}
	}
	if match == nil {
		return pingTarget{}, fmt.Errorf("%s: no peer with that IP, hostname or public key", q)
	}
	a, err := netip.ParseAddr(match.AssignedIP)
	if err != nil || !a.Is4() {
		return pingTarget{}, fmt.Errorf("%s: peer has no VPN IP yet", q)
	}
	return pingTarget{query: q, addr: a, peer: match}, nil
}

func peerMatches(q string, p device.PeerInfo) bool {
	if p.Hostname != "" && strings.EqualFold(q, p.Hostname) {
		return true
	}
	// Public keys need a few characters to be meaningful as a prefix.
	if len(q) < 4 || p.PublicKey == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(p.PublicKey), strings.ToLower(q)) {
		return true
	}
	if raw, err := hex.DecodeString(p.PublicKey); err == nil {
		return strings.HasPrefix(base64.StdEncoding.EncodeToString(raw), q)
	}
	return false
}

func durationParam(r *http.Request, name string, def, min, max time.Duration) (time.Duration, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms < 0 {
		return 0, fmt.Errorf("%s must be milliseconds", name)
	}
	d := time.Duration(ms) * time.Millisecond
	if d < min {
		d = min
	}
	if d > max {
		d = max
	}
	return d, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (s *APIServer) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON := func(code int, body PingResponse) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(body)
	}
	if r.Method != http.MethodGet {
		writeJSON(http.StatusMethodNotAllowed, PingResponse{Error: "method not allowed"})
		return
	}
	count := pingDefaultCount
	if v := r.URL.Query().Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(http.StatusBadRequest, PingResponse{Error: "count must be a positive integer"})
			return
		}
		count = min(n, pingMaxCount)
	}
	interval, err := durationParam(r, "interval", 250*time.Millisecond, pingMinInterval, pingMaxInterval)
	if err != nil {
		writeJSON(http.StatusBadRequest, PingResponse{Error: err.Error()})
		return
	}
	timeout, err := durationParam(r, "timeout", pingDefaultTimeout, 100*time.Millisecond, pingMaxTimeout)
	if err != nil {
		writeJSON(http.StatusBadRequest, PingResponse{Error: err.Error()})
		return
	}
	// Keep the whole run inside pingMaxDuration.
	for count > 1 && time.Duration(count-1)*interval+timeout > pingMaxDuration {
		count--
	}

	var queries []string
	for _, v := range r.URL.Query()["target"] {
		for _, q := range strings.Split(v, ",") {
			if q = strings.TrimSpace(q); q != "" {
				queries = append(queries, q)
			}
		}
	}
	var peers []device.PeerInfo
	if s.peers != nil {
		peers = s.peers()
	}
	targets, err := resolvePingTargets(queries, peers)
	if err != nil {
		writeJSON(http.StatusBadRequest, PingResponse{Error: err.Error()})
		return
	}

	select {
	case pingSlot <- struct{}{}:
		defer func() { <-pingSlot }()
	default:
		writeJSON(http.StatusTooManyRequests, PingResponse{Error: "another ping is already running; try again shortly"})
		return
	}

	addrs := make([]netip.Addr, len(targets))
	for i, t := range targets {
		addrs[i] = t.addr
	}
	ctx, cancel := context.WithTimeout(r.Context(), pingMaxDuration+5*time.Second)
	defer cancel()
	res, err := probeFunc(ctx, addrs, wifiprobe.Options{Count: count, Interval: interval, Timeout: timeout})
	if err != nil {
		writeJSON(http.StatusServiceUnavailable, PingResponse{Error: "ping failed: " + err.Error()})
		return
	}

	resp := PingResponse{Count: count, IntervalMs: interval.Milliseconds(), TimeoutMs: timeout.Milliseconds()}
	for _, t := range targets {
		pr := res[t.addr]
		out := PingResult{
			Target: t.query, IP: t.addr.String(), Path: PathUnknown,
			Sent: pr.Sent, Received: pr.Received,
			MinMs: ms(pr.Min), AvgMs: ms(pr.Avg), MaxMs: ms(pr.Max), JitterMs: ms(pr.Jitter),
		}
		if out.Sent == 0 {
			out.Sent = count
		}
		out.LossPct = float64(out.Sent-min(out.Received, out.Sent)) * 100 / float64(out.Sent)
		if p := t.peer; p != nil {
			out.Hostname, out.PublicKey, out.Path = p.Hostname, p.PublicKey, PeerPath(*p)
			out.Endpoint, out.P2PState, out.LastHandshake = p.Endpoint, p.P2PState, p.LastHandshake
		}
		resp.Results = append(resp.Results, out)
	}
	writeJSON(http.StatusOK, resp)
}
