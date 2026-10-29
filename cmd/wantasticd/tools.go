package main

// CLI diagnostic tools: status, peers and ping. They talk to the running
// daemon over the local IPC API (127.0.0.1, port from agent.GetIPCPort).

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

// daemonStartHint is how to start the service on this OS.
func daemonStartHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo launchctl kickstart system/com.wantastic.wantasticd"
	case "windows":
		return "sc.exe start wantasticd"
	default:
		return "sudo systemctl start wantasticd (OpenWrt: /etc/init.d/wantasticd start)"
	}
}

// Exit codes for the tools.
const (
	exitOK          = 0
	exitFailed      = 1
	exitUnreachable = 2
)

var errDaemonDown = errors.New("daemon not running (start: " + daemonStartHint() + ")")

// daemonGet fetches path from the IPC API and decodes JSON into v.
func daemonRestartHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo launchctl kickstart -k system/com.wantastic.wantasticd"
	case "windows":
		return "Restart-Service wantasticd"
	default:
		return "sudo systemctl restart wantasticd"
	}
}

func daemonGet(path string, timeout time.Duration, v any) error {
	return daemonGetFrom("http://127.0.0.1:"+agent.GetIPCPort(), path, timeout, v)
}

func daemonGetFrom(base, path string, timeout time.Duration, v any) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(base + path)
	if err != nil {
		return errDaemonDown
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read daemon response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// Endpoints are only ever added, so a 404 means the running daemon
		// predates this binary: it was updated on disk but not restarted.
		route, _, _ := strings.Cut(path, "?")
		return fmt.Errorf("the running daemon is older than this CLI and has no %s; restart it to load the installed version (%s)", route, daemonRestartHint())
	}
	if err := json.Unmarshal(body, v); err != nil {
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// humanDuration renders d compactly: 45s, 3m12s, 2h05m, 3d04h.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d.Seconds())
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	case s < 86400:
		return fmt.Sprintf("%dh%02dm", s/3600, (s%3600)/60)
	default:
		return fmt.Sprintf("%dd%02dh", s/86400, (s%86400)/3600)
	}
}

// handshakeAge turns a WireGuard last-handshake unix time into "12s ago".
func handshakeAge(unix int64, now time.Time) string {
	if unix <= 0 {
		return "never"
	}
	return humanDuration(now.Sub(time.Unix(unix, 0))) + " ago"
}

// displayKey shows a hex WireGuard key as abbreviated base64, the form users
// see in the portal.
func displayKey(key string) string {
	if raw, err := hex.DecodeString(key); err == nil && len(raw) == 32 {
		key = base64.StdEncoding.EncodeToString(raw)
	}
	if len(key) > 12 {
		return key[:8] + "…"
	}
	return key
}

func peerName(p device.PeerInfo) string {
	switch {
	case !p.IsP2P:
		return "(server)"
	case strings.TrimSpace(p.Hostname) != "":
		return p.Hostname
	default:
		return displayKey(p.PublicKey)
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// ── status ──────────────────────────────────────────────────────────────────

func runStatus(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Print the raw daemon status as JSON")
	fs.Parse(args)

	var st agent.StatusResponse
	if err := daemonGet("/api/status", 5*time.Second, &st); err != nil {
		fmt.Fprintf(w, "Status: Offline — %v\n", err)
		return exitUnreachable
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return exitOK
	}
	printStatus(w, st)
	return exitOK
}

func printStatus(w io.Writer, st agent.StatusResponse) {
	state := "Stopped"
	switch {
	case st.Running && st.DeviceRunning:
		state = "Connected"
	case st.Running:
		state = "Running (tunnel down)"
	}
	mode := "Userspace"
	if st.TUNMode {
		mode = "TUN (" + orDash(st.TUNName) + ")"
	}
	var direct, relay int
	for _, p := range st.Peers {
		switch agent.PeerPath(p) {
		case agent.PathDirect:
			direct++
		case agent.PathRelay:
			relay++
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }
	row("Status", state)
	if st.Version != "" {
		row("Version", st.Version)
	}
	row("Mode", mode)
	row("VPN IPs", orDash(strings.Join(st.IPs, ", ")))
	row("Public key", orDash(st.PubKey))
	if st.ServerEndpoint != "" {
		row("Server", st.ServerEndpoint)
	}
	if st.ExitNodeState != nil {
		row("Offer exit node", exitOfferLine(st.ExitNodeState))
		row("Using exit node", exitUseLine(st.ExitNodeState))
	} else {
		row("Exit node", fmt.Sprintf("%t", st.ExitNode))
	}
	row("Local access", fmt.Sprintf("%t", st.LocalAccess))
	if st.Version != "" {
		// Daemons that predate the version field do not report this either.
		row("Auto update", fmt.Sprintf("%t", st.AutoUpdate))
	} else {
		row("Daemon", "older build; restart it to load the installed version ("+daemonRestartHint()+")")
	}
	row("Traffic", fmt.Sprintf("↓ %s  ↑ %s", humanBytes(st.RxBytes), humanBytes(st.TxBytes)))
	row("Peers", fmt.Sprintf("%d (direct %d, relay %d)", direct+relay, direct, relay))
	if st.UptimeSec > 0 {
		row("Uptime", humanDuration(time.Duration(st.UptimeSec)*time.Second))
	}
	tw.Flush()
}

// ── peers ───────────────────────────────────────────────────────────────────

func runPeers(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Print peers as JSON")
	withPing := fs.Bool("ping", false, "Ping every peer once and add a LATENCY column")
	fs.Parse(args)

	var st agent.StatusResponse
	if err := daemonGet("/api/status", 5*time.Second, &st); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUnreachable
	}
	var latency map[string]agent.PingResult
	if *withPing {
		var pr agent.PingResponse
		if err := daemonGet("/api/ping?count=1&timeout=1000", 15*time.Second, &pr); err == nil && pr.Error == "" {
			latency = make(map[string]agent.PingResult, len(pr.Results))
			for _, r := range pr.Results {
				latency[r.IP] = r
			}
		} else if err == nil {
			fmt.Fprintf(os.Stderr, "ping: %s\n", pr.Error)
		} else {
			fmt.Fprintf(os.Stderr, "ping: %v\n", err)
		}
	}
	if *asJSON {
		type peerOut struct {
			device.PeerInfo
			Path      string   `json:"path"`
			LatencyMs *float64 `json:"latency_ms,omitempty"`
		}
		out := make([]peerOut, 0, len(st.Peers))
		for _, p := range st.Peers {
			po := peerOut{PeerInfo: p, Path: agent.PeerPath(p)}
			if r, ok := latency[p.AssignedIP]; ok && r.Received > 0 {
				v := r.AvgMs
				po.LatencyMs = &v
			}
			out = append(out, po)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return exitOK
	}
	printPeers(w, st.Peers, latency, time.Now())
	if es := st.ExitNodeState; es != nil && (es.Using != nil || es.Offering) {
		fmt.Fprintf(w, "\nExit node: using %s; offering %s\n", exitUseLine(es), exitOfferLine(es))
	}
	return exitOK
}

func printPeers(w io.Writer, peers []device.PeerInfo, latency map[string]agent.PingResult, now time.Time) {
	if len(peers) == 0 {
		fmt.Fprintln(w, "No peers.")
		return
	}
	// Server first; the daemon already sorts the rest by VPN IP.
	ordered := make([]device.PeerInfo, 0, len(peers))
	for _, p := range peers {
		if !p.IsP2P {
			ordered = append(ordered, p)
		}
	}
	for _, p := range peers {
		if p.IsP2P {
			ordered = append(ordered, p)
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "HOSTNAME\tVPN IP\tPATH\tENDPOINT\tHANDSHAKE\tRX\tTX\tSTATE"
	if latency != nil {
		header += "\tLATENCY"
	}
	fmt.Fprintln(tw, header)
	for _, p := range ordered {
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			peerName(p), orDash(p.AssignedIP), agent.PeerPath(p), orDash(p.Endpoint),
			handshakeAge(p.LastHandshake, now), humanBytes(p.RxBytes), humanBytes(p.TxBytes), orDash(p.P2PState))
		if latency != nil {
			lat := "-"
			if r, ok := latency[p.AssignedIP]; ok {
				if r.Received > 0 {
					lat = fmt.Sprintf("%.1f ms", r.AvgMs)
				} else {
					lat = "timeout"
				}
			}
			line += "\t" + lat
		}
		fmt.Fprintln(tw, line)
	}
	tw.Flush()
}

// ── ping ────────────────────────────────────────────────────────────────────

func runPing(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	count := fs.Int("c", 4, "Echo requests per target (1-20)")
	interval := fs.Duration("i", 250*time.Millisecond, "Interval between echo rounds")
	timeout := fs.Duration("W", time.Second, "Wait for late replies after the last round")
	asJSON := fs.Bool("json", false, "Print results as JSON")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: wantasticd ping [flags] [peer-ip|hostname|pubkey-prefix ...]")
		fmt.Fprintln(fs.Output(), "With no target every peer with a VPN IP is pinged.")
		fs.PrintDefaults()
	}
	fs.Parse(reorderFlags(args))

	q := url.Values{}
	q.Set("count", fmt.Sprint(*count))
	q.Set("interval", fmt.Sprint(interval.Milliseconds()))
	q.Set("timeout", fmt.Sprint(timeout.Milliseconds()))
	for _, t := range fs.Args() {
		q.Add("target", t)
	}
	budget := time.Duration(*count)*(*interval) + *timeout + 10*time.Second
	if budget > 90*time.Second {
		budget = 90 * time.Second
	}

	var pr agent.PingResponse
	if err := daemonGet("/api/ping?"+q.Encode(), budget, &pr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUnreachable
	}
	if pr.Error != "" {
		fmt.Fprintf(os.Stderr, "ping: %s\n", pr.Error)
		return exitFailed
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(pr)
	} else {
		printPing(w, pr)
	}
	for _, r := range pr.Results {
		if r.Received > 0 {
			return exitOK
		}
	}
	return exitFailed
}

// reorderFlags lets flags follow targets ("ping host -c 2"), which the flag
// package otherwise treats as positional arguments.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && name != "json" && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func printPing(w io.Writer, pr agent.PingResponse) {
	for _, r := range pr.Results {
		name := r.Target
		if r.Hostname != "" && r.Hostname != r.IP {
			name = r.Hostname
		}
		route := r.Path
		if r.Endpoint != "" {
			route += " via " + r.Endpoint
		}
		fmt.Fprintf(w, "--- %s (%s) %s ---\n", name, r.IP, route)
		fmt.Fprintf(w, "%d sent, %d received, %.0f%% loss", r.Sent, r.Received, r.LossPct)
		if r.Received > 0 {
			fmt.Fprintf(w, ", rtt min/avg/max/jitter = %.2f/%.2f/%.2f/%.2f ms", r.MinMs, r.AvgMs, r.MaxMs, r.JitterMs)
		}
		fmt.Fprintln(w)
		if r.P2PState != "" && r.Path != agent.PathDirect {
			fmt.Fprintf(w, "p2p: %s\n", r.P2PState)
		}
	}
}
