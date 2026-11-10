package runner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

// trayState drives the icon colour and the header line.
type trayState int

const (
	trayDaemonDown trayState = iota
	trayDisconnected
	trayConnected
	trayExitActive
	trayNotSignedIn
	// trayNoInternet: the tunnel is up but the hub cannot be reached (its
	// handshake is stale, or the gateway stopped answering): no internet on
	// this machine, or the hub is down. WireGuard keeps retrying, so this
	// recovers on its own.
	trayNoInternet
)

// gatewayMissesToDowngrade is how many consecutive unanswered gateway probes
// downgrade a connected tunnel, so one lost ICMP echo never flips the icon.
// A single reply recovers it at once.
const gatewayMissesToDowngrade = 2

// tunnelUp reports a state in which the tunnel is configured and running,
// whether or not traffic flows right now: Disconnect is the toggle's action
// and the gateway keeps being probed (so a downgrade can recover).
func tunnelUp(s trayState) bool {
	return s == trayConnected || s == trayExitActive || s == trayNoInternet
}

func stateOf(st *agent.StatusResponse, lat gatewayLatency) trayState {
	switch {
	case st == nil:
		return trayDaemonDown
	case st.Claim != nil:
		return trayNotSignedIn
	case !st.Running || !st.DeviceRunning:
		return trayDisconnected
	case hubUnreachable(st, lat):
		return trayNoInternet
	case st.ExitNodeState != nil && st.ExitNodeState.Using != nil && st.ExitNodeState.Using.State == "active":
		return trayExitActive
	default:
		return trayConnected
	}
}

// hubUnreachable is true when the daemon reports the hub's handshake as stale
// or the gateway missed gatewayMissesToDowngrade probes in a row. The
// handshake age only grows until the next handshake succeeds, so it cannot
// flap; its debounce is the minute of slack in agent.HubHandshakeFresh. A
// daemon too old to report HubReachable never downgrades on that fact.
func hubUnreachable(st *agent.StatusResponse, lat gatewayLatency) bool {
	if st.HubReachable != nil && !*st.HubReachable {
		return true
	}
	return lat.Measured && !lat.Replied && lat.Misses >= gatewayMissesToDowngrade
}

// gatewayLatency is the last round trip to the network's Wantastic gateway,
// measured while the menu is open.
type gatewayLatency struct {
	Measured bool    // a ping has completed
	Replied  bool    // and the gateway answered
	Ms       float64 // average round trip when it did
	// Misses counts consecutive unanswered probes (0 after a reply).
	Misses int
}

// latencyText is the Latency row for a connected tunnel.
func latencyText(l gatewayLatency) string {
	switch {
	case !l.Measured:
		return T("latency.empty")
	case !l.Replied:
		return T("latency.row", T("latency.noreply"))
	default:
		return T("latency.row", T("latency.ms", l.Ms))
	}
}

// trayView is everything the top of the menu shows, derived from one status
// poll by a pure function so it is unit tested.
type trayView struct {
	State         trayState
	Tooltip       string
	Header        string
	Address       string
	Traffic       string
	Latency       string
	Details       string
	ToggleTitle   string
	ToggleEnabled bool
	PeersTitle    string
	// LoginURL is the claim link Log in opens; empty once signed in.
	LoginURL string
}

func deriveTrayView(st *agent.StatusResponse, lat gatewayLatency) trayView {
	v := trayView{State: stateOf(st, lat), ToggleTitle: T("toggle.connect")}
	switch v.State {
	case trayDaemonDown:
		v.Header = T("header.daemon.down")
		v.Tooltip = T("tooltip.daemon.down")
		v.Details = T("details.start", daemonStartCommand())
		v.Address, v.Traffic, v.Latency = T("addr.empty"), T("traffic.empty"), T("latency.empty")
		v.PeersTitle = T("peers.empty")
		return v
	case trayNotSignedIn:
		v.Header = T("header.notsignedin")
		v.Tooltip = T("tooltip.notsignedin")
		v.Details = T("details.login")
		v.Address, v.Traffic, v.Latency = T("addr.empty"), T("traffic.empty"), T("latency.empty")
		v.PeersTitle = T("peers.empty")
		v.LoginURL = st.Claim.URL
		return v
	case trayDisconnected:
		v.Header = T("header.disconnected")
		v.Tooltip = T("tooltip.disconnected")
		v.ToggleEnabled = st.Running
	case trayNoInternet:
		v.Header = T("header.nointernet")
		if st.HubReachable != nil && !*st.HubReachable && st.HubLastHandshake == 0 {
			// Just connected: the first handshake is still on its way.
			v.Header = T("header.connecting")
		}
		v.Tooltip = T("tooltip.nointernet")
		v.ToggleTitle, v.ToggleEnabled = T("toggle.disconnect"), true
	case trayExitActive:
		u := st.ExitNodeState.Using
		name := clip(firstNonEmpty(u.Hostname, u.IP), maxHeaderName)
		v.Header = T("header.exit", name)
		v.Tooltip = T("tooltip.exit", name)
		v.ToggleTitle, v.ToggleEnabled = T("toggle.disconnect"), true
	default:
		v.Header = T("header.connected")
		v.Tooltip = T("tooltip.connected")
		v.ToggleTitle, v.ToggleEnabled = T("toggle.disconnect"), true
	}

	ip := "—"
	if len(st.IPs) > 0 {
		ip = strings.TrimSuffix(st.IPs[0], "/32")
	}
	v.Address = T("addr", ip)
	v.Traffic = T("traffic", trayBytes(st.RxBytes), trayBytes(st.TxBytes))
	v.Latency = T("latency.empty")
	if tunnelUp(v.State) {
		v.Latency = latencyText(lat)
	}

	// Offline, the details row says for how long the hub has been silent in
	// place of the daemon's uptime (the row is sized for either).
	var details []string
	hubSilent := v.State == trayNoInternet && st.HubReachable != nil && !*st.HubReachable
	switch {
	case hubSilent && st.HubLastHandshake > 0:
		details = append(details, T("details.handshake.ago", trayDuration(time.Duration(st.HubHandshakeAgeSec)*time.Second)))
	case hubSilent:
		details = append(details, T("details.handshake.never"))
	case st.UptimeSec > 0:
		details = append(details, T("details.up", trayDuration(time.Duration(st.UptimeSec)*time.Second)))
	}
	if st.ServerEndpoint != "" {
		details = append(details, T("details.server", st.ServerEndpoint))
	}
	v.Details = strings.Join(details, " · ")

	var direct, relay int
	for _, p := range st.Peers {
		switch agent.PeerPath(p) {
		case agent.PathDirect:
			direct++
		case agent.PathServer:
		default:
			relay++
		}
	}
	v.PeersTitle = T("peers", direct, relay)
	return v
}

const (
	// figureSpace is a space the width of a digit in the system menu fonts
	// (SF Pro, Segoe UI, Cantarell). Padding a number with it keeps columns
	// aligned as the digits change, which an ordinary space (about half a
	// digit) cannot. A font without the glyph falls back to a normal space:
	// a slightly looser pad, never a broken layout.
	figureSpace = '\u2007'
	// mantissaWidth right-aligns the number so the decimal point and the unit
	// after it hold their place as the value ticks (e.g. "1.0"→"12.3"→"999.9"
	// don't shift the second rate ↑). 5 covers "999.9"; the rare "1023.9" just
	// before a unit rolls over is one wider and simply isn't padded.
	mantissaWidth = 5
	// maxHeaderName bounds the exit-node name in the header so a long hostname
	// can't stretch the menu width.
	maxHeaderName = 24
)

// trayBytes renders n in binary units (B, KiB, MiB, GiB, …; 1024-based, with
// the "iB" suffix) for the menu. The mantissa is right-aligned in a fixed
// figure-space field so the string's width barely changes as the value ticks:
// within a unit magnitude the trailing part (and any "/s" or second rate)
// stays put. A change of unit magnitude (B↔KiB↔MiB) still shifts it — that is
// inherent and infrequent.
func trayBytes(n uint64) string {
	const unit = 1024
	num, u := fmt.Sprintf("%d", n), "B"
	if n >= unit {
		div, exp := uint64(unit), 0
		for m := n / unit; m >= unit; m /= unit {
			div *= unit
			exp++
		}
		num = fmt.Sprintf("%.1f", float64(n)/float64(div))
		u = string("KMGTPE"[exp]) + "iB"
	}
	return padLeft(num, mantissaWidth) + " " + u
}

// padLeft right-aligns s in a field of w figure spaces; shorter is returned
// unchanged.
func padLeft(s string, w int) string {
	if n := w - len([]rune(s)); n > 0 {
		return strings.Repeat(string(figureSpace), n) + s
	}
	return s
}

// clip shortens s to at most max runes, ending in an ellipsis when cut.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

func trayDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func daemonStartCommand() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo launchctl kickstart -k system/com.wantastic.wantasticd"
	case "windows":
		return "sc.exe start wantasticd"
	default:
		return "sudo systemctl start wantasticd"
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// pingSummary is the "Ping all peers" result line.
func pingSummary(pr *agent.PingResponse, err error) string {
	switch {
	case err != nil:
		return T("ping.failed", err.Error())
	case pr.Error != "":
		return T("ping.failed", pr.Error)
	case len(pr.Results) == 0:
		return T("ping.nopeers")
	}
	var up int
	var sum float64
	for _, r := range pr.Results {
		if r.Received > 0 {
			up++
			sum += r.AvgMs
		}
	}
	if up == 0 {
		return T("ping.none", len(pr.Results))
	}
	return T("ping.summary", up, len(pr.Results), sum/float64(up))
}

// peerMenuEntry is one row under Peers; its submenu shows Detail and copies
// VPNIP or PublicIP. Tooltip never carries live values: a tooltip whose text
// changes every refresh flickers while the pointer rests on it.
type peerMenuEntry struct {
	Title    string
	Tooltip  string
	Detail   string
	VPNIP    string
	PublicIP string
}

// buildPeerMenuEntries lists every peer except the server, direct ones first,
// with the latency of the last "Ping all peers" when there is one.
func buildPeerMenuEntries(peers []device.PeerInfo, latency map[string]agent.PingResult, now time.Time) []peerMenuEntry {
	var list []device.PeerInfo
	for _, p := range peers {
		if p.IsP2P {
			list = append(list, p)
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		return (agent.PeerPath(list[i]) == agent.PathDirect) && (agent.PeerPath(list[j]) != agent.PathDirect)
	})
	out := make([]peerMenuEntry, 0, len(list))
	for _, p := range list {
		path := agent.PeerPath(p)
		mark := "◌"
		if path == agent.PathDirect {
			mark = "●"
		}
		title := fmt.Sprintf("%s %s · %s", mark, peerLabel(p), path)
		if r, ok := latency[p.AssignedIP]; ok {
			if r.Received > 0 {
				title += " · " + T("latency.ms", r.AvgMs)
			} else {
				title += " · " + T("latency.noreply")
			}
		}
		handshake := T("handshake.never")
		if p.LastHandshake > 0 {
			handshake = T("handshake.ago", trayDuration(now.Sub(time.Unix(p.LastHandshake, 0))))
		}
		out = append(out, peerMenuEntry{
			Title:    "( " + title + " )",
			Tooltip:  T("peer.tooltip"),
			Detail:   fmt.Sprintf("%s · ↓ %s ↑ %s", handshake, trayBytes(p.RxBytes), trayBytes(p.TxBytes)),
			VPNIP:    strings.TrimSpace(p.AssignedIP),
			PublicIP: endpointHost(p.Endpoint),
		})
	}
	return out
}

// peerLabel names a peer row: its hostname, else its VPN IP, else its key.
func peerLabel(p device.PeerInfo) string {
	return firstNonEmpty(p.Hostname, p.AssignedIP, abbreviatePeerKey(p.PublicKey))
}

// endpointHost is the IP of a WireGuard "ip:port" endpoint.
func endpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap.Addr().Unmap().String()
	}
	return endpoint
}

func abbreviatePeerKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "…"
}

// Icon colours per state.
var trayStateColors = map[trayState]color.NRGBA{
	trayDaemonDown:   {0xEF, 0x44, 0x44, 0xFF}, // red
	trayDisconnected: {0x9C, 0xA3, 0xAF, 0xFF}, // grey
	trayConnected:    {0x22, 0xC5, 0x5E, 0xFF}, // green
	trayExitActive:   {0x3B, 0x82, 0xF6, 0xFF}, // blue
	trayNotSignedIn:  {0xF5, 0x9E, 0x0B, 0xFF}, // amber
	trayNoInternet:   {0xEA, 0x58, 0x0C, 0xFF}, // orange: up, but no path to the hub
}

// trayLogo is the Wantastic logo (console img/icon/logo.svg) in a 0..1 box.
var trayLogo = [][2]float64{
	{0.20, 0.20}, {0.50, 0.10}, {0.80, 0.20}, {0.65, 0.45},
	{0.80, 0.70}, {0.50, 0.90}, {0.20, 0.70}, {0.35, 0.45},
}

// trayIconPNG draws the menu-bar icon: the Wantastic logo in the state
// colour. Drawn in code so every platform and state shares one source.
func trayIconPNG(s trayState, size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fill := trayStateColors[s]
	const ss = 4 // supersampling per axis, for smooth edges
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var in int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/ss) / float64(size)
					if insidePolygon(px, py, trayLogo) {
						in++
					}
				}
			}
			if in > 0 {
				img.SetNRGBA(x, y, color.NRGBA{fill.R, fill.G, fill.B, uint8(in * 255 / (ss * ss))})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// insidePolygon is the even-odd rule test of (px, py) against poly.
func insidePolygon(px, py float64, poly [][2]float64) bool {
	in := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		a, b := poly[i], poly[j]
		if (a[1] > py) != (b[1] > py) && px < (b[0]-a[0])*(py-a[1])/(b[1]-a[1])+a[0] {
			in = !in
		}
	}
	return in
}

// pngToICO wraps a PNG in a single-image .ico, the format the Windows
// notification area needs.
func pngToICO(pngData []byte, size int) []byte {
	var buf bytes.Buffer
	dim := byte(size)
	if size >= 256 {
		dim = 0
	}
	binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, 1})
	buf.Write([]byte{dim, dim, 0, 0})
	binary.Write(&buf, binary.LittleEndian, [2]uint16{1, 32})
	binary.Write(&buf, binary.LittleEndian, [2]uint32{uint32(len(pngData)), 22})
	buf.Write(pngData)
	return buf.Bytes()
}

// trashIconPNG draws a small bin (lid, handle, tapered body) for menus that
// show it as an item image.
func trashIconPNG(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fill := color.NRGBA{0x6b, 0x72, 0x80, 0xff}
	body := [][2]float64{{0.22, 0.32}, {0.78, 0.32}, {0.71, 0.92}, {0.29, 0.92}}
	in := func(x, y float64) bool {
		switch {
		case y >= 0.18 && y <= 0.26 && x >= 0.12 && x <= 0.88: // lid
			return true
		case y >= 0.08 && y < 0.18 && x >= 0.38 && x <= 0.62: // handle
			return true
		case insidePolygon(x, y, body):
			// two slots, so it reads as a bin at 16 px
			return !(y > 0.42 && y < 0.82 && ((x > 0.40 && x < 0.45) || (x > 0.55 && x < 0.60)))
		}
		return false
	}
	const ss = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			n := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					if in((float64(x)+(float64(sx)+0.5)/ss)/float64(size), (float64(y)+(float64(sy)+0.5)/ss)/float64(size)) {
						n++
					}
				}
			}
			if n > 0 {
				img.SetNRGBA(x, y, color.NRGBA{fill.R, fill.G, fill.B, uint8(n * 255 / (ss * ss))})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
