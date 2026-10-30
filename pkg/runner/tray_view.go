package runner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
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
)

func stateOf(st *agent.StatusResponse) trayState {
	switch {
	case st == nil:
		return trayDaemonDown
	case !st.Running || !st.DeviceRunning:
		return trayDisconnected
	case st.ExitNodeState != nil && st.ExitNodeState.Using != nil && st.ExitNodeState.Using.State == "active":
		return trayExitActive
	default:
		return trayConnected
	}
}

// trafficSample is one status poll's byte counters, for live rates.
type trafficSample struct {
	rx, tx uint64
	at     time.Time
}

// trayView is everything the top of the menu shows, derived from one status
// poll by a pure function so it is unit tested.
type trayView struct {
	State         trayState
	Tooltip       string
	Header        string
	Address       string
	Traffic       string
	Rate          string
	Details       string
	ToggleTitle   string
	ToggleEnabled bool
	PeersTitle    string
}

func deriveTrayView(st *agent.StatusResponse, prev, cur trafficSample) trayView {
	v := trayView{State: stateOf(st), ToggleTitle: "Connect"}
	switch v.State {
	case trayDaemonDown:
		v.Header = "○ Daemon not running"
		v.Tooltip = "Wantastic: daemon not running"
		v.Details = "Start it: " + daemonStartCommand()
		v.Address, v.Traffic, v.Rate = "IP: —", "Traffic: —", "Speed: —"
		v.PeersTitle = "Peers: —"
		return v
	case trayDisconnected:
		v.Header = "○ Disconnected"
		v.Tooltip = "Wantastic: disconnected"
		v.ToggleEnabled = st.Running
	case trayExitActive:
		u := st.ExitNodeState.Using
		v.Header = "● Connected via exit " + firstNonEmpty(u.Hostname, u.IP)
		v.Tooltip = "Wantastic: internet via " + firstNonEmpty(u.Hostname, u.IP)
		v.ToggleTitle, v.ToggleEnabled = "Disconnect", true
	default:
		v.Header = "● Connected"
		v.Tooltip = "Wantastic: connected"
		v.ToggleTitle, v.ToggleEnabled = "Disconnect", true
	}

	ip := "—"
	if len(st.IPs) > 0 {
		ip = strings.TrimSuffix(st.IPs[0], "/32")
	}
	v.Address = "IP: " + ip
	v.Traffic = fmt.Sprintf("Traffic: ↓ %s  ↑ %s", trayBytes(st.RxBytes), trayBytes(st.TxBytes))
	v.Rate = "Speed: " + trafficRate(prev, cur)

	var details []string
	if st.UptimeSec > 0 {
		details = append(details, "Up "+trayDuration(time.Duration(st.UptimeSec)*time.Second))
	}
	if st.ServerEndpoint != "" {
		details = append(details, "server "+st.ServerEndpoint)
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
	v.PeersTitle = fmt.Sprintf("Peers: %d direct, %d relay", direct, relay)
	return v
}

// trafficRate is the throughput between two polls; a counter that went
// backwards (tunnel restarted) has no meaningful rate yet.
func trafficRate(prev, cur trafficSample) string {
	dt := cur.at.Sub(prev.at).Seconds()
	if prev.at.IsZero() || dt <= 0 || cur.rx < prev.rx || cur.tx < prev.tx {
		return "—"
	}
	rx := uint64(float64(cur.rx-prev.rx) / dt)
	tx := uint64(float64(cur.tx-prev.tx) / dt)
	return fmt.Sprintf("↓ %s/s  ↑ %s/s", trayBytes(rx), trayBytes(tx))
}

func trayBytes(n uint64) string {
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
		return "Ping failed: " + err.Error()
	case pr.Error != "":
		return "Ping failed: " + pr.Error
	case len(pr.Results) == 0:
		return "Ping: no peers to ping"
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
		return fmt.Sprintf("Ping: 0/%d peers answered", len(pr.Results))
	}
	return fmt.Sprintf("Ping: %d/%d peers answered · avg %.0f ms", up, len(pr.Results), sum/float64(up))
}

// peerMenuEntry is one row under Peers; clicking it copies CopyText.
type peerMenuEntry struct {
	Title    string
	Tooltip  string
	CopyText string
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
				title += fmt.Sprintf(" · %.0f ms", r.AvgMs)
			} else {
				title += " · no reply"
			}
		}
		tip := []string{"VPN IP: " + firstNonEmpty(p.AssignedIP, "—")}
		if p.Endpoint != "" {
			tip = append(tip, "Endpoint: "+p.Endpoint)
		}
		if p.LastHandshake > 0 {
			tip = append(tip, "Handshake: "+trayDuration(now.Sub(time.Unix(p.LastHandshake, 0)))+" ago")
		} else {
			tip = append(tip, "Handshake: never")
		}
		tip = append(tip, fmt.Sprintf("Traffic: ↓ %s ↑ %s", trayBytes(p.RxBytes), trayBytes(p.TxBytes)))
		copyText := firstNonEmpty(p.AssignedIP, p.Endpoint, p.PublicKey)
		tip = append(tip, "Click to copy "+copyText)
		out = append(out, peerMenuEntry{Title: title, Tooltip: strings.Join(tip, "\n"), CopyText: copyText})
	}
	return out
}

func peerLabel(p device.PeerInfo) string {
	host, ip := strings.TrimSpace(p.Hostname), strings.TrimSpace(p.AssignedIP)
	switch {
	case host != "" && ip != "":
		return fmt.Sprintf("%s (%s)", host, ip)
	case ip != "":
		return ip
	case host != "":
		return host
	default:
		return abbreviatePeerKey(p.PublicKey)
	}
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
}

// trayIconPNG draws the menu-bar icon: a disc in the state colour with a
// white "W". Drawn in code so every platform and state shares one source.
func trayIconPNG(s trayState, size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fill := trayStateColors[s]
	w := [][2]float64{{0.22, 0.31}, {0.36, 0.70}, {0.50, 0.40}, {0.64, 0.70}, {0.78, 0.31}}
	const ss = 4 // supersampling per axis, for smooth edges
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var discN, letterN int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/ss) / float64(size)
					if math.Hypot(px-0.5, py-0.5) > 0.47 {
						continue
					}
					discN++
					for i := 0; i+1 < len(w); i++ {
						if segmentDist(px, py, w[i], w[i+1]) < 0.055 {
							letterN++
							break
						}
					}
				}
			}
			if discN == 0 {
				continue
			}
			t := float64(letterN) / float64(discN)
			blend := func(c uint8) uint8 { return uint8(float64(c)*(1-t) + 255*t + 0.5) }
			img.SetNRGBA(x, y, color.NRGBA{blend(fill.R), blend(fill.G), blend(fill.B), uint8(discN * 255 / (ss * ss))})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func segmentDist(px, py float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := ((px-a[0])*dx + (py-a[1])*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(a[0]+t*dx), py-(a[1]+t*dy))
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
