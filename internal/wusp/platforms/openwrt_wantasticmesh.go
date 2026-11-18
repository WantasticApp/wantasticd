package platforms

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// WantasticMesh (wmeshd) on OpenWrt/QSDK. The agent reads the daemon's UCI
// section and the status file it replaces every two seconds; it never speaks
// the mesh control protocol and never reads a key. A write is one UCI option,
// committed; wmeshd's procd service restarts on its own config trigger, so
// the wireless configuration is not touched.

const (
	wantasticMeshBinary     = "/usr/sbin/wmeshd"
	wantasticMeshStatusFile = "/tmp/wmesh-status.json"
	wantasticMeshAgentsFile = "/etc/wmeshd/agents.txt"
	wantasticMeshInitScript = "/etc/init.d/wmeshd"
	wantasticMeshUCIConfig  = "wmesh"
	wantasticMeshUCISection = "global"
	// The daemon rewrites its status every 2 s; older than this it is not running.
	wantasticMeshStatusFresh = 15 * time.Second
	wantasticMeshStatusMax   = 512 << 10
)

// wantasticMeshRoot lets tests point the collector at a fixture tree.
var wantasticMeshRoot = ""

func wantasticMeshPath(path string) string { return wantasticMeshRoot + path }

type wantasticMeshRadio struct {
	Index       uint64 `json:"index"`
	Band        string `json:"band"`
	Channel     uint64 `json:"channel"`
	WidthMHz    uint64 `json:"width_mhz"`
	TxPowerDBm  int64  `json:"tx_power_dbm"`
	Utilization uint64 `json:"utilization"`
	Backhaul    bool   `json:"backhaul"`
	MLO         bool   `json:"mlo"`
	MLDLink     uint64 `json:"mld_link"`
	MAC         string `json:"mac"`
	Iface       string `json:"iface"`
}

type wantasticMeshLink struct {
	PeerMAC       string `json:"peer_mac"`
	Radio         uint64 `json:"radio"`
	RSSI          int64  `json:"rssi_dbm"`
	AgeMs         uint64 `json:"age_ms"`
	Confidence    uint64 `json:"confidence"`
	Backhaul      bool   `json:"backhaul"`
	Bidirectional bool   `json:"bidirectional"`
	MLO           bool   `json:"mlo"`
	Approximate   bool   `json:"approximate"`
}

// wantasticMeshLinkTelemetry is a node's own driver counters for one link.
type wantasticMeshLinkTelemetry struct {
	PeerMAC    string  `json:"peer_mac"`
	Radio      uint64  `json:"radio"`
	TxMbps     float64 `json:"tx_mbps"`
	RxMbps     float64 `json:"rx_mbps"`
	TxBytes    uint64  `json:"tx_bytes"`
	RxBytes    uint64  `json:"rx_bytes"`
	TxRetries  uint64  `json:"tx_retries"`
	TxFailed   uint64  `json:"tx_failed"`
	InactiveMs uint64  `json:"inactive_ms"`
}

type wantasticMeshSurvey struct {
	FreqMHz     uint64   `json:"freq_mhz"`
	NoiseDBm    int64    `json:"noise_dbm"`
	Utilization *float64 `json:"utilization_pct"`
}

type wantasticMeshPosition struct {
	Fix  bool    `json:"fix"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	AltM int64   `json:"alt_m"`
}

type wantasticMeshNode struct {
	ID             string                `json:"id"`
	Stale          bool                  `json:"stale"`
	TelemetryStale bool                  `json:"telemetry_stale"`
	AgeS           uint64                `json:"age_s"`
	Reports        uint64                `json:"reports"`
	ReportAgeS     uint64                `json:"report_age_s"`
	Radios         []wantasticMeshRadio  `json:"radios"`
	Links          []wantasticMeshLink   `json:"links"`
	Position       wantasticMeshPosition `json:"position"`
	RTTUs          uint64                `json:"rtt_us"`
	RTTNs          *struct {
		P50 uint64 `json:"p50"`
		P95 uint64 `json:"p95"`
	} `json:"rtt_ns"`
	// telemetry is this node's own link counters (a leaf's status only).
	telemetry []wantasticMeshLinkTelemetry
}

// wantasticMeshStatus mirrors wmeshd's status document (schema 1). Unknown
// fields are ignored, so a newer daemon keeps working with this agent.
type wantasticMeshStatus struct {
	Schema           int    `json:"schema"`
	Role             string `json:"role"`
	NodeID           string `json:"node_id"`
	NetworkID        string `json:"network_id"`
	At               string `json:"at"`
	UptimeS          uint64 `json:"uptime_s"`
	AgentsConfigured uint64 `json:"agents_configured"`
	Controller       struct {
		ID    string `json:"id"`
		Alive bool   `json:"alive"`
	} `json:"controller"`
	Backhaul struct {
		Managed   bool   `json:"managed"`
		Up        bool   `json:"up"`
		SSID      string `json:"ssid"`
		Interface string `json:"interface"`
	} `json:"backhaul"`
	// Agent role: this node's own radios, links and position.
	Radios        []wantasticMeshRadio         `json:"radios"`
	Links         []wantasticMeshLink          `json:"links"`
	LinkTelemetry []wantasticMeshLinkTelemetry `json:"link_telemetry"`
	Surveys       []wantasticMeshSurvey        `json:"surveys"`
	Position      wantasticMeshPosition        `json:"position"`
	Transport     struct {
		Type       string `json:"type"`
		Interfaces uint64 `json:"interfaces"`
	} `json:"transport"`
	Metrics struct {
		TxFrames          uint64            `json:"tx_frames"`
		RxFrames          uint64            `json:"rx_frames"`
		TxBytes           uint64            `json:"tx_bytes"`
		RxBytes           uint64            `json:"rx_bytes"`
		FramesPerSec      float64           `json:"frames_per_sec"`
		ExchangesStarted  uint64            `json:"exchanges_started"`
		ExchangesComplete uint64            `json:"exchanges_complete"`
		ExchangeSuccess   float64           `json:"exchange_success_pct"`
		AuthFailures      uint64            `json:"auth_failures"`
		DecodeErrors      uint64            `json:"decode_errors"`
		LatencyNs         map[string]uint64 `json:"latency_ns"`
	} `json:"metrics"`
	KernelStack struct {
		Steering struct {
			Available bool   `json:"available"`
			Enabled   bool   `json:"enabled"`
			Sent      uint64 `json:"sent"`
		} `json:"steering"`
		VendorIE struct {
			Injected uint64 `json:"injected"`
		} `json:"vendor_ie"`
	} `json:"kernel_stack"`
	// Controller role: the root's summary of the mesh.
	ActiveNodes   uint64 `json:"active_nodes"`
	StaleNodes    uint64 `json:"stale_nodes"`
	BackhaulLinks uint64 `json:"backhaul_links"`
	MLORadios     uint64 `json:"mlo_radios"`
	Topology      struct {
		MeshConnected bool `json:"mesh_connected"`
	} `json:"topology"`
	Environment struct {
		ChannelConflicts uint64 `json:"channel_conflicts"`
	} `json:"environment"`
	Nodes     []wantasticMeshNode `json:"nodes"`
	Distances []struct {
		A      string  `json:"a"`
		B      string  `json:"b"`
		Meters float64 `json:"meters"`
	} `json:"distances"`
	Plan struct {
		Channels []struct {
			Node  string `json:"node"`
			Radio uint64 `json:"radio"`
			Band  uint64 `json:"band_code"`
			From  uint64 `json:"from"`
			To    uint64 `json:"to"`
		} `json:"channels"`
		Heals []struct {
			Node   string `json:"node"`
			Kind   string `json:"kind"`
			Reason string `json:"reason"`
		} `json:"heals"`
	} `json:"plan"`
}

// wantasticMeshStatusPath finds the status file: the init script's default,
// else the -status argument of the running wmeshd. It returns the device path
// (without the test root), or "" when there is none.
func wantasticMeshStatusPath() string {
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshStatusFile)); err == nil {
		return wantasticMeshStatusFile
	}
	entries, err := os.ReadDir(wantasticMeshPath("/proc"))
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		dir := wantasticMeshPath("/proc/" + entry.Name() + "/")
		cmdline, err := os.ReadFile(dir + "cmdline")
		if err != nil || len(cmdline) == 0 || len(cmdline) > 8192 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		comm, _ := os.ReadFile(dir + "comm")
		if strings.TrimSpace(string(comm)) != "wmeshd" && filepath.Base(args[0]) != "wmeshd" {
			continue
		}
		if path := wantasticMeshStatusArg(args[1:]); path != "" {
			return path
		}
	}
	return ""
}

// wantasticMeshStatusArg returns the -status value of a wmeshd command line
// (Go flag syntax: -status p, -status=p, --status p), when it is a clean
// absolute path.
func wantasticMeshStatusArg(args []string) string {
	for i, arg := range args {
		if arg == "--" {
			break
		}
		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		if name == arg {
			continue
		}
		value := ""
		switch {
		case name == "status" && i+1 < len(args):
			value = args[i+1]
		case strings.HasPrefix(name, "status="):
			value = strings.TrimPrefix(name, "status=")
		default:
			continue
		}
		if value == "" || len(value) > 256 || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return ""
		}
		return value
	}
	return ""
}

// readWantasticMeshStatus returns the daemon's status, its age and the path it
// was read from; ok is false when the file is missing, oversized, of an
// unknown schema or invalid.
func readWantasticMeshStatus(now time.Time) (status wantasticMeshStatus, age time.Duration, file string, ok bool) {
	file = wantasticMeshStatusPath()
	if file == "" {
		return status, 0, "", false
	}
	path := wantasticMeshPath(file)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > wantasticMeshStatusMax {
		return status, 0, file, false
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &status) != nil || status.Schema != 1 {
		return wantasticMeshStatus{}, 0, file, false
	}
	age = now.Sub(info.ModTime())
	if at, err := time.Parse(time.RFC3339, status.At); err == nil && now.Sub(at) > age {
		age = now.Sub(at)
	}
	if age < 0 {
		age = 0
	}
	return status, age, file, true
}

func formatWantasticMeshMAC(hex string) string {
	if len(hex) != 12 {
		return ""
	}
	for _, c := range hex {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return ""
		}
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.ToLower(strings.Join(parts, ":"))
}

func wantasticMeshBandName(code uint64) string {
	switch code {
	case 1:
		return "2.4GHz"
	case 2:
		return "5GHz"
	case 3:
		return "6GHz"
	}
	return ""
}

func appendWantasticMeshNode(msg *wusp.Message, base string, node wantasticMeshNode, self bool) {
	msg.Set(base+"ID", wusp.String(node.ID))
	msg.SetBool(base+"Self", self)
	msg.SetBool(base+"Stale", node.Stale)
	msg.SetBool(base+"TelemetryStale", node.TelemetryStale)
	msg.SetUint(base+"Age", node.AgeS)
	msg.SetUint(base+"Reports", node.Reports)
	msg.SetUint(base+"ReportAge", node.ReportAgeS)
	if node.RTTUs > 0 && !node.Stale {
		msg.SetUint(base+"RTT", node.RTTUs)
	}
	if node.RTTNs != nil && !node.Stale {
		msg.SetUint(base+"RTTP50", node.RTTNs.P50/1000)
		msg.SetUint(base+"RTTP95", node.RTTNs.P95/1000)
	}
	msg.SetBool(base+"HasFix", node.Position.Fix)
	if node.Position.Fix {
		msg.Set(base+"Latitude", wusp.Float(node.Position.Lat))
		msg.Set(base+"Longitude", wusp.Float(node.Position.Lon))
		msg.SetInt(base+"Altitude", node.Position.AltM)
	}
	radios := node.Radios
	if len(radios) > wusp.WUSPWantasticMeshMaxRadios {
		radios = radios[:wusp.WUSPWantasticMeshMaxRadios]
	}
	msg.SetUint(base+"RadioNumberOfEntries", uint64(len(radios)))
	for i, radio := range radios {
		p := fmt.Sprintf("%sRadio.%d.", base, i+1)
		msg.SetUint(p+"Index", radio.Index)
		msg.Set(p+"Band", wusp.String(radio.Band))
		msg.SetUint(p+"Channel", radio.Channel)
		msg.SetUint(p+"Width", radio.WidthMHz)
		msg.SetInt(p+"TxPower", radio.TxPowerDBm)
		msg.SetUint(p+"Utilization", radio.Utilization)
		msg.SetBool(p+"Backhaul", radio.Backhaul)
		msg.SetBool(p+"MLO", radio.MLO)
		if radio.MLO {
			msg.SetUint(p+"MLDLink", radio.MLDLink)
		}
		if hw, err := net.ParseMAC(formatWantasticMeshMAC(radio.MAC)); err == nil {
			msg.Set(p+"MAC", wusp.MAC(hw))
		}
		iface := radio.Iface
		if !wantasticMeshName.MatchString(iface) {
			iface = ""
		}
		msg.Set(p+"Interface", wusp.String(iface))
	}
	links := node.Links
	if len(links) > wusp.WUSPWantasticMeshMaxLinks {
		links = links[:wusp.WUSPWantasticMeshMaxLinks]
	}
	count := 0
	for _, link := range links {
		mac := formatWantasticMeshMAC(link.PeerMAC)
		if mac == "" {
			continue
		}
		count++
		p := fmt.Sprintf("%sLink.%d.", base, count)
		msg.Set(p+"PeerMAC", wusp.String(mac))
		msg.SetUint(p+"Radio", link.Radio)
		msg.SetInt(p+"SignalStrength", link.RSSI)
		msg.SetUint(p+"Age", link.AgeMs)
		msg.SetUint(p+"Confidence", link.Confidence)
		msg.SetBool(p+"Backhaul", link.Backhaul)
		msg.SetBool(p+"Bidirectional", link.Bidirectional)
		msg.SetBool(p+"MLO", link.MLO)
		msg.SetBool(p+"Approximate", link.Approximate)
		var counters *wantasticMeshLinkTelemetry
		for i := range node.telemetry {
			if t := &node.telemetry[i]; strings.EqualFold(t.PeerMAC, link.PeerMAC) && t.Radio == link.Radio {
				counters = t
				break
			}
		}
		// Always reported: a row keeps its index across reads, so a flag left
		// out would keep saying an earlier link had counters.
		msg.SetBool(p+"HasTelemetry", counters != nil)
		if counters != nil {
			msg.SetUint(p+"TxRate", uint64(counters.TxMbps*1000))
			msg.SetUint(p+"RxRate", uint64(counters.RxMbps*1000))
			msg.SetUint(p+"BytesSent", counters.TxBytes)
			msg.SetUint(p+"BytesReceived", counters.RxBytes)
			msg.SetUint(p+"Retransmissions", counters.TxRetries)
			msg.SetUint(p+"Failed", counters.TxFailed)
			msg.SetUint(p+"InactiveTime", counters.InactiveMs)
		}
	}
	msg.SetUint(base+"LinkNumberOfEntries", uint64(count))
}

// appendOpenWrtWantasticMesh reports wmeshd's settings and live state. A
// device without wmeshd reports only Installed=false.
func (b *OpenWrtBackend) appendOpenWrtWantasticMesh(msg *wusp.Message) {
	if msg == nil {
		return
	}
	prefix := wusp.WUSPWantasticMeshPrefix
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshBinary)); err != nil {
		msg.SetBool(prefix+"Installed", false)
		msg.Set(prefix+"Status", wusp.String("not_installed"))
		return
	}
	msg.SetBool(prefix+"Installed", true)

	options := map[string]string{}
	if config, err := b.readUCIConfig(wantasticMeshUCIConfig); err == nil {
		if section := config.findSection(wantasticMeshUCISection); section != nil {
			options = section.Options
		}
	}
	option := func(name, fallback string) string {
		if value := strings.TrimSpace(options[name]); value != "" {
			return value
		}
		return fallback
	}
	enabled := option("enabled", "0") == "1"
	role := option("role", "relay")
	if role != "root" {
		role = "relay"
	}
	keyFile := option("key_file", "/etc/wmeshd/control.key")
	_, keyErr := os.Stat(wantasticMeshPath(keyFile))
	_, agentsErr := os.Stat(wantasticMeshPath(wantasticMeshAgentsFile))

	msg.SetBool(prefix+"Enable", enabled)
	msg.Set(prefix+"Role", wusp.String(role))
	msg.Set(prefix+"NetworkID", wusp.String(strings.ToLower(option("net", ""))))
	msg.Set(prefix+"ControllerID", wusp.String(strings.ToLower(option("controller_id", ""))))
	msg.Set(prefix+"ControllerAddress", wusp.String(option("controller_addr", "")))
	if port, err := strconv.ParseUint(option("port", "48213"), 10, 16); err == nil && port > 0 {
		msg.SetUint(prefix+"Port", port)
	}
	msg.SetBool(prefix+"GPS", option("gps", "0") == "1")
	msg.SetBool(prefix+"KeyPresent", (role == "root" && agentsErr == nil) || (role != "root" && keyErr == nil))
	msg.Set(prefix+"Backhaul.SSID", wusp.String(option("backhaul_ssid", "")))
	msg.Set(prefix+"Backhaul.Radio", wusp.String(option("backhaul_radio", "")))
	msg.Set(prefix+"Backhaul.Interface", wusp.String(option("backhaul_sta_if", "wmbhsta0")))
	msg.Set(prefix+"Backhaul.BSSID", wusp.String(strings.ToLower(option("backhaul_bssid", ""))))
	if freq, err := strconv.ParseUint(option("backhaul_freq", "0"), 10, 16); err == nil {
		msg.SetUint(prefix+"Backhaul.Frequency", freq)
	}
	msg.SetBool(prefix+"Backhaul.FourAddress", option("backhaul_4addr", "0") == "1")
	msg.Set(prefix+"Backhaul.MLOSSID", wusp.String(option("backhaul_mlo_ssid", "")))
	msg.Set(prefix+"Backhaul.MLORadios", wusp.String(option("backhaul_mlo_radios", "")))
	msg.Set(prefix+"Backhaul.MLOFrequencies", wusp.String(option("backhaul_mlo_freqs", "")))
	msg.SetBool(prefix+"Steering", option("steering", "1") == "1")
	msg.SetBool(prefix+"Mesh11s", option("mesh11s", "0") == "1")
	msg.Set(prefix+"Mesh11s.ID", wusp.String(option("mesh11s_id", "")))
	msg.Set(prefix+"Mesh11s.Radio", wusp.String(option("mesh11s_radio", "")))
	msg.Set(prefix+"Mesh11s.Interface", wusp.String(option("mesh11s_if", "")))
	msg.SetUint(prefix+"Mesh11s.Frequency", wantasticMeshUintOption(option("mesh11s_freq", "0"), 7125))
	msg.SetBool(prefix+"Mesh11s.Forwarding", option("mesh11s_forwarding", "1") == "1")
	msg.Set(prefix+"Mesh11s.Bridge", wusp.String(option("mesh11s_bridge", "")))
	msg.SetBool(prefix+"TDMA", option("tdma", "0") == "1")
	msg.Set(prefix+"TDMA.Interfaces", wusp.String(option("tdma_interfaces", "")))
	msg.SetUint(prefix+"TDMA.Interval", wantasticMeshUintOption(option("tdma_interval_ms", "0"), 60000))
	// wmeshd stores the 802.11s and TDMA options but does not start those
	// managers yet; the settings take effect once a daemon reports otherwise.
	msg.SetBool(prefix+"Mesh11sSupported", false)
	msg.SetBool(prefix+"TDMASupported", false)
	msg.SetUint(prefix+"BusyPoll", wantasticMeshUintOption(option("busy_poll_us", "0"), 1000))
	msg.Set(prefix+"SupportedOperations", wusp.String(wantasticMeshOperations))

	// What the init script refuses to start without, in its own order.
	missing := ""
	switch {
	case option("net", "") == "":
		missing = "network id is not set"
	case role == "root" && agentsErr != nil:
		missing = "the root's agent keystore (" + wantasticMeshAgentsFile + ") is missing"
	case role != "root" && keyErr != nil:
		missing = "the control key file (" + keyFile + ") is missing"
	case role != "root" && option("controller_id", "") == "":
		missing = "controller id is not set"
	}

	status, age, statusFile, ok := readWantasticMeshStatus(time.Now())
	msg.Set(prefix+"StatusFile", wusp.String(statusFile))
	running := ok && age <= wantasticMeshStatusFresh
	state := "running"
	switch {
	case !enabled:
		state = "disabled"
	case missing != "":
		state = "misconfigured"
	case !ok:
		state = "starting"
	case !running:
		state = "stopped"
	}
	msg.Set(prefix+"Status", wusp.String(state))
	msg.Set(prefix+"StatusDetail", wusp.String(missing))
	msg.SetBool(prefix+"Backhaul.Managed", running && status.Backhaul.Managed)
	msg.SetBool(prefix+"Backhaul.Up", running && status.Backhaul.Up)
	// Every scalar is reported on every read: the hub merges reads into its
	// stored copy, so a value left out would keep its last running figure.
	msg.SetUint(prefix+"StatusAge", uint64(age/time.Second))
	msg.Set(prefix+"NodeID", wusp.String(status.NodeID))
	if !running {
		// A stopped daemon's last graph is history, not the mesh as it is.
		msg.SetUint(prefix+"Uptime", 0)
		msg.SetBool(prefix+"ControllerAlive", false)
		msg.SetUint(prefix+"AgentsConfigured", 0)
		msg.Set(prefix+"Transport", wusp.String(""))
		msg.SetBool(prefix+"MeshConnected", false)
		for _, leaf := range []string{"TransportInterfaces", "ActiveNodes", "StaleNodes", "BackhaulLinks", "MLORadios", "ChannelConflicts", "AuthFailures", "DecodeErrors"} {
			msg.SetUint(prefix+leaf, 0)
		}
		msg.Set(prefix+"ExchangeSuccess", wusp.Float(0))
		for _, table := range []string{"Node", "Survey", "Distance", "PlanChannel", "PlanHeal"} {
			msg.SetUint(prefix+table+"NumberOfEntries", 0)
		}
		for _, leaf := range []string{"Metrics.TxFrames", "Metrics.RxFrames", "Metrics.TxBytes", "Metrics.RxBytes", "Metrics.ExchangesStarted", "Metrics.ExchangesComplete", "Metrics.LatencyNumberOfEntries", "SteeringSent", "VendorIEInjected"} {
			msg.SetUint(prefix+leaf, 0)
		}
		msg.Set(prefix+"Metrics.FramesPerSecond", wusp.Float(0))
		msg.SetBool(prefix+"SteeringAvailable", false)
		return
	}
	msg.SetUint(prefix+"Uptime", status.UptimeS)
	msg.SetBool(prefix+"ControllerAlive", status.Role == "controller" || status.Controller.Alive)
	msg.SetUint(prefix+"AgentsConfigured", status.AgentsConfigured)
	msg.Set(prefix+"Transport", wusp.String(status.Transport.Type))
	msg.SetUint(prefix+"TransportInterfaces", status.Transport.Interfaces)
	root := status.Role == "controller"
	msg.SetBool(prefix+"MeshConnected", root && status.Topology.MeshConnected)
	msg.SetUint(prefix+"ActiveNodes", status.ActiveNodes)
	msg.SetUint(prefix+"StaleNodes", status.StaleNodes)
	msg.SetUint(prefix+"BackhaulLinks", status.BackhaulLinks)
	msg.SetUint(prefix+"MLORadios", status.MLORadios)
	msg.SetUint(prefix+"ChannelConflicts", status.Environment.ChannelConflicts)
	msg.Set(prefix+"ExchangeSuccess", wusp.Float(status.Metrics.ExchangeSuccess))
	msg.SetUint(prefix+"AuthFailures", status.Metrics.AuthFailures)
	msg.SetUint(prefix+"DecodeErrors", status.Metrics.DecodeErrors)
	msg.SetUint(prefix+"Metrics.TxFrames", status.Metrics.TxFrames)
	msg.SetUint(prefix+"Metrics.RxFrames", status.Metrics.RxFrames)
	msg.SetUint(prefix+"Metrics.TxBytes", status.Metrics.TxBytes)
	msg.SetUint(prefix+"Metrics.RxBytes", status.Metrics.RxBytes)
	fps := status.Metrics.FramesPerSec
	if fps < 0 {
		fps = 0
	}
	msg.Set(prefix+"Metrics.FramesPerSecond", wusp.Float(fps))
	msg.SetUint(prefix+"Metrics.ExchangesStarted", status.Metrics.ExchangesStarted)
	msg.SetUint(prefix+"Metrics.ExchangesComplete", status.Metrics.ExchangesComplete)
	latencies := 0
	for _, name := range []string{"announce_to_query", "full_rtt", "query_to_report"} {
		p50, ok := status.Metrics.LatencyNs[name+"_p50"]
		if !ok || latencies >= wusp.WUSPWantasticMeshMaxLatency {
			continue
		}
		latencies++
		p := fmt.Sprintf("%sMetrics.Latency.%d.", prefix, latencies)
		msg.Set(p+"Name", wusp.String(name))
		msg.SetUint(p+"P50", p50/1000)
		msg.SetUint(p+"P95", status.Metrics.LatencyNs[name+"_p95"]/1000)
		msg.SetUint(p+"P99", status.Metrics.LatencyNs[name+"_p99"]/1000)
	}
	msg.SetUint(prefix+"Metrics.LatencyNumberOfEntries", uint64(latencies))
	msg.SetBool(prefix+"SteeringAvailable", status.KernelStack.Steering.Available)
	msg.SetUint(prefix+"SteeringSent", status.KernelStack.Steering.Sent)
	msg.SetUint(prefix+"VendorIEInjected", status.KernelStack.VendorIE.Injected)

	surveys := status.Surveys
	if len(surveys) > wusp.WUSPWantasticMeshMaxSurveys {
		surveys = surveys[:wusp.WUSPWantasticMeshMaxSurveys]
	}
	msg.SetUint(prefix+"SurveyNumberOfEntries", uint64(len(surveys)))
	for i, survey := range surveys {
		p := fmt.Sprintf("%sSurvey.%d.", prefix, i+1)
		msg.SetUint(p+"Frequency", survey.FreqMHz)
		msg.SetInt(p+"Noise", survey.NoiseDBm)
		busy := 0.0
		if survey.Utilization != nil {
			busy = *survey.Utilization
		}
		msg.Set(p+"Utilization", wusp.Float(busy))
	}

	nodes := status.Nodes
	if !root {
		nodes = []wantasticMeshNode{{ID: status.NodeID, Radios: status.Radios, Links: status.Links, Position: status.Position, telemetry: status.LinkTelemetry}}
	}
	if len(nodes) > wusp.WUSPWantasticMeshMaxNodes {
		nodes = nodes[:wusp.WUSPWantasticMeshMaxNodes]
	}
	msg.SetUint(prefix+"NodeNumberOfEntries", uint64(len(nodes)))
	for i, node := range nodes {
		appendWantasticMeshNode(msg, fmt.Sprintf("%sNode.%d.", prefix, i+1), node, node.ID == status.NodeID)
	}
	distances := status.Distances
	if len(distances) > wusp.WUSPWantasticMeshMaxDistances {
		distances = distances[:wusp.WUSPWantasticMeshMaxDistances]
	}
	msg.SetUint(prefix+"DistanceNumberOfEntries", uint64(len(distances)))
	for i, distance := range distances {
		p := fmt.Sprintf("%sDistance.%d.", prefix, i+1)
		msg.Set(p+"A", wusp.String(distance.A))
		msg.Set(p+"B", wusp.String(distance.B))
		msg.Set(p+"Meters", wusp.Float(distance.Meters))
	}
	channels := status.Plan.Channels
	if len(channels) > wusp.WUSPWantasticMeshMaxPlanRows {
		channels = channels[:wusp.WUSPWantasticMeshMaxPlanRows]
	}
	msg.SetUint(prefix+"PlanChannelNumberOfEntries", uint64(len(channels)))
	for i, move := range channels {
		p := fmt.Sprintf("%sPlanChannel.%d.", prefix, i+1)
		msg.Set(p+"Node", wusp.String(move.Node))
		msg.SetUint(p+"Radio", move.Radio)
		msg.Set(p+"Band", wusp.String(wantasticMeshBandName(move.Band)))
		msg.SetUint(p+"From", move.From)
		msg.SetUint(p+"To", move.To)
	}
	heals := status.Plan.Heals
	if len(heals) > wusp.WUSPWantasticMeshMaxPlanRows {
		heals = heals[:wusp.WUSPWantasticMeshMaxPlanRows]
	}
	msg.SetUint(prefix+"PlanHealNumberOfEntries", uint64(len(heals)))
	for i, heal := range heals {
		p := fmt.Sprintf("%sPlanHeal.%d.", prefix, i+1)
		msg.Set(p+"Node", wusp.String(heal.Node))
		msg.Set(p+"Kind", wusp.String(heal.Kind))
		msg.Set(p+"Reason", wusp.String(heal.Reason))
	}
}

var (
	wantasticMeshHex16 = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)
	wantasticMeshHex32 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	wantasticMeshName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
)

func boolOption(value wusp.Value) string {
	if value.AsBool() {
		return "1"
	}
	return "0"
}

// setOpenWrtWantasticMeshParam writes one wmeshd setting. Every value is
// validated here because the init script passes options to the daemon's
// command line and environment.
func (b *OpenWrtBackend) setOpenWrtWantasticMeshParam(ctx context.Context, path string, value wusp.Value) error {
	if !strings.HasPrefix(path, wusp.WUSPWantasticMeshPrefix) {
		return wusp.ErrUSPPathUnsupported
	}
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshBinary)); err != nil {
		return fmt.Errorf("WantasticMesh is not installed on this device")
	}
	text := strings.TrimSpace(wusp.ValueToString(value))
	var option, setting string
	switch strings.TrimPrefix(path, wusp.WUSPWantasticMeshPrefix) {
	case "Enable":
		option, setting = "enabled", boolOption(value)
	case "Role":
		if text != "root" && text != "relay" {
			return fmt.Errorf("role must be root or relay")
		}
		option, setting = "role", text
	case "NetworkID":
		if text != "" && !wantasticMeshHex16.MatchString(text) {
			return fmt.Errorf("network id must be 16 hex characters")
		}
		option, setting = "net", strings.ToLower(text)
	case "ControllerID":
		if text != "" && !wantasticMeshHex32.MatchString(text) {
			return fmt.Errorf("controller id must be 32 hex characters")
		}
		option, setting = "controller_id", strings.ToLower(text)
	case "ControllerAddress":
		if text != "" {
			ip := net.ParseIP(text)
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("controller address must be an IPv4 address")
			}
			text = ip.To4().String()
		}
		option, setting = "controller_addr", text
	case "Port":
		port, ok := wuspUintValue(value)
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
		option, setting = "port", strconv.FormatUint(port, 10)
	case "GPS":
		option, setting = "gps", boolOption(value)
	case "Backhaul.SSID":
		if len(text) > 32 || strings.ContainsAny(text, "\x00\r\n\"'`$\\") {
			return fmt.Errorf("backhaul SSID is not valid")
		}
		option, setting = "backhaul_ssid", text
	case "Backhaul.Radio":
		if text != "" && !wantasticMeshName.MatchString(text) {
			return fmt.Errorf("backhaul radio is not a valid radio name")
		}
		option, setting = "backhaul_radio", text
	case "Backhaul.Interface":
		if !wantasticMeshName.MatchString(text) {
			return fmt.Errorf("backhaul interface is not a valid interface name")
		}
		option, setting = "backhaul_sta_if", text
	case "Backhaul.BSSID":
		if text != "" {
			mac, err := net.ParseMAC(text)
			if err != nil || len(mac) != 6 {
				return fmt.Errorf("backhaul BSSID must be a MAC address")
			}
			text = mac.String()
		}
		option, setting = "backhaul_bssid", text
	case "Backhaul.Frequency":
		freq, ok := wuspUintValue(value)
		if !ok || freq > 7125 {
			return fmt.Errorf("backhaul frequency must be in MHz, 0 for any")
		}
		setting = ""
		if freq > 0 {
			setting = strconv.FormatUint(freq, 10)
		}
		option = "backhaul_freq"
	case "Backhaul.FourAddress":
		option, setting = "backhaul_4addr", boolOption(value)
	case "Backhaul.MLOSSID":
		if len(text) > 32 || strings.ContainsAny(text, "\x00\r\n\"'`$\\") {
			return fmt.Errorf("multi-link backhaul SSID is not valid")
		}
		option, setting = "backhaul_mlo_ssid", text
	case "Backhaul.MLORadios":
		radios, err := wantasticMeshList(text, func(item string) bool { return wantasticMeshName.MatchString(item) })
		if err != nil {
			return fmt.Errorf("multi-link radios must be up to 4 radio names, comma separated")
		}
		option, setting = "backhaul_mlo_radios", radios
	case "Backhaul.MLOFrequencies":
		freqs, err := wantasticMeshList(text, func(item string) bool {
			mhz, err := strconv.ParseUint(item, 10, 16)
			return err == nil && mhz >= 2400 && mhz <= 7125
		})
		if err != nil {
			return fmt.Errorf("multi-link frequencies must be up to 4 values in MHz, comma separated")
		}
		option, setting = "backhaul_mlo_freqs", freqs
	case "Steering":
		option, setting = "steering", boolOption(value)
	case "Mesh11s":
		option, setting = "mesh11s", boolOption(value)
	case "Mesh11s.ID":
		if len(text) > 32 || !wantasticMeshSafeText(text) {
			return fmt.Errorf("802.11s mesh id is not valid")
		}
		option, setting = "mesh11s_id", text
	case "Mesh11s.Radio":
		if text != "" && !wantasticMeshName.MatchString(text) {
			return fmt.Errorf("802.11s radio is not a valid radio name")
		}
		option, setting = "mesh11s_radio", text
	case "Mesh11s.Interface":
		if text != "" && !wantasticMeshName.MatchString(text) {
			return fmt.Errorf("802.11s interface is not a valid interface name")
		}
		option, setting = "mesh11s_if", text
	case "Mesh11s.Frequency":
		freq, ok := wuspUintValue(value)
		if !ok || (freq != 0 && (freq < 2400 || freq > 7125)) {
			return fmt.Errorf("802.11s frequency must be 2400-7125 MHz, 0 for the radio's own")
		}
		option, setting = "mesh11s_freq", ""
		if freq > 0 {
			setting = strconv.FormatUint(freq, 10)
		}
	case "Mesh11s.Forwarding":
		option, setting = "mesh11s_forwarding", boolOption(value)
	case "Mesh11s.Bridge":
		if text != "" && !wantasticMeshName.MatchString(text) {
			return fmt.Errorf("802.11s bridge is not a valid interface name")
		}
		option, setting = "mesh11s_bridge", text
	case "TDMA":
		option, setting = "tdma", boolOption(value)
	case "TDMA.Interfaces":
		ifaces, err := wantasticMeshList(text, func(item string) bool { return wantasticMeshName.MatchString(item) })
		if err != nil {
			return fmt.Errorf("TDMA interfaces must be up to 4 interface names, comma separated")
		}
		option, setting = "tdma_interfaces", ifaces
	case "TDMA.Interval":
		ms, ok := wuspUintValue(value)
		if !ok || (ms != 0 && (ms < 1000 || ms > 60000)) {
			return fmt.Errorf("TDMA interval must be 1000-60000 ms, 0 for the default")
		}
		option, setting = "tdma_interval_ms", ""
		if ms > 0 {
			setting = strconv.FormatUint(ms, 10)
		}
	case "BusyPoll":
		us, ok := wuspUintValue(value)
		if !ok || us > 1000 {
			return fmt.Errorf("busy-poll must be 0-1000 microseconds")
		}
		option, setting = "busy_poll_us", ""
		if us > 0 {
			setting = strconv.FormatUint(us, 10)
		}
	default:
		return wusp.ErrUSPPathUnsupported
	}
	return b.setUCIOption(ctx, wantasticMeshUCIConfig, wantasticMeshUCISection, option, setting, true, wantasticMeshInitScript)
}

// wantasticMeshSafeText reports whether text can reach the init script's
// environment unquoted-safe: no quotes, $, backticks, backslashes or control
// characters.
func wantasticMeshSafeText(text string) bool {
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(text, "\"'`$\\")
}

// wantasticMeshList normalises a comma or space separated list of up to four
// items, each accepted by valid; "" stays empty.
func wantasticMeshList(text string, valid func(string) bool) (string, error) {
	items := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' })
	if len(items) > 4 {
		return "", fmt.Errorf("too many items")
	}
	for _, item := range items {
		if !valid(item) {
			return "", fmt.Errorf("invalid item")
		}
	}
	return strings.Join(items, ","), nil
}

// wantasticMeshUintOption reads a numeric UCI option, 0 when empty, invalid
// or above max.
func wantasticMeshUintOption(text string, max uint64) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil || n > max {
		return 0
	}
	return n
}

// wuspUintValue reads an unsigned number sent as a number or as text.
func wuspUintValue(value wusp.Value) (uint64, bool) {
	switch value.Tag {
	case wusp.TagUint:
		return value.AsUint(), true
	case wusp.TagInt:
		return uint64(value.AsInt()), value.AsInt() >= 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(wusp.ValueToString(value)), 10, 64)
	return n, err == nil
}

// wantasticMeshOperations lists the Operate commands this backend runs.
const wantasticMeshOperations = "Restart,Radio.SetChannel,Radio.SetTxPower"

// RestartWantasticMesh restarts the wmeshd service through its init script.
// It runs only on an explicit Operate.
func (b *OpenWrtBackend) RestartWantasticMesh(ctx context.Context) error {
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshBinary)); err != nil {
		return fmt.Errorf("WantasticMesh is not installed on this device")
	}
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshInitScript)); err != nil {
		return fmt.Errorf("the wmeshd service script is missing")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := b.commandRunner(ctx, wantasticMeshInitScript, "restart"); err != nil {
		return fmt.Errorf("restart wmeshd: %w", err)
	}
	return nil
}

// WantasticMeshRadioChange is one guarded radio change requested through
// Radio.SetChannel() or Radio.SetTxPower().
type WantasticMeshRadioChange struct {
	Interface string
	// Value is the target channel (SetChannel) or dBm (SetTxPower).
	Value uint64
	// RevertSeconds is the console's revert window, 15-600. wmeshd's guard
	// verifies the change itself and reverts on its own watchdog; its CLI has
	// no window argument, so this is validated but not forwarded.
	RevertSeconds uint64
	// Probe applies the change and restores it at once (wmeshd -revert).
	Probe bool
}

// wantasticMeshRadioArgs builds the wmeshd argv for a guarded change, exactly
// as cmd/wmeshd/radio_cmd.go parses it: radio channel -iface X -channel N
// [-revert], radio txpower -iface X -dbm N [-revert].
func wantasticMeshRadioArgs(kind string, change WantasticMeshRadioChange) ([]string, error) {
	// A leading '-' would read as a flag on wmeshd's command line.
	if !wantasticMeshName.MatchString(change.Interface) || strings.HasPrefix(change.Interface, "-") {
		return nil, fmt.Errorf("interface is not a valid interface name")
	}
	if change.RevertSeconds < 15 || change.RevertSeconds > 600 {
		return nil, fmt.Errorf("revert window must be 15-600 seconds")
	}
	var args []string
	switch kind {
	case "channel":
		if change.Value < 1 || change.Value > 196 {
			return nil, fmt.Errorf("channel must be 1-196")
		}
		args = []string{"radio", "channel", "-iface", change.Interface, "-channel", strconv.FormatUint(change.Value, 10)}
	case "txpower":
		if change.Value > 30 {
			return nil, fmt.Errorf("transmit power must be 0-30 dBm")
		}
		args = []string{"radio", "txpower", "-iface", change.Interface, "-dbm", strconv.FormatUint(change.Value, 10)}
	default:
		return nil, fmt.Errorf("unknown radio change %q", kind)
	}
	if change.Probe {
		args = append(args, "-revert")
	}
	return args, nil
}

var wantasticMeshRadioResult = regexp.MustCompile(`before=(?:ch)?(-?[0-9]+)(?:dBm)?\s+after=(?:ch)?(-?[0-9]+)(?:dBm)?`)

func (b *OpenWrtBackend) runWantasticMeshRadio(ctx context.Context, kind string, change WantasticMeshRadioChange) (before, after string, err error) {
	args, err := wantasticMeshRadioArgs(kind, change)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(wantasticMeshPath(wantasticMeshBinary)); err != nil {
		return "", "", fmt.Errorf("WantasticMesh is not installed on this device")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	output, err := b.commandRunner(ctx, wantasticMeshBinary, args...)
	if err != nil {
		return "", "", fmt.Errorf("wmeshd radio %s: %w", kind, err)
	}
	match := wantasticMeshRadioResult.FindStringSubmatch(string(output))
	if match == nil {
		return "", "", fmt.Errorf("wmeshd radio %s gave no before/after result", kind)
	}
	return match[1], match[2], nil
}

// SetWantasticMeshChannel runs wmeshd's guarded channel switch. It runs only
// on an explicit Operate and returns the channel before and after.
func (b *OpenWrtBackend) SetWantasticMeshChannel(ctx context.Context, change WantasticMeshRadioChange) (before, after string, err error) {
	return b.runWantasticMeshRadio(ctx, "channel", change)
}

// SetWantasticMeshTxPower runs wmeshd's guarded tx-power change. It runs only
// on an explicit Operate and returns the dBm before and after.
func (b *OpenWrtBackend) SetWantasticMeshTxPower(ctx context.Context, change WantasticMeshRadioChange) (before, after string, err error) {
	return b.runWantasticMeshRadio(ctx, "txpower", change)
}
