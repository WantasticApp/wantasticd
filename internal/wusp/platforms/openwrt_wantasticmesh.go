package platforms

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
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
	Radios    []wantasticMeshRadio  `json:"radios"`
	Links     []wantasticMeshLink   `json:"links"`
	Position  wantasticMeshPosition `json:"position"`
	Nodes     []wantasticMeshNode   `json:"nodes"`
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

// readWantasticMeshStatus returns the daemon's status and its age; ok is
// false when the file is missing, oversized, of an unknown schema or invalid.
func readWantasticMeshStatus(now time.Time) (status wantasticMeshStatus, age time.Duration, ok bool) {
	path := wantasticMeshPath(wantasticMeshStatusFile)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > wantasticMeshStatusMax {
		return status, 0, false
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &status) != nil || status.Schema != 1 {
		return wantasticMeshStatus{}, 0, false
	}
	age = now.Sub(info.ModTime())
	if at, err := time.Parse(time.RFC3339, status.At); err == nil && now.Sub(at) > age {
		age = now.Sub(at)
	}
	if age < 0 {
		age = 0
	}
	return status, age, true
}

func formatWantasticMeshMAC(hex string) string {
	if len(hex) != 12 {
		return ""
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

	status, age, ok := readWantasticMeshStatus(time.Now())
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
		for _, table := range []string{"Node", "Distance", "PlanChannel", "PlanHeal"} {
			msg.SetUint(prefix+table+"NumberOfEntries", 0)
		}
		return
	}
	msg.SetUint(prefix+"Uptime", status.UptimeS)
	msg.SetBool(prefix+"ControllerAlive", status.Role == "controller" || status.Controller.Alive)
	msg.SetUint(prefix+"AgentsConfigured", status.AgentsConfigured)

	nodes := status.Nodes
	if status.Role != "controller" {
		nodes = []wantasticMeshNode{{ID: status.NodeID, Radios: status.Radios, Links: status.Links, Position: status.Position}}
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
	default:
		return wusp.ErrUSPPathUnsupported
	}
	return b.setUCIOption(ctx, wantasticMeshUCIConfig, wantasticMeshUCISection, option, setting, true, wantasticMeshInitScript)
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
