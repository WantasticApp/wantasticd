package platforms

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func wantasticMeshFixture(t *testing.T, uci, status string, files ...string) *OpenWrtBackend {
	t.Helper()
	root := t.TempDir()
	prev := wantasticMeshRoot
	wantasticMeshRoot = root
	t.Cleanup(func() { wantasticMeshRoot = prev })
	write := func(path, content string) {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		write(file, "x")
	}
	if uci != "" {
		write("/etc/config/wmesh", uci)
	}
	if status != "" {
		write(wantasticMeshStatusFile, status)
	}
	return &OpenWrtBackend{uciConfigDir: filepath.Join(root, "etc/config"), commandRunner: func(context.Context, string, ...string) ([]byte, error) { return nil, nil }}
}

func meshField(t *testing.T, msg *wusp.Message, leaf string) string {
	t.Helper()
	for _, f := range msg.Fields {
		if f.Path == wusp.WUSPWantasticMeshPrefix+leaf {
			if f.Val.Tag == wusp.TagTrue {
				return "true"
			}
			if f.Val.Tag == wusp.TagFalse {
				return "false"
			}
			return wuspValueText(f.Val)
		}
	}
	return "<absent>"
}

const rootUCI = `config wmesh 'global'
	option enabled '1'
	option role 'root'
	option net 'A1B2C3D4E5F60718'
	option port '48213'
	option backhaul_ssid 'wmesh-bh'
	option gps '1'
`

func TestWantasticMeshRootReportsTheWholeGraph(t *testing.T) {
	at := time.Now().UTC().Format(time.RFC3339)
	status := `{"schema":1,"role":"controller","node_id":"aa000000000000000000000000000000","network_id":"a1b2c3d4e5f60718","at":"` + at + `","uptime_s":3600,"agents_configured":1,
"active_nodes":1,"stale_nodes":1,"backhaul_links":1,"mlo_radios":1,
"transport":{"type":"l2","ethertype":"0x88b5","interfaces":3},
"topology":{"edges":[],"mesh_connected":true},"environment":{"bands":[],"channel_conflicts":2},
"metrics":{"exchanges_started":10,"exchange_success_pct":90.0,"auth_failures":1,"decode_errors":0},
"nodes":[{"id":"aa000000000000000000000000000000","stale":false,"age_s":1,"reports":9,"report_age_s":2,"rtt_us":850,
  "radios":[{"index":2,"band_code":3,"band":"6GHz","channel":129,"width_mhz":320,"tx_power_dbm":12,"utilization":9,"backhaul":true,"mlo":true,"mld_link":1}],
  "links":[{"peer_mac":"00037f12c3c3","radio":2,"rssi_dbm":-44,"age_ms":500,"confidence":90,"backhaul":true,"bidirectional":true,"mlo":false,"approximate":false},{"peer_mac":"bad","radio":0}],
  "position":{"gps":true,"fix":true,"lat":26.03672,"lon":-98.34417,"alt_m":30}},
 {"id":"bb000000000000000000000000000000","stale":true,"age_s":90,"radios":[],"links":[],"position":{"gps":false,"fix":false}}],
"distances":[{"a":"aa000000000000000000000000000000","b":"bb000000000000000000000000000000","meters":17.4}],
"plan":{"channels":[{"node":"bb000000000000000000000000000000","radio":1,"band_code":2,"from":36,"to":149}],"heals":[{"node":"bb000000000000000000000000000000","kind":"rejoin","reason":"silent for 90s"}]},
"future_field":true}`
	b := wantasticMeshFixture(t, rootUCI, status, wantasticMeshBinary, wantasticMeshAgentsFile)
	msg := wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)

	want := map[string]string{
		"Installed": "true", "Enable": "true", "Status": "running", "StatusDetail": "", "Role": "root",
		"NetworkID": "a1b2c3d4e5f60718", "KeyPresent": "true", "ControllerAlive": "true", "Uptime": "3600",
		"Backhaul.SSID": "wmesh-bh", "GPS": "true", "NodeNumberOfEntries": "2",
		"Node.1.Self": "true", "Node.1.HasFix": "true", "Node.1.Latitude": "26.03672",
		"Node.1.Radio.1.Band": "6GHz", "Node.1.Radio.1.Width": "320", "Node.1.Radio.1.MLO": "true", "Node.1.Radio.1.MLDLink": "1",
		"Node.1.LinkNumberOfEntries": "1", "Node.1.Link.1.PeerMAC": "00:03:7f:12:c3:c3", "Node.1.Link.1.SignalStrength": "-44", "Node.1.Link.1.Backhaul": "true",
		"Node.2.Self": "false", "Node.2.Stale": "true", "Node.2.Latitude": "<absent>",
		"DistanceNumberOfEntries": "1", "Distance.1.Meters": "17.4",
		"PlanChannel.1.Band": "5GHz", "PlanChannel.1.To": "149", "PlanHeal.1.Kind": "rejoin",
		"Transport": "l2", "TransportInterfaces": "3", "MeshConnected": "true", "ActiveNodes": "1", "StaleNodes": "1",
		"BackhaulLinks": "1", "MLORadios": "1", "ChannelConflicts": "2", "ExchangeSuccess": "90", "AuthFailures": "1",
		"Node.1.RTT": "850", "Node.2.RTT": "<absent>", "Node.1.Link.1.HasTelemetry": "false", "SurveyNumberOfEntries": "0",
	}
	for leaf, value := range want {
		if got := meshField(t, msg, leaf); got != value {
			t.Errorf("%s = %q, want %q", leaf, got, value)
		}
	}
	// Nothing secret, and nothing outside the declared model.
	declared := map[string]struct{}{}
	for _, p := range wusp.AllWUSPWantasticMeshParams {
		declared[p.Path] = struct{}{}
	}
	for _, f := range msg.Fields {
		if strings.Contains(strings.ToLower(f.Path), "key") && !strings.HasSuffix(f.Path, "KeyPresent") {
			t.Errorf("key material path reported: %s", f.Path)
		}
		if _, ok := declared[templatePath(f.Path)]; !ok {
			t.Errorf("%s is not in the data model", f.Path)
		}
	}
}

func templatePath(path string) string {
	parts := strings.Split(path, ".")
	for i, part := range parts {
		if part != "" && strings.Trim(part, "0123456789") == "" {
			parts[i] = "{i}"
		}
	}
	return strings.Join(parts, ".")
}

func TestWantasticMeshLeafStatesAndMissingDaemon(t *testing.T) {
	// Not installed: one fact, nothing else.
	b := wantasticMeshFixture(t, "", "")
	msg := wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	if meshField(t, msg, "Installed") != "false" || meshField(t, msg, "Status") != "not_installed" || len(msg.Fields) != 2 {
		t.Fatalf("not installed: %+v", msg.Fields)
	}

	leafUCI := "config wmesh 'global'\n\toption enabled '1'\n\toption role 'relay'\n\toption net 'a1b2c3d4e5f60718'\n\toption controller_id 'aa000000000000000000000000000000'\n"
	// Enabled but its key file is missing: misconfigured, with the reason.
	b = wantasticMeshFixture(t, leafUCI, "", wantasticMeshBinary)
	msg = wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	if meshField(t, msg, "Status") != "misconfigured" || !strings.Contains(meshField(t, msg, "StatusDetail"), "control key file") || meshField(t, msg, "KeyPresent") != "false" {
		t.Fatalf("misconfigured leaf: status=%s detail=%s", meshField(t, msg, "Status"), meshField(t, msg, "StatusDetail"))
	}

	// A running leaf reports itself as its only node.
	at := time.Now().UTC().Format(time.RFC3339)
	status := `{"schema":1,"role":"agent","node_id":"bb000000000000000000000000000000","at":"` + at + `","uptime_s":60,"controller":{"id":"aa000000000000000000000000000000","alive":true},"backhaul":{"managed":true,"up":true,"ssid":"wmesh-bh","interface":"wmbhsta0"},"radios":[{"index":2,"band":"6GHz","channel":129,"width_mhz":320}],
"links":[{"peer_mac":"00037f1256c0","radio":2,"rssi_dbm":-44,"backhaul":true,"mlo":true}],
"link_telemetry":[{"peer_mac":"00037f1256c0","radio":2,"signal_dbm":-44,"tx_mbps":2401.9,"rx_mbps":1921.5,"tx_bytes":123456789012,"rx_bytes":42,"tx_retries":7,"tx_failed":1,"inactive_ms":20}],
"surveys":[{"freq_mhz":6595,"noise_dbm":-93,"active_ms":1000,"busy_ms":120,"utilization_pct":12.0},{"freq_mhz":5955,"noise_dbm":-92}],
"transport":{"type":"l2","interfaces":2},"metrics":{"exchange_success_pct":100.0},"position":{"gps":false,"fix":false}}`
	b = wantasticMeshFixture(t, leafUCI, status, wantasticMeshBinary, "/etc/wmeshd/control.key")
	msg = wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	for leaf, value := range map[string]string{
		"Status": "running", "ControllerAlive": "true", "Backhaul.Up": "true", "NodeNumberOfEntries": "1", "Node.1.Self": "true", "Node.1.Radio.1.Channel": "129",
		// The leaf's own driver counters ride on its link row; a leaf is not the root.
		"Node.1.Link.1.HasTelemetry": "true", "Node.1.Link.1.TxRate": "2401900", "Node.1.Link.1.RxRate": "1921500",
		"Node.1.Link.1.BytesSent": "123456789012", "Node.1.Link.1.Retransmissions": "7", "Node.1.Link.1.Failed": "1", "Node.1.Link.1.InactiveTime": "20",
		"SurveyNumberOfEntries": "2", "Survey.1.Frequency": "6595", "Survey.1.Noise": "-93", "Survey.1.Utilization": "12", "Survey.2.Utilization": "0",
		"Transport": "l2", "MeshConnected": "false", "ExchangeSuccess": "100",
	} {
		if got := meshField(t, msg, leaf); got != value {
			t.Errorf("leaf %s = %q, want %q", leaf, got, value)
		}
	}

	// A status file the daemon stopped rewriting: stopped, and no stale graph.
	old := `{"schema":1,"role":"agent","node_id":"bb000000000000000000000000000000","at":"2026-01-01T00:00:00Z","radios":[{"index":1}]}`
	b = wantasticMeshFixture(t, leafUCI, old, wantasticMeshBinary, "/etc/wmeshd/control.key")
	msg = wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	if meshField(t, msg, "Status") != "stopped" || meshField(t, msg, "NodeNumberOfEntries") != "0" || meshField(t, msg, "Backhaul.Up") != "false" ||
		meshField(t, msg, "SurveyNumberOfEntries") != "0" || meshField(t, msg, "Transport") != "" {
		t.Fatalf("stopped leaf: %s nodes=%s", meshField(t, msg, "Status"), meshField(t, msg, "NodeNumberOfEntries"))
	}
}

func TestWantasticMeshSetValidatesAndWritesUCI(t *testing.T) {
	b := wantasticMeshFixture(t, "config wmesh 'global'\n\toption enabled '0'\n", "", wantasticMeshBinary)
	ctx := context.Background()
	p := wusp.WUSPWantasticMeshPrefix
	bad := map[string]wusp.Value{
		"Role":                    wusp.String("leader"),
		"NetworkID":               wusp.String("xyz"),
		"ControllerID":            wusp.String("aa"),
		"ControllerAddress":       wusp.String("10.0.0.1; reboot"),
		"Port":                    wusp.Uint(70000),
		"Backhaul.SSID":           wusp.String("bh\"$(reboot)"),
		"Backhaul.Interface":      wusp.String("wm bh"),
		"Backhaul.BSSID":          wusp.String("not-a-mac"),
		"Backhaul.Frequency":      wusp.Uint(99999),
		"Backhaul.MLORadios":      wusp.String("phy1,phy2;reboot"),
		"Backhaul.MLOFrequencies": wusp.String("5955,99999"),
		"Backhaul.MLOSSID":        wusp.String("mlo$(id)"),
	}
	for leaf, value := range bad {
		if err := b.setOpenWrtWantasticMeshParam(ctx, p+leaf, value); err == nil || err == wusp.ErrUSPPathUnsupported {
			t.Errorf("%s accepted %q (err=%v)", leaf, value.AsString(), err)
		}
	}
	good := map[string]wusp.Value{
		"Enable": wusp.Bool(true), "Role": wusp.String("relay"), "NetworkID": wusp.String("A1B2C3D4E5F60718"),
		"ControllerID": wusp.String("AA000000000000000000000000000000"), "ControllerAddress": wusp.String("10.99.99.1"),
		"Port": wusp.Uint(48213), "Backhaul.SSID": wusp.String("wmesh-bh"), "Backhaul.BSSID": wusp.String("00:03:7F:12:56:56"), "Backhaul.Frequency": wusp.Uint(6595),
		"Backhaul.MLOSSID": wusp.String("wmesh-mlo"), "Backhaul.MLORadios": wusp.String("phy1, phy2"), "Backhaul.MLOFrequencies": wusp.String("5955 6595"),
	}
	for leaf, value := range good {
		if err := b.setOpenWrtWantasticMeshParam(ctx, p+leaf, value); err != nil {
			t.Fatalf("%s rejected: %v", leaf, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(b.uciConfigDir, "wmesh"))
	for _, want := range []string{"option enabled '1'", "option role 'relay'", "option net 'a1b2c3d4e5f60718'", "option controller_id 'aa000000000000000000000000000000'", "option controller_addr '10.99.99.1'", "option backhaul_ssid 'wmesh-bh'", "option backhaul_bssid '00:03:7f:12:56:56'", "option backhaul_freq '6595'", "option backhaul_mlo_ssid 'wmesh-mlo'", "option backhaul_mlo_radios 'phy1,phy2'", "option backhaul_mlo_freqs '5955,6595'"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("uci missing %q in:\n%s", want, data)
		}
	}
	if err := b.setOpenWrtWantasticMeshParam(ctx, p+"KeyPresent", wusp.Bool(true)); err != wusp.ErrUSPPathUnsupported {
		t.Errorf("read-only path was writable: %v", err)
	}
	if err := b.setOpenWrtWantasticMeshParam(ctx, "Device.WiFi.Radio.1.Channel", wusp.Uint(1)); err != wusp.ErrUSPPathUnsupported {
		t.Errorf("foreign path handled: %v", err)
	}
}

func wuspValueText(v wusp.Value) string {
	switch v.Tag {
	case wusp.TagUint:
		return strconv.FormatUint(v.AsUint(), 10)
	case wusp.TagInt:
		return strconv.FormatInt(v.AsInt(), 10)
	case wusp.TagFloat:
		return strconv.FormatFloat(v.AsFloat(), 'f', -1, 64)
	}
	return v.AsString()
}
