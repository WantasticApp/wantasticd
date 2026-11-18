package platforms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestWantasticMeshPerformanceFeaturesAndRadioMACs(t *testing.T) {
	at := time.Now().UTC().Format(time.RFC3339)
	status := `{"schema":1,"role":"controller","node_id":"aa000000000000000000000000000000","at":"` + at + `","uptime_s":60,
"metrics":{"tx_frames":1200,"rx_frames":800,"tx_bytes":5000000000,"rx_bytes":42000,"frames_per_sec":33.3,"exchanges_started":10,"exchanges_complete":9,"exchange_success_pct":90.0,"auth_failures":0,"decode_errors":0,"uptime_s":60,
  "latency_ns":{"announce_to_query_p50":1500000,"announce_to_query_p95":2500000,"announce_to_query_p99":3500000,"full_rtt_p50":4000000,"full_rtt_p95":5000000,"full_rtt_p99":9000000}},
"kernel_stack":{"steering":{"available":true,"enabled":true,"sent":7},"vendor_ie":{"injected":2},"phase1":{}},
"nodes":[{"id":"aa000000000000000000000000000000","age_s":1,"rtt_ns":{"p50":850000,"p95":1250000},
  "radios":[{"index":0,"band":"5GHz","channel":36,"mac":"00037F1256C0","iface":"ath0"},{"index":1,"band":"6GHz","channel":37,"mac":"","iface":"bad name;"}],"links":[]},
 {"id":"bb000000000000000000000000000000","age_s":1,"radios":[{"index":0,"mac":"","iface":""}],"links":[]}]}`
	uci := rootUCI + "\toption steering '0'\n\toption mesh11s '1'\n\toption mesh11s_id 'wm11s'\n\toption mesh11s_radio 'phy1'\n\toption mesh11s_if 'mesh0'\n\toption mesh11s_freq '5180'\n\toption mesh11s_forwarding '0'\n\toption mesh11s_bridge 'br-lan'\n\toption tdma '1'\n\toption tdma_interfaces 'ath0,ath1'\n\toption tdma_interval_ms '2000'\n\toption busy_poll_us '50'\n"
	b := wantasticMeshFixture(t, uci, status, wantasticMeshBinary, wantasticMeshAgentsFile)
	msg := wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	want := map[string]string{
		"StatusFile": wantasticMeshStatusFile, "Status": "running",
		"Metrics.TxFrames": "1200", "Metrics.RxFrames": "800", "Metrics.TxBytes": "5000000000", "Metrics.RxBytes": "42000",
		"Metrics.FramesPerSecond": "33.3", "Metrics.ExchangesStarted": "10", "Metrics.ExchangesComplete": "9",
		"Metrics.LatencyNumberOfEntries": "2",
		"Metrics.Latency.1.Name":         "announce_to_query", "Metrics.Latency.1.P50": "1500", "Metrics.Latency.1.P95": "2500", "Metrics.Latency.1.P99": "3500",
		"Metrics.Latency.2.Name": "full_rtt", "Metrics.Latency.2.P50": "4000", "Metrics.Latency.2.P99": "9000",
		"SteeringAvailable": "true", "SteeringSent": "7", "VendorIEInjected": "2",
		"Node.1.RTTP50": "850", "Node.1.RTTP95": "1250", "Node.2.RTTP50": "<absent>",
		"Node.1.Radio.1.MAC": "00:03:7f:12:56:c0", "Node.1.Radio.1.Interface": "ath0",
		"Node.1.Radio.2.MAC": "<absent>", "Node.1.Radio.2.Interface": "", "Node.2.Radio.1.MAC": "<absent>",
		"Steering": "false", "Mesh11s": "true", "Mesh11s.ID": "wm11s", "Mesh11s.Radio": "phy1", "Mesh11s.Interface": "mesh0",
		"Mesh11s.Frequency": "5180", "Mesh11s.Forwarding": "false", "Mesh11s.Bridge": "br-lan", "Mesh11sSupported": "false",
		"TDMA": "true", "TDMA.Interfaces": "ath0,ath1", "TDMA.Interval": "2000", "TDMASupported": "false", "BusyPoll": "50",
		"SupportedOperations": "Restart,Radio.SetChannel,Radio.SetTxPower",
	}
	for leaf, value := range want {
		if got := meshField(t, msg, leaf); got != value {
			t.Errorf("%s = %q, want %q", leaf, got, value)
		}
	}
	declared := map[string]struct{}{}
	for _, p := range wusp.AllWUSPWantasticMeshParams {
		declared[p.Path] = struct{}{}
	}
	for _, f := range msg.Fields {
		if _, ok := declared[templatePath(f.Path)]; !ok {
			t.Errorf("%s is not in the data model", f.Path)
		}
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Errorf("reported message does not validate: %v", err)
	}

	// A leaf reports query_to_report without p99, and defaults when UCI is silent.
	leafStatus := `{"schema":1,"role":"agent","node_id":"bb000000000000000000000000000000","at":"` + at + `","controller":{"alive":true},
"metrics":{"latency_ns":{"query_to_report_p50":2000000,"query_to_report_p95":3000000}},"radios":[{"index":0,"mac":"00037f1256c1","iface":"ath1"}]}`
	leafUCI := "config wmesh 'global'\n\toption enabled '1'\n\toption net 'a1b2c3d4e5f60718'\n\toption controller_id 'aa000000000000000000000000000000'\n"
	b = wantasticMeshFixture(t, leafUCI, leafStatus, wantasticMeshBinary, "/etc/wmeshd/control.key")
	msg = wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	for leaf, value := range map[string]string{
		"Metrics.LatencyNumberOfEntries": "1", "Metrics.Latency.1.Name": "query_to_report", "Metrics.Latency.1.P95": "3000", "Metrics.Latency.1.P99": "0",
		"Node.1.Radio.1.MAC": "00:03:7f:12:56:c1", "Node.1.Radio.1.Interface": "ath1",
		"Steering": "true", "Mesh11s": "false", "Mesh11s.Forwarding": "true", "TDMA": "false", "TDMA.Interval": "0", "BusyPoll": "0",
		"SteeringAvailable": "false", "SteeringSent": "0",
	} {
		if got := meshField(t, msg, leaf); got != value {
			t.Errorf("leaf %s = %q, want %q", leaf, got, value)
		}
	}
}

func TestWantasticMeshStoppedDaemonReportsZeros(t *testing.T) {
	old := `{"schema":1,"role":"controller","node_id":"aa000000000000000000000000000000","at":"2026-01-01T00:00:00Z",
"metrics":{"tx_frames":9,"frames_per_sec":3.0,"latency_ns":{"full_rtt_p50":1}},"kernel_stack":{"steering":{"available":true,"sent":4},"vendor_ie":{"injected":1}}}`
	b := wantasticMeshFixture(t, rootUCI, old, wantasticMeshBinary, wantasticMeshAgentsFile)
	msg := wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	for leaf, value := range map[string]string{
		"Status": "stopped", "StatusFile": wantasticMeshStatusFile,
		"Metrics.TxFrames": "0", "Metrics.RxFrames": "0", "Metrics.TxBytes": "0", "Metrics.RxBytes": "0", "Metrics.FramesPerSecond": "0",
		"Metrics.ExchangesStarted": "0", "Metrics.ExchangesComplete": "0", "Metrics.LatencyNumberOfEntries": "0",
		"SteeringAvailable": "false", "SteeringSent": "0", "VendorIEInjected": "0", "NodeNumberOfEntries": "0",
		"Metrics.Latency.1.Name": "<absent>", "Steering": "true",
	} {
		if got := meshField(t, msg, leaf); got != value {
			t.Errorf("stopped %s = %q, want %q", leaf, got, value)
		}
	}

	// No status file and no daemon: starting, StatusFile empty.
	b = wantasticMeshFixture(t, rootUCI, "", wantasticMeshBinary, wantasticMeshAgentsFile)
	msg = wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	if meshField(t, msg, "Status") != "starting" || meshField(t, msg, "StatusFile") != "" || meshField(t, msg, "Metrics.TxFrames") != "0" {
		t.Fatalf("no daemon: status=%s file=%q", meshField(t, msg, "Status"), meshField(t, msg, "StatusFile"))
	}
}

func TestWantasticMeshFindsStatusFileFromCmdline(t *testing.T) {
	at := time.Now().UTC().Format(time.RFC3339)
	status := `{"schema":1,"role":"controller","node_id":"aa000000000000000000000000000000","at":"` + at + `","metrics":{"tx_frames":5}}`
	b := wantasticMeshFixture(t, rootUCI, "", wantasticMeshBinary, wantasticMeshAgentsFile)
	write := func(path, content string) {
		full := filepath.Join(wantasticMeshRoot, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Another process with a -status flag is ignored; wmeshd's is used.
	write("/proc/1/comm", "init\n")
	write("/proc/1/cmdline", "/sbin/init\x00-status\x00/tmp/other.json\x00")
	write("/proc/self/comm", "wmeshd\n")
	write("/proc/417/comm", "wmeshd\n")
	write("/proc/417/cmdline", "/usr/sbin/wmeshd\x00controller\x00-net\x00a1b2\x00-status\x00/var/run/wmesh/status.json\x00")
	write("/var/run/wmesh/status.json", status)
	write("/tmp/other.json", status)
	msg := wusp.NewMessage()
	b.appendOpenWrtWantasticMesh(msg)
	if meshField(t, msg, "StatusFile") != "/var/run/wmesh/status.json" || meshField(t, msg, "Status") != "running" || meshField(t, msg, "Metrics.TxFrames") != "5" {
		t.Fatalf("cmdline discovery: file=%q status=%s", meshField(t, msg, "StatusFile"), meshField(t, msg, "Status"))
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"agent", "-status=/tmp/a.json"}, "/tmp/a.json"},
		{[]string{"agent", "--status", "/tmp/b.json"}, "/tmp/b.json"},
		{[]string{"agent", "-status", "relative.json"}, ""},
		{[]string{"agent", "-status", "/tmp/../etc/shadow"}, ""},
		{[]string{"agent", "-status"}, ""},
		{[]string{"agent", "--", "-status", "/tmp/c.json"}, ""},
		{[]string{"agent", "-statusx", "/tmp/d.json"}, ""},
	} {
		if got := wantasticMeshStatusArg(tc.args); got != tc.want {
			t.Errorf("wantasticMeshStatusArg(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestWantasticMeshFeatureSettersValidate(t *testing.T) {
	b := wantasticMeshFixture(t, "config wmesh 'global'\n\toption enabled '0'\n", "", wantasticMeshBinary)
	ctx := context.Background()
	p := wusp.WUSPWantasticMeshPrefix
	bad := []struct {
		leaf  string
		value wusp.Value
	}{
		{"Mesh11s.ID", wusp.String("mesh'id")},
		{"Mesh11s.ID", wusp.String("mesh$(reboot)")},
		{"Mesh11s.ID", wusp.String("a`id`")},
		{"Mesh11s.ID", wusp.String("a\\b")},
		{"Mesh11s.ID", wusp.String("a\"b")},
		{"Mesh11s.ID", wusp.String("a\nb")},
		{"Mesh11s.ID", wusp.String(strings.Repeat("x", 33))},
		{"Mesh11s.Radio", wusp.String("phy1;reboot")},
		{"Mesh11s.Interface", wusp.String("averyveryverylongname")},
		{"Mesh11s.Interface", wusp.String("mesh 0")},
		{"Mesh11s.Bridge", wusp.String("br-$(id)")},
		{"Mesh11s.Frequency", wusp.Uint(2000)},
		{"Mesh11s.Frequency", wusp.Uint(8000)},
		{"Mesh11s.Frequency", wusp.String("5180; reboot")},
		{"TDMA.Interfaces", wusp.String("a,b,c,d,e")},
		{"TDMA.Interfaces", wusp.String("ath0,`id`")},
		{"TDMA.Interval", wusp.Uint(999)},
		{"TDMA.Interval", wusp.Uint(60001)},
		{"TDMA.Interval", wusp.Int(-5)},
		{"BusyPoll", wusp.Uint(1001)},
		{"BusyPoll", wusp.String("50 && reboot")},
	}
	for _, tc := range bad {
		if err := b.setOpenWrtWantasticMeshParam(ctx, p+tc.leaf, tc.value); err == nil || err == wusp.ErrUSPPathUnsupported {
			t.Errorf("%s accepted %q (err=%v)", tc.leaf, wusp.ValueToString(tc.value), err)
		}
	}
	good := []struct {
		leaf  string
		value wusp.Value
	}{
		{"Steering", wusp.Bool(false)}, {"Mesh11s", wusp.Bool(true)}, {"Mesh11s.ID", wusp.String("wm-mesh 11s")},
		{"Mesh11s.Radio", wusp.String("phy1")}, {"Mesh11s.Interface", wusp.String("mesh0")}, {"Mesh11s.Frequency", wusp.Uint(5180)},
		{"Mesh11s.Forwarding", wusp.Bool(false)}, {"Mesh11s.Bridge", wusp.String("br-lan")},
		{"TDMA", wusp.Bool(true)}, {"TDMA.Interfaces", wusp.String("ath0, ath1")}, {"TDMA.Interval", wusp.String("2000")}, {"BusyPoll", wusp.Uint(50)},
	}
	for _, tc := range good {
		if err := b.setOpenWrtWantasticMeshParam(ctx, p+tc.leaf, tc.value); err != nil {
			t.Fatalf("%s rejected: %v", tc.leaf, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(b.uciConfigDir, "wmesh"))
	for _, want := range []string{"option steering '0'", "option mesh11s '1'", "option mesh11s_id 'wm-mesh 11s'", "option mesh11s_radio 'phy1'", "option mesh11s_if 'mesh0'", "option mesh11s_freq '5180'", "option mesh11s_forwarding '0'", "option mesh11s_bridge 'br-lan'", "option tdma '1'", "option tdma_interfaces 'ath0,ath1'", "option tdma_interval_ms '2000'", "option busy_poll_us '50'"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("uci missing %q in:\n%s", want, data)
		}
	}
	// 0 clears the numeric options back to the daemon's default.
	for _, leaf := range []string{"Mesh11s.Frequency", "TDMA.Interval", "BusyPoll"} {
		if err := b.setOpenWrtWantasticMeshParam(ctx, p+leaf, wusp.Uint(0)); err != nil {
			t.Fatalf("%s=0 rejected: %v", leaf, err)
		}
	}
	data, _ = os.ReadFile(filepath.Join(b.uciConfigDir, "wmesh"))
	for _, gone := range []string{"mesh11s_freq '5180'", "tdma_interval_ms '2000'", "busy_poll_us '50'"} {
		if strings.Contains(string(data), gone) {
			t.Errorf("%q still set after writing 0:\n%s", gone, data)
		}
	}
}

type wantasticMeshCall struct {
	name string
	args []string
}

func wantasticMeshRecorder(b *OpenWrtBackend, output string, fail error) *[]wantasticMeshCall {
	calls := &[]wantasticMeshCall{}
	b.commandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, wantasticMeshCall{name, append([]string(nil), args...)})
		return []byte(output), fail
	}
	return calls
}

func TestWantasticMeshOperateCommands(t *testing.T) {
	ctx := context.Background()
	b := wantasticMeshFixture(t, rootUCI, "", wantasticMeshBinary, wantasticMeshInitScript)

	calls := wantasticMeshRecorder(b, "", nil)
	if err := b.RestartWantasticMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*calls, []wantasticMeshCall{{wantasticMeshInitScript, []string{"restart"}}}) {
		t.Fatalf("restart ran %+v", *calls)
	}

	calls = wantasticMeshRecorder(b, "before=ch36 after=ch149\n", nil)
	before, after, err := b.SetWantasticMeshChannel(ctx, WantasticMeshRadioChange{Interface: "ath1", Value: 149, RevertSeconds: 60})
	if err != nil || before != "36" || after != "149" {
		t.Fatalf("channel: %s -> %s err=%v", before, after, err)
	}
	if !reflect.DeepEqual(*calls, []wantasticMeshCall{{wantasticMeshBinary, []string{"radio", "channel", "-iface", "ath1", "-channel", "149"}}}) {
		t.Fatalf("channel ran %+v", *calls)
	}

	calls = wantasticMeshRecorder(b, "before=20dBm after=17dBm\n", nil)
	before, after, err = b.SetWantasticMeshTxPower(ctx, WantasticMeshRadioChange{Interface: "ath0", Value: 17, RevertSeconds: 15, Probe: true})
	if err != nil || before != "20" || after != "17" {
		t.Fatalf("txpower: %s -> %s err=%v", before, after, err)
	}
	if !reflect.DeepEqual(*calls, []wantasticMeshCall{{wantasticMeshBinary, []string{"radio", "txpower", "-iface", "ath0", "-dbm", "17", "-revert"}}}) {
		t.Fatalf("txpower ran %+v", *calls)
	}

	// Bad inputs never reach the binary.
	calls = wantasticMeshRecorder(b, "", nil)
	for _, tc := range []struct {
		kind   string
		change WantasticMeshRadioChange
	}{
		{"channel", WantasticMeshRadioChange{Interface: "ath0; reboot", Value: 36, RevertSeconds: 60}},
		{"channel", WantasticMeshRadioChange{Interface: "-revert", Value: 36, RevertSeconds: 60}},
		{"channel", WantasticMeshRadioChange{Interface: "ath0", Value: 0, RevertSeconds: 60}},
		{"channel", WantasticMeshRadioChange{Interface: "ath0", Value: 197, RevertSeconds: 60}},
		{"channel", WantasticMeshRadioChange{Interface: "ath0", Value: 36, RevertSeconds: 14}},
		{"channel", WantasticMeshRadioChange{Interface: "ath0", Value: 36, RevertSeconds: 601}},
		{"txpower", WantasticMeshRadioChange{Interface: "ath0", Value: 31, RevertSeconds: 60}},
		{"txpower", WantasticMeshRadioChange{Interface: "", Value: 10, RevertSeconds: 60}},
	} {
		var err error
		if tc.kind == "channel" {
			_, _, err = b.SetWantasticMeshChannel(ctx, tc.change)
		} else {
			_, _, err = b.SetWantasticMeshTxPower(ctx, tc.change)
		}
		if err == nil {
			t.Errorf("%s %+v accepted", tc.kind, tc.change)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("invalid inputs ran commands: %+v", *calls)
	}

	// A failing guard is reported, not swallowed.
	wantasticMeshRecorder(b, "", errors.New("exit status 1: switch channel on ath0: readback mismatch"))
	if _, _, err := b.SetWantasticMeshChannel(ctx, WantasticMeshRadioChange{Interface: "ath0", Value: 36, RevertSeconds: 60}); err == nil || !strings.Contains(err.Error(), "readback") {
		t.Fatalf("guard failure: %v", err)
	}

	// Without the binary, nothing runs.
	b = wantasticMeshFixture(t, rootUCI, "")
	calls = wantasticMeshRecorder(b, "", nil)
	if _, _, err := b.SetWantasticMeshChannel(ctx, WantasticMeshRadioChange{Interface: "ath0", Value: 36, RevertSeconds: 60}); err == nil {
		t.Fatal("channel change ran without wmeshd")
	}
	if err := b.RestartWantasticMesh(ctx); err == nil {
		t.Fatal("restart ran without wmeshd")
	}
	if len(*calls) != 0 {
		t.Fatalf("commands ran without wmeshd: %+v", *calls)
	}
}
