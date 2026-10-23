package platforms

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wifiprobe"
	"wantastic-agent/internal/wusp"
)

func fakeWiFiTelemetry(t *testing.T) (*wifiTelemetryCoordinator, *time.Time, *uint64) {
	t.Helper()
	clock := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	staBytes := uint64(1_000_000)
	mac, _ := net.ParseMAC("a4:83:e7:01:02:03")
	ip := netip.MustParseAddr("192.168.1.50")
	deps := wifiTelemetryDeps{
		listVAPs: func(string) []wifiTelemetryVAP {
			return []wifiTelemetryVAP{{Name: "ath0", Radio: "wifi1", Mode: "ap", Vendor: true, Driver: "qca-wifi"}}
		},
		stations: func(string, wifiTelemetryVAP) []iwinfo.AssocEntry {
			return []iwinfo.AssocEntry{{
				MAC: mac, Signal: -61, SignalKnown: true, TxRate: 866000, TxRateKnown: true,
				RxBytes: staBytes / 4, RxBytesKnown: true, TxBytes: staBytes, TxBytesKnown: true,
				Source: "wlanconfig",
			}}
		},
		counters: func(string, string) wifiIfaceCounters {
			return wifiIfaceCounters{RxBytes: staBytes / 4, TxBytes: staBytes, OK: true}
		},
		survey: func(string) ([]iwinfo.SurveyEntry, error) {
			return []iwinfo.SurveyEntry{{InUse: true, Frequency: 5180, Noise: -96, ActiveTime: uint64(clock.Unix()) * 1000, BusyTime: uint64(clock.Unix()) * 250}}, nil
		},
		radioLink:      func(string) (iwinfo.RadioLink, error) { return iwinfo.RadioLink{}, errNotVendorVAP },
		vendorDistance: func(string) (int, string, bool) { return 0, "", false },
		txPower:        func(string) (int, bool) { return 23, true },
		neighbors:      func() map[string]netip.Addr { return map[string]netip.Addr{"a4:83:e7:01:02:03": ip} },
		probe: func(_ context.Context, targets []netip.Addr, _ wifiprobe.Options) (map[netip.Addr]wifiprobe.Result, error) {
			if len(targets) != 1 || targets[0] != ip {
				t.Fatalf("unexpected probe targets %v", targets)
			}
			return map[netip.Addr]wifiprobe.Result{ip: {Sent: 4, Received: 3, Min: 2 * time.Millisecond, Max: 9 * time.Millisecond, Avg: 4 * time.Millisecond, Jitter: time.Millisecond}}, nil
		},
	}
	c := newWiFiTelemetryCoordinator(deps)
	c.now = func() time.Time { return clock }
	c.started = true // drive samples manually
	return c, &clock, &staBytes
}

func TestWiFiTelemetrySamplesThroughputLatencyAndHistory(t *testing.T) {
	c, clock, staBytes := fakeWiFiTelemetry(t)
	c.sample(context.Background())
	*clock = clock.Add(time.Minute)
	*staBytes += 75_000_000 // 75 MB in 60 s = 10 Mbit/s downlink
	c.sample(context.Background())

	snap := c.snapshotAndStart("")
	if !snap.Supported || len(snap.Radios) != 1 || len(snap.Stations) != 1 {
		t.Fatalf("unexpected snapshot %+v", snap)
	}
	station := snap.Stations[0]
	if !station.ThroughputKnown || station.Downlink != 10000 {
		t.Fatalf("downlink %d known=%t", station.Downlink, station.ThroughputKnown)
	}
	if !station.Latency.Known || station.Latency.Lost != 1 || station.Latency.Avg != 4*time.Millisecond {
		t.Fatalf("latency %+v", station.Latency)
	}
	if station.Distance <= 0 {
		t.Fatal("expected an FSPL distance estimate")
	}
	radio := snap.Radios[0]
	if radio.Frequency != 5180 || radio.Noise != -96 || radio.TxPower != 23 || !radio.UtilKnown || radio.Utilization != 25 {
		t.Fatalf("radio %+v", radio)
	}
	if len(snap.StationHist["a4:83:e7:01:02:03"]) != 2 || len(snap.RadioHistory["wifi1"]) != 2 {
		t.Fatalf("history depth station=%d radio=%d", len(snap.StationHist["a4:83:e7:01:02:03"]), len(snap.RadioHistory["wifi1"]))
	}

	msg := &wusp.Message{}
	if err := appendWiFiTelemetrySnapshotFields(msg, snap); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, field := range msg.Fields {
		fields[field.Path] = wusp.ValueToString(field.Val)
	}
	p := wusp.WUSPWiFiTelemetryPrefix
	for path, want := range map[string]string{
		p + "Status":                       "Ready",
		p + "LatencyMethod":                "icmp",
		p + "StationNumberOfEntries":       "1",
		p + "Radio.1.Driver":               "qca-wifi",
		p + "Radio.1.Channel":              "36",
		p + "Radio.1.DownlinkThroughput":   "10000",
		p + "Station.1.SignalStrength":     "-61",
		p + "Station.1.SNR":                "35",
		p + "Station.1.IPAddress":          "192.168.1.50",
		p + "Station.1.Radio":              p + "Radio.1.",
		p + "Station.1.LatencyAverage":     "4000",
		p + "Station.1.LatencyLostCount":   "1",
		p + "Station.1.DistanceMethod":     "fspl",
		p + "Station.1.DownlinkThroughput": "10000",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	var block []byte
	for _, field := range msg.Fields {
		if field.Path == p+"Station.1.History" {
			block = field.Val.AsBytes()
		}
	}
	history, err := wusp.DecodeWiFiHistoryBlock(block)
	if err != nil || len(history) != 2 {
		t.Fatalf("history %v %v", history, err)
	}
	if history[1].Values[wusp.WiFiMetricDownlink] != 10000 || history[1].Values[wusp.WiFiMetricLatencyLoss] != 250 {
		t.Fatalf("history values %+v", history[1].Values)
	}
}

func TestWiFiTelemetryCollectingWithholdsCounts(t *testing.T) {
	msg := &wusp.Message{}
	if err := appendWiFiTelemetrySnapshotFields(msg, wifiTelemetrySnapshot{}); err != nil {
		t.Fatal(err)
	}
	for _, field := range msg.Fields {
		if strings.HasSuffix(field.Path, "NumberOfEntries") {
			t.Fatalf("counts must not be sent before the first sample: %s", field.Path)
		}
	}
}

func TestWiFiTelemetryPrunesDepartedStations(t *testing.T) {
	c, clock, _ := fakeWiFiTelemetry(t)
	c.sample(context.Background())
	c.deps.stations = func(string, wifiTelemetryVAP) []iwinfo.AssocEntry { return nil }
	*clock = clock.Add(time.Duration(wusp.WiFiHistoryDepth+1) * wifiTelemetryInterval)
	c.sample(context.Background())
	if len(c.staHist) != 0 || len(c.prevSta) != 0 {
		t.Fatalf("departed station history kept: %d", len(c.staHist))
	}
}

func TestEstimateStationDistance(t *testing.T) {
	entry := iwinfo.AssocEntry{Signal: -60, SignalKnown: true}
	// 20 dBm - (-60) = 80 dB at 5180 MHz -> ~46 m in free space.
	if d := estimateStationDistance(20, entry, 5180); d < 40 || d > 50 {
		t.Fatalf("distance %d", d)
	}
	if d := estimateStationDistance(20, iwinfo.AssocEntry{}, 5180); d != 0 {
		t.Fatalf("unknown signal must yield 0, got %d", d)
	}
}

func TestParseProcNetARP(t *testing.T) {
	data := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.50     0x1         0x2         a4:83:e7:01:02:03     *        br-lan
192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        br-lan
`
	got := parseProcNetARP(bufio.NewScanner(strings.NewReader(data)))
	if len(got) != 1 || got["a4:83:e7:01:02:03"].String() != "192.168.1.50" {
		t.Fatalf("unexpected %v", got)
	}
}

func TestWiFiTelemetryUsesStationsObservedByCollector(t *testing.T) {
	mac, _ := net.ParseMAC("0a:4a:c6:92:4b:c9")
	recordObservedStations("zz-test0", []iwinfo.AssocEntry{{MAC: mac, Signal: -70, SignalKnown: true, Source: "hostapd-ubus"}})
	recordObservedRadio("zz-test0", &iwinfo.InterfaceInfo{Noise: -91, TxPower: 28, Frequency: 5745})
	stations := collectWiFiTelemetryStations(t.TempDir(), wifiTelemetryVAP{Name: "zz-test0", Radio: "phy2"})
	if len(stations) != 1 || stations[0].MAC.String() != mac.String() {
		t.Fatalf("collector stations not merged: %+v", stations)
	}
	if seen, ok := observedRadio("zz-test0"); !ok || seen.Noise != -91 || seen.TxPower != 28 {
		t.Fatalf("radio facts not cached: %+v", seen)
	}
}
