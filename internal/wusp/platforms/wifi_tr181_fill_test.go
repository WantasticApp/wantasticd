package platforms

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wifiprobe"
	"wantastic-agent/internal/wusp"
)

// QSDK (IPQ9574, qca-wifi) layout shared by the tests: radio netdev wifi2,
// the UCI-listed AP VAP ath3 and the SON backhaul STA VAP ath31 that the
// driver creates at runtime and /etc/config/wireless never lists.
var qsdkUplinkBSSID = net.HardwareAddr{0x02, 0x03, 0x7f, 0x12, 0xd7, 0xd7}

func messageFields(msg *wusp.Message) map[string]string {
	out := make(map[string]string, len(msg.Fields))
	for _, field := range msg.Fields {
		out[field.Path] = wusp.ValueToString(field.Val)
	}
	return out
}

func TestWiFiTelemetryQSDKStationVAPUplink(t *testing.T) {
	clock := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	rx, tx := uint64(1_000_000), uint64(2_000_000)
	retries, packets := uint32(100), uint32(1000)
	deps := wifiTelemetryDeps{
		listVAPs: func(string) []wifiTelemetryVAP {
			return []wifiTelemetryVAP{
				{Name: "ath3", Radio: "wifi2", Mode: "ap", Vendor: true, Driver: "qca-wifi"},
				{Name: "ath31", Radio: "wifi2", Mode: "station", Vendor: true, Driver: "qca-wifi"},
			}
		},
		// qca-wifi STA VAPs answer station dumps with an empty list.
		stations: func(string, wifiTelemetryVAP) []iwinfo.AssocEntry { return nil },
		counters: func(_, ifname string) wifiIfaceCounters {
			if ifname != "ath31" {
				return wifiIfaceCounters{}
			}
			return wifiIfaceCounters{RxBytes: rx, TxBytes: tx, OK: true}
		},
		survey:    func(string) ([]iwinfo.SurveyEntry, error) { return nil, errors.New("no survey") },
		radioLink: func(string) (iwinfo.RadioLink, error) { return iwinfo.RadioLink{}, errNotVendorVAP },
		txPower:   func(string) (int, bool) { return 0, false },
		bssid: func(ifname string) (net.HardwareAddr, bool) {
			return qsdkUplinkBSSID, ifname == "ath31"
		},
		stationLookup: func(ifname string, mac net.HardwareAddr) (iwinfo.AssocEntry, error) {
			// GET_STATION answers with counters and rates but no signal.
			return iwinfo.AssocEntry{
				MAC: mac, RxRate: 866700, RxRateKnown: true,
				TxRetries: retries, TxRetriesKnown: true, TxPackets: packets, TxPacketsKnown: true,
			}, nil
		},
		signal:  func(ifname string) (int, bool) { return -58, ifname == "ath31" },
		bitrate: func(ifname string) (uint32, bool) { return 433300, ifname == "ath31" },
		probe: func(context.Context, []netip.Addr, wifiprobe.Options) (map[netip.Addr]wifiprobe.Result, error) {
			return nil, nil
		},
	}
	c := newWiFiTelemetryCoordinator(deps)
	c.now = func() time.Time { return clock }
	c.started = true

	c.sample(context.Background())
	snap := c.snapshotAndStart("")
	if len(snap.Uplinks) != 1 || snap.Uplinks[0].ThroughputKnown || snap.Uplinks[0].RetransPercentKnown {
		t.Fatalf("first sample must not claim deltas: %+v", snap.Uplinks)
	}

	clock = clock.Add(time.Minute)
	rx += 75_000_000 // 10 Mbit/s received from the AP
	tx += 15_000_000 // 2 Mbit/s sent to the AP
	retries += 50
	packets += 500
	c.sample(context.Background())
	snap = c.snapshotAndStart("")
	if len(snap.VAPs) != 2 {
		t.Fatalf("snapshot VAPs %+v", snap.VAPs)
	}
	uplink := snap.Uplinks[0]
	if !uplink.ThroughputKnown || uplink.Downlink != 10000 || uplink.Uplink != 2000 {
		t.Fatalf("station VAP direction: downlink=%d uplink=%d known=%t", uplink.Downlink, uplink.Uplink, uplink.ThroughputKnown)
	}
	if !uplink.RetransPercentKnown || uplink.RetransPercent != 10 {
		t.Fatalf("retransmissions %d known=%t", uplink.RetransPercent, uplink.RetransPercentKnown)
	}

	msg := &wusp.Message{}
	if err := appendWiFiTelemetrySnapshotFields(msg, snap); err != nil {
		t.Fatal(err)
	}
	fields := messageFields(msg)
	p := wusp.WUSPWiFiTelemetryPrefix
	for path, want := range map[string]string{
		p + "Uplink.1.Interface":          "ath31",
		p + "Uplink.1.BSSID":              qsdkUplinkBSSID.String(),
		p + "Uplink.1.SignalStrength":     "-58",
		p + "Uplink.1.TxRateKbps":         "433300",
		p + "Uplink.1.RxRateKbps":         "866700",
		p + "Uplink.1.DownlinkThroughput": "10000",
		p + "Uplink.1.UplinkThroughput":   "2000",
		p + "Uplink.1.BytesReceived":      "76000000",
		p + "Uplink.1.BytesSent":          "17000000",
		p + "Uplink.1.Retransmissions":    "150",
		p + "Uplink.1.Source":             "wext+nl80211-get",
		p + "Uplink.1.Radio":              p + "Radio.1.",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	// Nothing the drivers did not report may appear as a placeholder zero.
	for _, path := range []string{
		p + "Radio.1.OperatingFrequency", p + "Radio.1.Channel", p + "Radio.1.ChannelWidth",
		p + "Radio.1.CenterFrequency", p + "Radio.1.Noise", p + "Radio.1.TransmitPower",
		p + "Radio.1.ConfiguredDistance", p + "Uplink.1.Noise", p + "Uplink.1.FrequencyMHz",
		p + "Uplink.1.TxMCS", p + "Uplink.1.SignalChains",
	} {
		if value, ok := fields[path]; ok {
			t.Errorf("%s = %q must be absent when unknown", path, value)
		}
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}

func TestWiFiTelemetryStationRowsOmitUnknownValues(t *testing.T) {
	mac, _ := net.ParseMAC("a4:83:e7:01:02:03")
	snap := wifiTelemetrySnapshot{
		Supported: true, Sampled: true,
		Radios:   []wifiTelemetryRadio{{Name: "wifi2", Driver: "qca-wifi", DistanceSource: "none"}},
		Stations: []wifiTelemetryStation{{Entry: iwinfo.AssocEntry{MAC: mac, Source: "wlanconfig"}, Interface: "ath3", Radio: "wifi2"}},
	}
	msg := &wusp.Message{}
	if err := appendWiFiTelemetrySnapshotFields(msg, snap); err != nil {
		t.Fatal(err)
	}
	fields := messageFields(msg)
	p := wusp.WUSPWiFiTelemetryPrefix
	for _, suffix := range []string{"SignalStrength", "Noise", "SNR", "TxRate", "RxRate", "ExpectedThroughput", "EstimatedDistance"} {
		if value, ok := fields[p+"Station.1."+suffix]; ok {
			t.Errorf("Station.1.%s = %q must be absent when unknown", suffix, value)
		}
	}
	if fields[p+"Station.1.DistanceMethod"] != "none" {
		t.Errorf("DistanceMethod = %q", fields[p+"Station.1.DistanceMethod"])
	}
}

func newQSDKBackend(t *testing.T, snap wifiTelemetrySnapshot) *OpenWrtBackend {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	netClassDir := filepath.Join(root, "sys", "class", "net")
	mustWriteFile(t, filepath.Join(configDir, "wireless"), "config wifi-device 'wifi2'\n\toption type 'qcawificfg80211'\n\toption channel 'auto'\n\toption hwmode '11axa'\n\toption htmode 'auto'\nconfig wifi-iface 'wlan2'\n\toption device 'wifi2'\n\toption ifname 'ath3'\n\toption mode 'ap'\n\toption ssid 'T2-AP'\n")
	for name, files := range map[string]map[string]string{
		"wifi2":     {"operstate": "up\n", "address": "00:03:7f:aa:00:02\n"},
		"ath3":      {"operstate": "up\n", "parent": "wifi2\n", "address": "02:03:7f:aa:00:03\n"},
		"ath31":     {"operstate": "up\n", "parent": "wifi2\n", "address": "02:03:7f:aa:00:31\n"},
		"ath32":     {"operstate": "up\n", "parent": "wifi2\n", "address": "02:03:7f:aa:00:32\n"},
		"ath3.sta1": {"operstate": "up\n", "parent": "wifi2\n", "address": "02:03:7f:aa:00:33\n"},
		"ath41":     {"operstate": "up\n", "parent": "wifi3\n", "address": "02:03:7f:aa:00:41\n"},
	} {
		for file, value := range files {
			mustWriteFile(t, filepath.Join(netClassDir, name, file), value)
		}
	}
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: configDir,
		NetClassDir:  netClassDir,
		ARPPath:      filepath.Join(root, "arp"),
		RouteNeighbors: func() ([]linuxNeighborObservation, error) {
			return nil, nil
		},
		CommandRunner: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("external commands disabled")
		},
		UbusCaller: func(string, string, time.Duration) ([]byte, error) {
			return nil, wusp.ErrUSPPathUnsupported
		},
		WiFiAssocList: func(string) ([]iwinfo.AssocEntry, error) { return nil, nil },
		WiFiInfo: func(ifName string) (*iwinfo.InterfaceInfo, error) {
			if ifName == "ath41" {
				return &iwinfo.InterfaceInfo{Name: ifName, SSID: "T2-6G-Backhaul"}, nil
			}
			return nil, errors.New("not readable")
		},
		WiFiHWModeList:    func(string) (*iwinfo.HWModes, error) { return nil, errors.New("unsupported") },
		WiFiHTModeList:    func(string) ([]string, error) { return nil, errors.New("unsupported") },
		WiFiTxPowerLevels: func(context.Context, string) []int { return nil },
		WiFiWiphy:         func(string) (*iwinfo.Wiphy, error) { return nil, errors.New("unsupported") },
		Now:               func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	backend.wifiTelemetry = func() wifiTelemetrySnapshot { return snap }
	return backend
}

func TestOpenWrtQSDKRuntimeVAPsFillDeviceWiFi(t *testing.T) {
	stationMAC, _ := net.ParseMAC("a4:83:e7:01:02:03")
	snap := wifiTelemetrySnapshot{
		Supported: true, Sampled: true,
		VAPs: []wifiTelemetryVAP{
			{Name: "ath3", Radio: "wifi2", Mode: "ap", Vendor: true},
			{Name: "ath31", Radio: "wifi2", Mode: "station", Vendor: true},
			// Not associated and no SSID: carries no network, no row.
			{Name: "ath32", Radio: "wifi2", Mode: "station", Vendor: true},
			// Per-peer WDS child: never a row of its own.
			{Name: "ath3.sta1", Radio: "wifi2", Mode: "ap", Vendor: true},
			// Radio wifi3 exists only at runtime.
			{Name: "ath41", Radio: "wifi3", Mode: "ap", Vendor: true},
		},
		Radios: []wifiTelemetryRadio{
			{Name: "wifi2", Frequency: 5745, CenterFrequency: 5775, ChannelWidth: 80, Noise: -95, Interfaces: []string{"ath3", "ath31", "ath32"}},
			{Name: "wifi3", Frequency: 5975, CenterFrequency: 6105, ChannelWidth: 320, Interfaces: []string{"ath41"}},
		},
		Uplinks: []wifiTelemetryUplink{{
			Interface: "ath31", Radio: "wifi2", SSID: "T2-Backhaul",
			Entry: iwinfo.AssocEntry{
				MAC: qsdkUplinkBSSID, Signal: -58, SignalKnown: true,
				TxRate: 433300, TxRateKnown: true,
				// Above the TR-181 EndPoint range: left to the Uplink row.
				RxRate: 866700, RxRateKnown: true,
				TxRateInfo: iwinfo.RateInfo{PHY: iwinfo.PHYHE, BandwidthMHz: 80, Negotiated: true},
			},
			RetransPercent: 10, RetransPercentKnown: true,
		}},
		Stations: []wifiTelemetryStation{{
			Entry: iwinfo.AssocEntry{MAC: stationMAC}, Interface: "ath3", Radio: "wifi2",
			RetransPercent: 7, RetransPercentKnown: true,
		}},
	}
	backend := newQSDKBackend(t, snap)
	backend.wifiAssocList = func(ifName string) ([]iwinfo.AssocEntry, error) {
		if ifName == "ath3" {
			return []iwinfo.AssocEntry{{MAC: stationMAC, Signal: -61, SignalKnown: true}}, nil
		}
		return nil, nil
	}

	msg := &wusp.Message{}
	backend.appendWiFiFields(context.Background(), msg)
	fields := messageFields(msg)

	for path, want := range map[string]string{
		"Device.WiFi.RadioNumberOfEntries":       "2",
		"Device.WiFi.SSIDNumberOfEntries":        "3",
		"Device.WiFi.AccessPointNumberOfEntries": "1",
		"Device.WiFi.EndPointNumberOfEntries":    "1",

		// UCI radio with channel/htmode auto: runtime channel, width, noise
		// and the generation it was seen running.
		"Device.WiFi.Radio.1.Name":                             "wifi2",
		"Device.WiFi.Radio.1.Channel":                          "149",
		"Device.WiFi.Radio.1.OperatingFrequencyBand":           "5GHz",
		"Device.WiFi.Radio.1.OperatingChannelBandwidth":        "Auto",
		"Device.WiFi.Radio.1.CurrentOperatingChannelBandwidth": "80MHz",
		"Device.WiFi.Radio.1.Stats.Noise":                      "-95",
		"Device.WiFi.Radio.1.OperatingStandards":               "a,n,ac,ax",

		// Runtime-only radio after the UCI rows.
		"Device.WiFi.Radio.2.Name":                             "wifi3",
		"Device.WiFi.Radio.2.Status":                           "Up",
		"Device.WiFi.Radio.2.OperatingFrequencyBand":           "6GHz",
		"Device.WiFi.Radio.2.Channel":                          "5",
		"Device.WiFi.Radio.2.CurrentOperatingChannelBandwidth": "320MHz-1",

		// UCI AP VAP: own BSSID.
		"Device.WiFi.SSID.1.Name":        "ath3",
		"Device.WiFi.SSID.1.SSID":        "T2-AP",
		"Device.WiFi.SSID.1.BSSID":       "02:03:7f:aa:00:03",
		"Device.WiFi.SSID.1.MACAddress":  "02:03:7f:aa:00:03",
		"Device.WiFi.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",

		// Runtime SON backhaul STA VAP: BSSID is the AP it is associated with.
		"Device.WiFi.SSID.2.Name":        "ath31",
		"Device.WiFi.SSID.2.Status":      "Up",
		"Device.WiFi.SSID.2.SSID":        "T2-Backhaul",
		"Device.WiFi.SSID.2.MACAddress":  "02:03:7f:aa:00:31",
		"Device.WiFi.SSID.2.BSSID":       "02:03:7f:12:d7:d7",
		"Device.WiFi.SSID.2.LowerLayers": "Device.WiFi.Radio.1.",

		"Device.WiFi.SSID.3.Name":        "ath41",
		"Device.WiFi.SSID.3.SSID":        "T2-6G-Backhaul",
		"Device.WiFi.SSID.3.BSSID":       "02:03:7f:aa:00:41",
		"Device.WiFi.SSID.3.LowerLayers": "Device.WiFi.Radio.2.",

		"Device.WiFi.EndPoint.1.Enable":                   "true",
		"Device.WiFi.EndPoint.1.Status":                   "Enabled",
		"Device.WiFi.EndPoint.1.SSIDReference":            "Device.WiFi.SSID.2.",
		"Device.WiFi.EndPoint.1.Stats.SignalStrength":     "-58",
		"Device.WiFi.EndPoint.1.Stats.LastDataUplinkRate": "433300",
		"Device.WiFi.EndPoint.1.Stats.Retransmissions":    "10",

		"Device.WiFi.AccessPoint.1.AssociatedDevice.1.SignalStrength":  "-61",
		"Device.WiFi.AccessPoint.1.AssociatedDevice.1.Retransmissions": "7",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	for _, path := range []string{
		"Device.WiFi.EndPoint.1.Stats.LastDataDownlinkRate",
		"Device.WiFi.Radio.3.Name",
		"Device.WiFi.SSID.4.Name",
		"Device.WiFi.AccessPoint.2.SSIDReference",
		"Device.WiFi.Radio.2.Stats.Noise",
		"Device.WiFi.Radio.2.OperatingStandards",
	} {
		if value, ok := fields[path]; ok {
			t.Errorf("%s = %q must be absent", path, value)
		}
	}
	for path := range fields {
		if strings.Contains(path, "ath32") || strings.Contains(fields[path], "ath3.sta1") || strings.Contains(fields[path], "ath32") {
			t.Errorf("helper/unassociated VAP leaked into %s", path)
		}
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}

	// Writes still resolve Radio/SSID indices against UCI only.
	if section := backend.resolveWiFiRadioSection(2); section != "" {
		t.Fatalf("runtime radio row resolved to UCI section %q", section)
	}
}

func TestOpenWrtStationSSIDWithoutUplinkHasNoBSSID(t *testing.T) {
	backend := newQSDKBackend(t, wifiTelemetrySnapshot{})
	// A UCI-listed STA VAP that is not associated must not report its own
	// address as the AP BSSID.
	mustWriteFile(t, filepath.Join(backend.uciConfigDir, "wireless"), "config wifi-device 'wifi2'\n\toption hwmode '11axa'\n\toption channel '149'\n\toption htmode 'HT80'\nconfig wifi-iface 'bh_sta'\n\toption device 'wifi2'\n\toption ifname 'ath31'\n\toption mode 'sta'\n\toption ssid 'T2-Backhaul'\n")

	msg := &wusp.Message{}
	backend.appendWiFiFields(context.Background(), msg)
	fields := messageFields(msg)
	if fields["Device.WiFi.SSID.1.Name"] != "ath31" || fields["Device.WiFi.SSID.1.MACAddress"] != "02:03:7f:aa:00:31" {
		t.Fatalf("unexpected SSID row %v", fields)
	}
	if bssid, ok := fields["Device.WiFi.SSID.1.BSSID"]; ok {
		t.Fatalf("unassociated station BSSID = %q, want absent", bssid)
	}
	if fields["Device.WiFi.EndPoint.1.SSIDReference"] != "Device.WiFi.SSID.1." || fields["Device.WiFi.EndPointNumberOfEntries"] != "1" {
		t.Fatalf("EndPoint row missing: %v", fields)
	}
	for _, suffix := range []string{"SignalStrength", "LastDataDownlinkRate", "LastDataUplinkRate", "Retransmissions"} {
		if value, ok := fields["Device.WiFi.EndPoint.1.Stats."+suffix]; ok {
			t.Errorf("EndPoint.1.Stats.%s = %q must be absent without an uplink", suffix, value)
		}
	}
	if fields["Device.WiFi.Radio.1.CurrentOperatingChannelBandwidth"] != "80MHz" {
		t.Errorf("configured width must stay authoritative: %q", fields["Device.WiFi.Radio.1.CurrentOperatingChannelBandwidth"])
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}

func TestTR181CurrentBandwidth(t *testing.T) {
	for _, tc := range []struct {
		width, center int
		want          string
	}{
		{80, 5775, "80MHz"}, {160, 5250, "160MHz"}, {320, 6105, "320MHz-1"},
		{320, 6265, "320MHz-2"}, {320, 0, ""}, {0, 0, ""}, {10, 0, ""},
	} {
		if got := tr181CurrentBandwidth(tc.width, tc.center); got != tc.want {
			t.Errorf("tr181CurrentBandwidth(%d, %d) = %q, want %q", tc.width, tc.center, got, tc.want)
		}
	}
}
