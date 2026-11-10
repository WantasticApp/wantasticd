package platforms

import (
	"context"
	"net"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

func telemetryFields(t *testing.T, snap wifiTelemetrySnapshot, seed ...wusp.Field) map[string]string {
	t.Helper()
	msg := &wusp.Message{}
	for _, f := range seed {
		msg.Set(f.Path, f.Val)
	}
	if err := appendWiFiTelemetrySnapshotFields(msg, snap); err != nil {
		t.Fatal(err)
	}
	// The schema validation on the real encode path (the data model cache)
	// must accept every new field: type tags, enums and limits.
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
	encoded, err := wusp.EncodeMessageLZ4(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := wusp.DecodeMessage(encoded)
	if err != nil || len(decoded.Fields) != len(msg.Fields) {
		t.Fatalf("round trip: %v (%d of %d fields)", err, len(decoded.Fields), len(msg.Fields))
	}
	out := map[string]string{}
	for _, field := range msg.Fields {
		out[field.Path] = wusp.ValueToString(field.Val)
	}
	return out
}

func heStation(mac net.HardwareAddr) iwinfo.AssocEntry {
	he := iwinfo.RateInfo{PHY: iwinfo.PHYHE, MCS: 11, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 800, DCMKnown: true}
	return iwinfo.AssocEntry{
		MAC: mac, Signal: -55, SignalKnown: true,
		TxRate: 1_201_000, TxRateKnown: true, RxRate: 866_700, RxRateKnown: true,
		ConnectedTime: 3600, ConnectedTimeKnown: true,
		TxRateInfo:  he,
		RxRateInfo:  iwinfo.RateInfo{PHY: iwinfo.PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400},
		ChainSignal: []int8{-55, -53}, ChainSignalAvg: []int8{-56, -54},
		TxDuration: 123_456_789, TxDurationKnown: true, RxDuration: 98_765, RxDurationKnown: true,
		Source: "nl80211",
	}
}

func TestWiFiTelemetryStationModulationFields(t *testing.T) {
	mac, _ := net.ParseMAC("a4:83:e7:01:02:03")
	bare, _ := net.ParseMAC("a4:83:e7:01:02:04")
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	snap := wifiTelemetrySnapshot{
		Supported: true, Sampled: true, LastSample: now,
		Radios: []wifiTelemetryRadio{{Name: "phy0", DistanceSource: "none", CollectedAt: now}},
		Stations: []wifiTelemetryStation{
			{Entry: heStation(mac), Interface: "wlan0", Radio: "phy0", CollectedAt: now},
			{Entry: iwinfo.AssocEntry{MAC: bare, Signal: -70, SignalKnown: true}, Interface: "wlan0", Radio: "phy0", CollectedAt: now},
		},
	}
	fields := telemetryFields(t, snap)
	p := wusp.WUSPWiFiTelemetryPrefix + "Station.1."
	for path, want := range map[string]string{
		p + "TxPHY": "he", p + "TxMCS": "11", p + "TxNSS": "2", p + "TxBandwidthMHz": "80", p + "TxGuardIntervalNs": "800", p + "TxDCM": "false",
		p + "RxPHY": "vht", p + "RxMCS": "9", p + "RxNSS": "2", p + "RxBandwidthMHz": "80", p + "RxGuardIntervalNs": "400",
		p + "SignalChains": "-55,-53", p + "SignalChainAvg": "-56,-54",
		p + "TxAirtimeUs": "123456789", p + "RxAirtimeUs": "98765",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	if _, ok := fields[p+"RxDCM"]; ok {
		t.Error("RxDCM is not reported and must be omitted")
	}
	q := wusp.WUSPWiFiTelemetryPrefix + "Station.2."
	for _, suffix := range []string{"TxPHY", "TxMCS", "TxNSS", "TxBandwidthMHz", "TxGuardIntervalNs", "TxDCM", "RxPHY", "RxMCS", "RxNSS", "RxBandwidthMHz", "RxGuardIntervalNs", "RxDCM", "SignalChains", "SignalChainAvg", "TxAirtimeUs", "RxAirtimeUs"} {
		if v, ok := fields[q+suffix]; ok {
			t.Errorf("%s must be omitted when unknown, got %q", q+suffix, v)
		}
	}
	if fields[wusp.WUSPWiFiTelemetryPrefix+"UplinkNumberOfEntries"] != "0" {
		t.Errorf("UplinkNumberOfEntries = %q", fields[wusp.WUSPWiFiTelemetryPrefix+"UplinkNumberOfEntries"])
	}
	for path := range fields {
		if !telemetryModelHas(path) {
			t.Errorf("emitted path %s is not in the WUSP model", path)
		}
	}
}

// A CPE whose wlan0 is in station mode: the nl80211 station dump on the
// STA interface lists the access point, which becomes Uplink.1.
func TestWiFiTelemetryUplinkFromStationDump(t *testing.T) {
	apMAC, _ := net.ParseMAC("80:2a:a8:01:02:03")
	clock := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	deps := wifiTelemetryDeps{
		listVAPs: func(string) []wifiTelemetryVAP {
			return []wifiTelemetryVAP{{Name: "wlan0", Radio: "phy0", Mode: "station", Driver: "mac80211", Frequency: 5500}}
		},
		stations: func(string, wifiTelemetryVAP) []iwinfo.AssocEntry {
			return []iwinfo.AssocEntry{heStation(apMAC)}
		},
		counters: func(string, string) wifiIfaceCounters { return wifiIfaceCounters{} },
		survey: func(string) ([]iwinfo.SurveyEntry, error) {
			return []iwinfo.SurveyEntry{{InUse: true, Frequency: 5500, Noise: -95}}, nil
		},
		radioLink: func(string) (iwinfo.RadioLink, error) {
			return iwinfo.RadioLink{Frequency: 5500, CenterFrequency: 5530, ChannelWidth: 80, SSID: "backhaul-ptp"}, nil
		},
		bssid: func(string) (net.HardwareAddr, bool) {
			t.Fatal("SIOCGIWAP is only a fallback for an empty station dump")
			return nil, false
		},
	}
	c := newWiFiTelemetryCoordinator(deps)
	c.now = func() time.Time { return clock }
	c.started = true
	c.sample(context.Background())
	snap := c.snapshotAndStart("")
	if len(snap.Uplinks) != 1 {
		t.Fatalf("uplinks %+v", snap.Uplinks)
	}
	fields := telemetryFields(t, snap)
	p := wusp.WUSPWiFiTelemetryPrefix + "Uplink.1."
	for path, want := range map[string]string{
		wusp.WUSPWiFiTelemetryPrefix + "UplinkNumberOfEntries": "1",
		p + "Alias": "uplink-wlan0", p + "Interface": "wlan0", p + "Radio": wusp.WUSPWiFiTelemetryPrefix + "Radio.1.",
		p + "BSSID": "80:2a:a8:01:02:03", p + "SSID": "backhaul-ptp",
		p + "FrequencyMHz": "5500", p + "BandwidthMHz": "80",
		p + "SignalStrength": "-55", p + "Noise": "-95", p + "SignalChains": "-55,-53",
		p + "TxRateKbps": "1201000", p + "RxRateKbps": "866700", p + "ConnectedTime": "3600",
		p + "TxPHY": "he", p + "TxMCS": "11", p + "TxNSS": "2", p + "TxBandwidthMHz": "80", p + "TxGuardIntervalNs": "800",
		p + "RxPHY": "vht", p + "RxMCS": "9", p + "RxGuardIntervalNs": "400",
		p + "TxAirtimeUs": "123456789", p + "RxAirtimeUs": "98765",
		p + "Source": "nl80211",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	for path := range fields {
		if !telemetryModelHas(path) {
			t.Errorf("emitted path %s is not in the WUSP model", path)
		}
	}
}

// A qca-wifi STA VAP with an empty station dump: SIOCGIWAP gives the BSSID,
// per-MAC GET_STATION what the driver answers, Device.WiFi the SSID.
func TestWiFiTelemetryUplinkVendorFallback(t *testing.T) {
	apMAC, _ := net.ParseMAC("80:2a:a8:0a:0b:0c")
	clock := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	deps := wifiTelemetryDeps{
		listVAPs: func(string) []wifiTelemetryVAP {
			return []wifiTelemetryVAP{{Name: "ath1", Radio: "wifi1", Mode: "station", Vendor: true, Driver: "qca-wifi"}}
		},
		stations:  func(string, wifiTelemetryVAP) []iwinfo.AssocEntry { return nil },
		counters:  func(string, string) wifiIfaceCounters { return wifiIfaceCounters{} },
		survey:    func(string) ([]iwinfo.SurveyEntry, error) { return nil, errNotVendorVAP },
		radioLink: func(string) (iwinfo.RadioLink, error) { return iwinfo.RadioLink{}, errNotVendorVAP },
		frequency: func(string) (int, bool) { return 5745, true },
		bssid:     func(string) (net.HardwareAddr, bool) { return apMAC, true },
		stationLookup: func(_ string, mac net.HardwareAddr) (iwinfo.AssocEntry, error) {
			return iwinfo.AssocEntry{MAC: mac, Signal: -62, SignalKnown: true, TxRate: 54_000, TxRateKnown: true,
				TxRateInfo: iwinfo.RateInfo{PHY: iwinfo.PHYLegacy, BandwidthMHz: 20}}, nil
		},
	}
	c := newWiFiTelemetryCoordinator(deps)
	c.now = func() time.Time { return clock }
	c.started = true
	c.sample(context.Background())
	snap := c.snapshotAndStart("")
	fields := telemetryFields(t, snap,
		wusp.Field{Path: "Device.WiFi.SSID.2.Name", Val: wusp.String("ath1")},
		wusp.Field{Path: "Device.WiFi.SSID.2.SSID", Val: wusp.String("tower-7")},
	)
	p := wusp.WUSPWiFiTelemetryPrefix + "Uplink.1."
	for path, want := range map[string]string{
		p + "BSSID": "80:2a:a8:0a:0b:0c", p + "SSID": "tower-7", p + "FrequencyMHz": "5745",
		p + "SignalStrength": "-62", p + "TxRateKbps": "54000", p + "TxPHY": "legacy", p + "TxBandwidthMHz": "20",
		p + "Source": "wext+nl80211-get",
	} {
		if fields[path] != want {
			t.Errorf("%s = %q, want %q", path, fields[path], want)
		}
	}
	for _, suffix := range []string{"TxMCS", "TxNSS", "TxGuardIntervalNs", "RxPHY", "RxRateKbps", "Noise", "SignalChains", "ConnectedTime", "TxAirtimeUs", "BandwidthMHz"} {
		if v, ok := fields[p+suffix]; ok {
			t.Errorf("%s must be omitted when unknown, got %q", p+suffix, v)
		}
	}
}

func TestWiFiTelemetryNoUplinkWhenNotAssociated(t *testing.T) {
	deps := wifiTelemetryDeps{
		listVAPs: func(string) []wifiTelemetryVAP {
			return []wifiTelemetryVAP{{Name: "wlan0", Radio: "phy0", Mode: "station"}}
		},
		stations:  func(string, wifiTelemetryVAP) []iwinfo.AssocEntry { return nil },
		counters:  func(string, string) wifiIfaceCounters { return wifiIfaceCounters{} },
		survey:    func(string) ([]iwinfo.SurveyEntry, error) { return nil, errNotVendorVAP },
		radioLink: func(string) (iwinfo.RadioLink, error) { return iwinfo.RadioLink{}, errNotVendorVAP },
		bssid:     func(string) (net.HardwareAddr, bool) { return nil, false },
	}
	c := newWiFiTelemetryCoordinator(deps)
	c.started = true
	c.sample(context.Background())
	if snap := c.snapshotAndStart(""); len(snap.Uplinks) != 0 {
		t.Fatalf("unexpected uplinks %+v", snap.Uplinks)
	}
}

func TestMergeWiFiAssociationsKeepsModulation(t *testing.T) {
	mac, _ := net.ParseMAC("a4:83:e7:01:02:03")
	nl := heStation(mac)
	vendor := iwinfo.AssocEntry{MAC: mac, Source: "wlanconfig", Signal: -56, SignalKnown: true,
		TxRateInfo: iwinfo.RateInfo{PHY: iwinfo.PHYHE, NSS: 2, BandwidthMHz: 160, Negotiated: true}}
	// The vendor row is merged last and preferred, as in the telemetry and
	// Device.WiFi collectors; the per-frame nl80211 modulation must survive.
	merged := mergeWiFiAssociations([]iwinfo.AssocEntry{nl}, []iwinfo.AssocEntry{vendor})
	if len(merged) != 1 {
		t.Fatalf("merged %d", len(merged))
	}
	m := merged[0]
	if m.TxRateInfo != nl.TxRateInfo || m.RxRateInfo != nl.RxRateInfo {
		t.Fatalf("modulation lost: tx %+v rx %+v", m.TxRateInfo, m.RxRateInfo)
	}
	if iwinfo.FormatChainSignal(m.ChainSignal) != "-55,-53" || !m.TxDurationKnown || m.TxDuration != nl.TxDuration {
		t.Fatalf("chains/airtime lost: %+v", m)
	}
}

func TestDecodeIWInfoUbusRateInfo(t *testing.T) {
	data := []byte(`{"results":[{"mac":"A4:83:E7:01:02:03","signal":-55,
		"rx":{"rate":866700,"mcs":9,"40mhz":false,"short_gi":true,"vht":true,"he":false,"ht":false,"mhz":80,"nss":2},
		"tx":{"rate":1201000,"mcs":11,"he":true,"mhz":80,"nss":2,"he_gi":0,"he_dcm":1}},
		{"mac":"A4:83:E7:01:02:04","rx":{"rate":270000,"mcs":15,"40mhz":true,"short_gi":false,"ht":true,"mhz":40},
		"tx":{"rate":54000,"ht":false,"vht":false,"mhz":20}}]}`)
	entries, err := decodeIWInfoAssociationsKnown(data)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries %v err %v", entries, err)
	}
	if got, want := entries[0].RxRateInfo, (iwinfo.RateInfo{PHY: iwinfo.PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400}); got != want {
		t.Errorf("vht rx %+v", got)
	}
	if got, want := entries[0].TxRateInfo, (iwinfo.RateInfo{PHY: iwinfo.PHYHE, MCS: 11, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 800, DCM: true, DCMKnown: true}); got != want {
		t.Errorf("he tx %+v", got)
	}
	if got, want := entries[1].RxRateInfo, (iwinfo.RateInfo{PHY: iwinfo.PHYHT, MCS: 15, MCSKnown: true, NSS: 2, BandwidthMHz: 40, GuardIntervalNs: 800}); got != want {
		t.Errorf("ht40 rx %+v", got)
	}
	if got, want := entries[1].TxRateInfo, (iwinfo.RateInfo{PHY: iwinfo.PHYLegacy, BandwidthMHz: 20}); got != want {
		t.Errorf("legacy tx %+v", got)
	}
}

var telemetryModel = wusp.NewDevice(wusp.ImportedModelSummary{}, wusp.WUSPWiFiTelemetryObjects, wusp.AllWUSPWiFiTelemetryParams)

func telemetryModelHas(path string) bool {
	_, ok := telemetryModel.GetParam(path)
	return ok
}
