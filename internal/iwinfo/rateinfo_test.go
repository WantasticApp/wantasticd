package iwinfo

import (
	"strings"
	"testing"
)

func TestNL80211RateFieldsModulation(t *testing.T) {
	fields := func(set func(*nl80211RateFields)) nl80211RateFields {
		f := newNL80211RateFields()
		set(&f)
		return f
	}
	cases := []struct {
		name string
		in   nl80211RateFields
		kbps uint32
		want RateInfo
	}{
		{
			name: "HE 80 MHz 2SS MCS11 GI 0.8",
			in: fields(func(f *nl80211RateFields) {
				f.Bitrate32, f.HEMCS, f.HENSS, f.HEGI, f.HEDCM, f.WidthMHz = 12010, 11, 2, 0, 0, 80
			}),
			kbps: 1_201_000,
			want: RateInfo{PHY: PHYHE, MCS: 11, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 800, DCMKnown: true},
		},
		{
			name: "VHT 80 MHz 2SS MCS9 short GI",
			in: fields(func(f *nl80211RateFields) {
				f.Bitrate16, f.VHTMCS, f.VHTNSS, f.WidthMHz, f.ShortGI = 8667, 9, 2, 80, true
			}),
			kbps: 866_700,
			want: RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400},
		},
		{
			name: "HT40 MCS15 long GI",
			in: fields(func(f *nl80211RateFields) {
				f.Bitrate16, f.HTMCS, f.WidthMHz = 2700, 15, 40
			}),
			kbps: 270_000,
			want: RateInfo{PHY: PHYHT, MCS: 15, MCSKnown: true, NSS: 2, BandwidthMHz: 40, GuardIntervalNs: 800},
		},
		{
			name: "legacy 54 Mbit/s",
			in:   fields(func(f *nl80211RateFields) { f.Bitrate16 = 540 }),
			kbps: 54_000,
			want: RateInfo{PHY: PHYLegacy, BandwidthMHz: 20},
		},
		{
			name: "EHT 320 MHz 4SS MCS13 GI 3.2",
			in: fields(func(f *nl80211RateFields) {
				f.Bitrate32, f.EHTMCS, f.EHTNSS, f.EHTGI, f.WidthMHz = 288200, 13, 4, 2, 320
			}),
			kbps: 28_820_000,
			want: RateInfo{PHY: PHYEHT, MCS: 13, MCSKnown: true, NSS: 4, BandwidthMHz: 320, GuardIntervalNs: 3200},
		},
		{
			name: "HE OFDMA RU has no channel width, DCM on, GI 1.6",
			in: fields(func(f *nl80211RateFields) {
				f.Bitrate32, f.HEMCS, f.HENSS, f.HEGI, f.HEDCM, f.RUAlloc = 160, 1, 1, 1, 1, true
			}),
			kbps: 16_000,
			want: RateInfo{PHY: PHYHE, MCS: 1, MCSKnown: true, NSS: 1, GuardIntervalNs: 1600, DCM: true, DCMKnown: true},
		},
		{
			name: "HE without NSS/GI/DCM attributes leaves them unknown",
			in:   fields(func(f *nl80211RateFields) { f.Bitrate32, f.HEMCS = 1441, 7 }),
			kbps: 144_100,
			want: RateInfo{PHY: PHYHE, MCS: 7, MCSKnown: true, BandwidthMHz: 20},
		},
		{
			name: "empty rate_info is unknown",
			in:   newNL80211RateFields(),
			want: RateInfo{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kbps, got := tc.in.rate()
			if kbps != tc.kbps || got != tc.want {
				t.Fatalf("rate() = %d %+v, want %d %+v", kbps, got, tc.kbps, tc.want)
			}
			if tc.want == (RateInfo{}) && got.Known() {
				t.Fatal("unknown rate must report !Known()")
			}
		})
	}
}

func TestHTNSS(t *testing.T) {
	for mcs, want := range map[int]int{0: 1, 7: 1, 8: 2, 15: 2, 23: 3, 31: 4, 32: 1, 33: 2, 76: 4, 77: 0, -1: 0} {
		if got := htNSS(mcs); got != want {
			t.Errorf("htNSS(%d) = %d, want %d", mcs, got, want)
		}
	}
}

func TestWlanconfigModeRate(t *testing.T) {
	cases := map[string]RateInfo{
		"IEEE80211_MODE_11AXA_HE80":      {PHY: PHYHE, BandwidthMHz: 80, Negotiated: true},
		"IEEE80211_MODE_11AXA_HE160":     {PHY: PHYHE, BandwidthMHz: 160, Negotiated: true},
		"IEEE80211_MODE_11AXG_HE40PLUS":  {PHY: PHYHE, BandwidthMHz: 40, Negotiated: true},
		"IEEE80211_MODE_11AC_VHT80":      {PHY: PHYVHT, BandwidthMHz: 80, Negotiated: true},
		"IEEE80211_MODE_11AC_VHT80_80":   {PHY: PHYVHT, BandwidthMHz: 160, Negotiated: true},
		"IEEE80211_MODE_11NG_HT40MINUS":  {PHY: PHYHT, BandwidthMHz: 40, Negotiated: true},
		"IEEE80211_MODE_11NA_HT20":       {PHY: PHYHT, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11BEA_EHT320":    {PHY: PHYEHT, BandwidthMHz: 320, Negotiated: true},
		"IEEE80211_MODE_11A":             {PHY: PHYLegacy, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11G":             {PHY: PHYLegacy, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_AUTO":            {},
		"garbage":                        {},
		"IEEE80211_MODE_11AXA_HE":        {PHY: PHYHE, Negotiated: true},
		"ieee80211_mode_11axa_he80":      {PHY: PHYHE, BandwidthMHz: 80, Negotiated: true},
		"IEEE80211_MODE_11AXA_HE80_80":   {PHY: PHYHE, BandwidthMHz: 160, Negotiated: true},
		"IEEE80211_MODE_11AC_VHT160":     {PHY: PHYVHT, BandwidthMHz: 160, Negotiated: true},
		"IEEE80211_MODE_11NA_HT40PLUS":   {PHY: PHYHT, BandwidthMHz: 40, Negotiated: true},
		"IEEE80211_MODE_11BEA_EHT160":    {PHY: PHYEHT, BandwidthMHz: 160, Negotiated: true},
		"IEEE80211_MODE_11AXA_HE20":      {PHY: PHYHE, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11AC_VHT40PLUS":  {PHY: PHYVHT, BandwidthMHz: 40, Negotiated: true},
		"IEEE80211_MODE_11AC_VHT20":      {PHY: PHYVHT, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11NG_HT20":       {PHY: PHYHT, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11B":             {PHY: PHYLegacy, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11AXG_HE20":      {PHY: PHYHE, BandwidthMHz: 20, Negotiated: true},
		"IEEE80211_MODE_11BEG_EHT40PLUS": {PHY: PHYEHT, BandwidthMHz: 40, Negotiated: true},
	}
	for mode, want := range cases {
		if got := wlanconfigModeRate(mode); got != want {
			t.Errorf("wlanconfigModeRate(%q) = %+v, want %+v", mode, got, want)
		}
	}
}

func TestParseWlanconfigStationsModulation(t *testing.T) {
	out := `ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS XCAPS ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS   VHTCAPS ASSOCTIME    IEs   MODE RXNSS TXNSS PSMODE
aa:bb:cc:00:00:01    3   36   1201M   1080M   41      30      55    4      0  65535   EPSs  BRP          0       b              0      AWPM     gpsSRs     0       00:12:31 RSN WME IEEE80211_MODE_11AXA_HE80  2 2   0
aa:bb:cc:00:00:02    7    6     54M     48M   27      20      40   12      0  65535   EPSs  BRP          0       b              0      AWPM     gpsSRs     0       01:02:03 RSN WME IEEE80211_MODE_11G  1 1   1
`
	entries := ParseWlanconfigStations(out, -95, true)
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	want := RateInfo{PHY: PHYHE, NSS: 2, BandwidthMHz: 80, Negotiated: true}
	if entries[0].TxRateInfo != want || entries[0].RxRateInfo != want {
		t.Fatalf("HE80 rate info tx=%+v rx=%+v", entries[0].TxRateInfo, entries[0].RxRateInfo)
	}
	if entries[0].TxRateInfo.MCSKnown || entries[0].TxRateInfo.GuardIntervalNs != 0 {
		t.Fatal("wlanconfig list sta has no MCS/GI; they must stay unknown")
	}
	legacy := RateInfo{PHY: PHYLegacy, NSS: 1, BandwidthMHz: 20, Negotiated: true}
	if entries[1].TxRateInfo != legacy {
		t.Fatalf("legacy rate info %+v", entries[1].TxRateInfo)
	}
}

func TestParseHostapdRateInfo(t *testing.T) {
	cases := []struct {
		in        string
		kbps      uint32
		rateKnown bool
		want      RateInfo
	}{
		{"8667 vhtmcs 9 vhtnss 2 shortGI", 866_700, true, RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, GuardIntervalNs: 400}},
		{"12010 hemcs 11 henss 2", 1_201_000, true, RateInfo{PHY: PHYHE, MCS: 11, MCSKnown: true, NSS: 2}},
		{"2700 mcs 15", 270_000, true, RateInfo{PHY: PHYHT, MCS: 15, MCSKnown: true, NSS: 2, GuardIntervalNs: 800}},
		{"540", 54_000, true, RateInfo{}},
		{"", 0, false, RateInfo{}},
		{"x mcs y", 0, false, RateInfo{}},
	}
	for _, tc := range cases {
		kbps, known, got := parseHostapdRateInfo(tc.in)
		if kbps != tc.kbps || known != tc.rateKnown || got != tc.want {
			t.Errorf("parseHostapdRateInfo(%q) = %d %t %+v, want %d %t %+v", tc.in, kbps, known, got, tc.kbps, tc.rateKnown, tc.want)
		}
	}
	entries := ParseHostapdStations("a4:83:e7:01:02:03\nflags=[AUTH][ASSOC][AUTHORIZED][VHT]\nrx_rate_info=8667 vhtmcs 9 vhtnss 2 shortGI\ntx_rate_info=7800 vhtmcs 8 vhtnss 2\n")
	if len(entries) != 1 {
		t.Fatalf("got %d hostapd entries", len(entries))
	}
	e := entries[0]
	if e.RxRate != 866_700 || !e.RxRateKnown || e.RxRateInfo.MCS != 9 || e.TxRateInfo.MCS != 8 || e.TxRateInfo.GuardIntervalNs != 800 {
		t.Fatalf("hostapd entry %+v", e)
	}
}

func TestRateInfoFromFields(t *testing.T) {
	cases := []struct {
		name string
		got  RateInfo
		want RateInfo
	}{
		{"he", RateInfoFromFields(PHYHE, 1_201_000, 11, 2, 80, false, 0, 0), RateInfo{PHY: PHYHE, MCS: 11, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 800, DCMKnown: true}},
		{"ht40", RateInfoFromFields(PHYHT, 270_000, 15, -1, 40, true, -1, -1), RateInfo{PHY: PHYHT, MCS: 15, MCSKnown: true, NSS: 2, BandwidthMHz: 40, GuardIntervalNs: 400}},
		{"legacy", RateInfoFromFields("", 54_000, -1, -1, 20, false, -1, -1), RateInfo{PHY: PHYLegacy, BandwidthMHz: 20}},
		{"vht flag without mcs", RateInfoFromFields(PHYVHT, 866_700, -1, 2, 80, false, -1, -1), RateInfo{PHY: PHYVHT, NSS: 2, BandwidthMHz: 80}},
		{"nothing", RateInfoFromFields("", 0, -1, -1, 0, false, -1, -1), RateInfo{}},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
}

func TestMergeRateInfo(t *testing.T) {
	perFrame := RateInfo{PHY: PHYHE, MCS: 9, MCSKnown: true, NSS: 1, BandwidthMHz: 40, GuardIntervalNs: 800}
	negotiated := RateInfo{PHY: PHYHE, NSS: 2, BandwidthMHz: 80, Negotiated: true}
	if got := MergeRateInfo(negotiated, perFrame); got != perFrame {
		t.Fatalf("per-frame must win over a preferred negotiated value: %+v", got)
	}
	if got := MergeRateInfo(perFrame, negotiated); got != perFrame {
		t.Fatalf("per-frame must win: %+v", got)
	}
	if got := MergeRateInfo(RateInfo{}, negotiated); got != negotiated {
		t.Fatalf("unknown takes the other: %+v", got)
	}
	vht := RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true}
	if got := MergeRateInfo(vht, RateInfo{PHY: PHYHE, BandwidthMHz: 80, NSS: 2}); got != vht {
		t.Fatalf("different PHYs must not mix: %+v", got)
	}
	partial := RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true}
	if got := MergeRateInfo(partial, RateInfo{PHY: PHYVHT, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400}); got != (RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400}) {
		t.Fatalf("same PHY fills gaps: %+v", got)
	}
}

func TestChainSignalHelpers(t *testing.T) {
	chains := orderedChainSignal(map[uint16]int8{1: -53, 0: -55, 3: -60, 20: -1})
	if got := FormatChainSignal(chains); got != "-55,-53,-60" {
		t.Fatalf("chains %q", got)
	}
	if FormatChainSignal(nil) != "" {
		t.Fatal("no chains must format empty")
	}
	if _, ok := wextAssociatedBSSID([]byte{0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("zero BSSID is not associated")
	}
	if _, ok := wextAssociatedBSSID([]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44}); ok {
		t.Fatal("44:44:.. marker is not associated")
	}
	if mac, ok := wextAssociatedBSSID([]byte{0x80, 0x2a, 0xa8, 1, 2, 3}); !ok || !strings.EqualFold(mac.String(), "80:2a:a8:01:02:03") {
		t.Fatalf("bssid %v %t", mac, ok)
	}
}
