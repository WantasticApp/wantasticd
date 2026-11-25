package fiberonu

import (
	"bytes"
	"context"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// The Wi-Fi setters through both path families: the vendor
// Device.WUSP_ONU.Network.* leaves and their TR-181 Device.WiFi.* names.
// Each case runs on a fresh fixture and must produce the exact tcapi
// sequence, and the two families the same one.

// setVendor writes one vendor leaf the way the console's Set does.
func setVendor(t *testing.T, opts Options, leaf string, value wusp.Value) error {
	t.Helper()
	return SetONUParam(opts, netP+leaf, value, nil)
}

// setTR181 writes one Device.WiFi leaf the way the console's Set does.
func setTR181(t *testing.T, opts Options, path string, value wusp.Value) error {
	t.Helper()
	return SetONUParam(opts, "Device.WiFi."+path, value, nil)
}

// sameSequence runs a vendor and a TR-181 write on fresh fixtures and
// checks both produce want.
func sameSequence(t *testing.T, prep func(*wlanFake), vendorLeaf string, vendorValue wusp.Value, tr181Path string, tr181Value wusp.Value, want ...string) {
	t.Helper()
	opts, fake := wlanFixture(t)
	if prep != nil {
		prep(fake)
	}
	if err := setVendor(t, opts, vendorLeaf, vendorValue); err != nil {
		t.Fatalf("vendor %s: %v", vendorLeaf, err)
	}
	wantWrites(t, fake, want...)

	opts, fake = wlanFixture(t)
	if prep != nil {
		prep(fake)
	}
	if err := setTR181(t, opts, tr181Path, tr181Value); err != nil {
		t.Fatalf("Device.WiFi.%s: %v", tr181Path, err)
	}
	wantWrites(t, fake, want...)
}

func wpa3Supported(f *wlanFake) { f.store["WebCustom_Entry/isWPA3ModeSupported"] = "Yes" }

func TestWiFiSSIDRename24Entry0(t *testing.T) {
	sameSequence(t, nil,
		"SSID.1.Name", wusp.String("Casa Lopez"),
		"SSID.1.SSID", wusp.String("Casa Lopez"),
		"set WebCurSet_Entry wlan_id 0",
		"set WLan_Entry0 SSID Casa Lopez",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")
}

func TestWiFiPassphrase5GHzIsSecret(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)

	// SSID.4 / AccessPoint.4 is WLan11ac_Entry1 (WPA2PSK/AES).
	want := []string{
		"set WebCurSet_Entry wlan_ac_id 1",
		"set WLan11ac_Entry1 AuthMode WPA2PSK",
		"set WLan11ac_Entry1 WPAPSK " + testSecret,
		"set WLan11ac_Entry1 EncrypType AES",
		"save", "commit WLan11ac_Entry", "commit Wlan11ac_Common", "save",
	}
	sameSequence(t, nil,
		"SSID.4.Passphrase", wusp.String(testSecret),
		"AccessPoint.4.Security.KeyPassphrase", wusp.String(testSecret),
		want...)
	if strings.Contains(logs.String(), testSecret) {
		t.Fatalf("the passphrase reached the log: %q", logs.String())
	}

	// A failing write reports tcapi's output with the key replaced.
	opts, fake := wlanFixture(t)
	fake.fail = "set WLan11ac_Entry1 WPAPSK"
	err := setTR181(t, opts, "AccessPoint.4.Security.KeyPassphrase", wusp.String(testSecret))
	if err == nil || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "<hidden>") {
		t.Fatalf("want a scrubbed failure, got %v", err)
	}
	if strings.Contains(logs.String(), testSecret) {
		t.Fatalf("the passphrase reached the log: %q", logs.String())
	}
}

func TestWiFiSecurityModeToWPA2WPA3Transition(t *testing.T) {
	// 2.4 GHz SSID.1 is WPAPSKWPA2PSK/TKIPAES: the transition mode forces
	// AES; the stored key stays (WPA2PSK -> PSK modes keep it).
	sameSequence(t, wpa3Supported,
		"SSID.1.AuthMode", wusp.String("WPA2PSKWPA3PSK"),
		"AccessPoint.1.Security.ModeEnabled", wusp.String("WPA3-Personal-Transition"),
		"set WebCurSet_Entry wlan_id 0",
		"set WLan_Entry0 AuthMode WPA2PSKWPA3PSK",
		"set WLan_Entry0 EncrypType AES",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")

	// WPA2-Personal keeps a stored cipher the mode allows.
	sameSequence(t, nil,
		"SSID.1.AuthMode", wusp.String("WPA2PSK"),
		"AccessPoint.1.Security.ModeEnabled", wusp.String("WPA2-Personal"),
		"set WebCurSet_Entry wlan_id 0",
		"set WLan_Entry0 AuthMode WPA2PSK",
		"set WLan_Entry0 EncrypType TKIPAES",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")

	// Open -> WPA3 transition on 5 GHz needs the key in the same Apply();
	// the TR-181 names work there too.
	opts, fake := wlanFixture(t)
	wpa3Supported(fake)
	input := wusp.NewMessage()
	input.Set("Device.WiFi.AccessPoint.3.Security.ModeEnabled", wusp.String("WPA3-Personal-Transition"))
	input.Set("Device.WiFi.AccessPoint.3.Security.KeyPassphrase", wusp.String(testSecret))
	if err := ONUNetworkOperate(context.Background(), opts, netP+"WLAN.Apply()", input); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WebCurSet_Entry wlan_ac_id 0",
		"set WLan11ac_Entry0 AuthMode WPA2PSKWPA3PSK",
		"set WLan11ac_Entry0 WPAPSK "+testSecret,
		"set WLan11ac_Entry0 EncrypType AES",
		"set WLan11ac_Entry0 RekeyInterval 3600",
		"save", "commit WLan11ac_Entry", "commit Wlan11ac_Common", "save")
}

func TestWiFiChannelAndAuto(t *testing.T) {
	// 2.4 GHz, region 1, 20/40 MHz: the extension channel follows.
	sameSequence(t, nil,
		"Radio.1.Channel", wusp.Uint(6),
		"Radio.1.Channel", wusp.Uint(6),
		"set WLan_Common Channel 6", "set WLan_Common HT_EXTCHA 0",
		"commit WLan_Common", "save")
	// Automatic: Channel 0 / AutoChannelEnable true.
	sameSequence(t, func(f *wlanFake) { f.store["WLan_Common/Channel"] = "6" },
		"Radio.1.Channel", wusp.Uint(0),
		"Radio.1.AutoChannelEnable", wusp.Bool(true),
		"set WLan_Common Channel 0", "set WLan_Common HT_EXTCHA 1",
		"commit WLan_Common", "save")

	// 5 GHz, CountryRegionABand 0.
	sameSequence(t, nil,
		"Radio.2.Channel", wusp.Uint(36),
		"Radio.2.Channel", wusp.Uint(36),
		"set WLan11ac_Common Channel 36", "save", "commit Wlan11ac_Common", "save")
	sameSequence(t, nil,
		"Radio.2.Channel", wusp.Uint(0),
		"Radio.2.AutoChannelEnable", wusp.Bool(true),
		"set WLan11ac_Common Channel 0", "save", "commit Wlan11ac_Common", "save")

	// AutoChannelEnable false pins the channel the radio operates on.
	opts, fake := wlanFixture(t)
	fake.store["WLan_Common/HT_BW"] = "0"
	fake.store["Info_WLan/CurrentChannel"] = "11"
	if err := setTR181(t, opts, "Radio.1.AutoChannelEnable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake, "set WLan_Common Channel 11", "commit WLan_Common", "save")
	// ... and is a no-op on a fixed channel.
	opts, fake = wlanFixture(t)
	if err := setTR181(t, opts, "Radio.2.AutoChannelEnable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake)

	// Mexico/FCC (CountryRegion 0) stops at 11.
	opts, fake = wlanFixture(t)
	fake.store["WLan_Common/CountryRegion"] = "0"
	if err := setTR181(t, opts, "Radio.1.Channel", wusp.Uint(11)); err != nil {
		t.Fatal(err)
	}
}

func TestWiFiBandwidth(t *testing.T) {
	// 2.4 GHz: 20 MHz / 20/40 MHz (TR-181 Auto).
	sameSequence(t, nil,
		"Radio.1.Bandwidth", wusp.String("20 MHz"),
		"Radio.1.OperatingChannelBandwidth", wusp.String("20MHz"),
		"set WLan_Common HT_BW 0", "set WLan_Common HT_EXTCHA 0", "set WLan_Common HT_BSSCoexistence 0",
		"commit WLan_Common", "save")
	sameSequence(t, func(f *wlanFake) { f.store["WLan_Common/HT_BW"] = "0"; f.store["WLan_Common/Channel"] = "1" },
		"Radio.1.Bandwidth", wusp.String("20/40 MHz"),
		"Radio.1.OperatingChannelBandwidth", wusp.String("Auto"),
		"set WLan_Common HT_BW 1", "set WLan_Common HT_EXTCHA 1", "set WLan_Common HT_BSSCoexistence 1",
		"commit WLan_Common", "save")

	// 5 GHz (802.11ac): 20, 40, 80, and 160 on a 7615.
	sameSequence(t, nil,
		"Radio.2.Bandwidth", wusp.String("20 MHz"),
		"Radio.2.OperatingChannelBandwidth", wusp.String("20MHz"),
		"set WLan11ac_Common HT_BW 0", "save", "commit Wlan11ac_Common", "save")
	sameSequence(t, nil,
		"Radio.2.Bandwidth", wusp.String("20/40 MHz"),
		"Radio.2.OperatingChannelBandwidth", wusp.String("40MHz"),
		"set WLan11ac_Common HT_BW 1", "set WLan11ac_Common VHT_BW 0", "save", "commit Wlan11ac_Common", "save")
	sameSequence(t, nil,
		"Radio.2.Bandwidth", wusp.String("80 MHz"),
		"Radio.2.OperatingChannelBandwidth", wusp.String("80MHz"),
		"set WLan11ac_Common HT_BW 1", "set WLan11ac_Common VHT_BW 1", "save", "commit Wlan11ac_Common", "save")
	sameSequence(t, func(f *wlanFake) { f.store["WLan11ac_Common/rt_device"] = "7615" },
		"Radio.2.Bandwidth", wusp.String("160 MHz"),
		"Radio.2.OperatingChannelBandwidth", wusp.String("160MHz"),
		"set WLan11ac_Common HT_BW 1", "set WLan11ac_Common VHT_BW 2", "save", "commit Wlan11ac_Common", "save")

	// 80 MHz needs 802.11ac.
	opts, fake := wlanFixture(t)
	fake.store["WLan11ac_Common/WirelessMode"] = "8"
	if err := setTR181(t, opts, "Radio.2.OperatingChannelBandwidth", wusp.String("80MHz")); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("want a refusal, got %v", err)
	}
	wantWrites(t, fake)
}

func TestWiFiRadioOffOn(t *testing.T) {
	for _, on := range []bool{false, true} {
		v := "0"
		if on {
			v = "1"
		}
		sameSequence(t, nil,
			"Radio.1.Enable", wusp.Bool(on),
			"Radio.1.Enable", wusp.Bool(on),
			"set WLan_Common APOn "+v, "commit WLan_Common", "save")
		sameSequence(t, nil,
			"Radio.2.Enable", wusp.Bool(on),
			"Radio.2.Enable", wusp.Bool(on),
			"set WLan11ac_Common APOn "+v, "save", "commit Wlan11ac_Common", "save")
	}
}

func TestWiFiHideSSID(t *testing.T) {
	// The first SSID: WPS goes off with the broadcast, as the pages do.
	sameSequence(t, func(f *wlanFake) { f.store["WLan_Entry0/WPSConfMode"] = "7" },
		"SSID.1.Hidden", wusp.Bool(true),
		"AccessPoint.1.SSIDAdvertisementEnabled", wusp.Bool(false),
		"set WebCurSet_Entry wlan_id 0",
		"set WLan_Entry0 HideSSID 1",
		"set WLan_Entry0 WPSConfMode 0",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")
	// Another SSID, and showing one again: HideSSID only.
	sameSequence(t, nil,
		"SSID.4.Hidden", wusp.Bool(false),
		"AccessPoint.4.SSIDAdvertisementEnabled", wusp.Bool(true),
		"set WebCurSet_Entry wlan_ac_id 1",
		"set WLan11ac_Entry1 HideSSID 0",
		"save", "commit WLan11ac_Entry", "commit Wlan11ac_Common", "save")
}

func TestWiFiTxPowerAndClients(t *testing.T) {
	sameSequence(t, nil,
		"Radio.1.TxPower", wusp.Uint(60),
		"Radio.1.TransmitPower", wusp.Int(60),
		"set WLan_Common TxPowerLevel 3", "commit WLan_Common", "save")
	sameSequence(t, nil,
		"Radio.2.TxPower", wusp.Uint(50),
		"Radio.2.TransmitPower", wusp.Int(50),
		"set WLan11ac_Common TxPower 50", "save", "commit Wlan11ac_Common", "save")
	sameSequence(t, nil,
		"SSID.2.MaxStations", wusp.Uint(16),
		"AccessPoint.2.MaxAllowedAssociations", wusp.Uint(16),
		"set WebCurSet_Entry wlan_id 1",
		"set WLan_Entry1 MaxStaNum 16",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")
	sameSequence(t, nil,
		"SSID.2.Enable", wusp.Bool(true),
		"SSID.2.Enable", wusp.Bool(true),
		"set WebCurSet_Entry wlan_id 1",
		"set WLan_Entry1 EnableSSID 1",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")
}

// One Apply() changing both bands commits each band once, in its own
// page's order.
func TestWiFiApplyGroupsPerBand(t *testing.T) {
	opts, fake := wlanFixture(t)
	input := wusp.NewMessage()
	input.Set("Device.WiFi.Radio.1.TransmitPower", wusp.Int(80))
	input.Set("Device.WiFi.SSID.1.SSID", wusp.String("Casa"))
	input.Set("Device.WiFi.AccessPoint.2.SSIDAdvertisementEnabled", wusp.Bool(false))
	input.Set(netP+"Radio.2.Channel", wusp.Uint(149))
	input.Set(netP+"SSID.3.Name", wusp.String("Casa-5G"))
	if err := ONUNetworkOperate(context.Background(), opts, netP+"WLAN.Apply()", input); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WLan_Common TxPowerLevel 2",
		"set WebCurSet_Entry wlan_id 0", "set WLan_Entry0 SSID Casa", "commit WLan_Entry",
		"set WebCurSet_Entry wlan_id 1", "set WLan_Entry1 HideSSID 1", "commit WLan_Entry",
		"save", "commit WLan_Common", "save",
		"set WLan11ac_Common Channel 149",
		"set WebCurSet_Entry wlan_ac_id 0", "set WLan11ac_Entry0 SSID Casa-5G",
		"save", "commit WLan11ac_Entry", "commit Wlan11ac_Common", "save")
}

func TestWiFiInvalidInputsWriteNothing(t *testing.T) {
	type write struct {
		path  string // vendor leaf, or Device.WiFi path
		value wusp.Value
	}
	cases := []struct {
		name string
		prep func(*wlanFake)
		w    []write
		want string
	}{
		{"2.4 GHz channel 12 in Mexico/FCC", func(f *wlanFake) { f.store["WLan_Common/CountryRegion"] = "0" },
			[]write{{netP + "Radio.1.Channel", wusp.Uint(12)}}, "not offered in this region"},
		{"TR-181 2.4 GHz channel 12 in Mexico/FCC", func(f *wlanFake) { f.store["WLan_Common/CountryRegion"] = "0" },
			[]write{{"Device.WiFi.Radio.1.Channel", wusp.Uint(12)}}, "not offered in this region"},
		{"5 GHz channel 140 in FCC region 0", nil,
			[]write{{"Device.WiFi.Radio.2.Channel", wusp.Uint(140)}}, "not offered in this region"},
		{"5 GHz channel 6", nil,
			[]write{{netP + "Radio.2.Channel", wusp.Uint(6)}}, "not offered in this region"},
		{"7-character passphrase", nil,
			[]write{{netP + "SSID.4.Passphrase", wusp.String("1234567")}}, "8 to 63"},
		{"TR-181 7-character passphrase", nil,
			[]write{{"Device.WiFi.AccessPoint.4.Security.KeyPassphrase", wusp.String("1234567")}}, "8 to 63"},
		{"WPA3 with TKIP", wpa3Supported,
			[]write{{netP + "SSID.1.AuthMode", wusp.String("WPA3PSK")}, {netP + "SSID.1.Encryption", wusp.String("TKIP")}}, "encryption \"TKIP\" is not offered"},
		{"TR-181 WPA3 with TKIP", wpa3Supported,
			[]write{{"Device.WiFi.AccessPoint.1.Security.ModeEnabled", wusp.String("WPA3-Personal")}, {"Device.WiFi.AccessPoint.1.Security.EncryptionMode", wusp.String("TKIP")}}, "encryption \"TKIP\" is not offered"},
		{"33-byte SSID", nil,
			[]write{{netP + "SSID.1.Name", wusp.String(strings.Repeat("x", 33))}}, "1 to 32"},
		{"TR-181 33-byte SSID", nil,
			[]write{{"Device.WiFi.SSID.3.SSID", wusp.String(strings.Repeat("x", 33))}}, "1 to 32"},
		{"unknown TR-181 security mode", nil,
			[]write{{"Device.WiFi.AccessPoint.1.Security.ModeEnabled", wusp.String("WPA2-Enterprise")}}, "not offered"},
		{"TR-181 Auto width on 5 GHz", nil,
			[]write{{"Device.WiFi.Radio.2.OperatingChannelBandwidth", wusp.String("Auto")}}, "not offered"},
		{"TR-181 40MHz on 2.4 GHz without the firmware switch", nil,
			[]write{{"Device.WiFi.Radio.1.OperatingChannelBandwidth", wusp.String("40MHz")}}, "not offered"},
		{"TR-181 automatic power", nil,
			[]write{{"Device.WiFi.Radio.1.TransmitPower", wusp.Int(-1)}}, "automatic"},
		{"auto and a fixed channel", nil,
			[]write{{"Device.WiFi.Radio.1.AutoChannelEnable", wusp.Bool(true)}, {"Device.WiFi.Radio.1.Channel", wusp.Uint(6)}}, "both asked for"},
		{"auto off with the channel unreadable", nil,
			[]write{{"Device.WiFi.Radio.1.AutoChannelEnable", wusp.Bool(false)}}, "could not be read"},
		{"missing access point", nil,
			[]write{{"Device.WiFi.AccessPoint.9.SSIDAdvertisementEnabled", wusp.Bool(false)}}, "does not exist"},
	}
	for _, c := range cases {
		opts, fake := wlanFixture(t)
		if c.prep != nil {
			c.prep(fake)
		}
		var err error
		if len(c.w) == 1 {
			err = SetONUParam(opts, c.w[0].path, c.w[0].value, nil)
		} else {
			input := wusp.NewMessage()
			for _, w := range c.w {
				input.Set(w.path, w.value)
			}
			err = ONUNetworkOperate(context.Background(), opts, netP+"WLAN.Apply()", input)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
		if len(fake.writes) != 0 {
			t.Errorf("%s: a refused change wrote %q", c.name, fake.writes)
		}
	}
}

// Device.WiFi paths that are not writable here are left to other handlers.
func TestWiFiTR181UnsupportedPaths(t *testing.T) {
	opts, fake := wlanFixture(t)
	for _, p := range []string{
		"Device.WiFi.Radio.1.Name",
		"Device.WiFi.SSID.1.MACAddress",
		"Device.WiFi.AccessPoint.1.Security.PreSharedKey",
		"Device.WiFi.AccessPoint.1.AssociatedDevice.1.Active",
		"Device.WiFi.Radio.01.Enable",
	} {
		if err := SetONUParam(opts, p, wusp.String("x"), nil); !errors.Is(err, wusp.ErrUSPPathUnsupported) {
			t.Errorf("%s: want ErrUSPPathUnsupported, got %v", p, err)
		}
	}
	wantWrites(t, fake)

	// Without the MediaTek driver (no ra0/rai0) nothing is handled.
	opts.SysClassNetDir = t.TempDir()
	if err := SetONUParam(opts, "Device.WiFi.Radio.1.Enable", wusp.Bool(false), nil); !errors.Is(err, wusp.ErrUSPPathUnsupported) {
		t.Errorf("mac80211 build: want ErrUSPPathUnsupported, got %v", err)
	}
	wantWrites(t, fake)
}

// After a set, the next collection shows the new value on both the vendor
// and the TR-181 paths (the fake applies sets to its store, as cfg_manager
// does). The passphrase is never read back.
func TestWiFiReadAfterWrite(t *testing.T) {
	opts, fake := wlanFixture(t)
	wpa3Supported(fake)
	fake.store["WLan_Common/TxPowerLevel"] = "1"
	fake.store["WLan11ac_Common/TxPower"] = "100"
	fake.store["WLan11ac_Common/HT_BW"] = "0"

	writes := []struct {
		path  string
		value wusp.Value
	}{
		{"Device.WiFi.SSID.1.SSID", wusp.String("Casa")},
		{netP + "SSID.3.Name", wusp.String("Casa-5G")},
		{"Device.WiFi.AccessPoint.1.SSIDAdvertisementEnabled", wusp.Bool(false)},
		{"Device.WiFi.AccessPoint.1.Security.ModeEnabled", wusp.String("WPA3-Personal-Transition")},
		{"Device.WiFi.AccessPoint.4.Security.KeyPassphrase", wusp.String(testSecret)},
		{"Device.WiFi.AccessPoint.2.MaxAllowedAssociations", wusp.Uint(12)},
		{"Device.WiFi.SSID.2.Enable", wusp.Bool(true)},
		{"Device.WiFi.Radio.1.Channel", wusp.Uint(6)},
		{"Device.WiFi.Radio.1.TransmitPower", wusp.Int(40)},
		{netP + "Radio.2.Bandwidth", wusp.String("80 MHz")},
		{"Device.WiFi.Radio.2.AutoChannelEnable", wusp.Bool(true)},
		{netP + "Radio.2.TxPower", wusp.Uint(25)},
		{"Device.WiFi.Radio.2.Enable", wusp.Bool(false)},
	}
	for _, w := range writes {
		if err := SetONUParam(opts, w.path, w.value, nil); err != nil {
			t.Fatalf("%s: %v", w.path, err)
		}
	}

	msg := wusp.NewMessage()
	tc, cancel := newTcapi(context.Background(), opts)
	defer cancel()
	snap := collectWLAN(context.Background(), opts, tc, msg)
	collectWiFiTR181(context.Background(), opts, snap, msg)

	want := map[string]string{
		netP + "SSID.1.Name":                                      "Casa",
		netP + "SSID.1.Hidden":                                    "true",
		netP + "SSID.1.AuthMode":                                  "WPA2PSKWPA3PSK",
		netP + "SSID.1.Encryption":                                "AES",
		netP + "SSID.2.MaxStations":                               "12",
		netP + "SSID.2.Enable":                                    "true",
		netP + "SSID.3.Name":                                      "Casa-5G",
		netP + "Radio.1.Channel":                                  "6",
		netP + "Radio.1.TxPower":                                  "40",
		netP + "Radio.2.Bandwidth":                                "80 MHz",
		netP + "Radio.2.Channel":                                  "0",
		netP + "Radio.2.AutoChannel":                              "true",
		netP + "Radio.2.TxPower":                                  "25",
		netP + "Radio.2.Enable":                                   "false",
		"Device.WiFi.SSID.1.SSID":                                 "Casa",
		"Device.WiFi.SSID.3.SSID":                                 "Casa-5G",
		"Device.WiFi.SSID.2.Enable":                               "true",
		"Device.WiFi.AccessPoint.2.Enable":                        "true",
		"Device.WiFi.AccessPoint.1.SSIDAdvertisementEnabled":      "false",
		"Device.WiFi.AccessPoint.1.Security.ModeEnabled":          "WPA3-Personal-Transition",
		"Device.WiFi.AccessPoint.1.Security.EncryptionMode":       "AES",
		"Device.WiFi.AccessPoint.4.Security.ModeEnabled":          "WPA2-Personal",
		"Device.WiFi.AccessPoint.2.MaxAllowedAssociations":        "12",
		"Device.WiFi.AccessPoint.2.MaxAssociatedDevices":          "12",
		"Device.WiFi.Radio.1.Channel":                             "6",
		"Device.WiFi.Radio.1.AutoChannelEnable":                   "false",
		"Device.WiFi.Radio.1.TransmitPower":                       "40",
		"Device.WiFi.Radio.2.OperatingChannelBandwidth":           "80MHz",
		"Device.WiFi.Radio.2.AutoChannelEnable":                   "true",
		"Device.WiFi.Radio.2.TransmitPower":                       "25",
		"Device.WiFi.Radio.2.Enable":                              "false",
		"Device.WiFi.Radio.2.SupportedOperatingChannelBandwidths": "20MHz,40MHz,80MHz",
		"Device.WiFi.Radio.1.TransmitPowerSupported":              "100,80,60,40,20",
		"Device.WiFi.AccessPoint.1.Security.ModesSupported":       "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA3-Personal,WPA3-Personal-Transition",
	}
	got := map[string]string{}
	for _, f := range msg.Fields {
		got[f.Path] = wusp.ValueToString(f.Val)
		if strings.Contains(got[f.Path], testSecret) || strings.Contains(f.Path, "Passphrase") || strings.Contains(f.Path, "PreSharedKey") {
			t.Errorf("the snapshot carries key material at %s", f.Path)
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// The setters wrote the key; the collection never read it.
	if fake.store["WLan11ac_Entry1/WPAPSK"] != testSecret {
		t.Fatal("the passphrase was not written")
	}
}

// Every writable Device.WiFi leaf the setter accepts is a readWrite
// parameter of the TR-181 model the hub serves, and every vendor Wi-Fi
// leaf it accepts is writable in the ONU model.
func TestWiFiWritablePathsAreModelled(t *testing.T) {
	access := map[string]wusp.Access{}
	for _, p := range wusp.DeviceWiFiParams {
		access[p.Path] = p.Access
	}
	for _, leaf := range []string{
		"Radio.{i}.Enable", "Radio.{i}.Channel", "Radio.{i}.AutoChannelEnable",
		"Radio.{i}.OperatingChannelBandwidth", "Radio.{i}.TransmitPower",
		"SSID.{i}.SSID", "SSID.{i}.Enable",
		"AccessPoint.{i}.Enable", "AccessPoint.{i}.SSIDAdvertisementEnabled",
		"AccessPoint.{i}.MaxAllowedAssociations", "AccessPoint.{i}.MaxAssociatedDevices",
		"AccessPoint.{i}.Security.ModeEnabled", "AccessPoint.{i}.Security.EncryptionMode",
		"AccessPoint.{i}.Security.KeyPassphrase",
	} {
		path := "Device.WiFi." + leaf
		if !isWiFiTR181Leaf(strings.ReplaceAll(path, "{i}", "1")) {
			t.Errorf("%s is not accepted by the setter", path)
		}
		if a := access[path]; a != wusp.ReadWrite {
			t.Errorf("%s access = %q, want readWrite", path, a)
		}
	}
	onu := map[string]wusp.Access{}
	for _, p := range wusp.AllWUSPONUParams {
		onu[p.Path] = p.Access
	}
	for _, leaf := range []string{
		"Radio.{i}.Enable", "Radio.{i}.Channel", "Radio.{i}.Bandwidth", "Radio.{i}.Mode", "Radio.{i}.TxPower",
		"SSID.{i}.Name", "SSID.{i}.Enable", "SSID.{i}.Hidden", "SSID.{i}.AuthMode",
		"SSID.{i}.Encryption", "SSID.{i}.MaxStations",
	} {
		if a := onu[netP+leaf]; a != wusp.ReadWrite {
			t.Errorf("%s access = %q, want readWrite", netP+leaf, a)
		}
		if !isWLANConfigLeaf(strings.ReplaceAll(leaf, "{i}", "1")) {
			t.Errorf("%s is not accepted by the setter", leaf)
		}
	}
	if onu[netP+"SSID.{i}.Passphrase"] != wusp.WriteOnly {
		t.Error("SSID.{i}.Passphrase must stay writeOnly")
	}
	if !reflect.DeepEqual(encrypTypeTR181("TKIPAES"), []string{"TKIP", "AES"}) {
		t.Error("TKIPAES must read back as TKIP,AES")
	}
}
