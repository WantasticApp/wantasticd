package fiberonu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// wlanFake is a stateful tcapi: gets read the store, writes are recorded in
// order (and applied, so a later read sees them).
type wlanFake struct {
	store  map[string]string
	writes []string
	gets   int
	fail   string // a write starting with this text fails, echoing its arguments
}

func (f *wlanFake) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	if !strings.HasSuffix(name, "tcapi") {
		return nil, errors.New("not found")
	}
	line := strings.Join(args, " ")
	switch args[0] {
	case "get":
		f.gets++
		if v, ok := f.store[args[1]+"/"+args[2]]; ok {
			return []byte(v + "\n"), nil
		}
		return []byte("no attribute information\n"), nil
	case "set", "commit", "save":
		f.writes = append(f.writes, line)
		if f.fail != "" && strings.HasPrefix(line, f.fail) {
			return []byte("verify setting fail while tcapi set " + line + "\n"), nil
		}
		if args[0] == "set" {
			f.store[args[1]+"/"+args[2]] = args[3]
		}
		return nil, nil
	}
	return nil, errors.New("unknown tcapi verb")
}

const testSecret = "correct horse 42"

func wlanFixture(t *testing.T) (Options, *wlanFake) {
	t.Helper()
	sysNet := filepath.Join(t.TempDir(), "sys_class_net")
	for _, name := range []string{"ra0", "ra1", "rai0", "rai1"} {
		d := filepath.Join(sysNet, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "flags"), []byte("0x1003\n"), 0o644)
	}
	fake := &wlanFake{store: map[string]string{
		"WLan_Common/APOn":              "1",
		"WLan_Common/BssidNum":          "2",
		"WLan_Common/Channel":           "0",
		"WLan_Common/CountryRegion":     "1",
		"WLan_Common/WirelessMode":      "9",
		"WLan_Common/HT_BW":             "1",
		"WLan_Common/HT_BSSCoexistence": "1",
		"WLan_Entry0/SSID":              "Home",
		"WLan_Entry0/EnableSSID":        "1",
		"WLan_Entry0/AuthMode":          "WPAPSKWPA2PSK",
		"WLan_Entry0/EncrypType":        "TKIPAES",
		"WLan_Entry0/WPAPSK":            "old-secret-key",
		"WLan_Entry1/SSID":              "Guest",
		"WLan_Entry1/EnableSSID":        "0",
		"WLan_Entry1/AuthMode":          "OPEN",
		"WLan_Entry1/EncrypType":        "NONE",

		"WLan11ac_Common/APOn":               "1",
		"WLan11ac_Common/BssidNum":           "2",
		"WLan11ac_Common/Channel":            "149",
		"WLan11ac_Common/CountryRegionABand": "0",
		"WLan11ac_Common/WirelessMode":       "14",
		"WLan11ac_Entry0/SSID":               "Home-5G",
		"WLan11ac_Entry0/EnableSSID":         "1",
		"WLan11ac_Entry0/AuthMode":           "OPEN",
		"WLan11ac_Entry0/EncrypType":         "NONE",
		"WLan11ac_Entry1/SSID":               "Guest-5G",
		"WLan11ac_Entry1/EnableSSID":         "0",
		"WLan11ac_Entry1/AuthMode":           "WPA2PSK",
		"WLan11ac_Entry1/EncrypType":         "AES",
		"WLan11ac_Entry1/RekeyInterval":      "3600",

		"WebCustom_Entry/isMaxStaNumSupported": "Yes",
		"WebCustom_Entry/isPerSSIDSupport":     "Yes",
	}}
	return Options{SysClassNetDir: sysNet, TcapiPath: "/userfs/bin/tcapi", Exec: fake.exec}, fake
}

const netP = wusp.WUSPONUPrefix + "Network."

func setLeaf(opts Options, leaf string, value wusp.Value) error {
	return SetONUNetworkParam(context.Background(), opts, netP+leaf, value)
}

func apply(opts Options, pairs ...string) error {
	input := &wusp.Message{}
	for i := 0; i+1 < len(pairs); i += 2 {
		input.Set(netP+pairs[i], wusp.String(pairs[i+1]))
	}
	return ONUNetworkOperate(context.Background(), opts, netP+"WLAN.Apply()", input)
}

func wantWrites(t *testing.T, fake *wlanFake, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(fake.writes, want) {
		t.Fatalf("tcapi writes:\n got  %q\n want %q", fake.writes, want)
	}
}

func TestWLANRadioEnableSequence(t *testing.T) {
	opts, fake := wlanFixture(t)
	if err := setLeaf(opts, "Radio.1.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake, "set WLan_Common APOn 0", "commit WLan_Common", "save")

	fake.writes = nil
	if err := setLeaf(opts, "Radio.2.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake, "set WLan11ac_Common APOn 0", "save", "commit Wlan11ac_Common", "save")
}

func TestWLANChannelSetsExtensionChannel(t *testing.T) {
	cases := []struct {
		channel, ext string
	}{
		{"1", "1"},  // select index 1: upper extension channel
		{"4", "1"},  // index 4
		{"6", "0"},  // between: the stored choice, 0 when unset
		{"11", "0"}, // index 11: lower
		{"0", "1"},  // Auto is index 0
	}
	for _, c := range cases {
		opts, fake := wlanFixture(t)
		if err := setLeaf(opts, "Radio.1.Channel", wusp.String(c.channel)); err != nil {
			t.Fatalf("channel %s: %v", c.channel, err)
		}
		wantWrites(t, fake,
			"set WLan_Common Channel "+c.channel,
			"set WLan_Common HT_EXTCHA "+c.ext,
			"commit WLan_Common", "save")
	}

	// 20 MHz: the channel has no companion.
	opts, fake := wlanFixture(t)
	fake.store["WLan_Common/HT_BW"] = "0"
	if err := setLeaf(opts, "Radio.1.Channel", wusp.String("6")); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake, "set WLan_Common Channel 6", "commit WLan_Common", "save")
}

func TestWLANBandwidthSequence(t *testing.T) {
	opts, fake := wlanFixture(t)
	if err := setLeaf(opts, "Radio.1.Bandwidth", wusp.String("20 MHz")); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WLan_Common HT_BW 0",
		"set WLan_Common HT_EXTCHA 0",
		"set WLan_Common HT_BSSCoexistence 0",
		"commit WLan_Common", "save")

	opts, fake = wlanFixture(t)
	fake.store["WLan_Common/HT_BW"] = "0"
	fake.store["WLan_Common/Channel"] = "11"
	if err := setLeaf(opts, "Radio.1.Bandwidth", wusp.String("20/40 MHz")); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WLan_Common HT_BW 1",
		"set WLan_Common HT_EXTCHA 0",
		"set WLan_Common HT_BSSCoexistence 1",
		"commit WLan_Common", "save")
}

func TestWLANModeSequenceAndCipherGuard(t *testing.T) {
	opts, fake := wlanFixture(t)
	if err := setLeaf(opts, "Radio.1.Mode", wusp.String("802.11b/g")); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake, "set WLan_Common WirelessMode 0", "commit WLan_Common", "save")

	// 802.11n-only is refused while a network still uses TKIP.
	opts, fake = wlanFixture(t)
	err := setLeaf(opts, "Radio.1.Mode", wusp.String("802.11n"))
	if err == nil || !strings.Contains(err.Error(), "AES") {
		t.Fatalf("want an AES refusal, got %v", err)
	}
	wantWrites(t, fake)
}

func TestWLANApplyOneCommitPerChangeSet(t *testing.T) {
	opts, fake := wlanFixture(t)
	err := apply(opts,
		"Radio.1.Channel", "11",
		"SSID.2.Interface", "ra1",
		"SSID.2.Name", "Guests",
		"SSID.2.Enable", "true",
		"SSID.2.Hidden", "true",
		"SSID.2.MaxStations", "8",
		"SSID.2.AuthMode", "WPA2PSK",
		"SSID.2.Encryption", "AES",
		"SSID.2.Passphrase", testSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WLan_Common Channel 11",
		"set WLan_Common HT_EXTCHA 0",
		"set WebCurSet_Entry wlan_id 1",
		"set WLan_Entry1 HideSSID 1",
		"set WLan_Entry1 SSID Guests",
		"set WLan_Entry1 EnableSSID 1",
		"set WLan_Entry1 MaxStaNum 8",
		"set WLan_Entry1 AuthMode WPA2PSK",
		"set WLan_Entry1 WPAPSK "+testSecret,
		"set WLan_Entry1 EncrypType AES",
		"commit WLan_Entry", "save",
		"commit WLan_Common", "save")
}

func TestWLAN5GHzSSIDSequence(t *testing.T) {
	opts, fake := wlanFixture(t)
	// SSID.3 is the first 5 GHz network (after two 2.4 GHz ones).
	err := apply(opts,
		"SSID.3.Name", "Home-5",
		"SSID.3.AuthMode", "WPAPSKWPA2PSK",
		"SSID.3.Passphrase", testSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WebCurSet_Entry wlan_ac_id 0",
		"set WLan11ac_Entry0 SSID Home-5",
		"set WLan11ac_Entry0 AuthMode WPAPSKWPA2PSK",
		"set WLan11ac_Entry0 WPAPSK "+testSecret,
		"set WLan11ac_Entry0 EncrypType AES",
		"set WLan11ac_Entry0 RekeyInterval 3600",
		"save",
		"commit WLan11ac_Entry",
		"commit Wlan11ac_Common",
		"save")

	// A stored RekeyInterval is left alone; opening a network sets NONE.
	opts, fake = wlanFixture(t)
	if err := apply(opts, "SSID.4.AuthMode", "OPEN"); err != nil {
		t.Fatal(err)
	}
	wantWrites(t, fake,
		"set WebCurSet_Entry wlan_ac_id 1",
		"set WLan11ac_Entry1 AuthMode OPEN",
		"set WLan11ac_Entry1 EncrypType NONE",
		"save", "commit WLan11ac_Entry", "commit Wlan11ac_Common", "save")
}

func TestWLANRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		prep  func(*wlanFake)
		pairs []string
		want  string
	}{
		{"channel outside the region", nil, []string{"Radio.1.Channel", "14"}, "not offered in this region"},
		{"5 GHz channel outside the region", nil, []string{"Radio.2.Channel", "100"}, "not offered in this region"},
		{"5 GHz 160 MHz without a 7615", nil, []string{"Radio.2.Bandwidth", "160 MHz"}, "not offered"},
		{"5 GHz width in 802.11a", func(f *wlanFake) { f.store["WLan11ac_Common/WirelessMode"] = "2" }, []string{"Radio.2.Bandwidth", "20 MHz"}, "802.11n or 802.11ac"},
		{"5 GHz mode", nil, []string{"Radio.2.Mode", "802.11b/g/n"}, "5 GHz mode"},
		{"2.4 GHz power not offered", nil, []string{"Radio.1.TxPower", "50"}, "100,80,60,40,20"},
		{"5 GHz power not offered", nil, []string{"Radio.2.TxPower", "60"}, "100,80,50,25,10"},
		{"40 MHz without the firmware switch", nil, []string{"Radio.1.Bandwidth", "40 MHz"}, "not offered"},
		{"width in a non-n mode", func(f *wlanFake) { f.store["WLan_Common/WirelessMode"] = "0" }, []string{"Radio.1.Bandwidth", "20 MHz"}, "802.11n mode"},
		{"unknown mode", nil, []string{"Radio.1.Mode", "802.11ax"}, "not offered"},
		{"missing radio", nil, []string{"Radio.3.Enable", "true"}, "does not exist"},
		{"missing ssid", nil, []string{"SSID.9.Hidden", "true"}, "does not exist"},
		{"empty name", nil, []string{"SSID.1.Name", ""}, "1 to 32"},
		{"long name", nil, []string{"SSID.1.Name", strings.Repeat("a", 33)}, "1 to 32"},
		{"non-ASCII name", nil, []string{"SSID.1.Name", "café"}, "printable ASCII"},
		{"name ending in a space", nil, []string{"SSID.1.Name", "Home "}, "end with a space"},
		{"duplicate name", nil, []string{"SSID.1.Name", "Guest"}, "already uses that name"},
		{"short password", nil, []string{"SSID.1.Passphrase", "1234567"}, "8 to 63"},
		{"64 non-hex", nil, []string{"SSID.1.Passphrase", strings.Repeat("z", 64)}, "hexadecimal"},
		{"65 characters", nil, []string{"SSID.1.Passphrase", strings.Repeat("a", 65)}, "8 to 63"},
		{"comma on 2.4 GHz", nil, []string{"SSID.1.Passphrase", "abc,defgh"}, "comma"},
		{"WPA without a password", nil, []string{"SSID.2.AuthMode", "WPA2PSK"}, "set a password"},
		{"password on an open network", nil, []string{"SSID.2.Passphrase", testSecret}, "takes no password"},
		{"WEP", nil, []string{"SSID.1.AuthMode", "WEP-64Bits"}, "not offered"},
		{"WPA3 without firmware support", nil, []string{"SSID.1.AuthMode", "WPA3PSK"}, "not offered"},
		{"bad cipher", nil, []string{"SSID.1.Encryption", "GCMP256"}, "not offered"},
		{"client limit too high", nil, []string{"SSID.1.MaxStations", "41"}, "client limit"},
		{"client limit zero on 2.4 GHz", nil, []string{"SSID.1.MaxStations", "0"}, "client limit"},
		{"row moved", nil, []string{"SSID.2.Interface", "ra3", "SSID.2.Hidden", "true"}, "refresh"},
		{"unknown input", nil, []string{"DNS.Server.1.Address", "1.1.1.1"}, "does not accept"},
		{"nothing", nil, nil, "nothing to change"},
	}
	for _, c := range cases {
		opts, fake := wlanFixture(t)
		if c.prep != nil {
			c.prep(fake)
		}
		err := apply(opts, c.pairs...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
		if len(fake.writes) != 0 {
			t.Errorf("%s: a refused change wrote %q", c.name, fake.writes)
		}
		if err != nil && strings.Contains(err.Error(), testSecret) {
			t.Errorf("%s: the error carries the password", c.name)
		}
	}
}

func TestWLANValidChangeAfterInvalidLeafWritesNothing(t *testing.T) {
	opts, fake := wlanFixture(t)
	err := apply(opts, "SSID.1.Hidden", "true", "SSID.2.Name", "Home")
	if err == nil {
		t.Fatal("want a duplicate-name refusal")
	}
	wantWrites(t, fake)
}

func TestWLANFailureReportsTcapiOutputWithoutThePassword(t *testing.T) {
	opts, fake := wlanFixture(t)
	fake.fail = "set WLan_Entry0 WPAPSK"
	err := apply(opts, "SSID.1.Passphrase", testSecret)
	if err == nil {
		t.Fatal("want the tcapi failure")
	}
	if !strings.Contains(err.Error(), "verify setting fail while tcapi set") {
		t.Errorf("the error should carry tcapi's output: %v", err)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("the error carries the password: %v", err)
	}
	// It stops at the failed write: no commit, no save.
	wantWrites(t, fake, "set WebCurSet_Entry wlan_id 0", "set WLan_Entry0 AuthMode WPAPSKWPA2PSK", "set WLan_Entry0 WPAPSK "+testSecret)

	// A failed commit after the password was written is scrubbed too.
	opts, fake = wlanFixture(t)
	fake.fail = "commit WLan_Entry"
	err = apply(opts, "SSID.1.Passphrase", testSecret)
	if err == nil || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "commit WLan_Entry") {
		t.Errorf("want a scrubbed commit failure, got %v", err)
	}
}

func TestWLANCollectionNeverWritesNorReportsKeys(t *testing.T) {
	opts, fake := wlanFixture(t)
	fake.store["WLan_Entry0/WPAPSK"] = testSecret
	fake.store["WLan11ac_Entry1/WPAPSK"] = testSecret
	msg := &wusp.Message{}
	tc, cancel := newTcapi(context.Background(), opts)
	defer cancel()
	collectWLAN(context.Background(), opts, tc, msg)
	if len(fake.writes) != 0 {
		t.Fatalf("collection wrote to the device: %q", fake.writes)
	}
	if fake.gets == 0 {
		t.Fatal("the collection read nothing; the fixture is not wired")
	}
	for _, f := range msg.Fields {
		if strings.Contains(wusp.ValueToString(f.Val), testSecret) || strings.HasSuffix(f.Path, "Passphrase") {
			t.Fatalf("snapshot carries key material at %s", f.Path)
		}
	}
	want := map[string]string{
		"Radio.1.Writable":               "Enable,Channel,Mode,Bandwidth,TxPower",
		"Radio.1.TxPowersAvailable":      "100,80,60,40,20",
		"Radio.2.TxPowersAvailable":      "100,80,50,25,10",
		"Radio.2.BandwidthsAvailable":    "20 MHz,20/40 MHz,80 MHz",
		"Radio.1.ChannelsAvailable":      "1,2,3,4,5,6,7,8,9,10,11,12,13",
		"Radio.1.BandwidthsAvailable":    "20 MHz,20/40 MHz",
		"Radio.1.SecurityModesAvailable": "OPEN,WPAPSK,WPA2PSK,WPAPSKWPA2PSK",
		"Radio.1.SSIDWritable":           "Name,Hidden,AuthMode,Encryption,Passphrase,Enable,MaxStations",
		"Radio.2.Writable":               "Enable,Channel,Bandwidth,TxPower",
		"Radio.2.ChannelsAvailable":      "36,40,44,48,52,56,60,64,149,153,157,161,165",
	}
	got := map[string]string{}
	for _, f := range msg.Fields {
		got[strings.TrimPrefix(f.Path, netP)] = wusp.ValueToString(f.Val)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestWLANPassphraseIsWriteOnlyInTheModel(t *testing.T) {
	found := false
	for _, p := range wusp.AllWUSPONUParams {
		if p.Path == netP+"SSID.{i}.Passphrase" {
			found = true
			if p.Access != wusp.WriteOnly {
				t.Fatalf("Passphrase access = %s, want writeOnly", p.Access)
			}
		}
	}
	if !found {
		t.Fatal("SSID.{i}.Passphrase is not modelled")
	}
}
