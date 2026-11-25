package fiberonu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Fixtures for the lab ONU (HWTC93BB0308): mt7603eap on ra0..ra3, mt7663 on
// rai0..rai3, the config tree read through `tcapi get`.

// getMacTable24 is `iwpriv ra0 get_mac_table` laid out with the driver's
// RTMPIoctlGetMacTable format strings (mt7603eap.ko).
var getMacTable24 = "ra0       get_mac_table:\n" +
	fmt.Sprintf("%-19s%-4s%-4s%-4s%-4s%-8s%-7s%-7s%-7s%-10s%-6s%-6s%-6s%-6s%-7s%-7s\n",
		"MAC", "AID", "BSS", "PSM", "WMM", "MIMOPS", "RSSI0", "RSSI1", "RSSI2", "PhMd", "BW", "MCS", "SGI", "STBC", "Idle", "Rate") +
	fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X  %-4d%-4d%-4d%-4d%-8d%-7d%-7d%-7d%-10s%-6s%-6d%-6d%-6d%-7d%-7d%-10d, %d, %d%%\n",
		0x3C, 0x28, 0x6D, 0x11, 0x22, 0x33, 1, 0, 0, 1, 3, -52, -49, 0, "HTMIX", "40M", 7, 1, 0, 2, 150, 0, 1204, 0)

// table11ac lays a table out in the driver's 11ac layout (MODE column,
// folded RSSI0/1/2 printed "%-3d/%-3d/%-3d"), the header of the
// Show_MacTable_Proc dumps seen in the device log.
func table11ac(rows ...[3]int) string {
	text := fmt.Sprintf("%-19s%-5s%-5s%-4s%-4s%-4s%-7s%-10s%-6s%-4s%-6s%-6s%-6s%-7s%-7s%-7s\n",
		"MAC", "MODE", "AID", "BSS", "PSM", "WMM", "MIMOPS", "RSSI0/1/2", "PhMd", "BW", "MCS", "SGI", "STBC", "Idle", "Rate", "QosMap")
	for i, r := range rows { // r = BSS, RSSI0, RSSI1
		text += fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X  %-5x%-5d%-4d%-4d%-4d%-7d%-3d/%-3d/%-3d%-6s%-4s%-6d%-6d%-6d%-7d%-7d%-7d\n",
			0xA0, 0x88, 0xB4, 0x00, 0x00, i+1, 4, i+1, r[0], 0, 1, 3, r[1], r[2], 0, "VHT", "80M", 9, 1, 0, 5, 433, 0)
	}
	return text + fmt.Sprintf("sta_cnt=%d\n", len(rows))
}

// baseWiFiTcapi is the lab ONU's Wi-Fi config: both radios on, one SSID
// each, 2.4 GHz on channel 6 at 40 MHz, 5 GHz on channel 149.
func baseWiFiTcapi() map[string]string {
	return map[string]string{
		"WLan_Common/APOn":         "1",
		"WLan_Common/Channel":      "6",
		"WLan_Common/HT_BW":        "1",
		"WLan_Common/WirelessMode": "9",
		"WLan_Common/Country":      "MA",
		"WLan_Common/BssidNum":     "4",
		"WLan_Common/TxPowerLevel": "1",
		"WLan_Entry0/SSID":         "FTTH-BB0308",
		"WLan_Entry0/EnableSSID":   "1",
		"WLan_Entry0/HideSSID":     "0",
		"WLan_Entry0/AuthMode":     "WPA2PSK",
		"WLan_Entry0/EncrypType":   "AES",
		"WLan_Entry0/MaxStaNum":    "32",
		"WLan_Entry0/WPAPSK":       "do-not-read-me",
		"Info_WLan/CurrentChannel": "6",

		"WLan11ac_Common/APOn":         "1",
		"WLan11ac_Common/Channel":      "149",
		"WLan11ac_Common/HT_BW":        "1",
		"WLan11ac_Common/VHT_BW":       "1",
		"WLan11ac_Common/WirelessMode": "14",
		"WLan11ac_Common/BssidNum":     "4",
		"WLan11ac_Common/TxPower":      "100",
		"WLan11ac_Entry0/SSID":         "FTTH-BB0308-5G",
		"WLan11ac_Entry0/EnableSSID":   "1",
		"WLan11ac_Entry0/HideSSID":     "0",
		"WLan11ac_Entry0/AuthMode":     "WPA2PSK",
		"WLan11ac_Entry0/EncrypType":   "AES",
		"WLan11ac_Entry0/WPAPSK":       "do-not-read-me",
		"Info_WLan11ac/CurrentChannel": "N/A",
	}
}

type wifiONU struct {
	tcapi  map[string]string
	iwpriv map[string]string // interface -> get_mac_table output; absent fails
	calls  []string
}

func (f *wifiONU) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch {
	case strings.HasSuffix(name, "tcapi") && len(args) == 3 && args[0] == "get":
		if v, ok := f.tcapi[args[1]+"/"+args[2]]; ok {
			return []byte(v + "\n"), nil
		}
		return []byte("N/A\n"), nil
	case name == "iwpriv" && len(args) == 2 && args[1] == "get_mac_table":
		if out, ok := f.iwpriv[args[0]]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("iwpriv: interface not found")
	}
	return nil, errors.New("not found")
}

// wifiSysNet creates ra0..ra3 (and rai0..rai3 with fiveG), all up.
func wifiSysNet(t *testing.T, fiveG bool) string {
	t.Helper()
	dir := t.TempDir()
	prefixes := []string{"ra"}
	if fiveG {
		prefixes = append(prefixes, "rai")
	}
	for p, prefix := range prefixes {
		for n := 0; n < 4; n++ {
			d := filepath.Join(dir, fmt.Sprintf("%s%d", prefix, n))
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(d, "flags"), []byte("0x1003\n"), 0o644)
			os.WriteFile(filepath.Join(d, "address"), []byte(fmt.Sprintf("e0:5d:54:0%d:00:0%d\n", p, n)), 0o644)
		}
	}
	return dir
}

func collectWiFiFixture(t *testing.T, f *wifiONU, fiveG bool) *wusp.Message {
	t.Helper()
	opts := Options{SysClassNetDir: wifiSysNet(t, fiveG), TcapiPath: "/userfs/bin/tcapi", Exec: f.exec}
	msg := wusp.NewMessage()
	tc, done := newTcapi(context.Background(), opts)
	wlan := collectWLAN(context.Background(), opts, tc, msg)
	done()
	collectWiFiTR181(context.Background(), opts, wlan, msg)
	return msg
}

func wifiValue(msg *wusp.Message, path string) (string, bool) {
	v, ok := msg.Get("Device.WiFi." + path)
	if !ok {
		return "", false
	}
	return wusp.ValueToString(v), true
}

func TestCollectWiFiTR181(t *testing.T) {
	both := map[string]string{"ra0": getMacTable24, "rai0": "rai0      get_mac_table:\n" + table11ac()}
	radioOff := baseWiFiTcapi()
	for _, k := range []string{"WLan_Common/Channel", "WLan_Common/HT_BW", "WLan_Common/WirelessMode", "WLan_Common/TxPowerLevel", "Info_WLan/CurrentChannel"} {
		delete(radioOff, k) // read back as N/A
	}
	radioOff["WLan_Common/APOn"] = "0"
	radioOff["WLan_Entry0/EnableSSID"] = "0"
	radioOff["WLan_Entry0/HideSSID"] = "1"

	auto := baseWiFiTcapi()
	auto["WLan_Common/Channel"] = "0"
	auto["WLan_Common/HT_BSSCoexistence"] = "1"
	auto["Info_WLan/CurrentChannel"] = "11"
	auto["WLan11ac_Common/VHT_BW"] = "N/A"

	tests := []struct {
		name   string
		tcapi  map[string]string
		iwpriv map[string]string
		fiveG  bool
		want   map[string]string // "" = must be absent
	}{
		{
			name: "lab ONU, both radios, one 2.4 GHz client", tcapi: baseWiFiTcapi(), iwpriv: both, fiveG: true,
			want: map[string]string{
				"RadioNumberOfEntries":       "2",
				"SSIDNumberOfEntries":        "2",
				"AccessPointNumberOfEntries": "2",

				"Radio.1.Name":                      "ra0",
				"Radio.1.OperatingFrequencyBand":    "2.4GHz",
				"Radio.1.Enable":                    "true",
				"Radio.1.Status":                    "Up",
				"Radio.1.Channel":                   "6",
				"Radio.1.AutoChannelEnable":         "false",
				"Radio.1.OperatingChannelBandwidth": "40MHz",
				"Radio.1.OperatingStandards":        "b,g,n",
				"Radio.1.TransmitPower":             "100",
				"Radio.2.Name":                      "rai0",
				"Radio.2.OperatingFrequencyBand":    "5GHz",
				"Radio.2.Channel":                   "149", // CurrentChannel N/A: configured
				"Radio.2.OperatingChannelBandwidth": "80MHz",
				"Radio.2.OperatingStandards":        "a,n,ac",
				"Radio.2.TransmitPower":             "100",

				"SSID.1.SSID":        "FTTH-BB0308",
				"SSID.1.Name":        "ra0",
				"SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
				"SSID.1.Enable":      "true",
				"SSID.1.Status":      "Up",
				"SSID.1.BSSID":       "e0:5d:54:00:00:00",
				"SSID.2.SSID":        "FTTH-BB0308-5G",
				"SSID.2.Name":        "rai0",
				"SSID.2.LowerLayers": "Device.WiFi.Radio.2.",
				"SSID.2.BSSID":       "e0:5d:54:01:00:00",

				"AccessPoint.1.SSIDReference":                           "Device.WiFi.SSID.1.",
				"AccessPoint.1.Enable":                                  "true",
				"AccessPoint.1.Status":                                  "Enabled",
				"AccessPoint.1.SSIDAdvertisementEnabled":                "true",
				"AccessPoint.1.MaxAllowedAssociations":                  "32",
				"AccessPoint.1.AssociatedDeviceNumberOfEntries":         "1",
				"AccessPoint.1.AssociatedDevice.1.MACAddress":           "3c:28:6d:11:22:33",
				"AccessPoint.1.AssociatedDevice.1.Active":               "true",
				"AccessPoint.1.AssociatedDevice.1.SignalStrength":       "-49",
				"AccessPoint.1.AssociatedDevice.1.LastDataDownlinkRate": "150000",
				"AccessPoint.1.AssociatedDevice.1.OperatingStandard":    "n",
				"AccessPoint.2.SSIDReference":                           "Device.WiFi.SSID.2.",
				"AccessPoint.2.AssociatedDeviceNumberOfEntries":         "0",
				"AccessPoint.2.MaxAllowedAssociations":                  "",
			},
		},
		{
			name: "2.4 GHz only: no 5 GHz radio from the config tree alone", tcapi: baseWiFiTcapi(), iwpriv: both, fiveG: false,
			want: map[string]string{
				"RadioNumberOfEntries": "1",
				"SSIDNumberOfEntries":  "1",
				"Radio.2.Name":         "",
				"SSID.2.SSID":          "",
			},
		},
		{
			name: "auto channel, coexistence, VHT_BW unset", tcapi: auto, iwpriv: both, fiveG: true,
			want: map[string]string{
				"Radio.1.Channel":                   "11", // live channel wins
				"Radio.1.AutoChannelEnable":         "true",
				"Radio.1.OperatingChannelBandwidth": "Auto",
				"Radio.2.OperatingChannelBandwidth": "",
			},
		},
		{
			name: "2.4 GHz radio off, attributes N/A, station tables unreadable", tcapi: radioOff, iwpriv: nil, fiveG: true,
			want: map[string]string{
				"RadioNumberOfEntries":                          "2",
				"Radio.1.Enable":                                "false",
				"Radio.1.Status":                                "Down",
				"Radio.1.Channel":                               "",
				"Radio.1.AutoChannelEnable":                     "",
				"Radio.1.OperatingChannelBandwidth":             "",
				"Radio.1.OperatingStandards":                    "",
				"Radio.1.TransmitPower":                         "",
				"SSID.1.SSID":                                   "FTTH-BB0308",
				"SSID.1.Enable":                                 "false",
				"SSID.1.Status":                                 "Down",
				"AccessPoint.1.Status":                          "Disabled",
				"AccessPoint.1.SSIDAdvertisementEnabled":        "false",
				"AccessPoint.1.AssociatedDeviceNumberOfEntries": "", // no reading is not zero clients
				"AccessPoint.2.AssociatedDeviceNumberOfEntries": "",
			},
		},
		{
			name: "table without a recognisable header is no reading", tcapi: baseWiFiTcapi(), fiveG: true,
			iwpriv: map[string]string{"ra0": "ra0       get_mac_table:\n\x01\x00\x3c(m\x11\"3\n", "rai0": "rai0      get_mac_table:\n" + table11ac([3]int{0, -61, -64})},
			want: map[string]string{
				"AccessPoint.1.AssociatedDeviceNumberOfEntries":         "",
				"AccessPoint.2.AssociatedDeviceNumberOfEntries":         "1",
				"AccessPoint.2.AssociatedDevice.1.MACAddress":           "a0:88:b4:00:00:01",
				"AccessPoint.2.AssociatedDevice.1.SignalStrength":       "-61",
				"AccessPoint.2.AssociatedDevice.1.OperatingStandard":    "ac",
				"AccessPoint.2.AssociatedDevice.1.LastDataDownlinkRate": "433000",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &wifiONU{tcapi: tt.tcapi, iwpriv: tt.iwpriv}
			msg := collectWiFiFixture(t, f, tt.fiveG)
			for path, want := range tt.want {
				got, ok := wifiValue(msg, path)
				switch {
				case want == "" && ok:
					t.Errorf("%s = %q, want unset", path, got)
				case want != "" && !ok:
					t.Errorf("%s missing, want %q", path, want)
				case want != "" && got != want:
					t.Errorf("%s = %q, want %q", path, got, want)
				}
			}
			for _, call := range f.calls {
				for _, secret := range []string{"WPAPSK", "KeyPassphrase", "Key1Str", "RADIUS_Key", "WdsKey"} {
					if strings.Contains(call, secret) {
						t.Errorf("read a secret: %s", call)
					}
				}
				if strings.Contains(call, " set ") || strings.Contains(call, "show ") {
					t.Errorf("ran a non-passive command: %s", call)
				}
			}
		})
	}
}

// Every Device.WiFi path written must exist in the TR-181 model the hub
// serves, or it is dropped.
func TestWiFiTR181PathsAreModelled(t *testing.T) {
	f := &wifiONU{tcapi: baseWiFiTcapi(), iwpriv: map[string]string{"ra0": getMacTable24, "rai0": table11ac([3]int{0, -61, -64})}}
	msg := collectWiFiFixture(t, f, true)
	model := map[string]bool{}
	for _, p := range wusp.DeviceWiFiParams {
		model[p.Path] = true
	}
	n := 0
	for _, field := range msg.Fields {
		if !strings.HasPrefix(field.Path, "Device.WiFi.") {
			continue
		}
		n++
		parts := strings.Split(field.Path, ".")
		for i, part := range parts {
			if part != "" && strings.Trim(part, "0123456789") == "" {
				parts[i] = "{i}"
			}
		}
		if template := strings.Join(parts, "."); !model[template] {
			t.Errorf("%s is not in the TR-181 model (%s)", field.Path, template)
		}
	}
	if n == 0 {
		t.Fatal("no Device.WiFi paths collected")
	}
}

// A mac80211 build (no ra0/rai0) leaves Device.WiFi to linux.wifi.
func TestWiFiTR181NotOnMac80211(t *testing.T) {
	msg := wusp.NewMessage()
	opts := Options{SysClassNetDir: t.TempDir(), Exec: (&wifiONU{}).exec}
	collectWiFiTR181(context.Background(), opts, nil, msg)
	for _, field := range msg.Fields {
		t.Errorf("wrote %s", field.Path)
	}
}

// CollectONU wires the publisher: the console's Device.WiFi counts appear.
func TestCollectONUPublishesWiFi(t *testing.T) {
	f := &wifiONU{tcapi: baseWiFiTcapi(), iwpriv: map[string]string{"ra0": getMacTable24, "rai0": table11ac()}}
	root := t.TempDir()
	opts := Options{
		ProcPonPhyDir:  filepath.Join(root, "pon_phy"),
		ProcXponDir:    filepath.Join(root, "xpon"),
		ProcNetDir:     filepath.Join(root, "net"),
		TmpDir:         root,
		CGIBaseURL:     "http://127.0.0.1:1",
		SysClassNetDir: wifiSysNet(t, true),
		TcapiPath:      "/userfs/bin/tcapi",
		Exec:           f.exec,
		IfaceAddrs:     func() (map[string][]string, error) { return nil, nil },
	}
	msg := wusp.NewMessage()
	CollectONU(context.Background(), opts, true, msg)
	for path, want := range map[string]string{
		"RadioNumberOfEntries": "2",
		"SSID.1.SSID":          "FTTH-BB0308",
		"SSID.2.SSID":          "FTTH-BB0308-5G",
		"AccessPoint.1.AssociatedDeviceNumberOfEntries": "1",
	} {
		if got, ok := wifiValue(msg, path); got != want {
			t.Errorf("%s = %q (set %v), want %q", path, got, ok, want)
		}
	}
}

func TestParseMacTableLayouts(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		header bool
		want   []ralinkStation
	}{
		{
			name: "get_mac_table", text: getMacTable24, header: true,
			want: []ralinkStation{{mac: "3c:28:6d:11:22:33", bss: 0, hasBSS: true, rssi: []int{-52, -49, 0}, phyMode: "HTMIX", bandwidth: "40M", mcs: "7", rate: "150", powerSave: "0"}},
		},
		{
			name: "11ac layout, padded RSSI cell", text: table11ac([3]int{1, -5, -47}), header: true,
			want: []ralinkStation{{mac: "a0:88:b4:00:00:01", bss: 1, hasBSS: true, rssi: []int{-5, -47, 0}, phyMode: "VHT", bandwidth: "80M", mcs: "9", rate: "433", powerSave: "0"}},
		},
		{name: "header only", text: table11ac(), header: true},
		{name: "no header", text: "ra0       get_mac_table:\n", header: false},
		{name: "WDS table", text: "MAC                IDX AID PSM RSSI0  RSSI1  RSSI2\n00:11:22:33:44:55  0   1   0   -50    -50    0\n", header: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, header := parseMacTableHeader(tt.text)
			if header != tt.header {
				t.Errorf("header = %v, want %v", header, tt.header)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// iwpriv is not always on the agent's PATH; the firmware runs it from
// /userfs/bin.
func TestRunIwprivFallsBackToFirmwarePath(t *testing.T) {
	var names []string
	opts := Options{Exec: func(_ context.Context, name string, _ ...string) ([]byte, error) {
		names = append(names, name)
		if name == "iwpriv" {
			return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return []byte(getMacTable24), nil
	}}
	out, err := runIwpriv(context.Background(), opts, "ra0", "get_mac_table")
	if err != nil || string(out) != getMacTable24 {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if strings.Join(names, " ") != "iwpriv /userfs/bin/iwpriv" {
		t.Errorf("ran %v", names)
	}
}
