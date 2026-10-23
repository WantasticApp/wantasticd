package platforms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

func sixGHzWiphy() *iwinfo.Wiphy {
	band := iwinfo.WiphyBand{Band: "6GHz", HE: true, EHT: true, Widths: []int{20, 40, 80, 160, 320}}
	for channel := 1; channel <= 233; channel += 4 {
		band.Channels = append(band.Channels, iwinfo.WiphyChannel{Channel: channel, Frequency: 5950 + channel*5, MaxPowerDBM: 24, Disabled: channel > 93})
	}
	return &iwinfo.Wiphy{Index: 2, Bands: []iwinfo.WiphyBand{band}}
}

// A QSDK 6 GHz radio keeps hwmode 11axa and lists no ifnames in its wireless
// status; the wiphy behind its VAP decides band, channels, widths and power.
func TestOpenWrtWiFiCapabilitiesFromWiphy(t *testing.T) {
	root := t.TempDir()
	netClassDir := filepath.Join(root, "net")
	if err := os.MkdirAll(filepath.Join(netClassDir, "ath2"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(netClassDir, "ath2", "parent"), "wifi2\n")
	var queried []string
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: filepath.Join(root, "config"),
		NetClassDir:  netClassDir,
		UbusCaller: func(object, method string, _ time.Duration) ([]byte, error) {
			if object == "network.wireless" && method == "status" {
				return []byte(`{"wifi2":{"up":true,"config":{"hwmode":"11axa","channel":"auto","htmode":"HE160"},"interfaces":[]}}`), nil
			}
			return nil, wusp.ErrUSPPathUnsupported
		},
		WiFiHWModeList: func(string) (*iwinfo.HWModes, error) { return nil, errors.New("no sysfs caps") },
		WiFiHTModeList: func(string) ([]string, error) { return nil, errors.New("no sysfs caps") },
		WiFiWiphy: func(name string) (*iwinfo.Wiphy, error) {
			queried = append(queried, name)
			return sixGHzWiphy(), nil
		},
	})

	msg := wusp.NewMessage()
	backend.appendWiFiFields(context.Background(), msg)

	if got := fieldString(t, msg, "Device.WiFi.Radio.1.OperatingFrequencyBand"); got != "6GHz" {
		t.Fatalf("band=%q want 6GHz", got)
	}
	if len(queried) == 0 || queried[0] != "ath2" {
		t.Fatalf("wiphy queried for %v, want the ath2 VAP", queried)
	}
	assertListContains(t, msg, "Device.WiFi.Radio.1.SupportedFrequencyBands", "6GHz")
	assertListContains(t, msg, "Device.WiFi.Radio.1.PossibleChannels", "37")
	if channels := fieldString(t, msg, "Device.WiFi.Radio.1.PossibleChannels"); strings.Contains(channels, "97") {
		t.Fatalf("PossibleChannels=%q includes a disabled channel", channels)
	}
	assertListContains(t, msg, "Device.WiFi.Radio.1.SupportedOperatingChannelBandwidths", "160MHz")
	assertListContains(t, msg, "Device.WiFi.Radio.1.SupportedOperatingChannelBandwidths", "320MHz-1")
	assertListContains(t, msg, "Device.WiFi.Radio.1.SupportedStandards", "be")
	if standards := fieldString(t, msg, "Device.WiFi.Radio.1.SupportedStandards"); strings.Contains(standards, "a,") || strings.Contains(standards, "ac") {
		t.Fatalf("6GHz SupportedStandards=%q must exclude a/ac", standards)
	}
	assertListContains(t, msg, "Device.WiFi.Radio.1.TransmitPowerSupported", "100")
	assertListContains(t, msg, "Device.WiFi.Radio.1.TransmitPowerSupported", "50")
	if len(queried) != 1 {
		t.Fatalf("wiphy read %d times in one collect, want 1 (cached)", len(queried))
	}
}

func TestWiphyTxPowerLevelsMapToPercentages(t *testing.T) {
	levels := wiphyTxPowerLevels(sixGHzWiphy(), 0)
	if want := []int{12, 15, 18, 21, 22, 23, 24}; fmt.Sprint(levels) != fmt.Sprint(want) {
		t.Fatalf("levels=%v want %v", levels, want)
	}
	if dbm, ok := txPowerLevelForPercent(levels, 50); !ok || dbm != 21 {
		t.Fatalf("50%% → %d dBm (%v), want 21", dbm, ok)
	}
}

func fieldString(t *testing.T, msg *wusp.Message, path string) string {
	t.Helper()
	value, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing", path)
	}
	return wusp.ValueToString(value)
}

func TestNTPClientStatusFollowsKernelClock(t *testing.T) {
	saved := kernelClockSync
	t.Cleanup(func() { kernelClockSync = saved })
	kernelClockSync = func() (bool, bool) { return true, true }
	if got := ntpClientStatus(true); got != "Synchronized" {
		t.Fatalf("synced status=%q", got)
	}
	kernelClockSync = func() (bool, bool) { return false, true }
	if got := ntpClientStatus(true); got != "Unsynchronized" {
		t.Fatalf("unsynced status=%q", got)
	}
	if got := ntpClientStatus(false); got != "Disabled" {
		t.Fatalf("disabled status=%q", got)
	}
}

func TestLLDPLinkMediumIgnoresBridgesAndSeesVendorVAPs(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"br-lan/bridge", "eth0", "ath1"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, filepath.Join(dir, "ath1", "parent"), "wifi1\n")
	cases := map[string]string{"br-lan": "", "eth0": "Ethernet", "ath1": "Wi-Fi", "ath0": "Wi-Fi", "missing0": ""}
	for ifName, want := range cases {
		if got := lldpLinkMedium(dir, ifName, map[string]bool{}); got != want {
			t.Errorf("%s: medium=%q want %q", ifName, got, want)
		}
	}
}
