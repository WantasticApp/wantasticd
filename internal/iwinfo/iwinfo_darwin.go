//go:build darwin && !iwinfo

// macOS fallback: uses system_profiler and airport CLI for WiFi data.

package iwinfo

import (
	"fmt"
	"os/exec"
	"strings"

	"wantastic-agent/internal/netctl"
)

var ctl = netctl.New()

func Available(ifname string) bool {
	// macOS WiFi interface is typically en0
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), ifname)
}

func GetInfo(ifname string) (*InterfaceInfo, error) {
	info := &InterfaceInfo{Name: ifname}

	// Use airport CLI (private framework but always available)
	airport := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	if out, err := exec.Command(airport, "-I").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if k, v, ok := strings.Cut(line, ": "); ok {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				switch k {
				case "SSID":
					info.SSID = v
				case "BSSID":
					info.BSSID = v
				case "agrCtlRSSI":
					fmt.Sscanf(v, "%d", &info.Signal)
				case "agrCtlNoise":
					fmt.Sscanf(v, "%d", &info.Noise)
				case "lastTxRate":
					fmt.Sscanf(v, "%d", &info.Bitrate)
					info.Bitrate *= 1000 // Mbps → kbps
				case "channel":
					// Format: "36,80" or "6"
					parts := strings.Split(v, ",")
					fmt.Sscanf(parts[0], "%d", &info.Channel)
				case "maxRate":
					fmt.Sscanf(v, "%d", &info.QualityMax)
				}
			}
		}
	}
	return info, nil
}

func GetHWModeList(ifname string) (*HWModes, error) {
	caps, err := ctl.WiFiGetCapabilities(ifname)
	if err != nil {
		return nil, err
	}
	return &HWModes{
		N: caps.HT, AC: caps.VHT, AX: caps.HE, BE: caps.EHT,
		A: hasBand(caps.Bands, "5GHz"),
		G: hasBand(caps.Bands, "2.4GHz"),
		B: hasBand(caps.Bands, "2.4GHz"),
	}, nil
}

func GetHTModeList(ifname string) ([]string, error) {
	caps, err := ctl.WiFiGetCapabilities(ifname)
	if err != nil {
		return nil, err
	}
	return caps.SupportedHTModes, nil
}

func hasBand(bands []string, target string) bool {
	for _, b := range bands {
		if b == target {
			return true
		}
	}
	return false
}

func GetHTMode(ifname string) (string, error) {
	airport := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	out, err := exec.Command(airport, "-I").CombinedOutput()
	if err != nil {
		return "NOHT", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ": "); ok {
			if strings.TrimSpace(k) == "channel" {
				v = strings.TrimSpace(v)
				// "36,80" → VHT80, "6" → HT20
				parts := strings.Split(v, ",")
				if len(parts) == 2 {
					return "VHT" + parts[1], nil
				}
				return "HT20", nil
			}
		}
	}
	return "NOHT", nil
}

func GetPHYName(ifname string) (string, error) {
	return ifname, nil // macOS uses the interface name directly
}

func GetAssocList(ifname string) ([]AssocEntry, error) {
	return nil, nil // macOS doesn't expose AP station list without private API
}

func GetSurvey(ifname string) ([]SurveyEntry, error) {
	return nil, nil
}

func Close() {}
