//go:build windows

// Windows implementation using wlanapi.dll via syscall.
// No CGo needed — Windows native WiFi API is accessible via DLL calls.

package iwinfo

import (
	"fmt"
	"os/exec"
	"strings"
)

// TODO: Replace netsh parsing with direct wlanapi.dll syscalls for:
//   - WlanOpenHandle / WlanEnumInterfaces / WlanGetAvailableNetworkList
//   - WlanQueryInterface for RSSI, channel, PHY type
//   - WlanGetNetworkBssList for station data
// For now, uses netsh as a portable fallback.

func Available(ifname string) bool {
	out, _ := exec.Command("netsh", "wlan", "show", "interfaces").CombinedOutput()
	return strings.Contains(string(out), ifname) || strings.Contains(string(out), "Wi-Fi")
}

func GetInfo(ifname string) (*InterfaceInfo, error) {
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("netsh wlan: %w", err)
	}

	info := &InterfaceInfo{Name: ifname}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, " : "); ok {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch {
			case strings.Contains(k, "SSID") && !strings.Contains(k, "BSSID"):
				info.SSID = v
			case strings.Contains(k, "BSSID"):
				info.BSSID = v
			case strings.Contains(k, "Signal"):
				// "85%" → approximate to dBm
				var pct int
				fmt.Sscanf(v, "%d", &pct)
				info.Signal = pct/2 - 100
				info.Quality = pct
				info.QualityMax = 100
			case strings.Contains(k, "Channel"):
				fmt.Sscanf(v, "%d", &info.Channel)
			case strings.Contains(k, "Receive rate"):
				var rate float64
				fmt.Sscanf(v, "%f", &rate)
				info.Bitrate = int(rate * 1000)
			case strings.Contains(k, "Radio type"):
				info.HardwareName = v
			}
		}
	}
	return info, nil
}

func GetHWModeList(ifname string) (*HWModes, error) {
	out, err := exec.Command("netsh", "wlan", "show", "drivers").CombinedOutput()
	if err != nil {
		return nil, err
	}
	data := string(out)
	return &HWModes{
		B:  strings.Contains(data, "802.11b"),
		G:  strings.Contains(data, "802.11g"),
		N:  strings.Contains(data, "802.11n"),
		A:  strings.Contains(data, "802.11a"),
		AC: strings.Contains(data, "802.11ac"),
		AX: strings.Contains(data, "802.11ax"),
		BE: strings.Contains(data, "802.11be"),
	}, nil
}

func GetHTModeList(ifname string) ([]string, error) {
	hw, err := GetHWModeList(ifname)
	if err != nil {
		return nil, err
	}
	var modes []string
	if hw.N {
		modes = append(modes, "HT20", "HT40")
	}
	if hw.AC {
		modes = append(modes, "VHT20", "VHT40", "VHT80", "VHT160")
	}
	if hw.AX {
		modes = append(modes, "HE20", "HE40", "HE80", "HE160")
	}
	if hw.BE {
		modes = append(modes, "EHT20", "EHT40", "EHT80", "EHT160", "EHT320")
	}
	return modes, nil
}

func GetHTMode(ifname string) (string, error) {
	info, err := GetInfo(ifname)
	if err != nil {
		return "NOHT", nil
	}
	// Infer from radio type string
	ht := info.HardwareName
	switch {
	case strings.Contains(ht, "802.11ax"), strings.Contains(ht, "Wi-Fi 6"):
		return "HE80", nil
	case strings.Contains(ht, "802.11ac"):
		return "VHT80", nil
	case strings.Contains(ht, "802.11n"):
		return "HT40", nil
	default:
		return "NOHT", nil
	}
}

func GetPHYName(ifname string) (string, error) { return ifname, nil }
func GetAssocList(ifname string) ([]AssocEntry, error) { return nil, nil }
func GetSurvey(ifname string) ([]SurveyEntry, error) { return nil, nil }
func Close() {}
