//go:build linux && !iwinfo

// Linux fallback: reads real WiFi data from sysfs/procfs and netctl.
// No CGo required — pure Go.

package iwinfo

import (
	"fmt"
	"net"
	"os"
	"strings"

	"wantastic-agent/internal/netctl"
)

var ctl = netctl.New()

func Available(ifname string) bool {
	_, err := os.Stat("/sys/class/net/" + ifname + "/phy80211")
	return err == nil
}

func GetInfo(ifname string) (*InterfaceInfo, error) {
	base := "/sys/class/net/" + ifname
	if _, err := os.Stat(base + "/phy80211"); err != nil {
		return nil, fmt.Errorf("not a WiFi interface: %s", ifname)
	}

	info := &InterfaceInfo{Name: ifname}

	if data, err := os.ReadFile(base + "/phy80211/name"); err == nil {
		info.PHYName = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(base + "/address"); err == nil {
		info.BSSID = strings.TrimSpace(string(data))
	}

	// /proc/net/wireless: signal, noise, quality
	if data, err := os.ReadFile("/proc/net/wireless"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, ifname+":") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					fmt.Sscanf(strings.TrimSuffix(fields[2], "."), "%d", &info.Quality)
					fmt.Sscanf(strings.TrimSuffix(fields[3], "."), "%d", &info.Signal)
				}
				if len(fields) >= 5 {
					fmt.Sscanf(strings.TrimSuffix(fields[4], "."), "%d", &info.Noise)
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

func GetHTMode(ifname string) (string, error) {
	if data, err := os.ReadFile("/sys/class/net/" + ifname + "/wireless/htmode"); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	return "NOHT", nil
}

func GetPHYName(ifname string) (string, error) {
	data, err := os.ReadFile("/sys/class/net/" + ifname + "/phy80211/name")
	if err != nil {
		return "", fmt.Errorf("not a WiFi interface: %s", ifname)
	}
	return strings.TrimSpace(string(data)), nil
}

func GetAssocList(ifname string) ([]AssocEntry, error) {
	stations, err := ctl.WiFiGetStations(ifname)
	if err != nil {
		return nil, err
	}
	var entries []AssocEntry
	for _, sta := range stations {
		mac, _ := net.ParseMAC(sta.MAC)
		entries = append(entries, AssocEntry{
			MAC: mac, Signal: int8(sta.Signal), Noise: int8(sta.Noise),
			RxBytes: sta.RxBytes, TxBytes: sta.TxBytes,
			ConnectedTime: sta.ConnectedSecs, Inactive: sta.Inactive,
			RxRate: sta.RxRate, TxRate: sta.TxRate,
		})
	}
	return entries, nil
}

func GetSurvey(ifname string) ([]SurveyEntry, error) { return nil, nil }

func Close() {}

func hasBand(bands []string, t string) bool {
	for _, b := range bands {
		if b == t {
			return true
		}
	}
	return false
}
