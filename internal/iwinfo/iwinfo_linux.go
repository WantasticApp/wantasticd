//go:build linux && !iwinfo

// Linux fallback: reads real WiFi data from sysfs/procfs and netctl.
// No CGo required — pure Go.

package iwinfo

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	linuxwifi "github.com/mdlayher/wifi"
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
	nlEntries, err := assocListFromNL80211(ifname)
	if err == nil {
		return nlEntries, nil
	}

	// Some vendor drivers do not implement nl80211. Keep debugfs as a final
	// no-dependency fallback, although it is commonly unavailable on OpenWrt.
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
			SignalKnown: sta.Signal != 0, NoiseKnown: sta.Noise != 0,
			RxBytesKnown: true, TxBytesKnown: true,
			ConnectedTimeKnown: true, InactiveKnown: true,
			RxRateKnown: true, TxRateKnown: true,
		})
	}
	return entries, nil
}

func assocListFromNL80211(ifname string) ([]AssocEntry, error) {
	client, iface, err := nl80211Interface(ifname)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	stations, err := client.StationInfo(iface)
	if err != nil {
		return nil, fmt.Errorf("nl80211 station dump for %s: %w", ifname, err)
	}
	entries := make([]AssocEntry, 0, len(stations))
	for _, station := range stations {
		if station == nil {
			continue
		}
		entries = append(entries, AssocEntry{
			MAC:           append(net.HardwareAddr(nil), station.HardwareAddr...),
			Signal:        clampInt8(station.Signal),
			SignalAvg:     clampInt8(station.SignalAverage),
			Inactive:      durationUint32(station.Inactive, time.Millisecond),
			ConnectedTime: durationUint32(station.Connected, time.Second),
			RxPackets:     nonNegativeUint32(station.ReceivedPackets),
			TxPackets:     nonNegativeUint32(station.TransmittedPackets),
			RxBytes:       nonNegativeUint64(station.ReceivedBytes),
			TxBytes:       nonNegativeUint64(station.TransmittedBytes),
			TxRetries:     nonNegativeUint32(station.TransmitRetries),
			TxFailed:      nonNegativeUint32(station.TransmitFailed),
			// mdlayher/wifi reports bit/s; libiwinfo and AssocEntry use kbit/s.
			RxRate:             nonNegativeUint32(station.ReceiveBitrate / 1000),
			TxRate:             nonNegativeUint32(station.TransmitBitrate / 1000),
			SignalKnown:        true,
			SignalAvgKnown:     true,
			InactiveKnown:      true,
			ConnectedTimeKnown: true,
			RxPacketsKnown:     true,
			TxPacketsKnown:     true,
			RxBytesKnown:       true,
			TxBytesKnown:       true,
			TxRetriesKnown:     true,
			TxFailedKnown:      true,
			RxRateKnown:        true,
			TxRateKnown:        true,
		})
	}
	return entries, nil
}

func GetSurvey(ifname string) ([]SurveyEntry, error) {
	client, iface, err := nl80211Interface(ifname)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	survey, err := client.SurveyInfo(iface)
	if err != nil {
		return nil, fmt.Errorf("nl80211 survey dump for %s: %w", ifname, err)
	}
	entries := make([]SurveyEntry, 0, len(survey))
	for _, item := range survey {
		if item == nil {
			continue
		}
		entries = append(entries, SurveyEntry{
			InUse:      item.InUse,
			ActiveTime: durationUint64(item.ChannelTimeActive, time.Microsecond),
			BusyTime:   durationUint64(item.ChannelTimeBusy, time.Microsecond),
			RxTime:     durationUint64(item.ChannelTimeRx, time.Microsecond),
			TxTime:     durationUint64(item.ChannelTimeTx, time.Microsecond),
			Frequency:  nonNegativeUint32(item.Frequency),
			Noise:      clampInt8(item.Noise),
		})
	}
	return entries, nil
}

func nl80211Interface(ifname string) (*linuxwifi.Client, *linuxwifi.Interface, error) {
	client, err := linuxwifi.New()
	if err != nil {
		return nil, nil, fmt.Errorf("open nl80211: %w", err)
	}
	// Do not let a broken vendor driver stall a USP collection indefinitely.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	interfaces, err := client.Interfaces()
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("list nl80211 interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if iface != nil && iface.Name == ifname {
			// StationInfo and SurveyInfo are dump operations scoped by IFINDEX.
			// Supplying the AP's own MAC filters the dump to that address on
			// kernels which honor NL80211_ATTR_MAC, yielding no AP clients.
			copyIface := *iface
			copyIface.HardwareAddr = nil
			return client, &copyIface, nil
		}
	}
	client.Close()
	return nil, nil, fmt.Errorf("nl80211 interface %s not found", ifname)
}

func clampInt8(value int) int8 {
	if value < -128 {
		return -128
	}
	if value > 127 {
		return 127
	}
	return int8(value)
}

func nonNegativeUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if uint64(value) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func nonNegativeUint64(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func durationUint32(value time.Duration, unit time.Duration) uint32 {
	if value <= 0 || unit <= 0 {
		return 0
	}
	units := uint64(value / unit)
	if units > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(units)
}

func durationUint64(value time.Duration, unit time.Duration) uint64 {
	if value <= 0 || unit <= 0 {
		return 0
	}
	return uint64(value / unit)
}

func Close() {}

func hasBand(bands []string, t string) bool {
	for _, b := range bands {
		if b == t {
			return true
		}
	}
	return false
}
