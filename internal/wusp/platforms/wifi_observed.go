package platforms

import (
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/iwinfo"
)

// The Device.WiFi collectors use every station source the platform offers
// (OpenWrt ubus hostapd/iwinfo, vendor getStaList, hostapd sockets, nl80211,
// QCA ioctls). The telemetry sampler runs on its own schedule with a smaller
// set, so the collectors publish what they observed and the sampler merges
// it; both views then agree on stations, noise and TX power.

const observedWiFiMaxAge = 10 * time.Minute

type observedRadioInfo struct {
	Noise     int
	TxPower   int
	Frequency int
	At        time.Time
}

type observedStationSet struct {
	Stations []iwinfo.AssocEntry
	At       time.Time
}

var observedWiFi = struct {
	mu       sync.Mutex
	stations map[string]observedStationSet
	radios   map[string]observedRadioInfo
}{stations: map[string]observedStationSet{}, radios: map[string]observedRadioInfo{}}

func recordObservedStations(ifName string, stations []iwinfo.AssocEntry) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return
	}
	observedWiFi.mu.Lock()
	defer observedWiFi.mu.Unlock()
	observedWiFi.stations[ifName] = observedStationSet{Stations: append([]iwinfo.AssocEntry(nil), stations...), At: time.Now()}
}

func observedStations(ifName string) []iwinfo.AssocEntry {
	observedWiFi.mu.Lock()
	defer observedWiFi.mu.Unlock()
	set, ok := observedWiFi.stations[ifName]
	if !ok || time.Since(set.At) > observedWiFiMaxAge {
		return nil
	}
	return append([]iwinfo.AssocEntry(nil), set.Stations...)
}

func recordObservedRadio(ifName string, info *iwinfo.InterfaceInfo) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" || info == nil {
		return
	}
	observedWiFi.mu.Lock()
	defer observedWiFi.mu.Unlock()
	observedWiFi.radios[ifName] = observedRadioInfo{Noise: info.Noise, TxPower: info.TxPower, Frequency: info.Frequency, At: time.Now()}
}

func observedRadio(ifName string) (observedRadioInfo, bool) {
	observedWiFi.mu.Lock()
	defer observedWiFi.mu.Unlock()
	info, ok := observedWiFi.radios[ifName]
	if !ok || time.Since(info.At) > observedWiFiMaxAge {
		return observedRadioInfo{}, false
	}
	return info, true
}
