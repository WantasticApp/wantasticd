package platforms

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"wantastic-agent/internal/iwinfo"
)

// Vendor station sources shared by the OpenWrt and generic Linux WiFi
// collectors. QSDK (qca-wifi) and MadWifi VAPs answer nl80211 station dumps
// with an empty list, and qcacld SAP interfaces (SDX/QCMAP) only answer
// per-station queries, so a "successful" empty dump must never be the only
// source for those drivers.

var (
	vendorAssocList      = iwinfo.VendorAssocList
	nl80211StationLookup = iwinfo.NL80211Station
)

// maxPerStationLookups bounds per-MAC nl80211 queries per interface and
// collection cycle.
const maxPerStationLookups = 128

var errNotVendorVAP = errors.New("not a vendor (qca-wifi/madwifi) VAP")

// isVendorWiFiVAP reports whether ifName is a qca-wifi or MadWifi VAP. Those
// drivers expose the owning radio as /sys/class/net/<vap>/parent (wifiN);
// legacy builds without cfg80211 also lack the phy80211 link.
func isVendorWiFiVAP(netClassDir, ifName string) bool {
	if strings.TrimSpace(ifName) == "" {
		return false
	}
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	if iwinfo.VendorRadioParent(netClassDir, ifName) != "" {
		return true
	}
	if !strings.HasPrefix(ifName, "ath") {
		return false
	}
	if _, err := os.Stat(filepath.Join(netClassDir, ifName, "phy80211")); err != nil {
		return true
	}
	// QSDK in cfg80211 mode links athN to a phy but keeps the qca-wifi radio
	// netdevs (wifiN); its nl80211 station dump is still empty.
	radios, _ := filepath.Glob(filepath.Join(netClassDir, "wifi[0-9]*"))
	return len(radios) > 0
}

func readVendorAssociations(netClassDir string) func(string) ([]iwinfo.AssocEntry, error) {
	return func(ifName string) ([]iwinfo.AssocEntry, error) {
		if !isVendorWiFiVAP(netClassDir, ifName) {
			return nil, errNotVendorVAP
		}
		return vendorAssocList(ifName)
	}
}

// enrichStationsPerMAC fills stations known only by MAC (hostapd control
// socket, wlanconfig) with the per-station nl80211 view: signal, byte
// counters, bitrates and the expected throughput. Drivers which do not
// implement GET_STATION simply leave the rows unchanged.
func enrichStationsPerMAC(ifName string, stations []iwinfo.AssocEntry) []iwinfo.AssocEntry {
	if strings.TrimSpace(ifName) == "" || nl80211StationLookup == nil {
		return stations
	}
	lookups := 0
	for i := range stations {
		station := stations[i]
		if station.SignalKnown && station.RxBytesKnown && station.TxBytesKnown && station.ExpectedThroughputKnown {
			continue
		}
		if lookups >= maxPerStationLookups {
			break
		}
		lookups++
		detail, err := nl80211StationLookup(ifName, station.MAC)
		if err != nil {
			if errors.Is(err, iwinfo.ErrStationNotFound) {
				continue
			}
			// The interface or driver does not answer per-station queries.
			return stations
		}
		detail.MAC = station.MAC
		if detail.Source == "" {
			detail.Source = "nl80211-get"
		}
		merged := mergeWiFiAssociations([]iwinfo.AssocEntry{station}, []iwinfo.AssocEntry{detail})
		if len(merged) == 1 {
			stations[i] = merged[0]
		}
	}
	return stations
}
