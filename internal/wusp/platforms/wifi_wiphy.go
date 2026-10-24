package platforms

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/iwinfo"
)

// Radio capabilities change only with the regulatory domain, so one nl80211
// GET_WIPHY per radio every few minutes is enough.
const wiphyCacheTTL = 5 * time.Minute

type wiphyCache struct {
	read    func(string) (*iwinfo.Wiphy, error)
	mu      sync.Mutex
	entries map[string]wiphyCacheEntry
}

type wiphyCacheEntry struct {
	wiphy *iwinfo.Wiphy
	at    time.Time
}

func (c *wiphyCache) get(name string) *iwinfo.Wiphy {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[name]; ok && time.Since(entry.at) < wiphyCacheTTL {
		return entry.wiphy
	}
	read := c.read
	if read == nil {
		read = readWiphy
	}
	wiphy, err := read(name)
	if err != nil {
		wiphy = nil
	}
	if c.entries == nil {
		c.entries = map[string]wiphyCacheEntry{}
	}
	c.entries[name] = wiphyCacheEntry{wiphy: wiphy, at: time.Now()}
	return wiphy
}

// readWiphy asks nl80211 first and, for madwifi/qca-wifi VAPs without a
// cfg80211 wiphy, falls back to the driver's regulatory channel table
// (IEEE80211_IOCTL_GETCHANINFO, what wlanconfig "list chan" prints).
func readWiphy(name string) (*iwinfo.Wiphy, error) {
	wiphy, err := iwinfo.NL80211Wiphy(name)
	if err == nil {
		return wiphy, nil
	}
	if vendor, vendorErr := iwinfo.VendorWiphy(name); vendorErr == nil {
		return vendor, nil
	}
	return nil, err
}

func radioHasIfName(radio openWrtWirelessRadioStatus) bool {
	for _, iface := range radio.Interfaces {
		if strings.TrimSpace(iface.IfName) != "" {
			return true
		}
	}
	return false
}

// radioNetdev picks the netdev that represents a UCI radio for capability
// and runtime queries.
func (b *OpenWrtBackend) radioNetdev(section string, radio openWrtWirelessRadioStatus) string {
	for _, iface := range radio.Interfaces {
		if ifName := b.existingWiFiIfName(iface.IfName); ifName != "" {
			return ifName
		}
	}
	return b.vendorRadioNetdev(section)
}

// vendorRadioNetdev finds a qca-wifi/MadWifi VAP whose parent is the radio
// section (wifi2 → ath2), else the radio netdev itself when it exists.
func (b *OpenWrtBackend) vendorRadioNetdev(section string) string {
	section = strings.TrimSpace(section)
	if section == "" || strings.ContainsAny(section, "/ \t") {
		return ""
	}
	entries, _ := os.ReadDir(b.netClassDir)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, name, "parent"))) == section {
			return name
		}
	}
	if _, err := os.Stat(filepath.Join(b.netClassDir, section)); err == nil {
		return section
	}
	return ""
}

// currentFrequency is the operating frequency of ifName in MHz, 0 if unknown.
func (b *OpenWrtBackend) currentFrequency(ifName string) int {
	if ifName == "" {
		return 0
	}
	if link, err := iwinfo.NL80211RadioLink(ifName); err == nil && link.Frequency > 0 {
		return link.Frequency
	}
	if mhz, ok := iwinfo.WextFrequency(ifName); ok {
		return mhz
	}
	return 0
}

// wifiBandFromWiphy corrects a configured band the hardware cannot operate
// on: QSDK 6 GHz radios keep a 5 GHz-style hwmode, but their wiphy has only
// the 6 GHz band.
func wifiBandFromWiphy(configured string, wiphy *iwinfo.Wiphy) string {
	if wiphy == nil || len(wiphy.Bands) == 0 || wiphy.Band(configured) != nil {
		return configured
	}
	if len(wiphy.Bands) == 1 {
		return wiphy.Bands[0].Band
	}
	if configured == "5GHz" && wiphy.Band("6GHz") != nil {
		return "6GHz"
	}
	return configured
}

func wiphyHWModes(wiphy *iwinfo.Wiphy) *iwinfo.HWModes {
	modes := &iwinfo.HWModes{}
	for _, band := range wiphy.Bands {
		switch band.Band {
		case "2.4GHz":
			modes.B, modes.G = true, true
		case "5GHz":
			modes.A = true
			modes.AC = modes.AC || band.VHT
		}
		modes.N = modes.N || (band.HT && band.Band != "6GHz")
		modes.AX = modes.AX || band.HE
		modes.BE = modes.BE || band.EHT
	}
	return modes
}

func wiphyHTModes(wiphy *iwinfo.Wiphy) []string {
	var out []string
	for i := range wiphy.Bands {
		out = append(out, bandHTModes(&wiphy.Bands[i])...)
	}
	return out
}

func wiphyBandHTModes(wiphy *iwinfo.Wiphy, band string) []string {
	if b := wiphy.Band(band); b != nil {
		return bandHTModes(b)
	}
	return nil
}

func bandHTModes(band *iwinfo.WiphyBand) []string {
	var out []string
	for _, width := range band.Widths {
		w := strconv.Itoa(width)
		if band.HT && width <= 40 && band.Band != "6GHz" {
			out = append(out, "HT"+w)
		}
		if band.VHT && width <= 160 && band.Band == "5GHz" {
			out = append(out, "VHT"+w)
		}
		if band.HE && width <= 160 {
			out = append(out, "HE"+w)
		}
		if band.EHT {
			out = append(out, "EHT"+w)
		}
	}
	return out
}

// wiphyChannelList is the configurable channels of band, as strings.
func wiphyChannelList(wiphy *iwinfo.Wiphy, band string) []string {
	var out []string
	for _, channel := range wiphy.Band(band).UsableChannels() {
		out = append(out, strconv.Itoa(channel.Channel))
	}
	return out
}

// wiphyTxPowerLevels offers the regulatory maximum and useful steps below it
// (−1, −2, −3, −6, −9, −12 dB ≈ 79/63/50/25/13/6 % of full power).
func wiphyTxPowerLevels(wiphy *iwinfo.Wiphy, frequency int) []int {
	if wiphy == nil {
		return nil
	}
	maxDBM := 0
	if frequency > 0 {
		for i := range wiphy.Bands {
			for _, channel := range wiphy.Bands[i].UsableChannels() {
				if channel.Frequency == frequency {
					maxDBM = channel.MaxPowerDBM
				}
			}
		}
	}
	if maxDBM <= 0 {
		for i := range wiphy.Bands {
			maxDBM = max(maxDBM, wiphy.Bands[i].MaxPowerDBM())
		}
	}
	if maxDBM <= 0 {
		return nil
	}
	var levels []int
	for _, step := range []int{12, 9, 6, 3, 2, 1, 0} {
		if level := maxDBM - step; level > 0 {
			levels = append(levels, level)
		}
	}
	return levels
}
