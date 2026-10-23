//go:build linux

package iwinfo

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Capability bits used to derive channel widths (IEEE 802.11 HT/VHT/HE/EHT
// capability elements, as cfg80211 exposes them per band).
const (
	htCapSupWidth2040   = 0x0002
	vhtCapWidthMask     = 0x0000000c
	vhtCapWidth160      = 0x00000004
	vhtCapWidth160And80 = 0x00000008
	vhtCapExtNSSBWMask  = 0xc0000000
	hePhyCap040In24     = 0x02
	hePhyCap04080In5    = 0x04
	hePhyCap0160In5     = 0x08
	ehtPhyCap0320In6    = 0x02
)

// NL80211Wiphy reads the capabilities of the radio behind name, which may be
// a netdev (wlan0, ath2, wifi2) or a phy (phy1). It speaks nl80211 directly,
// so it needs no iw/iwinfo binary and works for any cfg80211 driver,
// including qca-wifi in cfg80211 mode.
func NL80211Wiphy(name string) (*Wiphy, error) {
	index, ifindex, err := wiphyTarget(name)
	if err != nil {
		return nil, err
	}
	c, err := dialNL80211()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// Split dumps carry every band attribute on modern kernels; the wiphy or
	// ifindex filter keeps the dump to this one radio.
	msgs, err := c.execute(unix.NL80211_CMD_GET_WIPHY, netlink.Dump, func(ae *netlink.AttributeEncoder) {
		if index >= 0 {
			ae.Uint32(unix.NL80211_ATTR_WIPHY, uint32(index))
		} else {
			ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifindex))
		}
		ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
	})
	if err != nil {
		return nil, fmt.Errorf("nl80211 get wiphy %s: %w", name, err)
	}
	wiphy := decodeWiphy(msgs, index)
	if wiphy == nil || len(wiphy.Bands) == 0 {
		return nil, fmt.Errorf("nl80211 reported no bands for %s", name)
	}
	return wiphy, nil
}

// wiphyTarget resolves name to a wiphy index (preferred) or an ifindex.
func wiphyTarget(name string) (int, int, error) {
	name = strings.TrimSpace(name)
	if !validIfName(name) {
		return -1, 0, fmt.Errorf("invalid radio name %q", name)
	}
	for _, path := range []string{
		filepath.Join("/sys/class/net", name, "phy80211", "index"),
		filepath.Join("/sys/class/ieee80211", name, "index"),
	} {
		if data, err := os.ReadFile(path); err == nil {
			if index, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && index >= 0 {
				return index, 0, nil
			}
		}
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return -1, 0, err
	}
	return -1, iface.Index, nil
}

type wiphyBandBuild struct {
	band     WiphyBand
	htCapa   uint16
	vhtCapa  uint32
	heCap0   byte
	ehtCap0  byte
	channels map[int]WiphyChannel
}

func decodeWiphy(msgs []genetlink.Message, want int) *Wiphy {
	builds := map[uint16]*wiphyBandBuild{}
	out := &Wiphy{Index: want}
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			continue
		}
		index := -1
		var bands []byte
		for ad.Next() {
			switch ad.Type() {
			case unix.NL80211_ATTR_WIPHY:
				index = int(ad.Uint32())
			case unix.NL80211_ATTR_WIPHY_BANDS:
				bands = ad.Bytes()
			}
		}
		if want >= 0 && index >= 0 && index != want {
			continue
		}
		if index >= 0 {
			out.Index = index
		}
		if len(bands) > 0 {
			decodeWiphyBands(bands, builds)
		}
	}
	ids := make([]int, 0, len(builds))
	for id := range builds {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		build := builds[uint16(id)]
		if build.band.Band == "" || len(build.channels) == 0 {
			continue
		}
		for _, channel := range build.channels {
			build.band.Channels = append(build.band.Channels, channel)
		}
		sort.Slice(build.band.Channels, func(i, j int) bool { return build.band.Channels[i].Frequency < build.band.Channels[j].Frequency })
		build.band.Widths = bandWidths(build)
		out.Bands = append(out.Bands, build.band)
	}
	sort.SliceStable(out.Bands, func(i, j int) bool { return bandOrder(out.Bands[i].Band) < bandOrder(out.Bands[j].Band) })
	return out
}

func decodeWiphyBands(data []byte, builds map[uint16]*wiphyBandBuild) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return
	}
	for ad.Next() {
		id := ad.Type()
		build := builds[id]
		if build == nil {
			build = &wiphyBandBuild{band: WiphyBand{Band: nl80211BandName(id)}, channels: map[int]WiphyChannel{}}
			builds[id] = build
		}
		bad, err := netlink.NewAttributeDecoder(ad.Bytes())
		if err != nil {
			continue
		}
		for bad.Next() {
			switch bad.Type() {
			case unix.NL80211_BAND_ATTR_FREQS:
				decodeWiphyFreqs(bad.Bytes(), build)
			case unix.NL80211_BAND_ATTR_HT_CAPA:
				build.band.HT = true
				build.htCapa = bad.Uint16()
			case unix.NL80211_BAND_ATTR_VHT_CAPA:
				build.band.VHT = true
				build.vhtCapa = bad.Uint32()
			case unix.NL80211_BAND_ATTR_IFTYPE_DATA:
				decodeWiphyIftypes(bad.Bytes(), build)
			}
		}
	}
}

func decodeWiphyFreqs(data []byte, build *wiphyBandBuild) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return
	}
	for ad.Next() {
		fad, err := netlink.NewAttributeDecoder(ad.Bytes())
		if err != nil {
			continue
		}
		var channel WiphyChannel
		for fad.Next() {
			switch fad.Type() {
			case unix.NL80211_FREQUENCY_ATTR_FREQ:
				channel.Frequency = int(fad.Uint32())
			case unix.NL80211_FREQUENCY_ATTR_DISABLED:
				channel.Disabled = true
			case unix.NL80211_FREQUENCY_ATTR_NO_IR:
				channel.NoIR = true
			case unix.NL80211_FREQUENCY_ATTR_RADAR:
				channel.Radar = true
			case unix.NL80211_FREQUENCY_ATTR_MAX_TX_POWER:
				channel.MaxPowerDBM = int(fad.Uint32()) / 100 // mBm
			}
		}
		if channel.Frequency == 0 {
			continue
		}
		channel.Channel = FrequencyChannel(channel.Frequency)
		build.channels[channel.Frequency] = channel
	}
}

// decodeWiphyIftypes keeps the HE/EHT PHY capabilities of the AP interface
// type when present, else of any type (they agree on width support).
func decodeWiphyIftypes(data []byte, build *wiphyBandBuild) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return
	}
	for ad.Next() {
		iad, err := netlink.NewAttributeDecoder(ad.Bytes())
		if err != nil {
			continue
		}
		for iad.Next() {
			switch iad.Type() {
			case unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY:
				if phy := iad.Bytes(); len(phy) > 0 {
					build.band.HE = true
					build.heCap0 |= phy[0]
				}
			case unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY:
				if phy := iad.Bytes(); len(phy) > 0 {
					build.band.EHT = true
					build.ehtCap0 |= phy[0]
				}
			}
		}
	}
}

func bandWidths(build *wiphyBandBuild) []int {
	widths := map[int]bool{20: true}
	two4 := build.band.Band == "2.4GHz"
	if build.htCapa&htCapSupWidth2040 != 0 {
		widths[40] = true
	}
	if build.band.VHT && !two4 {
		widths[80] = true
		if build.vhtCapa&vhtCapWidthMask != 0 || build.vhtCapa&vhtCapExtNSSBWMask != 0 {
			widths[160] = true
		}
	}
	if build.band.HE {
		if two4 && build.heCap0&hePhyCap040In24 != 0 {
			widths[40] = true
		}
		if !two4 && build.heCap0&hePhyCap04080In5 != 0 {
			widths[40], widths[80] = true, true
		}
		if !two4 && build.heCap0&hePhyCap0160In5 != 0 {
			widths[160] = true
		}
	}
	if build.band.EHT && build.band.Band == "6GHz" && build.ehtCap0&ehtPhyCap0320In6 != 0 {
		widths[320] = true
	}
	out := make([]int, 0, len(widths))
	for width := range widths {
		out = append(out, width)
	}
	sort.Ints(out)
	return out
}

func nl80211BandName(id uint16) string {
	switch id {
	case unix.NL80211_BAND_2GHZ:
		return "2.4GHz"
	case unix.NL80211_BAND_5GHZ:
		return "5GHz"
	case unix.NL80211_BAND_6GHZ:
		return "6GHz"
	case unix.NL80211_BAND_60GHZ:
		return "60GHz"
	}
	return ""
}

func bandOrder(band string) int {
	switch band {
	case "2.4GHz":
		return 0
	case "5GHz":
		return 1
	case "6GHz":
		return 2
	}
	return 3
}
