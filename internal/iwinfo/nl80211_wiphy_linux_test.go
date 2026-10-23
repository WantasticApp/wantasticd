//go:build linux

package iwinfo

import (
	"fmt"
	"testing"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func encodeWiphyBand(t *testing.T, id uint16, freqs map[uint32]uint32, extra func(*netlink.AttributeEncoder)) []byte {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.Nested(unix.NL80211_ATTR_WIPHY_BANDS, func(bands *netlink.AttributeEncoder) error {
		bands.Nested(id, func(band *netlink.AttributeEncoder) error {
			if len(freqs) > 0 {
				band.Nested(unix.NL80211_BAND_ATTR_FREQS, func(list *netlink.AttributeEncoder) error {
					i := uint16(0)
					for mhz, power := range freqs {
						list.Nested(i, func(freq *netlink.AttributeEncoder) error {
							freq.Uint32(unix.NL80211_FREQUENCY_ATTR_FREQ, mhz)
							freq.Uint32(unix.NL80211_FREQUENCY_ATTR_MAX_TX_POWER, power)
							if power == 0 {
								freq.Flag(unix.NL80211_FREQUENCY_ATTR_DISABLED, true)
							}
							return nil
						})
						i++
					}
					return nil
				})
			}
			if extra != nil {
				extra(band)
			}
			return nil
		})
		return nil
	})
	ae.Uint32(unix.NL80211_ATTR_WIPHY, 2)
	data, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Split dumps spread one band across messages: frequencies in one, PHY
// capabilities in another. Both must merge into the same band.
func TestDecodeWiphySplitSixGHz(t *testing.T) {
	freqs := encodeWiphyBand(t, unix.NL80211_BAND_6GHZ, map[uint32]uint32{5955: 2400, 6135: 2400, 7115: 0}, nil)
	caps := encodeWiphyBand(t, unix.NL80211_BAND_6GHZ, nil, func(band *netlink.AttributeEncoder) {
		band.Nested(unix.NL80211_BAND_ATTR_IFTYPE_DATA, func(list *netlink.AttributeEncoder) error {
			list.Nested(0, func(iftype *netlink.AttributeEncoder) error {
				iftype.Bytes(unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, []byte{hePhyCap04080In5 | hePhyCap0160In5, 0, 0})
				iftype.Bytes(unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, []byte{ehtPhyCap0320In6})
				return nil
			})
			return nil
		})
	})
	wiphy := decodeWiphy([]genetlink.Message{{Data: freqs}, {Data: caps}}, 2)
	if got := fmt.Sprint(wiphy.BandNames()); got != "[6GHz]" {
		t.Fatalf("bands=%s", got)
	}
	band := wiphy.Band("6GHz")
	if got := fmt.Sprint(band.Widths); got != "[20 40 80 160 320]" {
		t.Fatalf("widths=%s", got)
	}
	usable := band.UsableChannels()
	if len(usable) != 2 || usable[0].Channel != 1 || usable[1].Channel != 37 || usable[0].MaxPowerDBM != 24 {
		t.Fatalf("usable=%+v", usable)
	}
	if !band.HE || !band.EHT || band.HT || band.VHT {
		t.Fatalf("caps=%+v", band)
	}
}

func TestDecodeWiphyFiveGHzVHT160(t *testing.T) {
	data := encodeWiphyBand(t, unix.NL80211_BAND_5GHZ, map[uint32]uint32{5180: 2300, 5500: 3000}, func(band *netlink.AttributeEncoder) {
		band.Uint16(unix.NL80211_BAND_ATTR_HT_CAPA, htCapSupWidth2040)
		band.Uint32(unix.NL80211_BAND_ATTR_VHT_CAPA, vhtCapWidth160)
	})
	band := decodeWiphy([]genetlink.Message{{Data: data}}, 2).Band("5GHz")
	if band == nil || fmt.Sprint(band.Widths) != "[20 40 80 160]" || band.MaxPowerDBM() != 30 || band.ChannelPowerDBM(36) != 23 {
		t.Fatalf("band=%+v", band)
	}
}
