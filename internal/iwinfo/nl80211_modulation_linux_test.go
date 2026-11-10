//go:build linux

package iwinfo

import (
	"testing"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestDecodeNL80211StationModulation(t *testing.T) {
	cases := []struct {
		name string
		rate func(*netlink.AttributeEncoder)
		kbps uint32
		want RateInfo
	}{
		{"HE 80 MHz 2SS MCS11 GI 0.8", func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_RATE_INFO_BITRATE32, 12010)
			ae.Flag(unix.NL80211_RATE_INFO_80_MHZ_WIDTH, true)
			ae.Uint8(unix.NL80211_RATE_INFO_HE_MCS, 11)
			ae.Uint8(unix.NL80211_RATE_INFO_HE_NSS, 2)
			ae.Uint8(unix.NL80211_RATE_INFO_HE_GI, unix.NL80211_RATE_INFO_HE_GI_0_8)
			ae.Uint8(unix.NL80211_RATE_INFO_HE_DCM, 0)
		}, 1_201_000, RateInfo{PHY: PHYHE, MCS: 11, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 800, DCMKnown: true}},
		{"VHT 80 MHz 2SS MCS9 short GI", func(ae *netlink.AttributeEncoder) {
			ae.Uint16(unix.NL80211_RATE_INFO_BITRATE, 8667)
			ae.Uint32(unix.NL80211_RATE_INFO_BITRATE32, 8667)
			ae.Flag(unix.NL80211_RATE_INFO_80_MHZ_WIDTH, true)
			ae.Uint8(unix.NL80211_RATE_INFO_VHT_MCS, 9)
			ae.Uint8(unix.NL80211_RATE_INFO_VHT_NSS, 2)
			ae.Flag(unix.NL80211_RATE_INFO_SHORT_GI, true)
		}, 866_700, RateInfo{PHY: PHYVHT, MCS: 9, MCSKnown: true, NSS: 2, BandwidthMHz: 80, GuardIntervalNs: 400}},
		{"HT40 MCS15", func(ae *netlink.AttributeEncoder) {
			ae.Uint16(unix.NL80211_RATE_INFO_BITRATE, 2700)
			ae.Uint8(unix.NL80211_RATE_INFO_MCS, 15)
			ae.Flag(unix.NL80211_RATE_INFO_40_MHZ_WIDTH, true)
		}, 270_000, RateInfo{PHY: PHYHT, MCS: 15, MCSKnown: true, NSS: 2, BandwidthMHz: 40, GuardIntervalNs: 800}},
		{"legacy 54", func(ae *netlink.AttributeEncoder) {
			ae.Uint16(unix.NL80211_RATE_INFO_BITRATE, 540)
		}, 54_000, RateInfo{PHY: PHYLegacy, BandwidthMHz: 20}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ae := netlink.NewAttributeEncoder()
			ae.Bytes(unix.NL80211_ATTR_MAC, []byte{0x80, 0x2a, 0xa8, 1, 2, 3})
			ae.Nested(unix.NL80211_ATTR_STA_INFO, func(nae *netlink.AttributeEncoder) error {
				nae.Uint8(unix.NL80211_STA_INFO_SIGNAL, 0xc9) // -55
				nae.Nested(unix.NL80211_STA_INFO_CHAIN_SIGNAL, func(cae *netlink.AttributeEncoder) error {
					cae.Uint8(0, 0xc9) // -55
					cae.Uint8(1, 0xcb) // -53
					return nil
				})
				nae.Nested(unix.NL80211_STA_INFO_CHAIN_SIGNAL_AVG, func(cae *netlink.AttributeEncoder) error {
					cae.Uint8(0, 0xc8) // -56
					cae.Uint8(1, 0xca) // -54
					return nil
				})
				nae.Uint64(unix.NL80211_STA_INFO_TX_DURATION, 123_456_789)
				nae.Uint64(unix.NL80211_STA_INFO_RX_DURATION, 98_765)
				nae.Nested(unix.NL80211_STA_INFO_TX_BITRATE, func(rae *netlink.AttributeEncoder) error { tc.rate(rae); return nil })
				nae.Nested(unix.NL80211_STA_INFO_RX_BITRATE, func(rae *netlink.AttributeEncoder) error { tc.rate(rae); return nil })
				return nil
			})
			data, err := ae.Encode()
			if err != nil {
				t.Fatal(err)
			}
			entries := decodeNL80211Stations([]genetlink.Message{{Data: data}})
			if len(entries) != 1 {
				t.Fatalf("got %d entries", len(entries))
			}
			e := entries[0]
			if e.TxRate != tc.kbps || e.TxRateInfo != tc.want || e.RxRateInfo != tc.want {
				t.Fatalf("tx %d %+v rx %+v, want %d %+v", e.TxRate, e.TxRateInfo, e.RxRateInfo, tc.kbps, tc.want)
			}
			if FormatChainSignal(e.ChainSignal) != "-55,-53" || FormatChainSignal(e.ChainSignalAvg) != "-56,-54" {
				t.Fatalf("chains %v avg %v", e.ChainSignal, e.ChainSignalAvg)
			}
			if !e.TxDurationKnown || e.TxDuration != 123_456_789 || !e.RxDurationKnown || e.RxDuration != 98_765 {
				t.Fatalf("airtime %+v", e)
			}
		})
	}
}

func TestDecodeNL80211StationOmitsUnknownModulation(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.NL80211_ATTR_MAC, []byte{0x80, 0x2a, 0xa8, 1, 2, 3})
	ae.Nested(unix.NL80211_ATTR_STA_INFO, func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(unix.NL80211_STA_INFO_SIGNAL, 0xc9)
		return nil
	})
	data, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	entries := decodeNL80211Stations([]genetlink.Message{{Data: data}})
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	if e.TxRateInfo.Known() || e.RxRateInfo.Known() || e.ChainSignal != nil || e.TxDurationKnown || e.RxDurationKnown {
		t.Fatalf("absent attributes must stay unknown: %+v", e)
	}
	if e.TxMCS != 0 && e.TxMCS != -1 {
		t.Fatalf("legacy TxMCS %d", e.TxMCS)
	}
}
