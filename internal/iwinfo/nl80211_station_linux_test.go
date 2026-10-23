//go:build linux

package iwinfo

import (
	"testing"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestDecodeNL80211Stations(t *testing.T) {
	rate := func(ae *netlink.AttributeEncoder, bitrate32 uint32, mcs, nss uint8) {
		ae.Uint32(unix.NL80211_RATE_INFO_BITRATE32, bitrate32)
		ae.Uint8(unix.NL80211_RATE_INFO_HE_MCS, mcs)
		ae.Uint8(unix.NL80211_RATE_INFO_HE_NSS, nss)
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, 7)
	ae.Bytes(unix.NL80211_ATTR_MAC, []byte{0xa4, 0x83, 0xe7, 1, 2, 3})
	ae.Nested(unix.NL80211_ATTR_STA_INFO, func(nae *netlink.AttributeEncoder) error {
		nae.Uint32(unix.NL80211_STA_INFO_INACTIVE_TIME, 120)
		nae.Uint32(unix.NL80211_STA_INFO_CONNECTED_TIME, 3600)
		nae.Uint8(unix.NL80211_STA_INFO_SIGNAL, 0xc6)
		nae.Uint8(unix.NL80211_STA_INFO_SIGNAL_AVG, 0xc4)
		nae.Uint32(unix.NL80211_STA_INFO_RX_BYTES, 1)
		nae.Uint64(unix.NL80211_STA_INFO_RX_BYTES64, 5_000_000_000)
		nae.Uint64(unix.NL80211_STA_INFO_TX_BYTES64, 7_000_000_000)
		nae.Uint32(unix.NL80211_STA_INFO_TX_RETRIES, 12)
		nae.Uint32(unix.NL80211_STA_INFO_EXPECTED_THROUGHPUT, 410000)
		nae.Nested(unix.NL80211_STA_INFO_TX_BITRATE, func(rae *netlink.AttributeEncoder) error { rate(rae, 12010, 11, 2); return nil })
		nae.Nested(unix.NL80211_STA_INFO_RX_BITRATE, func(rae *netlink.AttributeEncoder) error {
			rae.Uint16(unix.NL80211_RATE_INFO_BITRATE, 650)
			rae.Uint8(unix.NL80211_RATE_INFO_MCS, 7)
			return nil
		})
		return nil
	})
	data, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	entries := decodeNL80211Stations([]genetlink.Message{{Data: data}, {Data: []byte{1, 2, 3}}})
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	if e.MAC.String() != "a4:83:e7:01:02:03" || e.Signal != -58 || e.SignalAvg != -60 || e.Inactive != 120 || e.ConnectedTime != 3600 {
		t.Fatalf("basic fields %+v", e)
	}
	if e.RxBytes != 5_000_000_000 || e.TxBytes != 7_000_000_000 || e.TxRetries != 12 {
		t.Fatalf("64-bit counters must win %+v", e)
	}
	if e.TxRate != 1_201_000 || e.TxMCS != 11 || e.TxNSS != 2 || e.RxRate != 65_000 || e.RxMCS != 7 {
		t.Fatalf("rates %+v", e)
	}
	if !e.ExpectedThroughputKnown || e.ExpectedThroughput != 410000 {
		t.Fatalf("expected throughput %+v", e)
	}
}
