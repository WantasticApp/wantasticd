//go:build linux

package iwinfo

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The nl80211 station reader below talks to the kernel directly instead of
// going through mdlayher/wifi so it can (a) query one station by MAC, which
// vendor drivers such as qcacld implement for SAP even when they return an
// empty dump, and (b) read attributes the library drops: expected throughput
// (the rate-control estimate of achievable goodput), ACK signal and beacon
// loss.

const nl80211RequestTimeout = 2 * time.Second

// ErrStationNotFound is returned by NL80211Station for an unknown MAC.
var ErrStationNotFound = errors.New("nl80211 station not found")

type nl80211Conn struct {
	conn   *genetlink.Conn
	family genetlink.Family
}

func dialNL80211() (*nl80211Conn, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("open generic netlink: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(nl80211RequestTimeout))
	family, err := conn.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve nl80211 family: %w", err)
	}
	return &nl80211Conn{conn: conn, family: family}, nil
}

func (c *nl80211Conn) Close() { _ = c.conn.Close() }

func (c *nl80211Conn) execute(cmd uint8, flags netlink.HeaderFlags, encode func(*netlink.AttributeEncoder)) ([]genetlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	encode(ae)
	data, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	return c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{Command: cmd, Version: c.family.Version},
		Data:   data,
	}, c.family.ID, netlink.Request|flags)
}

// NL80211Stations dumps every station on ifname with the extended attribute
// set. A successful empty result is returned as such; callers decide whether
// an empty dump is authoritative for the driver in use.
func NL80211Stations(ifname string) ([]AssocEntry, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	c, err := dialNL80211()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msgs, err := c.execute(unix.NL80211_CMD_GET_STATION, netlink.Dump, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(iface.Index))
	})
	if err != nil {
		return nil, fmt.Errorf("nl80211 station dump for %s: %w", ifname, err)
	}
	return decodeNL80211Stations(msgs), nil
}

// NL80211Station queries one station by MAC (NL80211_CMD_GET_STATION without
// NLM_F_DUMP).
func NL80211Station(ifname string, mac net.HardwareAddr) (AssocEntry, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return AssocEntry{}, err
	}
	if len(mac) != 6 {
		return AssocEntry{}, fmt.Errorf("invalid station MAC")
	}
	c, err := dialNL80211()
	if err != nil {
		return AssocEntry{}, err
	}
	defer c.Close()
	msgs, err := c.execute(unix.NL80211_CMD_GET_STATION, 0, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(iface.Index))
		ae.Bytes(unix.NL80211_ATTR_MAC, mac)
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return AssocEntry{}, ErrStationNotFound
		}
		return AssocEntry{}, fmt.Errorf("nl80211 get station %s on %s: %w", mac, ifname, err)
	}
	entries := decodeNL80211Stations(msgs)
	if len(entries) == 0 {
		return AssocEntry{}, ErrStationNotFound
	}
	return entries[0], nil
}

// RadioLink describes physical-layer settings of the radio behind ifname.
type RadioLink struct {
	PHY              int
	TxPowerDBM       int  // current transmit power
	TxPowerKnown     bool //
	CoverageClass    int  // IEEE 802.11 coverage class (0-255)
	CoverageKnown    bool //
	CoverageDistance int  // one-way distance in metres implied by CoverageClass
	Frequency        int  // primary 20 MHz channel in MHz
	CenterFrequency  int  // center of the whole operating channel in MHz
	ChannelWidth     int  // operating channel width in MHz (80+80 reported as 160)
}

// NL80211RadioLink reads the current TX power (GET_INTERFACE) and coverage
// class (GET_WIPHY) for ifname. Each coverage class step adds 3 µs to the
// slot time, i.e. 900 m of round-trip air propagation, so the configured
// one-way link distance is class × 450 m (cfg80211 coverage_class semantics,
// as set by OpenWrt's "distance" option).
func NL80211RadioLink(ifname string) (RadioLink, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return RadioLink{}, err
	}
	c, err := dialNL80211()
	if err != nil {
		return RadioLink{}, err
	}
	defer c.Close()
	out := RadioLink{PHY: -1}
	msgs, err := c.execute(unix.NL80211_CMD_GET_INTERFACE, 0, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(iface.Index))
	})
	if err != nil {
		return RadioLink{}, fmt.Errorf("nl80211 get interface %s: %w", ifname, err)
	}
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			continue
		}
		for ad.Next() {
			switch ad.Type() {
			case unix.NL80211_ATTR_WIPHY:
				out.PHY = int(ad.Uint32())
			case unix.NL80211_ATTR_WIPHY_FREQ:
				out.Frequency = int(ad.Uint32())
			case unix.NL80211_ATTR_CENTER_FREQ1:
				out.CenterFrequency = int(ad.Uint32())
			case unix.NL80211_ATTR_CHANNEL_WIDTH:
				out.ChannelWidth = nl80211WidthMHz(ad.Uint32())
			case unix.NL80211_ATTR_WIPHY_TX_POWER_LEVEL:
				// mBm; 0 means the driver did not report a level.
				if mbm := int32(ad.Uint32()); mbm > 0 {
					out.TxPowerDBM = int(mbm / 100)
					out.TxPowerKnown = true
				}
			}
		}
	}
	if out.PHY < 0 {
		return out, nil
	}
	msgs, err = c.execute(unix.NL80211_CMD_GET_WIPHY, 0, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_WIPHY, uint32(out.PHY))
	})
	if err != nil {
		return out, nil
	}
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			continue
		}
		for ad.Next() {
			if ad.Type() == unix.NL80211_ATTR_WIPHY_COVERAGE_CLASS {
				out.CoverageClass = int(ad.Uint8())
				out.CoverageKnown = true
				out.CoverageDistance = out.CoverageClass * 450
			}
		}
	}
	return out, nil
}

func decodeNL80211Stations(msgs []genetlink.Message) []AssocEntry {
	out := make([]AssocEntry, 0, len(msgs))
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			continue
		}
		var entry AssocEntry
		haveInfo := false
		for ad.Next() {
			switch ad.Type() {
			case unix.NL80211_ATTR_MAC:
				if b := ad.Bytes(); len(b) == 6 {
					entry.MAC = append(net.HardwareAddr(nil), b...)
				}
			case unix.NL80211_ATTR_STA_INFO:
				haveInfo = true
				ad.Nested(func(nad *netlink.AttributeDecoder) error {
					decodeNL80211StaInfo(nad, &entry)
					return nil
				})
			}
		}
		if ad.Err() != nil || !haveInfo || len(entry.MAC) != 6 {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func decodeNL80211StaInfo(ad *netlink.AttributeDecoder, e *AssocEntry) {
	var rx32, tx32 uint32
	var rx64, tx64 uint64
	have32, have64 := [2]bool{}, [2]bool{}
	for ad.Next() {
		switch ad.Type() {
		case unix.NL80211_STA_INFO_INACTIVE_TIME:
			e.Inactive, e.InactiveKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_CONNECTED_TIME:
			e.ConnectedTime, e.ConnectedTimeKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_SIGNAL:
			e.Signal, e.SignalKnown = int8(ad.Uint8()), true
		case unix.NL80211_STA_INFO_SIGNAL_AVG:
			e.SignalAvg, e.SignalAvgKnown = int8(ad.Uint8()), true
		case unix.NL80211_STA_INFO_RX_PACKETS:
			e.RxPackets, e.RxPacketsKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_TX_PACKETS:
			e.TxPackets, e.TxPacketsKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_TX_RETRIES:
			e.TxRetries, e.TxRetriesKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_TX_FAILED:
			e.TxFailed, e.TxFailedKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_RX_BYTES:
			rx32, have32[0] = ad.Uint32(), true
		case unix.NL80211_STA_INFO_TX_BYTES:
			tx32, have32[1] = ad.Uint32(), true
		case unix.NL80211_STA_INFO_RX_BYTES64:
			rx64, have64[0] = ad.Uint64(), true
		case unix.NL80211_STA_INFO_TX_BYTES64:
			tx64, have64[1] = ad.Uint64(), true
		case unix.NL80211_STA_INFO_EXPECTED_THROUGHPUT:
			e.ExpectedThroughput, e.ExpectedThroughputKnown = ad.Uint32(), true
		case unix.NL80211_STA_INFO_TX_BITRATE:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				rate, mcs, nss := decodeNL80211Rate(nad)
				e.TxRate, e.TxMCS, e.TxNSS, e.TxRateKnown = rate, mcs, nss, rate > 0
				return nil
			})
		case unix.NL80211_STA_INFO_RX_BITRATE:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				rate, mcs, nss := decodeNL80211Rate(nad)
				e.RxRate, e.RxMCS, e.RxNSS, e.RxRateKnown = rate, mcs, nss, rate > 0
				return nil
			})
		}
	}
	switch {
	case have64[0]:
		e.RxBytes, e.RxBytesKnown = rx64, true
	case have32[0]:
		e.RxBytes, e.RxBytesKnown = uint64(rx32), true
	}
	switch {
	case have64[1]:
		e.TxBytes, e.TxBytesKnown = tx64, true
	case have32[1]:
		e.TxBytes, e.TxBytesKnown = uint64(tx32), true
	}
}

// decodeNL80211Rate returns the bitrate in kbit/s (nl80211 reports units of
// 100 kbit/s), the MCS index (-1 when absent) and spatial streams.
func decodeNL80211Rate(ad *netlink.AttributeDecoder) (uint32, int8, uint8) {
	var rate16, rate32 uint32
	mcs := int8(-1)
	var nss uint8
	for ad.Next() {
		switch ad.Type() {
		case unix.NL80211_RATE_INFO_BITRATE:
			rate16 = uint32(ad.Uint16())
		case unix.NL80211_RATE_INFO_BITRATE32:
			rate32 = ad.Uint32()
		case unix.NL80211_RATE_INFO_MCS, unix.NL80211_RATE_INFO_VHT_MCS,
			unix.NL80211_RATE_INFO_HE_MCS, unix.NL80211_RATE_INFO_EHT_MCS:
			mcs = int8(ad.Uint8())
		case unix.NL80211_RATE_INFO_VHT_NSS, unix.NL80211_RATE_INFO_HE_NSS, unix.NL80211_RATE_INFO_EHT_NSS:
			nss = ad.Uint8()
		}
	}
	rate := rate32
	if rate == 0 {
		rate = rate16
	}
	return rate * 100, mcs, nss
}

func nl80211WidthMHz(width uint32) int {
	switch width {
	case unix.NL80211_CHAN_WIDTH_20_NOHT, unix.NL80211_CHAN_WIDTH_20:
		return 20
	case unix.NL80211_CHAN_WIDTH_40:
		return 40
	case unix.NL80211_CHAN_WIDTH_80:
		return 80
	case unix.NL80211_CHAN_WIDTH_80P80, unix.NL80211_CHAN_WIDTH_160:
		return 160
	case unix.NL80211_CHAN_WIDTH_320:
		return 320
	case unix.NL80211_CHAN_WIDTH_10:
		return 10
	case unix.NL80211_CHAN_WIDTH_5:
		return 5
	}
	return 0
}
