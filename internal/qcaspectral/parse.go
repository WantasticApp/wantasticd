// Package qcaspectral collects FFT spectral scan samples from Qualcomm
// Atheros (QCA/QSDK) WiFi drivers.
//
// Control uses the QCA nl80211 vendor commands (QSDK 11/12 cfg80211 mode) or,
// on qca-wifi 10.x, the SIOCGATHPHYERR/ath_diag ioctls used by the vendor
// spectraltool, on the radio netdev (wifiN). Samples arrive as SAMP messages
// broadcast by the driver on NETLINK_ATHEROS group 1. Three message layouts
// exist in the field and all are decoded here:
//
//   - qca-legacy: qca-wifi 10.2 direct-attach (SPECTRAL_SAMP_MSG, 512 bins)
//   - qca-cmn: wlan cmn_dev spectral_samp_msg (pri80 + sec80 bins)
//   - qca-cmn-optimized: cmn_dev built with OPTIMIZED_SAMP_MESSAGE
//
// Everything is pure Go (no cgo), so every CGO_ENABLED=0 Linux release build
// carries the collector. testdata/layout.c pins the packed offsets below.
package qcaspectral

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Layout identifies the driver SAMP message layout.
type Layout string

const (
	LayoutUnknown      Layout = "unknown"
	LayoutLegacy       Layout = "qca-legacy"
	LayoutCMN          Layout = "qca-cmn"
	LayoutCMNOptimized Layout = "qca-cmn-optimized"
)

const (
	sampSignature = 0xdeadbeef
	nlmsgHdrLen   = 16
)

// Packed-struct offsets, mirrored by _Static_assert in native_linux_cgo.go.
const (
	// qca-wifi 10.2 SPECTRAL_SAMP_MSG; samp_data starts at 20.
	legacyFreq          = 4
	legacyMAC           = 14
	legacyRSSI          = 20 + 2
	legacyTimestamp     = 20 + 16
	legacyMaxIndex      = 20 + 20
	legacyBinCount      = 20 + 55
	legacyBins          = 20 + 57
	legacyMaxBins       = 512
	legacyNoiseFloor    = 20 + 621
	legacyChannelWidth  = 20 + 623
	legacyMessageLength = 20 + 627

	// cmn_dev struct spectral_samp_msg; samp_data starts at 28.
	cmnFreq          = 4
	cmnSeg1          = 6
	cmnSeg2          = 8
	cmnMAC           = 22
	cmnRSSI          = 28 + 4
	cmnTimestamp     = 28 + 20
	cmnMaxIndex      = 28 + 24
	cmnBinCount      = 28 + 63
	cmnBinCountSec80 = 28 + 67
	cmnBins          = 28 + 69
	cmnMaxBins       = 1024
	cmnBinsSec80     = 28 + 1093
	cmnMaxBinsSec80  = 520
	cmnNoiseFloor    = 28 + 1665
	cmnChannelWidth  = 28 + 1669
	// Fields beyond ch_width were appended across releases; only the prefix
	// through ch_width is required.
	cmnMinLength = 28 + 1673
	cmnMaxLength = 28 + 1745

	// cmn_dev OPTIMIZED_SAMP_MESSAGE header; bins follow at optBins.
	optPri20         = 8
	optCFreq1        = 12
	optCFreq2        = 16
	optBinCount      = 28
	optDet0Timestamp = 32 + 8
	optDet0MaxIndex  = 32 + 44
	optDet0Noise     = 32 + 48
	optDet0RSSI      = 32 + 50
	optMAC           = 388
	optOperatingBW   = 395
	optBins          = 401
)

// Sample is one decoded driver report.
type Sample struct {
	Layout           Layout
	MAC              net.HardwareAddr
	Frequency        uint32 // primary 20 MHz, MHz
	CenterFrequency1 uint32 // MHz, 0 when not reported
	CenterFrequency2 uint32 // MHz, 0 when not reported
	ChannelWidth     uint32 // MHz, 0 when not reported
	TimestampMicros  uint32
	RSSI             int16
	NoiseFloor       int16
	MaxIndex         uint16
	Bins             []byte
}

var (
	ErrNotSpectral   = errors.New("qcaspectral: not a spectral SAMP message")
	ErrUnknownLayout = errors.New("qcaspectral: unrecognized SAMP message layout")
)

// ParseNetlink decodes one NETLINK_ATHEROS datagram. order must be the host
// byte order: the driver writes the message in kernel-native order, and QCA
// ships both little-endian ARM and big-endian MIPS SoCs.
func ParseNetlink(datagram []byte, order binary.ByteOrder) (Sample, error) {
	if len(datagram) < nlmsgHdrLen+8 {
		return Sample{}, ErrNotSpectral
	}
	nlLen := int(order.Uint32(datagram[0:4]))
	if nlLen < nlmsgHdrLen || nlLen > len(datagram) {
		nlLen = len(datagram)
	}
	// The driver sizes nlmsg_len from the struct, but the optimized layout
	// appends a variable bin array to a fixed-size skb, so keep the whole
	// datagram available as the bin bound.
	payload := datagram[nlmsgHdrLen:]
	declared := nlLen - nlmsgHdrLen
	if order.Uint32(payload[0:4]) != sampSignature {
		return Sample{}, ErrNotSpectral
	}
	if validFrequency(uint32(order.Uint16(payload[4:6]))) {
		switch {
		case declared >= legacyMessageLength && declared <= legacyMessageLength+8:
			return parseLegacy(payload, order)
		case declared >= cmnMinLength && declared <= cmnMaxLength+8:
			return parseCMN(payload[:declared], order)
		}
		return Sample{}, fmt.Errorf("%w: %d-byte payload", ErrUnknownLayout, declared)
	}
	if len(payload) >= optBins && validFrequency(order.Uint32(payload[optPri20:optPri20+4])) {
		return parseOptimized(payload, order)
	}
	return Sample{}, fmt.Errorf("%w: %d-byte payload", ErrUnknownLayout, declared)
}

func parseLegacy(p []byte, order binary.ByteOrder) (Sample, error) {
	count := int(order.Uint16(p[legacyBinCount:]))
	if count == 0 || count > legacyMaxBins {
		return Sample{}, fmt.Errorf("%w: legacy bin count %d", ErrUnknownLayout, count)
	}
	return Sample{
		Layout:          LayoutLegacy,
		MAC:             cloneMAC(p[legacyMAC : legacyMAC+6]),
		Frequency:       uint32(order.Uint16(p[legacyFreq:])),
		ChannelWidth:    channelWidthMHz(order.Uint32(p[legacyChannelWidth:])),
		TimestampMicros: order.Uint32(p[legacyTimestamp:]),
		RSSI:            int16(order.Uint16(p[legacyRSSI:])),
		NoiseFloor:      int16(order.Uint16(p[legacyNoiseFloor:])),
		MaxIndex:        order.Uint16(p[legacyMaxIndex:]),
		Bins:            append([]byte(nil), p[legacyBins:legacyBins+count]...),
	}, nil
}

func parseCMN(p []byte, order binary.ByteOrder) (Sample, error) {
	count := int(order.Uint16(p[cmnBinCount:]))
	countSec80 := int(order.Uint16(p[cmnBinCountSec80:]))
	if count == 0 || count > cmnMaxBins || countSec80 > cmnMaxBinsSec80 {
		return Sample{}, fmt.Errorf("%w: cmn bin counts %d/%d", ErrUnknownLayout, count, countSec80)
	}
	bins := make([]byte, 0, count+countSec80)
	bins = append(bins, p[cmnBins:cmnBins+count]...)
	bins = append(bins, p[cmnBinsSec80:cmnBinsSec80+countSec80]...)
	return Sample{
		Layout:           LayoutCMN,
		MAC:              cloneMAC(p[cmnMAC : cmnMAC+6]),
		Frequency:        uint32(order.Uint16(p[cmnFreq:])),
		CenterFrequency1: frequencyOrZero(uint32(order.Uint16(p[cmnSeg1:]))),
		CenterFrequency2: frequencyOrZero(uint32(order.Uint16(p[cmnSeg2:]))),
		ChannelWidth:     channelWidthMHz(order.Uint32(p[cmnChannelWidth:])),
		TimestampMicros:  order.Uint32(p[cmnTimestamp:]),
		RSSI:             int16(order.Uint16(p[cmnRSSI:])),
		NoiseFloor:       int16(order.Uint16(p[cmnNoiseFloor:])),
		MaxIndex:         order.Uint16(p[cmnMaxIndex:]),
		Bins:             bins,
	}, nil
}

func parseOptimized(p []byte, order binary.ByteOrder) (Sample, error) {
	// Bound the raw uint32 before converting: on 32-bit targets (MIPS/ARM
	// OpenWrt) int(0xffffffff) is -1, which would pass the checks below and
	// panic on the slice.
	raw := order.Uint32(p[optBinCount:])
	if raw == 0 || raw > 2048 || int(raw) > len(p)-optBins {
		return Sample{}, fmt.Errorf("%w: optimized bin count %d", ErrUnknownLayout, raw)
	}
	count := int(raw)
	return Sample{
		Layout:           LayoutCMNOptimized,
		MAC:              cloneMAC(p[optMAC : optMAC+6]),
		Frequency:        order.Uint32(p[optPri20:]),
		CenterFrequency1: frequencyOrZero(order.Uint32(p[optCFreq1:])),
		CenterFrequency2: frequencyOrZero(order.Uint32(p[optCFreq2:])),
		ChannelWidth:     channelWidthMHz(uint32(p[optOperatingBW])),
		TimestampMicros:  order.Uint32(p[optDet0Timestamp:]),
		RSSI:             int16(int8(p[optDet0RSSI])),
		NoiseFloor:       int16(order.Uint16(p[optDet0Noise:])),
		MaxIndex:         order.Uint16(p[optDet0MaxIndex:]),
		Bins:             append([]byte(nil), p[optBins:optBins+count]...),
	}, nil
}

func validFrequency(mhz uint32) bool { return mhz >= 2300 && mhz <= 7300 }

func frequencyOrZero(mhz uint32) uint32 {
	if validFrequency(mhz) {
		return mhz
	}
	return 0
}

// channelWidthMHz maps the driver channel width enum to MHz. Both the
// regulatory phy_ch_width and spectral_chan_width enums agree on 0..4
// (20, 40, 80, 160, 80+80) but diverge above that, so higher values are
// reported as unknown. Values that already look like MHz pass through.
func channelWidthMHz(v uint32) uint32 {
	switch v {
	case 0:
		return 20
	case 1:
		return 40
	case 2:
		return 80
	case 3, 4:
		return 160
	case 20, 40, 80, 160, 320:
		return v
	default:
		return 0
	}
}

func cloneMAC(b []byte) net.HardwareAddr { return append(net.HardwareAddr(nil), b...) }
