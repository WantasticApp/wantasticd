package iwinfo

import (
	"net"
	"strconv"
	"strings"
)

// Modulation (rate info) helpers shared by every station source. They carry
// no build tag so the mapping is unit-tested on every development OS; the
// nl80211 attribute walk lives in nl80211_station_linux.go.

// PHY names used in RateInfo.PHY.
const (
	PHYLegacy = "legacy"
	PHYHT     = "ht"
	PHYVHT    = "vht"
	PHYHE     = "he"
	PHYEHT    = "eht"
)

// RateInfo is the modulation of one direction of a link. Zero fields are
// unknown: PHY "" means nothing is known, MCS is valid only with MCSKnown.
type RateInfo struct {
	PHY             string // legacy, ht, vht, he or eht
	MCS             uint8  // standard MCS index; HT keeps the 0-31 (77) index
	MCSKnown        bool
	NSS             uint8 // spatial streams
	BandwidthMHz    int   // 5, 10, 20, 40, 80, 160 or 320
	GuardIntervalNs int   // 400, 800, 1600 or 3200
	DCM             bool  // HE dual carrier modulation
	DCMKnown        bool
	// Negotiated marks values derived from the association mode (QSDK
	// wlanconfig, hostapd flags) rather than from the last frame; a
	// per-frame RateInfo always wins over a negotiated one when merging.
	Negotiated bool
}

// Known reports whether any modulation field is present.
func (r RateInfo) Known() bool {
	return r.PHY != "" || r.MCSKnown || r.NSS > 0 || r.BandwidthMHz > 0 || r.GuardIntervalNs > 0 || r.DCMKnown
}

// MergeRateInfo returns preferred, completed from other. A per-frame value
// beats a negotiated one; fields are only borrowed between the same PHY so
// an HE MCS is never paired with a VHT width.
func MergeRateInfo(preferred, other RateInfo) RateInfo {
	if !preferred.Known() {
		return other
	}
	if !other.Known() {
		return preferred
	}
	if preferred.Negotiated && !other.Negotiated {
		preferred, other = other, preferred
	}
	if preferred.PHY != "" && other.PHY != "" && preferred.PHY != other.PHY {
		return preferred
	}
	if preferred.PHY == "" {
		preferred.PHY = other.PHY
	}
	if !preferred.MCSKnown && other.MCSKnown {
		preferred.MCS, preferred.MCSKnown = other.MCS, true
	}
	if preferred.NSS == 0 {
		preferred.NSS = other.NSS
	}
	if preferred.BandwidthMHz == 0 {
		preferred.BandwidthMHz = other.BandwidthMHz
	}
	if preferred.GuardIntervalNs == 0 {
		preferred.GuardIntervalNs = other.GuardIntervalNs
	}
	if !preferred.DCMKnown && other.DCMKnown {
		preferred.DCM, preferred.DCMKnown = other.DCM, true
	}
	return preferred
}

// nl80211RateFields is the decoded content of one nested nl80211 rate_info
// attribute (NL80211_STA_INFO_TX_BITRATE / RX_BITRATE). Negative indexes are
// absent attributes.
type nl80211RateFields struct {
	Bitrate16, Bitrate32         uint32 // 100 kbit/s units
	HTMCS, VHTMCS, HEMCS, EHTMCS int
	VHTNSS, HENSS, EHTNSS        int
	WidthMHz                     int // from the *_MHZ_WIDTH flags; 0 when none
	ShortGI                      bool
	HEGI, EHTGI, HEDCM           int
	RUAlloc                      bool // HE/EHT OFDMA resource unit, not a full channel
}

func newNL80211RateFields() nl80211RateFields {
	return nl80211RateFields{HTMCS: -1, VHTMCS: -1, HEMCS: -1, EHTMCS: -1, VHTNSS: -1, HENSS: -1, EHTNSS: -1, HEGI: -1, EHTGI: -1, HEDCM: -1}
}

// rate returns the bitrate in kbit/s and the modulation. Mirrors
// cfg80211_calculate_bitrate's view of the flags: MCS attributes select the
// PHY, no width flag means 20 MHz, HT/VHT GI is 400 ns with SHORT_GI and
// 800 ns otherwise, HE/EHT GI enums 0/1/2 are 0.8/1.6/3.2 µs.
func (f nl80211RateFields) rate() (uint32, RateInfo) {
	kbps := f.Bitrate32
	if kbps == 0 {
		kbps = f.Bitrate16
	}
	kbps *= 100
	var info RateInfo
	nss := -1
	switch {
	case f.EHTMCS >= 0:
		info.PHY, info.MCS, info.MCSKnown, nss = PHYEHT, uint8(f.EHTMCS), true, f.EHTNSS
		info.GuardIntervalNs = heGuardIntervalNs(f.EHTGI)
	case f.HEMCS >= 0:
		info.PHY, info.MCS, info.MCSKnown, nss = PHYHE, uint8(f.HEMCS), true, f.HENSS
		info.GuardIntervalNs = heGuardIntervalNs(f.HEGI)
		if f.HEDCM >= 0 {
			info.DCM, info.DCMKnown = f.HEDCM != 0, true
		}
	case f.VHTMCS >= 0:
		info.PHY, info.MCS, info.MCSKnown, nss = PHYVHT, uint8(f.VHTMCS), true, f.VHTNSS
		info.GuardIntervalNs = htGuardIntervalNs(f.ShortGI)
	case f.HTMCS >= 0:
		info.PHY, info.MCS, info.MCSKnown = PHYHT, uint8(f.HTMCS), true
		nss = htNSS(f.HTMCS)
		info.GuardIntervalNs = htGuardIntervalNs(f.ShortGI)
	case kbps > 0:
		info.PHY = PHYLegacy
	default:
		return kbps, RateInfo{}
	}
	if nss > 0 && nss <= 16 {
		info.NSS = uint8(nss)
	}
	switch {
	case f.WidthMHz > 0:
		info.BandwidthMHz = f.WidthMHz
	case f.RUAlloc:
		// An OFDMA resource unit is narrower than any channel width.
	default:
		info.BandwidthMHz = 20
	}
	return kbps, info
}

// RateInfoFromFields builds a RateInfo from libiwinfo-style rate fields
// (rpcd iwinfo assoclist rx/tx objects) with the nl80211 decoder's rules.
// Pass -1 for absent integers; phy "" with kbps > 0 is a legacy rate.
func RateInfoFromFields(phy string, kbps uint32, mcs, nss, widthMHz int, shortGI bool, gi, dcm int) RateInfo {
	f := newNL80211RateFields()
	f.Bitrate32 = kbps / 100
	if kbps > 0 && f.Bitrate32 == 0 {
		f.Bitrate32 = 1
	}
	f.ShortGI = shortGI
	if widthMHz > 0 {
		f.WidthMHz = widthMHz
	}
	if mcs > 255 {
		mcs = -1
	}
	switch phy {
	case PHYEHT:
		f.EHTMCS, f.EHTNSS, f.EHTGI = mcs, nss, gi
	case PHYHE:
		f.HEMCS, f.HENSS, f.HEGI, f.HEDCM = mcs, nss, gi, dcm
	case PHYVHT:
		f.VHTMCS, f.VHTNSS = mcs, nss
	case PHYHT:
		f.HTMCS = mcs
	case "", PHYLegacy:
	default:
		return RateInfo{}
	}
	_, info := f.rate()
	if phy != "" && phy != PHYLegacy && info.PHY == PHYLegacy {
		// The PHY flag without an MCS: keep the PHY, drop the guesses.
		info = RateInfo{PHY: phy, BandwidthMHz: info.BandwidthMHz}
		if nss > 0 && nss <= 16 {
			info.NSS = uint8(nss)
		}
	}
	return info
}

// htNSS derives spatial streams from an HT MCS index: 0-31 are 8 per
// stream, 32 is the 40 MHz duplicate (1 stream) and 33-76 are unequal
// modulation (2-4 streams).
func htNSS(mcs int) int {
	switch {
	case mcs < 0:
		return 0
	case mcs <= 31:
		return mcs/8 + 1
	case mcs == 32:
		return 1
	case mcs <= 38:
		return 2
	case mcs <= 52:
		return 3
	case mcs <= 76:
		return 4
	}
	return 0
}

func htGuardIntervalNs(short bool) int {
	if short {
		return 400
	}
	return 800
}

func heGuardIntervalNs(gi int) int {
	switch gi {
	case 0:
		return 800
	case 1:
		return 1600
	case 2:
		return 3200
	}
	return 0
}

// wlanconfigModeRate maps a QSDK/MadWifi phymode such as
// IEEE80211_MODE_11AXA_HE80 or IEEE80211_MODE_11NG_HT40PLUS to the
// negotiated PHY and channel width. Legacy modes are 20 MHz.
func wlanconfigModeRate(mode string) RateInfo {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	if !strings.HasPrefix(mode, "IEEE80211_MODE_") {
		return RateInfo{}
	}
	info := RateInfo{Negotiated: true}
	suffix := strings.TrimPrefix(mode, "IEEE80211_MODE_")
	var widthPart string
	switch {
	case strings.Contains(suffix, "EHT"):
		info.PHY = PHYEHT
		widthPart = suffix[strings.Index(suffix, "EHT")+3:]
	case strings.Contains(suffix, "HE"):
		info.PHY = PHYHE
		widthPart = suffix[strings.Index(suffix, "HE")+2:]
	case strings.Contains(suffix, "VHT"):
		info.PHY = PHYVHT
		widthPart = suffix[strings.Index(suffix, "VHT")+3:]
	case strings.Contains(suffix, "HT"):
		info.PHY = PHYHT
		widthPart = suffix[strings.Index(suffix, "HT")+2:]
	case suffix == "11A" || suffix == "11B" || suffix == "11G" || suffix == "TURBO_A" || suffix == "TURBO_G":
		info.PHY = PHYLegacy
		info.BandwidthMHz = 20
		return info
	default:
		return RateInfo{}
	}
	digits := 0
	for digits < len(widthPart) && widthPart[digits] >= '0' && widthPart[digits] <= '9' {
		digits++
	}
	if width, err := strconv.Atoi(widthPart[:digits]); err == nil {
		switch {
		case width == 80 && strings.HasPrefix(widthPart, "80_80"):
			info.BandwidthMHz = 160 // 80+80 MHz
		case width == 20, width == 40, width == 80, width == 160, width == 320:
			info.BandwidthMHz = width
		}
	}
	return info
}

// parseHostapdRateInfo parses a hostapd control STA "rx_rate_info" /
// "tx_rate_info" value: the rate in 100 kbit/s, then optional "mcs N",
// "vhtmcs N", "vhtnss N", "hemcs N", "henss N" and "shortGI". hostapd does
// not report the width, so BandwidthMHz stays unknown.
func parseHostapdRateInfo(value string) (uint32, bool, RateInfo) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, false, RateInfo{}
	}
	var kbps uint32
	rateKnown := false
	if v, err := strconv.ParseUint(fields[0], 10, 32); err == nil && v <= 0xffffffff/100 {
		kbps, rateKnown = uint32(v)*100, true
	}
	f := newNL80211RateFields()
	for i := 1; i < len(fields); i++ {
		key := fields[i]
		if key == "shortGI" {
			f.ShortGI = true
			continue
		}
		if i+1 >= len(fields) {
			break
		}
		n, err := strconv.Atoi(fields[i+1])
		if err != nil || n < 0 || n > 255 {
			continue
		}
		switch key {
		case "mcs":
			f.HTMCS = n
		case "vhtmcs":
			f.VHTMCS = n
		case "vhtnss":
			f.VHTNSS = n
		case "hemcs":
			f.HEMCS = n
		case "henss":
			f.HENSS = n
		case "ehtmcs":
			f.EHTMCS = n
		case "ehtnss":
			f.EHTNSS = n
		default:
			continue
		}
		i++
	}
	if f.HTMCS < 0 && f.VHTMCS < 0 && f.HEMCS < 0 && f.EHTMCS < 0 {
		// A bare rate says nothing about the modulation.
		return kbps, rateKnown, RateInfo{}
	}
	_, info := f.rate()
	info.BandwidthMHz = 0
	if info.PHY == PHYHE || info.PHY == PHYEHT {
		// hostapd does not print the HE/EHT GI.
		info.GuardIntervalNs = 0
	}
	return kbps, rateKnown, info
}

// orderedChainSignal returns per-chain readings ordered by chain index.
// Chains beyond 16 are ignored.
func orderedChainSignal(readings map[uint16]int8) []int8 {
	var out []int8
	for chain := uint16(0); chain < 16; chain++ {
		if v, ok := readings[chain]; ok {
			out = append(out, v)
		}
	}
	return out
}

// FormatChainSignal renders per-chain dBm values as "-55,-53".
func FormatChainSignal(chains []int8) string {
	if len(chains) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range chains {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
	return b.String()
}

// wextAssociatedBSSID validates a SIOCGIWAP address: all-zero, broadcast and
// the 44:44:44:44:44:44 "not associated" marker mean no BSS.
func wextAssociatedBSSID(b []byte) (net.HardwareAddr, bool) {
	if len(b) != 6 {
		return nil, false
	}
	zero, bcast, marker := true, true, true
	for _, v := range b {
		zero = zero && v == 0
		bcast = bcast && v == 0xff
		marker = marker && v == 0x44
	}
	if zero || bcast || marker || b[0]&1 != 0 {
		return nil, false
	}
	return append(net.HardwareAddr(nil), b...), true
}
