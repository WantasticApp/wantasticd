package iwinfo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Pure decoders for the vendor station sources. They carry no build tag so
// they are unit-tested on every development OS; vendor_linux.go owns the
// ioctls and process execution.

const (
	// sizeof(struct ieee80211req_sta_info) in madwifi net80211/ieee80211_ioctl.h.
	madwifiStaInfoFixedLen = 118
	madwifiRateMaxSize     = 15
	// rssi2dbm(): MadWifi and QCA report RSSI in dB above a nominal -95 dBm
	// noise floor when the radio has no measured one.
	nominalNoiseFloor = -95
	maxVendorStations = 2048
	ifNameSize        = 16
)

// ErrVendorLayout means the driver answered STA_INFO with a record layout
// this build cannot decode safely.
var ErrVendorLayout = fmt.Errorf("vendor station layout not recognised")

var (
	wlanconfigAssocTime = regexp.MustCompile(`^\d+:\d{2}:\d{2}$`)
	wlanconfigRate      = regexp.MustCompile(`^(\d+(?:\.\d+)?)M$`)
)

// decodeMadwifiStaInfo walks the STA_INFO buffer. Every record must satisfy
// the MadWifi invariant isi_len == roundup(118 + isi_ie_len, 4); one failing
// record rejects the whole buffer so a different vendor layout can never be
// misread as stations.
func decodeMadwifiStaInfo(buf []byte, noise int, noiseKnown bool) ([]AssocEntry, error) {
	if len(buf) < madwifiStaInfoFixedLen {
		if len(buf) == 0 {
			return nil, nil
		}
		return nil, ErrVendorLayout
	}
	ne := binary.NativeEndian
	var out []AssocEntry
	for off := 0; len(buf)-off >= madwifiStaInfoFixedLen; {
		rec := buf[off:]
		isiLen := int(ne.Uint16(rec[0:]))
		ieLen := int(ne.Uint16(rec[38:]))
		want := (madwifiStaInfoFixedLen + ieLen + 3) &^ 3
		if isiLen != want || isiLen > len(rec) {
			return nil, ErrVendorLayout
		}
		freq := int(ne.Uint16(rec[2:]))
		if freq != 0 && (freq < 2300 || freq > 7300) {
			return nil, ErrVendorLayout
		}
		mac := net.HardwareAddr(append([]byte(nil), rec[14:20]...))
		aid := ne.Uint16(rec[40:]) & 0x3fff
		if !validStationMAC(mac) || aid > 2007 {
			return nil, ErrVendorLayout
		}
		rssi := int(rec[9])
		nrates := int(rec[20])
		txrate := int(rec[36])
		entry := AssocEntry{
			MAC:                 mac,
			Signal:              vendorClampInt8(noise + rssi),
			SignalKnown:         true,
			Noise:               vendorClampInt8(noise),
			NoiseKnown:          noiseKnown,
			Inactive:            uint32(ne.Uint16(rec[114:])) * 1000,
			InactiveKnown:       true,
			AssociationID:       aid,
			AuthenticationKnown: true,
			// IEEE80211_NODE_AUTH (0x0001) in isi_state.
			Authenticated: ne.Uint16(rec[6:])&0x0001 != 0,
			Source:        "madwifi-ioctl",
		}
		if nrates > madwifiRateMaxSize {
			nrates = madwifiRateMaxSize
		}
		if txrate < nrates {
			// IEEE80211_RATE_VAL: rate in 500 kbit/s units.
			entry.TxRate = uint32(rec[21+txrate]&0x7f) * 500
			entry.TxRateKnown = entry.TxRate > 0
		}
		out = append(out, entry)
		if len(out) > maxVendorStations {
			return nil, fmt.Errorf("station table exceeds %d entries", maxVendorStations)
		}
		off += isiLen
	}
	return out, nil
}

// madwifiNodeStatsLayout returns the offsets of the counters we read from
// struct ieee80211req_sta_stats (8-byte MAC union + ieee80211_nodestats) and
// the total struct size, honouring the ABI's 64-bit alignment (4 on i386).
func madwifiNodeStatsLayout() (rxData, rxBytes, txData, txBytes, size int) {
	align64 := 8
	if runtime.GOARCH == "386" {
		align64 = 4
	}
	off := 8
	field := func(width int) int {
		a := width
		if width == 8 {
			a = align64
		}
		off = (off + a - 1) &^ (a - 1)
		at := off
		off += width
		return at
	}
	rxData = field(4)
	field(4) // rx_mgmt
	field(4) // rx_ctrl
	field(4) // rx_ucast
	field(4) // rx_mcast
	rxBytes = field(8)
	field(8)                  // rx_beacons
	for i := 0; i < 13; i++ { // rx_proberesp .. rx_unencrypted
		field(4)
	}
	txData = field(4)
	field(4) // tx_mgmt
	field(4) // tx_ucast
	field(4) // tx_mcast
	txBytes = field(8)
	for i := 0; i < 16; i++ { // tx_probereq .. psq_drops
		field(4)
	}
	size = (off + align64 - 1) &^ (align64 - 1)
	return
}

// ParseWlanconfigStations parses `wlanconfig athN list sta` from MadWifi and
// every qca-wifi release. Only the leading columns are positional — ADDR AID
// CHAN then either RATE (MadWifi) or TXRATE RXRATE (QCA), RSSI, and on QCA
// MINRSSI MAXRSSI IDLE. Later columns can be empty (XCAPS, IEs), so ASSOCTIME,
// MODE and the NSS columns are located by shape instead of by index.
func ParseWlanconfigStations(output string, noise int, noiseKnown bool) []AssocEntry {
	var out []AssocEntry
	header := []string(nil)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "ADDR") {
			header = fields
			continue
		}
		mac, err := net.ParseMAC(fields[0])
		if err != nil || !validStationMAC(mac) || len(fields) < 5 {
			continue
		}
		entry := AssocEntry{MAC: mac, Source: "wlanconfig", RxMCS: -1, TxMCS: -1}
		col := func(name string) (string, bool) {
			for i, h := range header {
				if strings.EqualFold(h, name) && i < len(fields) {
					return fields[i], true
				}
			}
			return "", false
		}
		if v, ok := col("AID"); ok {
			if aid, err := strconv.ParseUint(v, 10, 16); err == nil && aid <= 2007 {
				entry.AssociationID = uint16(aid)
			}
		}
		if v, ok := col("TXRATE"); ok {
			entry.TxRate, entry.TxRateKnown = parseWlanconfigRate(v)
		} else if v, ok := col("RATE"); ok {
			entry.TxRate, entry.TxRateKnown = parseWlanconfigRate(v)
		}
		if v, ok := col("RXRATE"); ok {
			entry.RxRate, entry.RxRateKnown = parseWlanconfigRate(v)
		}
		if v, ok := col("RSSI"); ok {
			if rssi, err := strconv.Atoi(v); err == nil && rssi >= -128 && rssi <= 127 {
				if rssi > 0 {
					// QCA/MadWifi RSSI is dB above the noise floor.
					rssi += noise
				}
				if rssi < 0 {
					entry.Signal, entry.SignalKnown = vendorClampInt8(rssi), true
				}
			}
		}
		if noiseKnown {
			entry.Noise, entry.NoiseKnown = vendorClampInt8(noise), true
		}
		if v, ok := col("IDLE"); ok {
			if idle, err := strconv.ParseUint(v, 10, 32); err == nil && idle < 1<<22 {
				entry.Inactive, entry.InactiveKnown = uint32(idle)*1000, true
			}
		}
		for i := 3; i < len(fields); i++ {
			field := fields[i]
			switch {
			case wlanconfigAssocTime.MatchString(field):
				parts := strings.Split(field, ":")
				h, _ := strconv.Atoi(parts[0])
				m, _ := strconv.Atoi(parts[1])
				s, _ := strconv.Atoi(parts[2])
				entry.ConnectedTime, entry.ConnectedTimeKnown = uint32(h*3600+m*60+s), true
			case strings.HasPrefix(field, "IEEE80211_MODE_"):
				entry.OperatingStandard = wlanconfigStandard(field)
				if i+2 < len(fields) {
					if rx, err := strconv.ParseUint(fields[i+1], 10, 8); err == nil && rx > 0 && rx <= 16 {
						entry.RxNSS = uint8(rx)
					}
					if tx, err := strconv.ParseUint(fields[i+2], 10, 8); err == nil && tx > 0 && tx <= 16 {
						entry.TxNSS = uint8(tx)
					}
				}
			}
		}
		out = append(out, entry)
		if len(out) >= maxVendorStations {
			break
		}
	}
	return out
}

func parseWlanconfigRate(value string) (uint32, bool) {
	match := wlanconfigRate.FindStringSubmatch(value)
	if match == nil {
		return 0, false
	}
	mbps, err := strconv.ParseFloat(match[1], 64)
	if err != nil || mbps <= 0 || mbps > 100000 {
		return 0, false
	}
	return uint32(mbps * 1000), true
}

func wlanconfigStandard(mode string) string {
	mode = strings.ToUpper(mode)
	switch {
	case strings.Contains(mode, "_11BE"), strings.Contains(mode, "EHT"):
		return "be"
	case strings.Contains(mode, "_11AX"), strings.Contains(mode, "HE"):
		return "ax"
	case strings.Contains(mode, "_11AC"), strings.Contains(mode, "VHT"):
		return "ac"
	case strings.Contains(mode, "_11NA"), strings.Contains(mode, "_11NG"), strings.Contains(mode, "_HT"):
		return "n"
	case strings.HasSuffix(mode, "_11A"):
		return "a"
	case strings.HasSuffix(mode, "_11G"):
		return "g"
	case strings.HasSuffix(mode, "_11B"):
		return "b"
	}
	return ""
}

func parseProcNetWirelessNoise(data, ifname string) (int, bool) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ifname+":") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, ifname+":"))
		if len(fields) < 4 {
			return 0, false
		}
		noise, err := strconv.Atoi(strings.TrimSuffix(fields[3], "."))
		if err != nil {
			return 0, false
		}
		// Some drivers report the unsigned 8-bit encoding (256-95).
		if noise > 63 {
			noise -= 256
		}
		if noise >= -130 && noise < 0 {
			return noise, true
		}
		return 0, false
	}
	return 0, false
}

func validIfName(name string) bool {
	if name == "" || len(name) >= ifNameSize || strings.ContainsAny(name, "/\\ \t\n") || strings.HasPrefix(name, "-") || name == "." || name == ".." {
		return false
	}
	return true
}

func validStationMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

// vendorClampInt8 is local so the file also builds with the libiwinfo
// (-tags iwinfo) backend, which does not carry the pure-Go helpers.
func vendorClampInt8(value int) int8 {
	if value < -128 {
		return -128
	}
	if value > 127 {
		return 127
	}
	return int8(value)
}

// decodeVendorChanInfo decodes the IEEE80211_IOCTL_GETCHANINFO reply
// (struct ieee80211req_chaninfo: a channel count, then ic_chans[]). madwifi
// uses 8-byte entries {freq u16, flags u16, ieee u8, maxregpower s8, ...};
// qca-wifi releases widen the flags to 64 bits and append fields, which
// moves the array to an 8-byte boundary and changes the entry size. The
// layout is therefore inferred: the first header offset and entry size for
// which every entry's IEEE channel matches its frequency wins. The
// regulatory maximum power follows the channel number in all known layouts.
func decodeVendorChanInfo(buf []byte) []WiphyChannel {
	if len(buf) < 12 {
		return nil
	}
	count := int(binary.NativeEndian.Uint32(buf))
	if count < 3 || count > 255 {
		return nil
	}
	for _, header := range []int{4, 8} {
		for stride := 8; stride <= 64; stride++ {
			if header+count*stride > len(buf) {
				break
			}
			for ieeeOff := 2; ieeeOff < stride-1; ieeeOff++ {
				channels, ok := vendorChanLayout(buf, header, stride, ieeeOff, count)
				if ok {
					return channels
				}
			}
		}
	}
	return nil
}

func vendorChanLayout(buf []byte, header, stride, ieeeOff, count int) ([]WiphyChannel, bool) {
	out := make([]WiphyChannel, 0, count)
	distinct := map[int]bool{}
	for i := 0; i < count; i++ {
		entry := buf[header+i*stride:]
		freq := int(binary.NativeEndian.Uint16(entry))
		channel := FrequencyChannel(freq)
		if channel == 0 || int(entry[ieeeOff]) != channel {
			return nil, false
		}
		distinct[freq] = true
		power := int(int8(entry[ieeeOff+1]))
		if power < 1 || power > 40 {
			power = 0
		}
		out = append(out, WiphyChannel{Channel: channel, Frequency: freq, MaxPowerDBM: power})
	}
	// A real table lists distinct channels; a repeated pattern means the
	// stride is a multiple of the real one.
	return out, len(distinct) == count
}

// wiphyFromChannels groups a flat channel table into bands.
func wiphyFromChannels(channels []WiphyChannel) *Wiphy {
	byBand := map[string]*WiphyBand{}
	var order []string
	for _, ch := range channels {
		band := ""
		switch {
		case ch.Frequency < 2500:
			band = "2.4GHz"
		case ch.Frequency < 5925:
			band = "5GHz"
		default:
			band = "6GHz"
		}
		if byBand[band] == nil {
			byBand[band] = &WiphyBand{Band: band}
			order = append(order, band)
		}
		byBand[band].Channels = append(byBand[band].Channels, ch)
	}
	w := &Wiphy{Index: -1}
	for _, name := range []string{"2.4GHz", "5GHz", "6GHz"} {
		if b := byBand[name]; b != nil {
			w.Bands = append(w.Bands, *b)
		}
	}
	return w
}

// ── Self-calibrated STA_INFO decoding for qca-wifi ──────────────────────────
//
// qca-wifi keeps madwifi's ioctl but not its struct: fields are widened,
// reordered and, in 12.x, MLO/11be fields are appended, so records are
// longer than madwifi's and differ between builds. Only the leading u16
// isi_len (the full record length) is stable; the telemetry library in
// QSDK walks the buffer with it. Without the header, field offsets are
// learned by lining up one raw buffer with the same stations as printed by
// wlanconfig, keeping an offset only when it is the single one that agrees
// for every station.

type vendorStaLayout struct {
	macOff, aidOff, rssiOff, idleOff, txRateOff, rxRateOff int
}

// usable reports whether the layout carries enough to replace wlanconfig.
func (l vendorStaLayout) usable() bool {
	return l.macOff >= 0 && l.rssiOff >= 0 && (l.txRateOff >= 0 || l.rxRateOff >= 0)
}

// splitStaRecords walks variable-length records by their u16 length.
func splitStaRecords(buf []byte) [][]byte {
	var out [][]byte
	for off := 0; off+16 <= len(buf); {
		n := int(binary.NativeEndian.Uint16(buf[off:]))
		if n == 0 {
			break
		}
		if n < 16 || off+n > len(buf) {
			return nil
		}
		out = append(out, buf[off:off+n])
		off += n
	}
	return out
}

func near(a, b, tolerance int) bool { return a-b <= tolerance && b-a <= tolerance }

// calibrateStaLayout learns field offsets from raw records and the same
// stations parsed from wlanconfig (noise is what that parse added to RSSI).
func calibrateStaLayout(buf []byte, ref []AssocEntry, noise int) (vendorStaLayout, bool) {
	layout := vendorStaLayout{-1, -1, -1, -1, -1, -1}
	records := splitStaRecords(buf)
	if len(records) == 0 || len(records) != len(ref) {
		return layout, false
	}
	minLen := len(records[0])
	for _, r := range records {
		minLen = min(minLen, len(r))
	}
	byMAC := map[string]AssocEntry{}
	for _, e := range ref {
		byMAC[e.MAC.String()] = e
	}
	// MAC: the one offset where every record holds a distinct listed MAC.
	matched := make([]AssocEntry, len(records))
	for off := 2; off+6 <= minLen && layout.macOff < 0; off++ {
		seen := map[string]bool{}
		ok := true
		for i, r := range records {
			mac := net.HardwareAddr(r[off : off+6]).String()
			e, found := byMAC[mac]
			if !found || seen[mac] {
				ok = false
				break
			}
			seen[mac] = true
			matched[i] = e
		}
		if ok {
			layout.macOff = off
		}
	}
	if layout.macOff < 0 {
		return layout, false
	}
	ne := binary.NativeEndian
	unique := func(width int, accept func(r []byte, e AssocEntry, off int) bool, known func(AssocEntry) bool) int {
		found := -1
		for off := 2; off+width <= minLen; off++ {
			if off+width > layout.macOff && off < layout.macOff+6 {
				continue
			}
			ok, evidence := true, 0
			for i, r := range records {
				if !known(matched[i]) {
					continue
				}
				evidence++
				if !accept(r, matched[i], off) {
					ok = false
					break
				}
			}
			if !ok || evidence == 0 {
				continue
			}
			if found >= 0 {
				return -1 // ambiguous
			}
			found = off
		}
		return found
	}
	layout.aidOff = unique(2, func(r []byte, e AssocEntry, off int) bool {
		return ne.Uint16(r[off:])&0x3fff == e.AssociationID
	}, func(e AssocEntry) bool { return e.AssociationID != 0 })
	layout.rssiOff = unique(1, func(r []byte, e AssocEntry, off int) bool {
		return near(int(r[off]), int(e.Signal)-noise, 1)
	}, func(e AssocEntry) bool { return e.SignalKnown })
	layout.idleOff = unique(2, func(r []byte, e AssocEntry, off int) bool {
		return near(int(ne.Uint16(r[off:])), int(e.Inactive/1000), 1)
	}, func(e AssocEntry) bool { return e.InactiveKnown && e.Inactive >= 3000 })
	rate := func(r []byte, want uint32, off int) bool {
		v := ne.Uint32(r[off:])
		return v > 0 && near(int(v), int(want), 1000)
	}
	layout.txRateOff = unique(4, func(r []byte, e AssocEntry, off int) bool { return rate(r, e.TxRate, off) },
		func(e AssocEntry) bool { return e.TxRateKnown && e.TxRate > 0 })
	layout.rxRateOff = unique(4, func(r []byte, e AssocEntry, off int) bool { return rate(r, e.RxRate, off) },
		func(e AssocEntry) bool { return e.RxRateKnown && e.RxRate > 0 })
	return layout, layout.usable()
}

// decodeCalibratedStaInfo decodes records with a learned layout.
func decodeCalibratedStaInfo(buf []byte, l vendorStaLayout, noise int, noiseKnown bool) ([]AssocEntry, bool) {
	records := splitStaRecords(buf)
	if records == nil && len(buf) >= 16 && binary.NativeEndian.Uint16(buf) != 0 {
		return nil, false
	}
	ne := binary.NativeEndian
	out := make([]AssocEntry, 0, len(records))
	for _, r := range records {
		if l.macOff+6 > len(r) {
			return nil, false
		}
		mac := net.HardwareAddr(append([]byte(nil), r[l.macOff:l.macOff+6]...))
		if !validStationMAC(mac) {
			return nil, false
		}
		e := AssocEntry{MAC: mac, Source: "qca-ioctl", RxMCS: -1, TxMCS: -1}
		if l.aidOff >= 0 && l.aidOff+2 <= len(r) {
			e.AssociationID = ne.Uint16(r[l.aidOff:]) & 0x3fff
		}
		if l.rssiOff >= 0 && l.rssiOff < len(r) {
			if rssi := int(r[l.rssiOff]); rssi > 0 && rssi < 128 {
				e.Signal, e.SignalKnown = vendorClampInt8(noise+rssi), true
			}
		}
		if noiseKnown {
			e.Noise, e.NoiseKnown = vendorClampInt8(noise), true
		}
		if l.idleOff >= 0 && l.idleOff+2 <= len(r) {
			e.Inactive, e.InactiveKnown = uint32(ne.Uint16(r[l.idleOff:]))*1000, true
		}
		if l.txRateOff >= 0 && l.txRateOff+4 <= len(r) {
			e.TxRate, e.TxRateKnown = ne.Uint32(r[l.txRateOff:]), true
		}
		if l.rxRateOff >= 0 && l.rxRateOff+4 <= len(r) {
			e.RxRate, e.RxRateKnown = ne.Uint32(r[l.rxRateOff:]), true
		}
		out = append(out, e)
	}
	return out, true
}
