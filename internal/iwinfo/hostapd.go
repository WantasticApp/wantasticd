package iwinfo

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

// GetHostapdAssocList queries hostapd's native control socket. It does not
// require hostapd_cli and works on images which expose stations through wpad
// but not through a complete nl80211 driver.
func GetHostapdAssocList(ifName string) ([]AssocEntry, error) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" || strings.ContainsAny(ifName, "/\x00\r\n\t ") {
		return nil, fmt.Errorf("invalid hostapd interface %q", ifName)
	}
	return getHostapdAssocList(ifName)
}

// ParseHostapdStations decodes the MIB blocks returned by STA-FIRST and
// STA-NEXT. Presence flags preserve known zero counters.
func ParseHostapdStations(blocks ...string) []AssocEntry {
	entries := make([]AssocEntry, 0, len(blocks))
	for _, block := range blocks {
		entry, ok := parseHostapdStation(block)
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func parseHostapdStation(block string) (AssocEntry, bool) {
	var entry AssocEntry
	lines := strings.Split(strings.TrimSpace(block), "\n")
	if len(lines) == 0 {
		return entry, false
	}
	mac, err := net.ParseMAC(strings.TrimSpace(lines[0]))
	if err != nil || len(mac) != 6 || isZeroHardwareAddr(mac) || mac[0]&1 != 0 {
		return entry, false
	}
	entry.MAC = mac
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "flags":
			entry.AuthenticationKnown = true
			entry.Authenticated = strings.Contains(value, "[AUTHORIZED]") || strings.Contains(value, "[AUTH]")
			entry.OperatingStandard = hostapdStandard(value)
		case "signal", "signal_avg":
			if parsed, err := strconv.ParseInt(firstField(value), 10, 8); err == nil {
				if key == "signal" {
					entry.Signal, entry.SignalKnown = int8(parsed), true
				} else {
					entry.SignalAvg, entry.SignalAvgKnown = int8(parsed), true
				}
			}
		case "inactive_msec":
			entry.Inactive, entry.InactiveKnown = parseHostapdUint32(value)
		case "connected_time":
			entry.ConnectedTime, entry.ConnectedTimeKnown = parseHostapdUint32(value)
		case "rx_packets":
			entry.RxPackets, entry.RxPacketsKnown = parseHostapdUint32(value)
		case "tx_packets":
			entry.TxPackets, entry.TxPacketsKnown = parseHostapdUint32(value)
		case "rx_bytes", "rx_bytes64":
			entry.RxBytes, entry.RxBytesKnown = parseHostapdUint64(value)
		case "tx_bytes", "tx_bytes64":
			entry.TxBytes, entry.TxBytesKnown = parseHostapdUint64(value)
		case "tx_retries":
			entry.TxRetries, entry.TxRetriesKnown = parseHostapdUint32(value)
		case "tx_failed":
			entry.TxFailed, entry.TxFailedKnown = parseHostapdUint32(value)
		case "rx_rate", "rx_bitrate":
			entry.RxRate, entry.RxRateKnown = parseHostapdRate(value)
		case "tx_rate", "tx_bitrate":
			entry.TxRate, entry.TxRateKnown = parseHostapdRate(value)
		}
	}
	return entry, true
}

func hostapdStandard(flags string) string {
	switch {
	case strings.Contains(flags, "[EHT]"):
		return "be"
	case strings.Contains(flags, "[HE]"):
		return "ax"
	case strings.Contains(flags, "[VHT]"):
		return "ac"
	case strings.Contains(flags, "[HT]"):
		return "n"
	default:
		return ""
	}
}

func parseHostapdUint64(value string) (uint64, bool) {
	parsed, err := strconv.ParseUint(firstField(value), 10, 64)
	return parsed, err == nil
}

func parseHostapdUint32(value string) (uint32, bool) {
	parsed, ok := parseHostapdUint64(value)
	if !ok {
		return 0, false
	}
	if parsed > uint64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(parsed), true
}

func parseHostapdRate(value string) (uint32, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, false
	}
	rate, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
		return 0, false
	}
	if len(fields) > 1 {
		switch strings.ToLower(strings.Trim(fields[1], ",;")) {
		case "mbit/s", "mbps":
			rate *= 1000
		case "gbit/s", "gbps":
			rate *= 1000000
		case "kbit/s", "kbps":
		default:
			return 0, false
		}
	}
	if rate > float64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(rate), true
}

func firstField(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func isZeroHardwareAddr(value net.HardwareAddr) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
