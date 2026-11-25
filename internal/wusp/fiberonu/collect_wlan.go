package fiberonu

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// ---- WLAN: radios, SSIDs, stations ----------------------------------------
//
// The EN7528 ONUs drive Wi-Fi with MediaTek's proprietary (Ralink-lineage)
// driver, mt7603eap.ko for 2.4 GHz: no mac80211, no /sys/class/ieee80211,
// no iw. The radio and SSID configuration lives in the firmware's config
// tree, which net-wlan.asp (2.4 GHz) and net-wlan11ac.asp (5 GHz) read:
//
//	WLan_Common / WLan11ac_Common     APOn, Channel, HT_BW, HT_BSSCoexistence,
//	                                  VHT_BW (5 GHz), WirelessMode, Country,
//	                                  CountryRegion, BssidNum, rt_device
//	WLan_Entry<n> / WLan11ac_Entry<n> SSID, EnableSSID, HideSSID, AuthMode,
//	                                  EncrypType, MaxStaNum
//
// SSID n of a band is interface ra<n> (2.4 GHz) or rai<n> (5 GHz): the
// firmware's libwlan_svc runs "ifconfig ra%d up", "brctl addif br0 rai%d"
// and "iwpriv ra%d set DisConnectSta=…" per SSID index. Keys and
// passphrases (WPAPSK, KeyPassphrase, Key1Str…, RADIUS_Key) are never read.

type wlanBand struct {
	band     string // "2.4GHz" / "5GHz"
	common   string // tcapi node with the radio settings
	entry    string // tcapi node prefix of the SSIDs
	ifPrefix string // interface prefix of the SSIDs
	vht      bool   // 5 GHz: bandwidth also depends on VHT_BW

	// Write side, as the band's page spells them: the nodes it commits
	// (TCWebApi_commit("WLan_Entry") / tcWebApi_commit("WLan11ac_Entry"),
	// TCWebApi_commit("WLan_Common") / tcWebApi_commit("Wlan11ac_Common"))
	// and the WebCurSet_Entry attribute that selects the SSID index the
	// entry commit applies (wlan_id / wlan_ac_id).
	commitCommon string
	commitEntry  string
	curSetAttr   string
}

var wlanBands = []wlanBand{
	{band: "2.4GHz", common: "WLan_Common", entry: "WLan_Entry", ifPrefix: "ra",
		commitCommon: "WLan_Common", commitEntry: "WLan_Entry", curSetAttr: "wlan_id"},
	{band: "5GHz", common: "WLan11ac_Common", entry: "WLan11ac_Entry", ifPrefix: "rai", vht: true,
		commitCommon: "Wlan11ac_Common", commitEntry: "WLan11ac_Entry", curSetAttr: "wlan_ac_id"},
}

// maxSSIDsPerBand bounds the SSID reads: the pages offer at most 8 SSIDs per
// band (SSID1-8 in sec-protocolfilter.asp; BssidNum defaults to 4).
const maxSSIDsPerBand = 8

// presentBands are the bands whose first SSID interface exists. The config
// tree carries WLan11ac nodes even on 2.4 GHz-only hardware, so a radio is
// reported only when the driver created its interface.
func presentBands(opts Options) []wlanBand {
	var out []wlanBand
	for _, b := range wlanBands {
		if _, err := os.Stat(filepath.Join(opts.sysClassNetDir(), b.ifPrefix+"0")); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// radioMainInterface is the first SSID interface of Radio.{idx}, the same
// enumeration the collector uses (used by the Radio.{i}.Enable setter).
func radioMainInterface(opts Options, idx int) string {
	bands := presentBands(opts)
	if idx < 1 || idx > len(bands) {
		return ""
	}
	return bands[idx-1].ifPrefix + "0"
}

// wirelessModeText names the WirelessMode codes the web pages offer:
// net-wlan.asp (stWlan) and net-wlan11ac.asp's mode select.
var wirelessModeText = map[string]string{
	"0":  "802.11b/g",
	"1":  "802.11b",
	"2":  "802.11a",
	"4":  "802.11g",
	"6":  "802.11n",
	"7":  "802.11g/n",
	"8":  "802.11a/n",
	"9":  "802.11b/g/n",
	"14": "802.11a/n/ac",
	"16": "802.11g/n/ax",
	"17": "802.11ax",
}

// channelWidth follows the web pages: 2.4 GHz HT_BW 0 is 20 MHz, 1 is
// 20/40 MHz with BSS coexistence and 40 MHz without (net-wlan.asp
// stWlan.BWControl); on 5 GHz HT_BW 0 is 20 MHz, otherwise VHT_BW picks
// 20/40, 80, 160 or 80+80 MHz (net-wlan11ac.asp selects).
func channelWidth(b wlanBand, htBW, coexistence, vhtBW string) string {
	switch htBW {
	case "":
		return ""
	case "0":
		return "20 MHz"
	}
	if !b.vht {
		if coexistence == "1" {
			return "20/40 MHz"
		}
		return "40 MHz"
	}
	switch vhtBW {
	case "1":
		return "80 MHz"
	case "2":
		return "160 MHz"
	case "3":
		return "80+80 MHz"
	default:
		return "20/40 MHz"
	}
}

type ssidRow struct {
	radio    int
	band     string
	index    int
	iface    string
	name     string
	enable   string
	hidden   string
	auth     string
	encrypt  string
	maxSta   string
	stations uint64
}

// wlanRadio is what collectWLAN read for one band, kept so the TR-181
// Device.WiFi publisher (collect_wifi_radios.go) reuses the reads instead of
// forking tcapi and iwpriv a second time. Empty strings were not read.
type wlanRadio struct {
	band     wlanBand
	index    int // Radio.{i}, 1-based
	enable   string
	channel  string
	htBW     string
	coex     string
	vhtBW    string
	modeCode string
	power    int64 // transmit power in percent, -2 when not read

	// What the radio's setters accept, for the TR-181 capability leaves.
	channels   []int
	bandwidths []string
}

// wlanSnapshot is the MediaTek WLAN state of one collection. tables holds
// the get_mac_table result per band (keyed by interface prefix); a band
// whose table could not be read is absent.
type wlanSnapshot struct {
	features wlanFeatures
	radios   []wlanRadio
	ssids    []ssidRow
	tables   map[string][]ralinkStation
}

// collectWLAN fills Network.Radio/SSID/Station and returns what it read
// from the MediaTek driver, or nil on a mac80211 build.
func collectWLAN(ctx context.Context, opts Options, tc *tcapiReader, msg *wusp.Message) *wlanSnapshot {
	bands := presentBands(opts)
	if len(bands) == 0 {
		// Not the MediaTek driver: fall back to mac80211 (sysfs + iw).
		collectMac80211Radios(msg)
		collectMac80211Stations(ctx, opts, msg)
		return nil
	}

	stations, tables := collectRalinkStations(ctx, opts, bands, msg)
	snap := &wlanSnapshot{tables: tables}

	var features wlanFeatures
	if tc != nil {
		features = readWLANFeatures(tc, false)
	}
	snap.features = features
	var ssids []ssidRow
	for i, b := range bands {
		radio := i + 1
		row := netPrefix + "Radio." + strconv.Itoa(radio) + "."
		get := func(attr string) string { return tc.get(b.common, attr) }
		msg.Set(row+"Band", wusp.String(b.band))

		count := maxSSIDsPerBand
		bssidNum := get("BssidNum")
		if n, err := strconv.Atoi(bssidNum); err == nil && n >= 1 && n <= maxSSIDsPerBand {
			count = n
			msg.Set(row+"SSIDCount", wusp.Uint(uint64(n)))
		}
		apOn := get("APOn")
		if apOn != "" {
			msg.Set(row+"Enable", wusp.Bool(apOn == "1"))
		}
		channel := get("Channel")
		if v, err := strconv.ParseUint(channel, 10, 64); err == nil {
			msg.Set(row+"Channel", wusp.Uint(v))
			msg.Set(row+"AutoChannel", wusp.Bool(v == 0))
		}
		coex := ""
		vht := ""
		htBW := get("HT_BW")
		if htBW != "" && htBW != "0" {
			if b.vht {
				vht = get("VHT_BW")
			} else {
				coex = get("HT_BSSCoexistence")
			}
		}
		if w := channelWidth(b, htBW, coex, vht); w != "" {
			msg.Set(row+"Bandwidth", wusp.String(w))
		}
		modeCode := get("WirelessMode")
		power := transmitPower(tc, b)
		if power >= 0 {
			msg.Set(row+"TxPower", wusp.Uint(uint64(power)))
		}
		if code := modeCode; code != "" {
			msg.Set(row+"ModeCode", wusp.String(code))
			text := wirelessModeText[code]
			if text == "" {
				text = "mode " + code
			}
			msg.Set(row+"Mode", wusp.String(text))
		}
		if v := get("Country"); v != "" {
			msg.Set(row+"Country", wusp.String(v))
		}
		region := get("CountryRegion")
		if region != "" {
			msg.Set(row+"CountryRegion", wusp.String(region))
		}
		chip := get("rt_device")
		bandFeatures := features
		bandFeatures.vht160 = b.vht && chip == "7615"
		channels, bandwidths := collectWLANCapabilities(tc, b, bandFeatures, modeCode, region, row, msg)
		snap.radios = append(snap.radios, wlanRadio{
			band: b, index: radio, enable: apOn, channel: channel,
			htBW: htBW, coex: coex, vhtBW: vht, modeCode: modeCode, power: power,
			channels: channels, bandwidths: bandwidths,
		})
		if chip != "" {
			msg.Set(row+"Chip", wusp.String(chip))
		}
		if up, ok := ifaceUp(opts, b.ifPrefix+"0"); ok {
			msg.Set(row+"Up", wusp.Bool(up))
		}

		var ifaces []string
		for n := 0; n < count; n++ {
			node := b.entry + strconv.Itoa(n)
			s := ssidRow{radio: radio, band: b.band, index: n, iface: b.ifPrefix + strconv.Itoa(n)}
			s.name = tc.get(node, "SSID")
			s.enable = tc.get(node, "EnableSSID")
			if s.name == "" && s.enable == "" {
				// Not configured. With BssidNum unknown this ends the band.
				if bssidNum == "" {
					break
				}
				continue
			}
			s.hidden = tc.get(node, "HideSSID")
			s.auth = tc.get(node, "AuthMode")
			s.encrypt = tc.get(node, "EncrypType")
			s.maxSta = tc.get(node, "MaxStaNum")
			s.stations = stations[s.iface]
			ifaces = append(ifaces, s.iface)
			ssids = append(ssids, s)
		}
		if len(ifaces) == 0 {
			ifaces = []string{b.ifPrefix + "0"}
		}
		msg.Set(row+"Interfaces", wusp.String(strings.Join(ifaces, ",")))
	}
	msg.Set(netPrefix+"RadioNumberOfEntries", wusp.Uint(uint64(len(bands))))

	for i, s := range ssids {
		row := netPrefix + "SSID." + strconv.Itoa(i+1) + "."
		msg.Set(row+"Name", wusp.String(s.name))
		msg.Set(row+"Radio", wusp.Uint(uint64(s.radio)))
		msg.Set(row+"Band", wusp.String(s.band))
		msg.Set(row+"Index", wusp.Uint(uint64(s.index+1)))
		msg.Set(row+"Interface", wusp.String(s.iface))
		if s.enable != "" {
			msg.Set(row+"Enable", wusp.Bool(s.enable == "1"))
		}
		if s.hidden != "" {
			msg.Set(row+"Hidden", wusp.Bool(s.hidden == "1"))
		}
		if s.auth != "" {
			msg.Set(row+"AuthMode", wusp.String(s.auth))
		}
		if s.encrypt != "" {
			msg.Set(row+"Encryption", wusp.String(s.encrypt))
		}
		if v, err := strconv.ParseUint(s.maxSta, 10, 64); err == nil {
			msg.Set(row+"MaxStations", wusp.Uint(v))
		}
		msg.Set(row+"StationCount", wusp.Uint(s.stations))
		if up, ok := ifaceUp(opts, s.iface); ok {
			msg.Set(row+"Up", wusp.Bool(up))
		}
	}
	msg.Set(netPrefix+"SSIDNumberOfEntries", wusp.Uint(uint64(len(ssids))))
	snap.ssids = ssids
	return snap
}

// ifaceUp reads IFF_UP from sysfs.
func ifaceUp(opts Options, name string) (bool, bool) {
	text := strings.TrimSpace(readFile(filepath.Join(opts.sysClassNetDir(), name, "flags")))
	v, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, 64)
	if err != nil {
		return false, false
	}
	return v&0x1 != 0, true
}

// ---- Stations from the MediaTek driver --------------------------------------
//
// `iwpriv <if> get_mac_table` is the driver's private ioctl that returns the
// association table to the caller (RTMPIoctlGetMacTable, "get_mac_table" in
// mt7603eap.ko's private table). `iwpriv <if> show stainfo`, which this
// collector used before, is a debug "show" handler that prints to the
// kernel log, so its stdout carries no stations. The table is per radio
// (every SSID of the band), so only the first interface of each band is
// asked; the BSS column says which SSID the client is on.
//
// Its format, from the driver's format strings:
//
//	"%-19s%-4s%-4s%-4s%-4s%-8s%-7s%-7s%-7s%-10s%-6s%-6s%-6s%-6s%-7s%-7s"
//	 MAC AID BSS PSM WMM MIMOPS RSSI0 RSSI1 RSSI2 PhMd BW MCS SGI STBC Idle Rate
//	then per client "%02X:…:%02X  " and the columns, ending "%-10d, %d, %d%%".
//
// The driver's newer (11ac) table layout, also in mt7603eap.ko and the one
// the 5 GHz driver's Show_MacTable_Proc dumps carry, adds a MODE column and
// folds the chains into one column:
//
//	"%-19s%-5s%-5s%-4s%-4s%-4s%-7s%-10s%-6s%-4s%-6s%-6s%-6s%-7s%-7s%-7s"
//	 MAC MODE AID BSS PSM WMM MIMOPS RSSI0/1/2[/3] PhMd BW MCS SGI STBC Idle Rate QosMap
//	with the RSSI cell printed "%-3d/%-3d/%-3d", so "-5 /-47/0  " can carry
//	padding inside the cell.

type ralinkStation struct {
	mac       string
	hasBSS    bool
	bss       int
	rssi      []int
	phyMode   string
	bandwidth string
	mcs       string
	rate      string
	powerSave string
}

var macRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

// slashPad joins a slash-separated cell that %-3d padding split ("-5 /-47").
var slashPad = regexp.MustCompile(`\s*/\s*`)

// parseMacTable reads get_mac_table output, header-driven so a driver that
// adds, drops or reorders columns still parses.
func parseMacTable(text string) []ralinkStation {
	out, _ := parseMacTableHeader(text)
	return out
}

// isMacTableHeader accepts the association-table header (MAC first, with AID
// and BSS columns); the WDS table ("MAC IDX AID …", no BSS) is not one.
func isMacTableHeader(fields []string) bool {
	if len(fields) < 3 || fields[0] != "MAC" {
		return false
	}
	aid, bss := false, false
	for _, f := range fields[1:] {
		aid = aid || f == "AID"
		bss = bss || f == "BSS"
	}
	return aid && bss
}

// parseMacTableHeader also reports whether an association-table header was
// seen: a header without rows is a read of zero clients, while output with
// no header (an error, or a driver that answers in binary) is no reading.
func parseMacTableHeader(text string) ([]ralinkStation, bool) {
	var header []string
	var out []ralinkStation
	seen := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(slashPad.ReplaceAllString(line, "/"))
		if len(fields) == 0 {
			continue
		}
		if isMacTableHeader(fields) {
			header = fields
			seen = true
			continue
		}
		if header == nil || !macRe.MatchString(fields[0]) {
			continue
		}
		col := func(name string) string {
			for i, h := range header {
				if h == name && i < len(fields) {
					return strings.TrimSuffix(fields[i], ",")
				}
			}
			return ""
		}
		st := ralinkStation{
			mac:       strings.ToLower(fields[0]),
			phyMode:   col("PhMd"),
			bandwidth: col("BW"),
			mcs:       col("MCS"),
			rate:      col("Rate"),
			powerSave: col("PSM"),
		}
		if n, err := strconv.Atoi(col("BSS")); err == nil && n >= 0 {
			st.bss, st.hasBSS = n, true
		}
		// One column per chain (RSSI0 RSSI1 RSSI2) or one folded column
		// (RSSI0/1/2, RSSI0/1/2/3).
		for i, h := range header {
			if !strings.HasPrefix(h, "RSSI") || i >= len(fields) {
				continue
			}
			for _, part := range strings.Split(strings.TrimSuffix(fields[i], ","), "/") {
				if v, err := strconv.Atoi(part); err == nil {
					st.rssi = append(st.rssi, v)
				}
			}
		}
		out = append(out, st)
	}
	return out, seen
}

// bestRSSI is the strongest chain that reports; 0 means an absent chain.
func bestRSSI(values []int) (int, bool) {
	best, ok := 0, false
	for _, v := range values {
		if v == 0 {
			continue
		}
		if !ok || v > best {
			best, ok = v, true
		}
	}
	return best, ok
}

// iwprivPath is where the firmware's own scripts run iwpriv from
// (libapi_lib_wifimgr: "/userfs/bin/iwpriv ra%d set …"); the bare name is
// tried first in case the agent's PATH has it.
const iwprivPath = "/userfs/bin/iwpriv"

// runIwpriv runs a read-only iwpriv query, falling back to the firmware's
// absolute path when iwpriv is not on PATH.
func runIwpriv(ctx context.Context, opts Options, args ...string) ([]byte, error) {
	out, err := opts.run(ctx, "iwpriv", args...)
	if err != nil && errors.Is(err, exec.ErrNotFound) {
		return opts.run(ctx, iwprivPath, args...)
	}
	return out, err
}

// collectRalinkStations fills Network.Station.* and returns the client count
// per SSID interface, plus each band's parsed table keyed by interface
// prefix (only for bands whose table was read).
func collectRalinkStations(ctx context.Context, opts Options, bands []wlanBand, msg *wusp.Message) (map[string]uint64, map[string][]ralinkStation) {
	counts := map[string]uint64{}
	tables := map[string][]ralinkStation{}
	idx := 0
	for _, b := range bands {
		main := b.ifPrefix + "0"
		out, err := runIwpriv(ctx, opts, main, "get_mac_table")
		if err != nil {
			continue
		}
		table, ok := parseMacTableHeader(string(out))
		if !ok {
			continue
		}
		tables[b.ifPrefix] = table
		for _, st := range table {
			idx++
			iface := b.ifPrefix + strconv.Itoa(st.bss)
			counts[iface]++
			row := netPrefix + "Station." + strconv.Itoa(idx) + "."
			msg.Set(row+"Interface", wusp.String(iface))
			msg.Set(row+"Band", wusp.String(b.band))
			msg.Set(row+"MACAddress", wusp.String(st.mac))
			if v, ok := bestRSSI(st.rssi); ok {
				msg.Set(row+"Signal", wusp.String(strconv.Itoa(v)+" dBm"))
			}
			if st.rate != "" {
				msg.Set(row+"TxBitrate", wusp.String(st.rate+" Mbit/s"))
			}
			if st.phyMode != "" {
				msg.Set(row+"PhyMode", wusp.String(st.phyMode))
			}
			if st.bandwidth != "" {
				msg.Set(row+"Bandwidth", wusp.String(st.bandwidth))
			}
			if st.mcs != "" {
				msg.Set(row+"MCS", wusp.String(st.mcs))
			}
			if st.powerSave != "" {
				msg.Set(row+"PowerSave", wusp.Bool(st.powerSave == "1"))
			}
		}
	}
	msg.Set(netPrefix+"StationNumberOfEntries", wusp.Uint(uint64(idx)))
	return counts, tables
}

// ---- mac80211 fallback (non-MediaTek builds) ---------------------------------

func collectMac80211Radios(msg *wusp.Message) {
	entries, err := os.ReadDir("/sys/class/ieee80211")
	if err != nil {
		return
	}
	idx := 0
	for _, entry := range entries {
		idx++
		name := entry.Name()
		row := netPrefix + "Radio." + strconv.Itoa(idx) + "."
		msg.Set(row+"Phy", wusp.String(name))
		phyDir := "/sys/class/ieee80211/" + name
		if ifaces, err := os.ReadDir(phyDir + "/device/net"); err == nil {
			var names []string
			for _, iface := range ifaces {
				names = append(names, iface.Name())
			}
			msg.Set(row+"Interfaces", wusp.String(strings.Join(names, ",")))
		}
		if band := strings.TrimSpace(readFile(phyDir + "/band")); band != "" {
			msg.Set(row+"Band", wusp.String(band))
		}
	}
	msg.Set(netPrefix+"RadioNumberOfEntries", wusp.Uint(uint64(idx)))
}

func collectMac80211Stations(ctx context.Context, opts Options, msg *wusp.Message) {
	stationIdx := 0
	for _, iface := range wlanInterfaces() {
		out, err := opts.run(ctx, "iw", "dev", iface, "station", "dump")
		if err != nil {
			continue
		}
		for _, block := range parseStationDump(string(out)) {
			stationIdx++
			row := netPrefix + "Station." + strconv.Itoa(stationIdx) + "."
			msg.Set(row+"Interface", wusp.String(iface))
			msg.Set(row+"MACAddress", wusp.String(block.mac))
			if block.signal != "" {
				msg.Set(row+"Signal", wusp.String(block.signal))
			}
			if block.rxRate != "" {
				msg.Set(row+"RxBitrate", wusp.String(block.rxRate))
			}
			if block.txRate != "" {
				msg.Set(row+"TxBitrate", wusp.String(block.txRate))
			}
			if block.rxBytes != 0 {
				msg.Set(row+"RxBytes", wusp.Uint(block.rxBytes))
			}
			if block.txBytes != 0 {
				msg.Set(row+"TxBytes", wusp.Uint(block.txBytes))
			}
			if block.connected != "" {
				msg.Set(row+"ConnectedTime", wusp.String(block.connected))
			}
			if block.inactive != "" {
				msg.Set(row+"InactiveTime", wusp.String(block.inactive))
			}
		}
	}
	msg.Set(netPrefix+"StationNumberOfEntries", wusp.Uint(uint64(stationIdx)))
}

func wlanInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, e := range entries {
		name := e.Name()
		if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err == nil {
			ifaces = append(ifaces, name)
		}
	}
	return ifaces
}

type stationInfo struct {
	mac       string
	signal    string
	rxRate    string
	txRate    string
	rxBytes   uint64
	txBytes   uint64
	connected string
	inactive  string
}

// parseStationDump reads `iw dev <if> station dump` (mac80211 only).
func parseStationDump(text string) []stationInfo {
	var stations []stationInfo
	var cur *stationInfo
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Station") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				stations = append(stations, stationInfo{mac: fields[1]})
				cur = &stations[len(stations)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		if k, v, ok := splitKV(line); ok {
			switch k {
			case "signal":
				cur.signal = v
			case "signal avg":
				if cur.signal == "" {
					cur.signal = v
				}
			case "rx bitrate":
				cur.rxRate = v
			case "tx bitrate":
				cur.txRate = v
			case "rx bytes":
				cur.rxBytes, _ = strconv.ParseUint(v, 10, 64)
			case "tx bytes":
				cur.txBytes, _ = strconv.ParseUint(v, 10, 64)
			case "connected time":
				cur.connected = v
			case "inactive time":
				cur.inactive = v
			}
		}
	}
	return stations
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}
