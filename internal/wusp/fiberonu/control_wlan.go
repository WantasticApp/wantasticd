package fiberonu

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// ---- Wi-Fi configuration writes ---------------------------------------------
//
// Every write here mirrors what the firmware's own pages do, read from the
// extracted image (boaroot/cgi-bin/net-wlan.asp for 2.4 GHz, net-wlan11ac.asp
// for 5 GHz, userfs/bin/boa, userfs/bin/tcapi, userfs/romfile_f.cfg):
//
//   - TCWebApi_set("WLan_Entry", attr, field) writes attribute attr of
//     WLan_Entry<wlan_id>, the SSID index the page selected first with
//     TCWebApi_set("WebCurSet_Entry","wlan_id", "wlSsidIdx") (2.4 GHz) or
//     tcWebApi_set("WebCurSet_Entry","wlan_ac_id","SSID_INDEX") (5 GHz).
//     The sets here name the indexed node directly (tcapi's own help:
//     "WLan_Entryx  WLAN SSIDx node, x: index, eg: WLan_Entry0"); the
//     WebCurSet_Entry index is still set before each entry, because the
//     entry commit is the page's un-indexed one and applies that index.
//   - The SSID name goes through TCWebApi_JsonHook("set_ssidname_info"),
//     which in boa is tcapi_get of the current index, charsetconv
//     (gb2312/utf-8) and tcapi_set(node, "SSID", name). For ASCII names the
//     conversion is the identity, so only printable ASCII names are accepted.
//   - 2.4 GHz save (Save_Flag=1): the sets, TCWebApi_commit("WLan_Entry"),
//     tcWebApi_save(), then TCWebApi_commit("WLan_Common"), tcWebApi_save().
//   - 5 GHz save (wlanWEPFlag=3): the sets, TCWebApi_save(),
//     tcWebApi_commit("WLan11ac_Entry"), then
//     tcWebApi_commit("Wlan11ac_Common") and TCWebApi_save().
//
// The pages post every field on each save, most of them unchanged. Only the
// attributes that change are set here (re-setting an attribute to its own
// value does not alter the store), and the page's companion attributes are
// set whenever the attribute they accompany changes. The pre-shared key is
// never read: a change that would need the existing key re-posted (moving
// from an open network to WPA) requires a new passphrase.
//
// 5 GHz channel, width and power follow the wlanWEPFlag=3 block: Channel
// from Channel_ID, HT_BW from WLANChannelBandwidth and, at 20/40 MHz or
// more, VHT_BW from WLan11acVHTChannelBandwidth (0 = 20/40, 1 = 20/40/80,
// 2 = 160 MHz, the last offered only when rt_device is 7615), TxPower from
// wlTxPwr (100/80/50/25/10). The page's TCWebApi_set("WLan_Common",
// "HT_EXTCHA", ...) in that block targets the 2.4 GHz node and is not
// copied. 11nMode/11acMode follow WirelessMode, which is not written on
// 5 GHz, so they are left as stored.
//
// Hiding SSID 1 of a band turns WPS off on it (WPSConfMode 0, the page's
// WpsConfModeNone): both pages disable WPS when the first SSID stops
// broadcasting. Neither page turns WPS off for WPA3 (the 5 GHz dowpscheck
// accepts WPA3PSK and WPA2PSKWPA3PSK with WPS), so a WPA3 change leaves it.
//
// Left out because the firmware does not prove them: the 5 GHz mode,
// WEP, 802.1X modes, country.

// wlanCommandTimeout bounds one tcapi set/commit/save. A commit rewrites the
// driver profile and restarts the interfaces, so it gets longer than a read.
const wlanCommandTimeout = 30 * time.Second

// 2.4 GHz channels per CountryRegion, as loadChannelList() in net-wlan.asp
// fills the channel select ("Auto" = 0 is always offered).
var wlan24Channels = map[string][]int{
	"0": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	"1": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	"2": {10, 11},
	"3": {10, 11, 12, 13},
	"4": {4},
	"5": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
	"6": {3, 4, 5, 6, 7, 8, 9},
}

// 5 GHz channels per CountryRegionABand, as net-wlan11ac.asp's
// RefreshChannPage() fills Channel_ID ("AUTO" = 0 is always offered).
// Region 0 is the MediaTek FCC plan without the 100-144 DFS block.
var wlan5Channels = map[string][]int{
	"0":  {36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165},
	"1":  {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140},
	"2":  {36, 40, 44, 48, 52, 56, 60, 64},
	"3":  {52, 56, 60, 64, 149, 153, 157, 161},
	"4":  {36, 52, 57, 149, 153, 157, 161, 165},
	"5":  {149, 153, 157, 161},
	"6":  {36, 40, 44, 48},
	"8":  {52, 56, 60, 64},
	"9":  {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165},
	"10": {36, 40, 44, 48, 149, 153, 157, 161, 165},
	"11": {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 149, 153, 157, 161},
}

// channelsFor is the channel list the page offers for the band's region.
// 2.4 GHz falls back to region 1 as the page does ("1 or else"); 5 GHz
// offers nothing but automatic for a region the page has no list for.
func channelsFor(b wlanBand, region string) []int {
	if b.vht {
		return wlan5Channels[region]
	}
	if list, ok := wlan24Channels[region]; ok {
		return list
	}
	return wlan24Channels["1"]
}

// 2.4 GHz modes the page's wlgMode select offers and the WirelessMode code
// SetCtlValue() posts for each.
var wlan24ModeCodes = map[string]string{
	"802.11b/g":   "0",
	"802.11b":     "1",
	"802.11g":     "4",
	"802.11n":     "6",
	"802.11g/n":   "7",
	"802.11b/g/n": "9",
}

var wlan24ModeOrder = []string{"802.11b/g/n", "802.11b/g", "802.11g/n", "802.11n", "802.11g", "802.11b"}

// The page shows the width control for b/g/n, n and (on 11ax builds) g/n/ax.
var wlanHTModes = map[string]bool{"6": true, "9": true, "16": true}

// 5 GHz: the page posts Is11nMode=1 for every mode past 802.11a (a/n 8,
// ac 14, ax 17) and Is11acMode=1 from 802.11ac on; only then does it show
// the width (HT_BW) and the VHT width (VHT_BW) selects.
var wlan5HTModes = map[string]bool{"8": true, "14": true, "17": true}
var wlan5VHTModes = map[string]bool{"14": true, "17": true}

// Transmit power the pages offer, in percent. 2.4 GHz posts the level
// (TxPowerLevel 1..5 = 100/80/60/40/20 %); 5 GHz posts the percent itself
// (TxPower; its options are labelled 100/80/60/40/20 % but carry
// 100/80/50/25/10).
var wlan24TxPowerLevels = map[uint64]string{100: "1", 80: "2", 60: "3", 40: "4", 20: "5"}
var wlan24TxPowers = []int{100, 80, 60, 40, 20}
var wlan5TxPowers = []int{100, 80, 50, 25, 10}

func txPowersFor(b wlanBand) []int {
	if b.vht {
		return wlan5TxPowers
	}
	return wlan24TxPowers
}

// maxStationsLimit is the largest client limit the firmware itself ships
// (romfile_f.cfg WLan_Entry0 MaxStaNum="40"); the pages only require a
// positive number.
const maxStationsLimit = 40

const rekeyIntervalDefault = "3600" // net-wlan11ac.asp default for keyRenewalInterval

var pskAuthModes = map[string]bool{"WPAPSK": true, "WPA2PSK": true, "WPAPSKWPA2PSK": true, "WPA3PSK": true, "WPA2PSKWPA3PSK": true}
var wpa3AuthModes = map[string]bool{"WPA3PSK": true, "WPA2PSKWPA3PSK": true}

// wlanFeatures are the WebCustom_Entry switches the pages test before
// offering a control.
type wlanFeatures struct {
	htbw40, wpa3, maxSta, npu, gud, perSSID bool
	vht160                                  bool // the 5 GHz chip is a 7615: 160 MHz is offered (set per band, from rt_device)
}

// readWLANFeatures reads the switches; the two that only refuse a write
// (npu, gud) are read when validating one, not on every collection.
func readWLANFeatures(tc *tcapiReader, forWrite bool) wlanFeatures {
	yes := func(attr string) bool { return tc.get("WebCustom_Entry", attr) == "Yes" }
	f := wlanFeatures{
		htbw40:  yes("isHTBW40M"),
		wpa3:    yes("isWPA3ModeSupported"),
		maxSta:  yes("isMaxStaNumSupported"),
		perSSID: yes("isPerSSIDSupport"),
	}
	if forWrite {
		f.npu = yes("isNPUSupported")
		f.gud = yes("isGUDSupported")
	}
	return f
}

// securityModes are the AuthMode values a band accepts through this agent.
func securityModes(f wlanFeatures) []string {
	modes := []string{"OPEN", "WPAPSK", "WPA2PSK", "WPAPSKWPA2PSK"}
	if f.wpa3 {
		modes = append(modes, "WPA3PSK", "WPA2PSKWPA3PSK")
	}
	return modes
}

func bandwidthChoices(b wlanBand, f wlanFeatures, modeCode string) []string {
	if b.vht {
		if !wlan5HTModes[modeCode] {
			return nil
		}
		out := []string{"20 MHz", "20/40 MHz"}
		if wlan5VHTModes[modeCode] {
			out = append(out, "80 MHz")
			if f.vht160 {
				out = append(out, "160 MHz")
			}
		}
		return out
	}
	if !wlanHTModes[modeCode] {
		return nil
	}
	out := []string{"20 MHz", "20/40 MHz"}
	if f.htbw40 {
		out = append(out, "40 MHz")
	}
	return out
}

func radioWritable(b wlanBand, f wlanFeatures, modeCode string) []string {
	out := []string{"Enable", "Channel"}
	if !b.vht {
		out = append(out, "Mode")
	}
	if len(bandwidthChoices(b, f, modeCode)) > 0 {
		out = append(out, "Bandwidth")
	}
	return append(out, "TxPower")
}

func ssidWritable(b wlanBand, f wlanFeatures) []string {
	out := []string{"Name", "Hidden", "AuthMode", "Encryption", "Passphrase"}
	if !b.vht || f.perSSID {
		out = append(out, "Enable")
	}
	if b.vht || f.maxSta {
		out = append(out, "MaxStations")
	}
	return out
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

// collectWLANCapabilities reports what this agent can change on a radio and
// the choices the firmware page offers, so the console renders its editor
// from the device instead of a fixed list. Read-only: tcapi get only. It
// returns the channels and widths the setters accept.
func collectWLANCapabilities(tc *tcapiReader, b wlanBand, f wlanFeatures, modeCode, region, row string, msg *wusp.Message) ([]int, []string) {
	if tc == nil {
		return nil, nil
	}
	if b.vht {
		region = tc.get(b.common, "CountryRegionABand")
	}
	channels := channelsFor(b, region)
	if len(channels) > 0 {
		msg.Set(row+"ChannelsAvailable", wusp.String(joinInts(channels)))
	}
	if !b.vht {
		switch tc.get(b.common, "HT_EXTCHA") {
		case "1":
			msg.Set(row+"ExtensionChannel", wusp.String("above"))
		case "0":
			msg.Set(row+"ExtensionChannel", wusp.String("below"))
		}
		msg.Set(row+"ModesAvailable", wusp.String(strings.Join(wlan24ModeOrder, ",")))
	}
	bandwidths := bandwidthChoices(b, f, modeCode)
	if len(bandwidths) > 0 {
		msg.Set(row+"BandwidthsAvailable", wusp.String(strings.Join(bandwidths, ",")))
	}
	msg.Set(row+"TxPowersAvailable", wusp.String(joinInts(txPowersFor(b))))
	msg.Set(row+"SecurityModesAvailable", wusp.String(strings.Join(securityModes(f), ",")))
	msg.Set(row+"Writable", wusp.String(strings.Join(radioWritable(b, f, modeCode), ",")))
	msg.Set(row+"SSIDWritable", wusp.String(strings.Join(ssidWritable(b, f), ",")))
	return channels, bandwidths
}

// ---- change set --------------------------------------------------------------

type radioChange struct {
	enable    *bool
	channel   *uint64
	auto      *bool // TR-181 AutoChannelEnable
	bandwidth *string
	bwTR181   bool // bandwidth is a TR-181 OperatingChannelBandwidth value
	mode      *string
	txPower   *uint64 // percent
}

type ssidChange struct {
	iface      string // optional guard: the interface the console saw on this row
	name       *string
	enable     *bool
	hidden     *bool
	auth       *string
	encryption *string
	passphrase *string
	maxSta     *uint64
}

type wlanChangeSet struct {
	radios map[int]*radioChange
	ssids  map[int]*ssidChange
}

func (c *wlanChangeSet) radio(i int) *radioChange {
	if c.radios == nil {
		c.radios = map[int]*radioChange{}
	}
	if c.radios[i] == nil {
		c.radios[i] = &radioChange{}
	}
	return c.radios[i]
}

func (c *wlanChangeSet) ssid(i int) *ssidChange {
	if c.ssids == nil {
		c.ssids = map[int]*ssidChange{}
	}
	if c.ssids[i] == nil {
		c.ssids[i] = &ssidChange{}
	}
	return c.ssids[i]
}

func (c *wlanChangeSet) empty() bool {
	for _, r := range c.radios {
		if r.enable != nil || r.channel != nil || r.auto != nil || r.bandwidth != nil || r.mode != nil || r.txPower != nil {
			return false
		}
	}
	for _, s := range c.ssids {
		if s.name != nil || s.enable != nil || s.hidden != nil || s.auth != nil || s.encryption != nil || s.passphrase != nil || s.maxSta != nil {
			return false
		}
	}
	return true
}

// isWLANConfigLeaf says whether a Network.* relative path is one of the
// Wi-Fi configuration leaves handled here (Radio.{i}.Enable included).
func isWLANConfigLeaf(rest string) bool {
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return false
	}
	switch parts[0] {
	case "Radio":
		switch parts[2] {
		case "Enable", "Channel", "Bandwidth", "Mode", "TxPower":
			return true
		}
	case "SSID":
		switch parts[2] {
		case "Name", "Enable", "Hidden", "AuthMode", "Encryption", "Passphrase", "MaxStations", "Interface":
			return true
		}
	}
	return false
}

func parseBoolValue(leaf, text string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "true", "1":
		v := true
		return &v, nil
	case "false", "0":
		v := false
		return &v, nil
	}
	return nil, fmt.Errorf("onu wlan: %s must be true or false", leaf)
}

// add records one leaf of a change set. The value text is not echoed in
// errors for Passphrase.
func (c *wlanChangeSet) add(rest, text string) error {
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return wusp.ErrUSPPathUnsupported
	}
	idx, err := strconv.Atoi(parts[1])
	if err != nil || idx < 1 {
		return wusp.ErrUSPPathUnsupported
	}
	leaf := parts[0] + "." + parts[2]
	switch leaf {
	case "Radio.Enable":
		v, err := parseBoolValue(leaf, text)
		if err != nil {
			return err
		}
		c.radio(idx).enable = v
	case "Radio.Channel":
		v, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
		if err != nil {
			return fmt.Errorf("onu wlan: Radio.Channel must be a channel number, or 0 for automatic")
		}
		c.radio(idx).channel = &v
	case "Radio.Bandwidth":
		v := strings.TrimSpace(text)
		c.radio(idx).bandwidth = &v
	case "Radio.Mode":
		v := strings.TrimSpace(text)
		c.radio(idx).mode = &v
	case "Radio.TxPower":
		v, err := strconv.ParseUint(strings.TrimSpace(text), 10, 8)
		if err != nil {
			return fmt.Errorf("onu wlan: Radio.TxPower must be a percentage")
		}
		c.radio(idx).txPower = &v
	case "SSID.Interface":
		c.ssid(idx).iface = strings.TrimSpace(text)
	case "SSID.Name":
		v := text
		c.ssid(idx).name = &v
	case "SSID.Enable":
		v, err := parseBoolValue(leaf, text)
		if err != nil {
			return err
		}
		c.ssid(idx).enable = v
	case "SSID.Hidden":
		v, err := parseBoolValue(leaf, text)
		if err != nil {
			return err
		}
		c.ssid(idx).hidden = v
	case "SSID.AuthMode":
		v := strings.TrimSpace(text)
		c.ssid(idx).auth = &v
	case "SSID.Encryption":
		v := strings.TrimSpace(text)
		c.ssid(idx).encryption = &v
	case "SSID.Passphrase":
		v := text
		c.ssid(idx).passphrase = &v
	case "SSID.MaxStations":
		v, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
		if err != nil {
			return fmt.Errorf("onu wlan: SSID.MaxStations must be a whole number")
		}
		c.ssid(idx).maxSta = &v
	default:
		return wusp.ErrUSPPathUnsupported
	}
	return nil
}

// setWLANParam applies one Wi-Fi leaf as its own change set.
func setWLANParam(ctx context.Context, opts Options, rest string, value wusp.Value) error {
	var change wlanChangeSet
	if err := change.add(rest, wusp.ValueToString(value)); err != nil {
		return err
	}
	return applyWLAN(ctx, opts, &change)
}

// applyWLANOperate runs Network.WLAN.Apply(): the input carries the changed
// leaves by their own parameter paths (…Network.Radio.1.Channel,
// …Network.SSID.2.Name, …Network.SSID.2.Passphrase, or their TR-181 names
// Device.WiFi.Radio.1.Channel, Device.WiFi.AccessPoint.2.Security.
// KeyPassphrase), validated together and committed once per band.
func applyWLANOperate(ctx context.Context, opts Options, input *wusp.Message) error {
	if input == nil {
		return fmt.Errorf("onu wlan: Apply() needs the changed settings as input")
	}
	const prefix = wusp.WUSPONUPrefix + "Network."
	var change wlanChangeSet
	for _, field := range input.Fields {
		path := strings.TrimSpace(field.Path)
		if isWiFiTR181Leaf(path) {
			// The TR-181 Device.WiFi names of the same settings.
			if err := change.addTR181(path, wusp.ValueToString(field.Val)); err != nil {
				return err
			}
			continue
		}
		rest, ok := strings.CutPrefix(path, prefix)
		if !ok || !isWLANConfigLeaf(rest) {
			return fmt.Errorf("onu wlan: Apply() does not accept input %q", fieldPathForError(field.Path))
		}
		if err := change.add(rest, wusp.ValueToString(field.Val)); err != nil {
			return err
		}
	}
	return applyWLAN(ctx, opts, &change)
}

func fieldPathForError(path string) string {
	if len(path) > 96 {
		return path[:96]
	}
	return path
}

// ---- resolution and validation -------------------------------------------------

type ssidSlot struct {
	band  wlanBand
	radio int
	n     int // entry index, 0-based
	name  string
}

// enumerateSSIDs lists SSID.{i} in the collector's order (collectWLAN), so
// a row and its setter always agree.
func enumerateSSIDs(tc *tcapiReader, bands []wlanBand) []ssidSlot {
	var out []ssidSlot
	for i, b := range bands {
		count := maxSSIDsPerBand
		bssidNum := tc.get(b.common, "BssidNum")
		if n, err := strconv.Atoi(bssidNum); err == nil && n >= 1 && n <= maxSSIDsPerBand {
			count = n
		}
		for n := 0; n < count; n++ {
			node := b.entry + strconv.Itoa(n)
			name := tc.get(node, "SSID")
			if name == "" && tc.get(node, "EnableSSID") == "" {
				if bssidNum == "" {
					break
				}
				continue
			}
			out = append(out, ssidSlot{band: b, radio: i + 1, n: n, name: name})
		}
	}
	return out
}

type tcapiWrite struct {
	node, attr, value string
	secret            bool
}

// bandPlan is the validated work for one band: sets on the common node,
// sets per entry, in the page's order.
type bandPlan struct {
	band    wlanBand
	common  []tcapiWrite
	entries map[int][]tcapiWrite
}

func boolAttr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func validPassphrase(b wlanBand, p string) error {
	if len(p) == 64 {
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return errors.New("onu wlan: a 64-character password must be hexadecimal")
			}
		}
		return nil
	}
	if len(p) < 8 || len(p) > 63 {
		return errors.New("onu wlan: the password must be 8 to 63 characters, or 64 hexadecimal digits")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c > 0x7e {
			return errors.New("onu wlan: the password must use printable ASCII characters only")
		}
		if !b.vht && c == ',' {
			return errors.New("onu wlan: the password must not contain a comma")
		}
		if b.vht && c == '"' {
			return errors.New("onu wlan: the password must not contain a double quote")
		}
	}
	return nil
}

func validSSIDName(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return errors.New("onu wlan: the network name must be 1 to 32 characters")
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return errors.New("onu wlan: the network name must use printable ASCII characters only")
		}
	}
	if name[len(name)-1] == ' ' {
		return errors.New("onu wlan: the network name must not end with a space")
	}
	return nil
}

// extChannel24 is HT_EXTCHA as WLANExtensionChannelChange() derives it from
// the channel select's index (index 0 is Auto): the first five entries take
// the upper extension channel, the ninth onwards the lower one, and the
// ones between keep the stored choice (0 when unset).
func extChannel24(channels []int, channel uint64, current string) string {
	idx := 0
	for i, c := range channels {
		if uint64(c) == channel {
			idx = i + 1
			break
		}
	}
	switch {
	case idx <= 4:
		return "1"
	case idx >= 8:
		return "0"
	case current == "1":
		return "1"
	}
	return "0"
}

func planRadio(tc *tcapiReader, b wlanBand, f wlanFeatures, idx int, rc *radioChange, slots []ssidSlot, plan *bandPlan) error {
	label := "Radio." + strconv.Itoa(idx)
	if b.vht && rc.mode != nil {
		return fmt.Errorf("onu wlan: %s: the 5 GHz mode cannot be changed by this agent", label)
	}
	modeCode := tc.get(b.common, "WirelessMode")
	if rc.mode != nil {
		code, ok := wlan24ModeCodes[*rc.mode]
		if !ok {
			return fmt.Errorf("onu wlan: %s: mode %q is not offered; choose one of %s", label, *rc.mode, strings.Join(wlan24ModeOrder, ", "))
		}
		if code == "6" {
			// The page offers only AES and no WEP when the mode is 802.11n.
			for _, s := range slots {
				if s.band.common != b.common {
					continue
				}
				node := b.entry + strconv.Itoa(s.n)
				auth := tc.get(node, "AuthMode")
				enc := tc.get(node, "EncrypType")
				if strings.HasPrefix(auth, "WEP") || strings.Contains(enc, "TKIP") {
					return fmt.Errorf("onu wlan: %s: 802.11n needs AES on every network; %q uses %s/%s", label, s.name, auth, enc)
				}
			}
		}
		modeCode = code
	}

	// Channel: 0 is automatic; otherwise one the page offers for the
	// configured region (CountryRegion / CountryRegionABand).
	regionAttr := "CountryRegion"
	if b.vht {
		regionAttr = "CountryRegionABand"
	}
	channels := channelsFor(b, tc.get(b.common, regionAttr))
	channel := uint64(0)
	if v, err := strconv.ParseUint(tc.get(b.common, "Channel"), 10, 16); err == nil {
		channel = v
	}
	newChannel := rc.channel
	if rc.auto != nil {
		switch {
		case *rc.auto && rc.channel != nil && *rc.channel != 0:
			return fmt.Errorf("onu wlan: %s: automatic channel selection and channel %d were both asked for", label, *rc.channel)
		case *rc.auto:
			zero := uint64(0)
			newChannel = &zero
		case rc.channel != nil && *rc.channel == 0:
			return fmt.Errorf("onu wlan: %s: automatic channel selection was turned off but channel 0 (automatic) was asked for", label)
		case rc.channel == nil && channel == 0:
			// Turning automatic selection off keeps the channel the radio
			// operates on now, as TR-181 asks.
			cur, err := strconv.ParseUint(tc.get(wifiInfoNode(b), "CurrentChannel"), 10, 16)
			if err != nil || cur == 0 {
				return fmt.Errorf("onu wlan: %s: the operating channel could not be read; set a channel instead", label)
			}
			newChannel = &cur
		}
	}
	if newChannel != nil {
		ok := *newChannel == 0
		for _, c := range channels {
			if uint64(c) == *newChannel {
				ok = true
			}
		}
		if !ok {
			if len(channels) == 0 {
				return fmt.Errorf("onu wlan: %s: this region has no channel list; only 0 (automatic) is accepted", label)
			}
			return fmt.Errorf("onu wlan: %s: channel %d is not offered in this region; choose 0 (automatic) or one of %s", label, *newChannel, joinInts(channels))
		}
		channel = *newChannel
	}

	// Width, in the vendor names (a TR-181 value is translated first).
	bandwidth := ""
	if rc.bandwidth != nil {
		bandwidth = *rc.bandwidth
		if rc.bwTR181 {
			v, err := tr181BandwidthToVendor(b, bandwidth)
			if err != nil {
				return fmt.Errorf("onu wlan: %s: %v", label, err)
			}
			bandwidth = v
		}
		choices := bandwidthChoices(b, f, modeCode)
		ok := false
		for _, c := range choices {
			if c == bandwidth {
				ok = true
			}
		}
		if !ok {
			if len(choices) == 0 {
				if b.vht {
					return fmt.Errorf("onu wlan: %s: the channel width can only be set in an 802.11n or 802.11ac mode", label)
				}
				return fmt.Errorf("onu wlan: %s: the channel width can only be set in an 802.11n mode", label)
			}
			return fmt.Errorf("onu wlan: %s: width %q is not offered; choose one of %s", label, bandwidth, strings.Join(choices, ", "))
		}
	}

	// Transmit power, in percent.
	powerValue := ""
	if rc.txPower != nil {
		for _, p := range txPowersFor(b) {
			if uint64(p) == *rc.txPower {
				powerValue = strconv.Itoa(p)
				if !b.vht {
					powerValue = wlan24TxPowerLevels[*rc.txPower]
				}
			}
		}
		if powerValue == "" {
			return fmt.Errorf("onu wlan: %s: transmit power %d%% is not offered; choose one of %s", label, *rc.txPower, joinInts(txPowersFor(b)))
		}
	}

	set := func(attr, value string) {
		plan.common = append(plan.common, tcapiWrite{node: b.common, attr: attr, value: value})
	}
	if b.vht {
		// net-wlan11ac.asp wlanWEPFlag=3 order: TxPower, Channel, APOn,
		// HT_BW, VHT_BW.
		if rc.txPower != nil {
			set("TxPower", powerValue)
		}
		if newChannel != nil {
			set("Channel", strconv.FormatUint(channel, 10))
		}
		if rc.enable != nil {
			set("APOn", boolAttr(*rc.enable))
		}
		switch bandwidth {
		case "20 MHz":
			set("HT_BW", "0")
		case "20/40 MHz":
			set("HT_BW", "1")
			set("VHT_BW", "0")
		case "80 MHz":
			set("HT_BW", "1")
			set("VHT_BW", "1")
		case "160 MHz":
			set("HT_BW", "1")
			set("VHT_BW", "2")
		}
		return nil
	}

	// net-wlan.asp Save_Flag order: APOn, WirelessMode, Channel,
	// TxPowerLevel, HT_BW, HT_EXTCHA, HT_BSSCoexistence.
	if rc.enable != nil {
		set("APOn", boolAttr(*rc.enable))
	}
	if rc.mode != nil {
		set("WirelessMode", modeCode)
	}
	if newChannel != nil {
		set("Channel", strconv.FormatUint(channel, 10))
	}
	if rc.txPower != nil {
		set("TxPowerLevel", powerValue)
	}
	htBW := tc.get(b.common, "HT_BW")
	coex := ""
	switch bandwidth {
	case "20 MHz":
		htBW, coex = "0", "0"
	case "20/40 MHz":
		htBW, coex = "1", "1"
	case "40 MHz":
		htBW, coex = "1", "0"
	}
	if bandwidth != "" {
		set("HT_BW", htBW)
	}
	// Companions, in the page's order: HT_EXTCHA follows HT_BW and the
	// channel; HT_BSSCoexistence follows the width.
	if bandwidth != "" || (newChannel != nil && htBW == "1") {
		ext := "0"
		if htBW == "1" {
			ext = extChannel24(channels, channel, tc.get(b.common, "HT_EXTCHA"))
		}
		set("HT_EXTCHA", ext)
	}
	if bandwidth != "" {
		set("HT_BSSCoexistence", coex)
	}
	return nil
}

func planSSID(tc *tcapiReader, f wlanFeatures, idx int, slot ssidSlot, sc *ssidChange, slots []ssidSlot, pendingMode string, plan *bandPlan) error {
	b := slot.band
	label := "SSID." + strconv.Itoa(idx)
	node := b.entry + strconv.Itoa(slot.n)
	iface := b.ifPrefix + strconv.Itoa(slot.n)
	if sc.iface != "" && sc.iface != iface {
		return fmt.Errorf("onu wlan: %s is now %s, not %s: refresh and try again", label, iface, sc.iface)
	}
	var writes []tcapiWrite
	set := func(attr, value string) { writes = append(writes, tcapiWrite{node: node, attr: attr, value: value}) }

	if sc.maxSta != nil {
		if !b.vht && !f.maxSta {
			return fmt.Errorf("onu wlan: %s: this firmware does not offer a client limit on 2.4 GHz", label)
		}
		min := uint64(1)
		if b.vht {
			min = 0
		}
		if *sc.maxSta < min || *sc.maxSta > maxStationsLimit {
			return fmt.Errorf("onu wlan: %s: the client limit must be %d to %d", label, min, maxStationsLimit)
		}
	}
	if sc.name != nil {
		if err := validSSIDName(*sc.name); err != nil {
			return err
		}
		if f.gud && slot.n == 0 && !strings.HasPrefix(*sc.name, "CMCC-") {
			return fmt.Errorf("onu wlan: %s: this firmware requires the first network name to start with CMCC-", label)
		}
		if f.npu && b.vht && slot.n != 0 && *sc.name != slot.name {
			return fmt.Errorf("onu wlan: %s: this firmware does not allow renaming this 5 GHz network", label)
		}
		for _, other := range slots {
			if other.band.common == b.common && other.n != slot.n && other.name == *sc.name {
				return fmt.Errorf("onu wlan: %s: another network on this radio already uses that name", label)
			}
		}
	}
	if sc.enable != nil && b.vht && !f.perSSID {
		return fmt.Errorf("onu wlan: %s: this firmware does not offer switching 5 GHz networks individually", label)
	}

	// Security: AuthMode, EncrypType and the key are validated as one.
	security := sc.auth != nil || sc.encryption != nil || sc.passphrase != nil
	var auth, enc string
	if security {
		curAuth := tc.get(node, "AuthMode")
		auth = curAuth
		if sc.auth != nil {
			auth = *sc.auth
		}
		offered := false
		for _, m := range securityModes(f) {
			if m == auth {
				offered = true
			}
		}
		if !offered {
			return fmt.Errorf("onu wlan: %s: security %q is not offered; choose one of %s", label, auth, strings.Join(securityModes(f), ", "))
		}
		if auth == "OPEN" {
			if sc.passphrase != nil {
				return fmt.Errorf("onu wlan: %s: an open network takes no password", label)
			}
			if sc.encryption != nil && *sc.encryption != "NONE" {
				return fmt.Errorf("onu wlan: %s: an open network uses encryption NONE", label)
			}
			enc = "NONE"
		} else {
			enc = tc.get(node, "EncrypType")
			if sc.encryption != nil {
				enc = *sc.encryption
			} else if enc != "TKIP" && enc != "AES" && enc != "TKIPAES" || wpa3AuthModes[auth] {
				enc = "AES"
			}
			allowed := []string{"TKIP", "AES", "TKIPAES"}
			modeCode := pendingMode
			if modeCode == "" && !b.vht {
				modeCode = tc.get(b.common, "WirelessMode")
			}
			if wpa3AuthModes[auth] || (!b.vht && modeCode == "6") {
				allowed = []string{"AES"}
			}
			ok := false
			for _, a := range allowed {
				if a == enc {
					ok = true
				}
			}
			if !ok {
				return fmt.Errorf("onu wlan: %s: encryption %q is not offered with %s; choose one of %s", label, enc, auth, strings.Join(allowed, ", "))
			}
			if sc.passphrase == nil && !pskAuthModes[curAuth] {
				return fmt.Errorf("onu wlan: %s: set a password when turning on %s", label, auth)
			}
			if sc.passphrase != nil {
				if err := validPassphrase(b, *sc.passphrase); err != nil {
					return err
				}
				if f.npu && !b.vht && slot.n != 0 {
					return fmt.Errorf("onu wlan: %s: this firmware does not allow changing this network's password", label)
				}
			}
		}
	}

	// Sets in each page's own order.
	if b.vht {
		if sc.maxSta != nil {
			set("MaxStaNum", strconv.FormatUint(*sc.maxSta, 10))
		}
		if sc.name != nil {
			set("SSID", *sc.name)
		}
		if sc.hidden != nil {
			set("HideSSID", boolAttr(*sc.hidden))
		}
		if sc.enable != nil {
			set("EnableSSID", boolAttr(*sc.enable))
		}
	} else {
		if sc.hidden != nil {
			set("HideSSID", boolAttr(*sc.hidden))
		}
		if sc.name != nil {
			set("SSID", *sc.name)
		}
		if sc.enable != nil {
			set("EnableSSID", boolAttr(*sc.enable))
		}
		if sc.maxSta != nil {
			set("MaxStaNum", strconv.FormatUint(*sc.maxSta, 10))
		}
	}
	if security {
		set("AuthMode", auth)
		if sc.passphrase != nil {
			writes = append(writes, tcapiWrite{node: node, attr: "WPAPSK", value: *sc.passphrase, secret: true})
		}
		set("EncrypType", enc)
		// The 5 GHz page posts RekeyInterval with every PSK mode, 3600
		// when the store has none.
		if b.vht && auth != "OPEN" && tc.get(node, "RekeyInterval") == "" {
			set("RekeyInterval", rekeyIntervalDefault)
		}
	}
	// Hiding the first SSID turns WPS off on it, as both pages do
	// (net-wlan.asp: WpsActive=0 posts WPSConfMode=WpsConfModeNone, "0";
	// net-wlan11ac.asp doBroadcastSSIDChange: "WPS will be disabled!").
	if sc.hidden != nil && *sc.hidden && slot.n == 0 {
		if mode := tc.get(node, "WPSConfMode"); mode != "" && mode != "0" {
			set("WPSConfMode", "0")
		}
	}
	if len(writes) > 0 {
		if plan.entries == nil {
			plan.entries = map[int][]tcapiWrite{}
		}
		plan.entries[slot.n] = writes
	}
	return nil
}

// applyWLAN validates the whole change set against the device's current
// configuration, then writes it. Nothing is written unless every leaf
// validates.
func applyWLAN(ctx context.Context, opts Options, change *wlanChangeSet) error {
	if change.empty() {
		return errors.New("onu wlan: nothing to change")
	}
	bands := presentBands(opts)
	if len(bands) == 0 {
		return errors.New("onu wlan: no MediaTek Wi-Fi radio on this device")
	}
	tc, cancel := newTcapi(ctx, opts)
	defer cancel()
	if tc == nil {
		return errors.New("onu wlan: the firmware configuration tool (tcapi) is not available")
	}
	features := readWLANFeatures(tc, true)
	for _, b := range bands {
		if b.vht {
			features.vht160 = tc.get(b.common, "rt_device") == "7615"
		}
	}
	slots := enumerateSSIDs(tc, bands)

	plans := map[string]*bandPlan{}
	planFor := func(b wlanBand) *bandPlan {
		if plans[b.common] == nil {
			plans[b.common] = &bandPlan{band: b}
		}
		return plans[b.common]
	}
	pendingMode := map[string]string{}
	for _, idx := range sortedKeys(change.radios) {
		if idx > len(bands) {
			return fmt.Errorf("onu wlan: Radio.%d does not exist", idx)
		}
		b := bands[idx-1]
		rc := change.radios[idx]
		if err := planRadio(tc, b, features, idx, rc, slots, planFor(b)); err != nil {
			return err
		}
		if rc.mode != nil {
			pendingMode[b.common] = wlan24ModeCodes[*rc.mode]
		}
	}
	for _, idx := range sortedKeys(change.ssids) {
		if idx > len(slots) {
			return fmt.Errorf("onu wlan: SSID.%d does not exist", idx)
		}
		slot := slots[idx-1]
		if err := planSSID(tc, features, idx, slot, change.ssids[idx], slots, pendingMode[slot.band.common], planFor(slot.band)); err != nil {
			return err
		}
	}
	if tc.ctx.Err() != nil {
		return errors.New("onu wlan: reading the current configuration timed out; nothing was changed")
	}

	w := &tcapiWriter{ctx: ctx, opts: opts}
	for _, b := range bands {
		plan := plans[b.common]
		if plan == nil || (len(plan.common) == 0 && len(plan.entries) == 0) {
			continue
		}
		if err := w.runPlan(plan); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// ---- tcapi writes --------------------------------------------------------------

// tcapiFailures are the messages the client prints when a write did not
// take (strings in /userfs/bin/tcapi); it can exit 0 with one of them.
var tcapiFailures = []string{
	"verify setting fail while tcapi set",
	"connection error",
	"unknown error",
	"no specific node",
	"no node information",
	"no specific attribute",
	"no attribute information",
}

type tcapiWriter struct {
	ctx     context.Context
	opts    Options
	secrets []string
}

// scrub removes every secret value of this change set from text bound for
// an error.
func (w *tcapiWriter) scrub(text string) string {
	for _, s := range w.secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "<hidden>")
		}
	}
	return strings.TrimSpace(text)
}

func (w *tcapiWriter) run(shown string, args ...string) error {
	cctx, cancel := context.WithTimeout(w.ctx, wlanCommandTimeout)
	defer cancel()
	var out []byte
	var err error
	if w.opts.Exec != nil {
		out, err = w.opts.Exec(cctx, w.opts.tcapiPath(), args...)
	} else {
		out, err = exec.CommandContext(cctx, w.opts.tcapiPath(), args...).CombinedOutput()
	}
	text := w.scrub(string(out))
	if err != nil {
		return fmt.Errorf("onu wlan: tcapi %s failed: %s: %s", shown, w.scrub(err.Error()), text)
	}
	for _, failure := range tcapiFailures {
		if strings.Contains(text, failure) {
			return fmt.Errorf("onu wlan: tcapi %s failed: %s", shown, text)
		}
	}
	return nil
}

func (w *tcapiWriter) set(c tcapiWrite) error {
	shown := "set " + c.node + " " + c.attr + " " + c.value
	if c.secret {
		w.secrets = append(w.secrets, c.value)
		shown = "set " + c.node + " " + c.attr + " <hidden>"
	}
	return w.run(shown, "set", c.node, c.attr, c.value)
}

func (w *tcapiWriter) commit(node string) error { return w.run("commit "+node, "commit", node) }
func (w *tcapiWriter) save() error              { return w.run("save", "save") }

// runPlan writes one band in its page's order: the radio's sets, then per
// changed SSID the WebCurSet_Entry index and the SSID's sets and its
// un-indexed entry commit, then the common commit and save.
//
//	2.4 GHz (net-wlan.asp Save_Flag=1):
//	  set WebCurSet_Entry wlan_id <n>; set WLan_Entry<n> ...;
//	  commit WLan_Entry; save; commit WLan_Common; save
//	5 GHz (net-wlan11ac.asp wlanWEPFlag=3):
//	  set WebCurSet_Entry wlan_ac_id <n>; set WLan11ac_Entry<n> ...;
//	  save; commit WLan11ac_Entry; commit Wlan11ac_Common; save
func (w *tcapiWriter) runPlan(plan *bandPlan) error {
	b := plan.band
	for _, c := range plan.common {
		if err := w.set(c); err != nil {
			return err
		}
	}
	entries := sortedKeys(plan.entries)
	for _, n := range entries {
		if err := w.set(tcapiWrite{node: "WebCurSet_Entry", attr: b.curSetAttr, value: strconv.Itoa(n)}); err != nil {
			return err
		}
		for _, c := range plan.entries[n] {
			if err := w.set(c); err != nil {
				return err
			}
		}
		if b.vht {
			if err := w.save(); err != nil {
				return err
			}
		}
		if err := w.commit(b.commitEntry); err != nil {
			return err
		}
	}
	if b.vht {
		if len(entries) == 0 {
			// The page saves before its commits.
			if err := w.save(); err != nil {
				return err
			}
		}
	} else if len(entries) > 0 {
		if err := w.save(); err != nil {
			return err
		}
	}
	if err := w.commit(b.commitCommon); err != nil {
		return err
	}
	return w.save()
}
