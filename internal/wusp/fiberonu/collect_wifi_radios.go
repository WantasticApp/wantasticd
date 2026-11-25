package fiberonu

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// ---- TR-181 Device.WiFi from the MediaTek driver ----------------------------
//
// The console's Radios and Wi-Fi clients counts, and its client rows, read
// TR-181 Device.WiFi.Radio/SSID/AccessPoint(.AssociatedDevice). On Linux the
// linux.wifi collector fills them over nl80211, which mt7603eap (2.4 GHz
// ra0..ra3) and mt7663 (5 GHz rai0..rai3) do not implement. This publishes
// the same leaves from what collectWLAN already read (tcapi WLan_Common /
// WLan11ac_Common and the WLan*_Entry<n> nodes, `iwpriv <if>0 get_mac_table`),
// plus the live channel and transmit power:
//
//	Info_WLan / Info_WLan11ac   CurrentChannel (what sta-user.asp shows)
//	WLan_Common                 TxPowerLevel 1..5 = 100/80/60/40/20 %
//	                            (net-wlan.asp wlTxPwr)
//	WLan11ac_Common             TxPower, percent (net-wlan11ac.asp wlTxPwr;
//	                            RT2860AP.dat TxPower=100)
//
// Radio.{i} follows presentBands (2.4 GHz first), SSID.{k} and
// AccessPoint.{k} follow the Network.SSID.{k} order, one AccessPoint per
// SSID. Only values that were read are published: an unset ("N/A") or
// unreadable attribute leaves its leaf out, and a band whose station table
// could not be read reports no AssociatedDevice count rather than zero.

const wifiPrefix = "Device.WiFi."

// wifiInfoNode is the live-status node of a band.
func wifiInfoNode(b wlanBand) string {
	if b.vht {
		return "Info_WLan11ac"
	}
	return "Info_WLan"
}

// wirelessModeStandards maps the WirelessMode codes of wirelessModeText to
// TR-181 OperatingStandards.
var wirelessModeStandards = map[string][]string{
	"0":  {"b", "g"},
	"1":  {"b"},
	"2":  {"a"},
	"4":  {"g"},
	"6":  {"n"},
	"7":  {"g", "n"},
	"8":  {"a", "n"},
	"9":  {"b", "g", "n"},
	"14": {"a", "n", "ac"},
	"16": {"g", "n", "ax"},
	"17": {"ax"},
}

// tr181Bandwidth is channelWidth in TR-181 enum form: 2.4 GHz 20/40 MHz with
// BSS coexistence is "Auto"; on 5 GHz HT_BW=1 needs VHT_BW to say more.
func tr181Bandwidth(b wlanBand, htBW, coexistence, vhtBW string) string {
	switch htBW {
	case "":
		return ""
	case "0":
		return "20MHz"
	}
	if !b.vht {
		if coexistence == "1" {
			return "Auto"
		}
		return "40MHz"
	}
	switch vhtBW {
	case "0":
		return "40MHz"
	case "1":
		return "80MHz"
	case "2":
		return "160MHz"
	case "3":
		return "80+80MHz"
	}
	return ""
}

// transmitPower is the radio's power in percent, or -2 when not read.
func transmitPower(tc *tcapiReader, b wlanBand) int64 {
	if b.vht {
		v, err := strconv.ParseInt(tc.get(b.common, "TxPower"), 10, 64)
		if err != nil || v < 1 || v > 100 {
			return -2
		}
		return v
	}
	switch tc.get(b.common, "TxPowerLevel") {
	case "1":
		return 100
	case "2":
		return 80
	case "3":
		return 60
	case "4":
		return 40
	case "5":
		return 20
	}
	return -2
}

// phyModeStandard maps the get_mac_table PhMd column to the station's
// TR-181 OperatingStandard.
func phyModeStandard(phyMode string, b wlanBand) string {
	switch m := strings.ToUpper(phyMode); {
	case m == "CCK":
		return "b"
	case m == "OFDM":
		if b.vht {
			return "a"
		}
		return "g"
	case strings.HasPrefix(m, "HT"):
		return "n"
	case strings.HasPrefix(m, "VHT"):
		return "ac"
	case strings.HasPrefix(m, "HE"):
		return "ax"
	}
	return ""
}

func wifiStatus(enabled, up bool) string {
	switch {
	case !enabled:
		return "Down"
	case up:
		return "Up"
	default:
		return "Dormant"
	}
}

func wifiAccessPointStatus(enabled, up bool) string {
	switch {
	case !enabled:
		return "Disabled"
	case up:
		return "Enabled"
	default:
		return "Error"
	}
}

// ifaceMAC reads an interface's hardware address from sysfs.
func ifaceMAC(opts Options, name string) net.HardwareAddr {
	mac, err := net.ParseMAC(strings.TrimSpace(readFile(filepath.Join(opts.sysClassNetDir(), name, "address"))))
	if err != nil || len(mac) != 6 {
		return nil
	}
	for _, octet := range mac {
		if octet != 0 {
			return mac
		}
	}
	return nil
}

// collectWiFiTR181 publishes Device.WiFi.* from the MediaTek WLAN reads.
// It writes nothing when wlan is nil (no ra0/rai0: a mac80211 build, where
// linux.wifi owns Device.WiFi).
func collectWiFiTR181(ctx context.Context, opts Options, wlan *wlanSnapshot, msg *wusp.Message) {
	if wlan == nil || len(wlan.radios) == 0 {
		return
	}
	tc, cancel := newTcapi(ctx, opts)
	defer cancel()

	radioPath := map[int]string{}
	radioBand := map[int]wlanBand{}
	for _, r := range wlan.radios {
		b := r.band
		path := wifiPrefix + "Radio." + strconv.Itoa(r.index) + "."
		radioPath[r.index] = path
		radioBand[r.index] = b
		main := b.ifPrefix + "0"
		msg.Set(path+"Name", wusp.String(main))
		msg.Set(path+"OperatingFrequencyBand", wusp.String(b.band))
		up, upKnown := ifaceUp(opts, main)
		if r.enable != "" {
			enabled := r.enable == "1"
			msg.Set(path+"Enable", wusp.Bool(enabled))
			if upKnown {
				msg.Set(path+"Status", wusp.String(wifiStatus(enabled, up)))
			}
		}
		configured, cfgErr := strconv.ParseUint(r.channel, 10, 64)
		if cfgErr == nil {
			msg.Set(path+"AutoChannelEnable", wusp.Bool(configured == 0))
		}
		if cur, err := strconv.ParseUint(tc.get(wifiInfoNode(b), "CurrentChannel"), 10, 64); err == nil && cur > 0 {
			msg.Set(path+"Channel", wusp.Uint(cur))
		} else if cfgErr == nil && configured > 0 {
			msg.Set(path+"Channel", wusp.Uint(configured))
		}
		if w := tr181Bandwidth(b, r.htBW, r.coex, r.vhtBW); w != "" {
			msg.Set(path+"OperatingChannelBandwidth", wusp.String(w))
		}
		if stds := wirelessModeStandards[r.modeCode]; len(stds) > 0 {
			items := make([]wusp.Value, len(stds))
			for i, s := range stds {
				items[i] = wusp.String(s)
			}
			msg.Set(path+"OperatingStandards", wusp.List(items...))
		}
		if r.power >= 0 {
			msg.Set(path+"TransmitPower", wusp.Int(r.power))
		}
		// What the setters accept (control_wlan.go), so the console offers
		// only values the firmware page offers.
		if len(r.channels) > 0 {
			msg.Set(path+"PossibleChannels", stringList(strconv.Itoa, r.channels))
		}
		if len(r.bandwidths) > 0 {
			var names []string
			for _, w := range r.bandwidths {
				if n := vendorBandwidthTR181(b, w); n != "" {
					names = append(names, n)
				}
			}
			msg.Set(path+"SupportedOperatingChannelBandwidths", stringList(func(s string) string { return s }, names))
		}
		msg.Set(path+"TransmitPowerSupported", stringList(strconv.Itoa, txPowersFor(b)))
	}
	var modesSupported []string
	for _, m := range securityModes(wlan.features) {
		modesSupported = append(modesSupported, authModeTR181[m])
	}

	for k, s := range wlan.ssids {
		n := strconv.Itoa(k + 1)
		ssidPath := wifiPrefix + "SSID." + n + "."
		apPath := wifiPrefix + "AccessPoint." + n + "."
		b := radioBand[s.radio]
		msg.Set(ssidPath+"Name", wusp.String(s.iface))
		msg.Set(ssidPath+"LowerLayers", wusp.List(wusp.String(radioPath[s.radio])))
		if s.name != "" {
			msg.Set(ssidPath+"SSID", wusp.String(s.name))
		}
		if mac := ifaceMAC(opts, s.iface); mac != nil {
			msg.Set(ssidPath+"BSSID", wusp.MAC(mac))
			msg.Set(ssidPath+"MACAddress", wusp.MAC(mac))
		}
		msg.Set(apPath+"SSIDReference", wusp.String(ssidPath))
		up, upKnown := ifaceUp(opts, s.iface)
		if s.enable != "" {
			enabled := s.enable == "1"
			msg.Set(ssidPath+"Enable", wusp.Bool(enabled))
			msg.Set(apPath+"Enable", wusp.Bool(enabled))
			if upKnown {
				msg.Set(ssidPath+"Status", wusp.String(wifiStatus(enabled, up)))
				msg.Set(apPath+"Status", wusp.String(wifiAccessPointStatus(enabled, up)))
			}
		}
		if s.hidden != "" {
			msg.Set(apPath+"SSIDAdvertisementEnabled", wusp.Bool(s.hidden != "1"))
		}
		if v, err := strconv.ParseUint(s.maxSta, 10, 64); err == nil {
			if v > 0 {
				msg.Set(apPath+"MaxAllowedAssociations", wusp.Uint(v))
			}
			msg.Set(apPath+"MaxAssociatedDevices", wusp.Uint(v))
		}
		msg.Set(apPath+"Security.ModesSupported", stringList(func(s string) string { return s }, modesSupported))
		if mode, ok := authModeTR181[s.auth]; ok {
			msg.Set(apPath+"Security.ModeEnabled", wusp.String(mode))
			if mode != "None" {
				if enc := encrypTypeTR181(s.encrypt); len(enc) > 0 {
					msg.Set(apPath+"Security.EncryptionMode", stringList(func(s string) string { return s }, enc))
				}
			}
		} else if s.auth != "" {
			// WEP, 802.1X and other modes this agent does not write: the
			// vendor name, so the console shows what is configured.
			msg.Set(apPath+"Security.ModeEnabled", wusp.String(s.auth))
		}

		table, read := wlan.tables[b.ifPrefix]
		if !read {
			continue
		}
		count := 0
		for _, st := range table {
			// The table is per radio; BSS is the SSID index on it. A row
			// without a BSS column can only be placed on a one-SSID band.
			if st.hasBSS && st.bss != s.index {
				continue
			}
			if !st.hasBSS && s.index != 0 {
				continue
			}
			mac, err := net.ParseMAC(st.mac)
			if err != nil {
				continue
			}
			count++
			devPath := apPath + "AssociatedDevice." + strconv.Itoa(count) + "."
			msg.Set(devPath+"MACAddress", wusp.MAC(mac))
			msg.Set(devPath+"Active", wusp.Bool(true))
			if std := phyModeStandard(st.phyMode, b); std != "" {
				msg.Set(devPath+"OperatingStandard", wusp.String(std))
			}
			if v, ok := bestRSSI(st.rssi); ok && v < 0 {
				msg.Set(devPath+"SignalStrength", wusp.Int(int64(v)))
			}
			// Rate is the driver's last TX rate to the station in Mbit/s.
			if v, err := strconv.ParseUint(st.rate, 10, 64); err == nil && v > 0 {
				msg.Set(devPath+"LastDataDownlinkRate", wusp.Uint(v*1000))
			}
		}
		msg.Set(apPath+"AssociatedDeviceNumberOfEntries", wusp.Uint(uint64(count)))
	}

	msg.Set(wifiPrefix+"RadioNumberOfEntries", wusp.Uint(uint64(len(wlan.radios))))
	msg.Set(wifiPrefix+"SSIDNumberOfEntries", wusp.Uint(uint64(len(wlan.ssids))))
	msg.Set(wifiPrefix+"AccessPointNumberOfEntries", wusp.Uint(uint64(len(wlan.ssids))))
}

// stringList renders values as a TR-181 list of strings.
func stringList[T any](format func(T) string, values []T) wusp.Value {
	items := make([]wusp.Value, len(values))
	for i, v := range values {
		items[i] = wusp.String(format(v))
	}
	return wusp.List(items...)
}
