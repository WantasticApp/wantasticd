package platforms

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

// Device.WiFi gap filling from the WUSP WiFi telemetry sample.
//
// UCI is the identity of OpenWrt Radio and SSID rows, but QSDK (qca-wifi)
// creates SON/mesh backhaul VAPs at runtime that /etc/config/wireless never
// lists, and "auto" channel/htmode settings say nothing about what the radio
// actually runs. The telemetry sampler already reads every up VAP, its radio,
// the operating channel and the AP behind each station-mode VAP once per
// interval; the Device.WiFi collector reuses that sample instead of querying
// the drivers a second time. Every value is emitted only when it is known.

// wifiRuntimeFill indexes the last telemetry sample for the Device.WiFi
// collector.
type wifiRuntimeFill struct {
	vaps        []wifiTelemetryVAP
	radioByName map[string]*wifiTelemetryRadio
	radioByIf   map[string]*wifiTelemetryRadio
	uplinkByIf  map[string]wifiTelemetryUplink
	stationByIf map[string]wifiTelemetryStation // "<ifname>|<mac>"
}

func newWiFiRuntimeFill(snap wifiTelemetrySnapshot) wifiRuntimeFill {
	fill := wifiRuntimeFill{
		vaps:        append([]wifiTelemetryVAP(nil), snap.VAPs...),
		radioByName: make(map[string]*wifiTelemetryRadio, len(snap.Radios)),
		radioByIf:   make(map[string]*wifiTelemetryRadio),
		uplinkByIf:  make(map[string]wifiTelemetryUplink, len(snap.Uplinks)),
		stationByIf: make(map[string]wifiTelemetryStation, len(snap.Stations)),
	}
	for i := range snap.Radios {
		radio := &snap.Radios[i]
		fill.radioByName[radio.Name] = radio
		for _, ifName := range radio.Interfaces {
			fill.radioByIf[ifName] = radio
		}
	}
	for _, uplink := range snap.Uplinks {
		fill.uplinkByIf[uplink.Interface] = uplink
	}
	for _, station := range snap.Stations {
		fill.stationByIf[station.Interface+"|"+strings.ToLower(station.Entry.MAC.String())] = station
	}
	sort.Slice(fill.vaps, func(i, j int) bool { return fill.vaps[i].Name < fill.vaps[j].Name })
	return fill
}

// radioFor returns the telemetry radio behind a UCI radio: by name (QSDK
// wifiN sections are the radio netdevs, UCI-less devices use phyN), by any
// of its interfaces, or radioN ↔ phyN.
func (f wifiRuntimeFill) radioFor(key string, netdevs []string) *wifiTelemetryRadio {
	if radio := f.radioByName[key]; radio != nil {
		return radio
	}
	for _, ifName := range netdevs {
		if radio := f.radioByIf[strings.TrimSpace(ifName)]; radio != nil {
			return radio
		}
	}
	if strings.HasPrefix(key, "radio") {
		return f.radioByName["phy"+strings.TrimPrefix(key, "radio")]
	}
	return nil
}

// stationRetransPercent is the TR-181 Retransmissions value (retries per
// 100 packets during the last telemetry interval) of one station.
func (f wifiRuntimeFill) stationRetransPercent(ifName string, mac net.HardwareAddr) (uint32, bool) {
	station, ok := f.stationByIf[ifName+"|"+strings.ToLower(mac.String())]
	if !ok || !station.RetransPercentKnown {
		return 0, false
	}
	return station.RetransPercent, true
}

// observedStandards derives Radio.OperatingStandards from the PHY the
// radio was seen using (uplink and station rate info or negotiated mode),
// for radios whose UCI htmode does not name a generation. The result is a
// lower bound: the radio provably runs at least that generation.
func (f wifiRuntimeFill) observedStandards(radio *wifiTelemetryRadio, band string, stations []wifiTelemetryStation) []string {
	if radio == nil {
		return nil
	}
	bandCode := map[string]string{"2.4GHz": "2g", "5GHz": "5g", "6GHz": "6g"}[band]
	if bandCode == "" {
		return nil
	}
	best := 0
	consider := func(e iwinfo.AssocEntry) {
		for _, phy := range []string{e.TxRateInfo.PHY, e.RxRateInfo.PHY, wifiPHYFromStandard(e.OperatingStandard)} {
			best = max(best, wifiPHYRank(phy))
		}
	}
	for _, uplink := range f.uplinkByIf {
		if uplink.Radio == radio.Name {
			consider(uplink.Entry)
		}
	}
	for _, station := range stations {
		if station.Radio == radio.Name {
			consider(station.Entry)
		}
	}
	htmode := map[int]string{1: "HT20", 2: "VHT20", 3: "HE20", 4: "EHT20"}[best]
	if htmode == "" {
		return nil
	}
	return wifiOperatingStandards(map[string]any{"band": bandCode, "htmode": htmode})
}

func wifiPHYRank(phy string) int {
	switch phy {
	case iwinfo.PHYHT:
		return 1
	case iwinfo.PHYVHT:
		return 2
	case iwinfo.PHYHE:
		return 3
	case iwinfo.PHYEHT:
		return 4
	}
	return 0
}

func wifiPHYFromStandard(standard string) string {
	switch strings.ToLower(strings.TrimSpace(standard)) {
	case "be":
		return iwinfo.PHYEHT
	case "ax":
		return iwinfo.PHYHE
	case "ac":
		return iwinfo.PHYVHT
	case "n":
		return iwinfo.PHYHT
	}
	return ""
}

// tr181CurrentBandwidth maps an operating channel width (and, for 320 MHz,
// the channel center) to the TR-181 CurrentOperatingChannelBandwidth enum.
// A 320 MHz channel whose center does not identify 320MHz-1 or 320MHz-2 is
// left unknown.
func tr181CurrentBandwidth(widthMHz, centerMHz int) string {
	switch widthMHz {
	case 20, 40, 80, 160:
		return fmt.Sprintf("%dMHz", widthMHz)
	case 320:
		if centerMHz < 5955 {
			return ""
		}
		switch (centerMHz - 5950) / 5 {
		case 31, 95, 159:
			return "320MHz-1"
		case 63, 127, 191:
			return "320MHz-2"
		}
	}
	return ""
}

// endPointRateKbpsInRange reports whether a rate fits the TR-181
// EndPoint.Stats LastData*Rate range (1 to 600 Mbit/s). Faster Wi-Fi 6/7
// rates are left out rather than clamped; WUSP_WiFiTelemetry.Uplink carries
// the exact value.
func endPointRateKbpsInRange(kbps uint32) bool { return kbps >= 1000 && kbps <= 600000 }

// wifiEndPointRow is one station-mode SSID row that gets an EndPoint.
type wifiEndPointRow struct {
	ssidPath string
	ifName   string
	enabled  bool
}

// appendWiFiEndPointFields emits Device.WiFi.EndPoint.{i} for a station-mode
// SSID row from the telemetry uplink of its interface. The AP's BSSID is on
// the referenced SSID row (see appendWiFiFields).
func appendWiFiEndPointFields(msg *wusp.Message, path string, row wifiEndPointRow, uplink *wifiTelemetryUplink) {
	appendField(msg, path+"Enable", wusp.Bool(row.enabled))
	status := "Disabled"
	if row.enabled {
		status = "Enabled"
	}
	appendField(msg, path+"Status", wusp.String(status))
	appendField(msg, path+"SSIDReference", wusp.String(row.ssidPath))
	if uplink == nil {
		return
	}
	e := uplink.Entry
	if assocSignedKnown(e.SignalKnown, e.Signal) && e.Signal < 0 {
		appendField(msg, path+"Stats.SignalStrength", wusp.Int(int64(e.Signal)))
	}
	// Downlink is AP → this end point: the station-mode interface's RX rate.
	if assocUint32Known(e.RxRateKnown, e.RxRate) && endPointRateKbpsInRange(e.RxRate) {
		appendField(msg, path+"Stats.LastDataDownlinkRate", wusp.Uint(uint64(e.RxRate)))
	}
	if assocUint32Known(e.TxRateKnown, e.TxRate) && endPointRateKbpsInRange(e.TxRate) {
		appendField(msg, path+"Stats.LastDataUplinkRate", wusp.Uint(uint64(e.TxRate)))
	}
	if uplink.RetransPercentKnown {
		appendField(msg, path+"Stats.Retransmissions", wusp.Uint(uint64(uplink.RetransPercent)))
	}
}

// appendRuntimeWiFiRadioFields emits a radio the telemetry sample found that
// no UCI wifi-device section describes. Its row is read-only: writes resolve Radio
// indices against UCI sections only (resolveWiFiRadioSection).
func appendRuntimeWiFiRadioFields(msg *wusp.Message, path string, radio *wifiTelemetryRadio, standards []string) {
	appendField(msg, path+"Enable", wusp.Bool(true))
	appendField(msg, path+"Status", wusp.String("Up"))
	appendField(msg, path+"Name", wusp.String(radio.Name))
	if value := tr181BandFromFrequency(radio.Frequency); value != "" {
		appendField(msg, path+"OperatingFrequencyBand", wusp.String(value))
	}
	if value := wifiChannelFromFrequency(radio.Frequency); value > 0 {
		appendField(msg, path+"Channel", wusp.Uint(uint64(value)))
	}
	if width := tr181CurrentBandwidth(radio.ChannelWidth, radio.CenterFrequency); width != "" {
		appendField(msg, path+"CurrentOperatingChannelBandwidth", wusp.String(width))
	}
	if validNoiseDBM(radio.Noise) {
		appendField(msg, path+"Stats.Noise", wusp.Int(int64(radio.Noise)))
	}
	if len(standards) > 0 {
		appendField(msg, path+"OperatingStandards", wifiStringList(standards))
	}
}
