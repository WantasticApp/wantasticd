package platforms

import (
	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

// Modulation (PHY/MCS/NSS/width/GI), per-chain signal and airtime for the
// WUSP WiFi telemetry Station and Uplink rows. Everything here is parsed from
// what the station sources already return on the normal collection cadence;
// nothing triggers a scan or a driver SET.

// mergeWiFiModulation completes station (the preferred source) with the
// modulation, chain and airtime fields of existing. A per-frame rate beats a
// negotiated one (wlanconfig phymode) whichever source is preferred.
func mergeWiFiModulation(station *iwinfo.AssocEntry, existing iwinfo.AssocEntry) {
	station.TxRateInfo = iwinfo.MergeRateInfo(station.TxRateInfo, existing.TxRateInfo)
	station.RxRateInfo = iwinfo.MergeRateInfo(station.RxRateInfo, existing.RxRateInfo)
	if len(station.ChainSignal) == 0 {
		station.ChainSignal = existing.ChainSignal
	}
	if len(station.ChainSignalAvg) == 0 {
		station.ChainSignalAvg = existing.ChainSignalAvg
	}
	if !station.TxDurationKnown && existing.TxDurationKnown {
		station.TxDuration, station.TxDurationKnown = existing.TxDuration, true
	}
	if !station.RxDurationKnown && existing.RxDurationKnown {
		station.RxDuration, station.RxDurationKnown = existing.RxDuration, true
	}
}

// iwinfoUbusRateInfo decodes one rx/tx object of rpcd-mod-iwinfo's
// assoclist: rate (kbit/s), ht/vht/he/eht flags, mcs, nss, mhz, 40mhz,
// short_gi, he_gi, he_dcm, eht_gi.
func iwinfoUbusRateInfo(rate map[string]any) iwinfo.RateInfo {
	flag := func(key string) bool {
		value, ok := rate[key]
		return ok && configAnyBool(value)
	}
	num := func(key string) int {
		if v, ok := configIntKnown(rate, key); ok && v >= 0 {
			return v
		}
		return -1
	}
	phy := ""
	switch {
	case flag("eht"):
		phy = iwinfo.PHYEHT
	case flag("he"):
		phy = iwinfo.PHYHE
	case flag("vht"):
		phy = iwinfo.PHYVHT
	case flag("ht"):
		phy = iwinfo.PHYHT
	}
	kbps := 0
	if v := num("rate"); v > 0 {
		kbps = v
	}
	width := num("mhz")
	if width <= 0 && flag("40mhz") {
		width = 40
	}
	gi := num("he_gi")
	if phy == iwinfo.PHYEHT {
		gi = num("eht_gi")
	}
	return iwinfo.RateInfoFromFields(phy, uint32(kbps), num("mcs"), num("nss"), width, flag("short_gi"), gi, num("he_dcm"))
}

// appendWiFiModulationFields emits the modulation, chain and airtime fields
// of entry under path, omitting every unknown value.
func appendWiFiModulationFields(msg *wusp.Message, path string, entry iwinfo.AssocEntry) {
	appendRateInfoFields(msg, path+"Tx", entry.TxRateInfo)
	appendRateInfoFields(msg, path+"Rx", entry.RxRateInfo)
	if entry.TxDurationKnown {
		appendField(msg, path+"TxAirtimeUs", wusp.Uint(entry.TxDuration))
	}
	if entry.RxDurationKnown {
		appendField(msg, path+"RxAirtimeUs", wusp.Uint(entry.RxDuration))
	}
	if chains := iwinfo.FormatChainSignal(entry.ChainSignal); chains != "" {
		appendField(msg, path+"SignalChains", wusp.String(chains))
	}
	if chains := iwinfo.FormatChainSignal(entry.ChainSignalAvg); chains != "" {
		appendField(msg, path+"SignalChainAvg", wusp.String(chains))
	}
}

func appendRateInfoFields(msg *wusp.Message, prefix string, info iwinfo.RateInfo) {
	if !info.Known() {
		return
	}
	if info.PHY != "" {
		appendField(msg, prefix+"PHY", wusp.String(info.PHY))
	}
	if info.MCSKnown {
		appendField(msg, prefix+"MCS", wusp.Int(int64(info.MCS)))
	}
	if info.NSS > 0 {
		appendField(msg, prefix+"NSS", wusp.Uint(uint64(info.NSS)))
	}
	if info.BandwidthMHz > 0 {
		appendField(msg, prefix+"BandwidthMHz", wusp.Uint(uint64(info.BandwidthMHz)))
	}
	if info.GuardIntervalNs > 0 {
		appendField(msg, prefix+"GuardIntervalNs", wusp.Uint(uint64(info.GuardIntervalNs)))
	}
	if info.DCMKnown {
		appendField(msg, prefix+"DCM", wusp.Bool(info.DCM))
	}
}
