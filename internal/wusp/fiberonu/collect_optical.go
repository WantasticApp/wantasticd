package fiberonu

import (
	"context"
	"math"
	"strconv"

	"wantastic-agent/internal/wusp"
)

// applyPonPhyTcapi reads the optical module through the config bus, the same
// source and units the firmware's own status pages use (sta-network.asp,
// sta-device.asp, selfcheck.asp read Info_PonPhy):
//
//	RxPower, TxPower  0.1 uW steps   -> dBm = 10*log10(raw/10000)
//	SupplyVoltage     100 uV steps   -> V   = raw/10000
//	TxBiasCurrent     2 uA steps     -> mA  = raw*2/1000
//	Temperature       1/256 degC, signed 16-bit
//
// /proc/pon_phy/ddmi on this firmware is a raw hex dump the DDMI parser
// cannot read, so without this the console showed no Rx/Tx light at all.
// Values override the /proc ones; unset ("N/A"), zero or unparsable
// readings are skipped, so a down link never reports a made-up level.
func applyPonPhyTcapi(ctx context.Context, opts Options, msg *wusp.Message) {
	tc, cancel := newTcapi(ctx, opts)
	defer cancel()
	if tc == nil {
		return
	}
	num := func(attr string) (float64, bool) {
		v, err := strconv.ParseFloat(tc.get("Info_PonPhy", attr), 64)
		return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
	}
	// Like sta-network.asp: optical power is only meaningful while the PON
	// link is up (LinkSta != "0"); with no light the module reports noise.
	linkDown := tc.get("XPON_LinkCfg", "LinkSta") == "0"
	dbm := func(attr, path string) {
		if linkDown {
			return
		}
		if raw, ok := num(attr); ok && raw > 0 {
			msg.Set(wusp.WUSPONUPrefix+path, wusp.Float(round1(10*math.Log10(raw/10000))))
		}
	}
	dbm("RxPower", "RxPower")
	dbm("TxPower", "TxPower")
	if raw, ok := num("SupplyVoltage"); ok && raw > 0 {
		msg.Set(wusp.WUSPONUPrefix+"Voltage", wusp.Float(math.Round(raw/10)/1000))
	}
	if raw, ok := num("TxBiasCurrent"); ok && raw > 0 {
		msg.Set(wusp.WUSPONUPrefix+"BiasCurrent", wusp.Float(round1(raw*2/1000)))
	}
	if raw, ok := num("Temperature"); ok && raw >= 0 && raw < 65536 {
		if raw >= 32768 {
			raw -= 65536
		}
		msg.Set(wusp.WUSPONUPrefix+"Temperature", wusp.Float(round1(raw/256)))
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
