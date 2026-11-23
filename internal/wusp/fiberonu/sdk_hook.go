package fiberonu

import (
	"fmt"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/fiberonu/sdk"
)

// applySDKState overrides the proc-derived link/activation/counter fields
// with the authoritative register snapshot from /dev/mem (cgo builds). The
// proc parser stays as the fallback for non-cgo builds and for platforms
// where /dev/mem is unavailable.
func applySDKState(msg *wusp.Message) {
	st, err := sdk.ReadPONState()
	if err != nil {
		return
	}
	// Activation: 0 = inactive, 1..5 = O1..O5.
	switch st.Activation {
	case sdk.ActivationInactive:
		msg.Set(wusp.WUSPONUPrefix+"ActivationState", wusp.String("inactive"))
	default:
		if st.Activation >= sdk.ActivationO1 && st.Activation <= sdk.ActivationO5 {
			msg.Set(wusp.WUSPONUPrefix+"ActivationState", wusp.String(fmt.Sprintf("O%d", st.Activation)))
		}
	}
	link := "down"
	if sdk.RxSyncOK(st.RxSync) {
		link = "up"
	}
	msg.Set(wusp.WUSPONUPrefix+"LinkStatus", wusp.String(link))
	msg.Set(wusp.WUSPONUPrefix+"EqualizationDelay", wusp.Uint(uint64(sdk.GEqdValue(st.GEqd))))
	msg.Set(wusp.WUSPONUPrefix+"GemRxCount", wusp.Uint(uint64(st.GemRxCount)))
	msg.Set(wusp.WUSPONUPrefix+"GemTxCount", wusp.Uint(uint64(st.GemTxCount)))
	msg.Set(wusp.WUSPONUPrefix+"RxCrcErrorCount", wusp.Uint(uint64(st.RxCrcErrCount)))
	msg.Set(wusp.WUSPONUPrefix+"GemHecErrorCount", wusp.Uint(uint64(st.HecErrCount)))
}
