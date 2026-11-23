package sdk

// PONState is the decoded live state of the XPON link, read straight from
// the chip registers (authoritative; the /proc files render the same
// registers as text).
type PONState struct {
	// Activation is the GPON activation state machine value: 0 = inactive,
	// 1..5 = O1..O5 (G_ACTIVATION bits [3:0]).
	Activation uint32
	// RxSync is the PHYRX_STATUS sync field (0xa = OK).
	RxSync uint32
	// PhyRD is the PHYSTA1 received-power-detect field, bits [20:18].
	PhyRD uint32
	// WanSel is the SCU WAN mode selection.
	WanSel uint32
	// GEqd is the equalization delay value.
	GEqd uint32
	// Counters mirror the DBG_* registers of the PON MAC.
	GemRxCount, GemTxCount     uint32
	RxCrcErrCount, HecErrCount uint32
}

// ReadPONState snapshots the registers behind Device.WUSP_ONU.* link
// state and counters.
func ReadPONState() (PONState, error) {
	var st PONState
	read := func(addr uint32, dst *uint32) error {
		v, err := RegRead(addr)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	if err := read(RegGActivation, &st.Activation); err != nil {
		return st, err
	}
	if err := read(RegPhyRxStatus, &st.RxSync); err != nil {
		return st, err
	}
	if err := read(RegPhySta1, &st.PhyRD); err != nil {
		return st, err
	}
	if err := read(RegScuWanConf, &st.WanSel); err != nil {
		return st, err
	}
	if err := read(RegGEqd, &st.GEqd); err != nil {
		return st, err
	}
	if err := read(RegDbgRxGemCnt, &st.GemRxCount); err != nil {
		return st, err
	}
	if err := read(RegDbgTxGemCnt, &st.GemTxCount); err != nil {
		return st, err
	}
	if err := read(RegDbgRxCrcErrCnt, &st.RxCrcErrCount); err != nil {
		return st, err
	}
	var one, two, uc uint32
	if err := read(RegDbgHecOneErr, &one); err != nil {
		return st, err
	}
	if err := read(RegDbgHecTwoErr, &two); err != nil {
		return st, err
	}
	if err := read(RegDbgHecUcErr, &uc); err != nil {
		return st, err
	}
	st.HecErrCount = one + two + uc
	return st, nil
}
