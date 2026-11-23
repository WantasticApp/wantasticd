package sdk

import "testing"

func TestActivationState(t *testing.T) {
	// Live register dump: G_ACTIVATION (0xBFB640BC): 0x1 with the OLT
	// down = O1. Bits above [3:0] must not leak in.
	if got := ActivationState(0x1); got != 1 {
		t.Fatalf("ActivationState(0x1) = %d, want 1", got)
	}
	if got := ActivationState(0x5); got != 5 {
		t.Fatalf("ActivationState(0x5) = %d, want 5", got)
	}
	if got := ActivationState(0x15); got != 5 {
		t.Fatalf("ActivationState(0x15) = %d, want 5 (masked)", got)
	}
	if got := ActivationState(0); got != 0 {
		t.Fatalf("ActivationState(0) = %d, want 0", got)
	}
}

func TestRxSyncOK(t *testing.T) {
	// GEPON_CSR_PHYRX_STATUS_SYNC_OK = 0xa.
	if !RxSyncOK(0x22e0a42a) { // bits [3:0] = 0xa
		t.Fatal("RxSyncOK should accept sync value 0xa in low nibble")
	}
	if RxSyncOK(0x22e0421) { // live dump while OLT down: low nibble 0x1
		t.Fatal("RxSyncOK should reject non-0xa low nibble")
	}
}

func TestPhySta1(t *testing.T) {
	// Live dump: PHYSTA1 = 0x4b0b1919 -> PHY_RD = bits[20:18] = 0x2.
	if got := PhyRD(0x4b0b1919); got != 2 {
		t.Fatalf("PhyRD(0x4b0b1919) = %d, want 2", got)
	}
	if got := PhyRXSync(0x4b0b1919); got != 0x9 {
		t.Fatalf("PhyRXSync(0x4b0b1919) = 0x%x, want 0x9", got)
	}
}

func TestRegisterWindow(t *testing.T) {
	// Every register the package touches must fall inside the single
	// 0xBFAF0000..+0x80000 mapping window.
	regs := []uint32{
		RegPhySta1, RegXponSta, RegPhyRxStatus, RegScuWanConf,
		RegGEqd, RegGActivation, RegDbgRxGemCnt, RegDbgRxCrcErrCnt,
		RegDbgRxGtcCnt, RegDbgTxGemCnt, RegDbgTxBstCnt,
		RegDbgHecOneErr, RegDbgHecTwoErr, RegDbgHecUcErr,
	}
	for _, reg := range regs {
		if reg < windowBase || reg+4 > windowBase+windowLen {
			t.Fatalf("register 0x%x outside window 0x%x..0x%x", reg, windowBase, windowBase+windowLen)
		}
	}
}
