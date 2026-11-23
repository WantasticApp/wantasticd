// Package sdk implements direct register access to the EcoNet EN75xx XPON
// PHY and PON MAC blocks, using the register map from the Airoha SDK
// (https://github.com/lotusmomo/airoha_sdk):
//
//	private/xpon_phy_10g/inc/en7580_reg.h   GEPON CSR / PHY registers
//	private/xpon_1g/inc/gpon/gpon_reg.h     GPON MAC registers
//
// The registers are read through /dev/mem (mmap) in cgo builds; without
// cgo the package compiles to stubs that report ErrNotSupported, and the
// caller falls back to the /proc surface.
package sdk

import "errors"

// ErrNotSupported is returned by every accessor in non-cgo builds.
var ErrNotSupported = errors.New("fiberonu/sdk: built without cgo")

// Register map (addresses are absolute PHYSICAL addresses on EN75xx).
// The SDK headers give the kernel's KSEG1 virtual view (0xBFAF0000,
// en7580_reg.h); the physical equivalents live 0xA0000000 lower
// (0x1FAF0000, en7581_reg.h) — that is what /dev/mem maps.
const (
	// GEPON CSR block (phys 0x1FAF0000), en7580/en7581_reg.h.
	RegBaseGeponCSR = 0x1FAF0000
	RegPhySta1      = RegBaseGeponCSR + 0x130 // GEPON_CSR_PHYSTA1
	RegXponSta      = RegBaseGeponCSR + 0x5E0 // XPON_STA
	RegPhyRxStatus  = RegBaseGeponCSR + 0x21C // GEPON_CSR_PHYRX_STATUS

	// SCU block (phys 0x1FB00000), en7580_reg.h / ponInfo.
	RegScuWanConf = 0x1FB00070 // SCU_WAN_CONF_REG

	// GPON MAC debug block (phys 0x1FB64000), gpon_reg.h.
	RegBaseGponMac = 0x1FB64000
	RegGEqd        = 0x1FB640A8 // G_EQD
	RegGActivation = 0x1FB640BC // G_ACTIVATION

	RegDbgRxGemCnt    = 0x1FB64300 // DBG_RX_GEM_CNT
	RegDbgRxCrcErrCnt = 0x1FB64304 // DBG_RX_CRC_ERR_CNT
	RegDbgRxGtcCnt    = 0x1FB64308 // DBG_RX_GTC_CNT
	RegDbgTxGemCnt    = 0x1FB6430C // DBG_TX_GEM_CNT
	RegDbgTxBstCnt    = 0x1FB64310 // DBG_TX_BST_CNT
	RegDbgHecOneErr   = 0x1FB64330 // DBG_GEM_HEC_ONE_ERR_CNT
	RegDbgHecTwoErr   = 0x1FB64334 // DBG_GEM_HEC_TWO_ERR_CNT
	RegDbgHecUcErr    = 0x1FB64338 // DBG_GEM_HEC_UC_ERR_CNT

	// One mapping window covers the whole block: 0x1FAF0000 is 4 KiB
	// aligned and the GPON MAC registers sit < 512 KiB above it.
	windowBase = RegBaseGeponCSR
	windowLen  = 0x80000
)

// Activation state machine values: G_ACTIVATION_ST_FLD_act_st, bits [3:0]
// (gpon_mac_reg_c_header_en7521.h). 0 = inactive, 1..5 = O1..O5.
const (
	ActivationInactive = 0
	ActivationO1       = 1
	ActivationO2       = 2
	ActivationO3       = 3
	ActivationO4       = 4
	ActivationO5       = 5
)

// ActivationState decodes bits [3:0] of G_ACTIVATION.
func ActivationState(reg uint32) uint32 { return reg & 0xF }

// RxSyncStatus decodes the PHYRX_STATUS sync field: GEPON_CSR_PHYRX_STATUS
// SYNC_STATUS mask (0xf), SYNC_OK value (0xa). Returns true when the
// receiver reports sync.
func RxSyncOK(reg uint32) bool { return reg&0xF == 0xA }

// PhySta1 carries the PHYSTA1 fields the vendor decodes in the live dump:
//
//	PHY Status: unplug (PHY_RD: 0x2 <b[20:18]>   RX_SYNC: 0x1 <b[3:0]>)
func PhyRD(reg uint32) uint32 { return (reg >> 18) & 0x7 }
func PhyRXSync(reg uint32) uint32 {
	return reg & 0xF
}

// WanSel is the WAN mode field of SCU_WAN_CONF_REG (wan_sel debug cmd).
func WanSel(reg uint32) uint32 { return reg & 0xF }

// GEqd is the GPON equalization delay value, nanoseconds as a 32-bit count.
func GEqdValue(reg uint32) uint32 { return reg }
