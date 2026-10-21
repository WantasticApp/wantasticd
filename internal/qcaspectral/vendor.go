package qcaspectral

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

// QCA nl80211 vendor interface for spectral scan, as used by QSDK 11/12
// cfg80211-mode drivers. Every value below is taken from hostap
// src/common/qca-vendor.h (https://w1.fi/cgit/hostap/plain/src/common/qca-vendor.h):
//
//	#define OUI_QCA 0x001374
//	QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START        = 154
//	QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_STOP         = 155
//	QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CONFIG   = 158
//	QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CAP_INFO = 160
//	QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_STATUS   = 161
const (
	ouiQCA = 0x001374

	vendorSubcmdSpectralStart     = 154
	vendorSubcmdSpectralStop      = 155
	vendorSubcmdSpectralGetConfig = 158
	vendorSubcmdSpectralGetCaps   = 160
	vendorSubcmdSpectralGetStatus = 161
)

// enum qca_wlan_vendor_attr_spectral_scan (u32 unless noted).
const (
	attrSpectralScanCookie        = 19 // u64, START reply / STOP request
	attrSpectralScanRequestType   = 23
	attrSpectralScanErrorCode     = 26
	attrSpectralDataTransportMode = 33
)

// enum qca_wlan_vendor_attr_spectral_scan_request_type.
const (
	requestTypeScanAndConfig = 0
	requestTypeScan          = 1
	requestTypeConfig        = 2
)

// enum qca_wlan_vendor_spectral_data_transport_mode.
const (
	transportNetlink = 0
	transportRelay   = 1
)

// enum qca_wlan_vendor_attr_spectral_cap (flags unless noted).
const (
	attrCapPhyDiag  = 1
	attrCapRadar    = 2
	attrCapSpectral = 3
	attrCapAdvanced = 4
	attrCapHWGen    = 5 // u32
)

// enum qca_wlan_vendor_attr_spectral_scan_status (flags).
const (
	attrStatusIsEnabled = 1
	attrStatusIsActive  = 2
)

// enum qca_wlan_vendor_spectral_scan_error_code.
var vendorSpectralErrors = map[uint32]string{
	0: "parameter unsupported",
	1: "mode unsupported",
	2: "invalid parameter value",
	3: "parameter not initialized",
}

// Control and transport labels exported through the WUSP model.
const (
	ControlPathVendor = "cfg80211-vendor"
	ControlPathIoctl  = "ath-diag-ioctl"
	ControlPathNone   = "none"

	TransportNetlink = "netlink"
	TransportRelay   = "relay"
)

// encodeStartRequest builds the vendor data for SPECTRAL_SCAN_START. With
// forceNetlink the request also configures netlink transport, which is the
// only transport this agent can read; the driver applies only the attributes
// present, so every other scan parameter is left as configured.
func encodeStartRequest(forceNetlink bool) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	if forceNetlink {
		ae.Uint32(attrSpectralScanRequestType, requestTypeScanAndConfig)
		ae.Uint32(attrSpectralDataTransportMode, transportNetlink)
	} else {
		ae.Uint32(attrSpectralScanRequestType, requestTypeScan)
	}
	return ae.Encode()
}

func encodeStopRequest(cookie uint64, haveCookie bool) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	if haveCookie {
		ae.Uint64(attrSpectralScanCookie, cookie)
	}
	return ae.Encode()
}

func encodeTransportConfig(mode uint32) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(attrSpectralScanRequestType, requestTypeConfig)
	ae.Uint32(attrSpectralDataTransportMode, mode)
	return ae.Encode()
}

type vendorAttrs map[uint16][]byte

func decodeVendorAttrs(data []byte) (vendorAttrs, error) {
	out := make(vendorAttrs)
	if len(data) == 0 {
		return out, nil
	}
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}
	for ad.Next() {
		out[ad.Type()] = append([]byte(nil), ad.Bytes()...)
	}
	return out, ad.Err()
}

func (a vendorAttrs) has(t uint16) bool { _, ok := a[t]; return ok }

func (a vendorAttrs) uint32(t uint16) (uint32, bool) {
	b, ok := a[t]
	if !ok || len(b) < 4 {
		return 0, false
	}
	return nativeUint32(b), true
}

func (a vendorAttrs) uint64(t uint16) (uint64, bool) {
	b, ok := a[t]
	if !ok || len(b) < 8 {
		return 0, false
	}
	return nativeUint64(b), true
}

func capsFromVendor(a vendorAttrs) Caps {
	caps := Caps{
		PhyDiag:     a.has(attrCapPhyDiag),
		Radar:       a.has(attrCapRadar),
		Spectral:    a.has(attrCapSpectral),
		Advanced:    a.has(attrCapAdvanced),
		ControlPath: ControlPathVendor,
	}
	if gen, ok := a.uint32(attrCapHWGen); ok {
		caps.HardwareGeneration = gen
	}
	return caps
}

func transportFromVendor(a vendorAttrs) string {
	mode, ok := a.uint32(attrSpectralDataTransportMode)
	switch {
	case !ok:
		return ""
	case mode == transportRelay:
		return TransportRelay
	case mode == transportNetlink:
		return TransportNetlink
	default:
		return fmt.Sprintf("mode-%d", mode)
	}
}

func vendorErrorDetail(a vendorAttrs) string {
	code, ok := a.uint32(attrSpectralScanErrorCode)
	if !ok {
		return ""
	}
	if text, known := vendorSpectralErrors[code]; known {
		return text
	}
	return fmt.Sprintf("driver error code %d", code)
}
