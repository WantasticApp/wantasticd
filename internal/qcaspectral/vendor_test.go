package qcaspectral

import (
	"testing"

	"github.com/mdlayher/netlink"
)

func TestVendorStartRequestForcesNetlinkOnlyWhenAsked(t *testing.T) {
	plain, err := encodeStartRequest(false)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := decodeVendorAttrs(plain)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := attrs.uint32(attrSpectralScanRequestType); v != requestTypeScan || attrs.has(attrSpectralDataTransportMode) {
		t.Fatalf("plain start must not reconfigure: %v", attrs)
	}
	forced, _ := encodeStartRequest(true)
	attrs, _ = decodeVendorAttrs(forced)
	if v, _ := attrs.uint32(attrSpectralScanRequestType); v != requestTypeScanAndConfig {
		t.Fatalf("forced start request type = %d", v)
	}
	if transportFromVendor(attrs) != TransportNetlink {
		t.Fatalf("forced start must select netlink transport")
	}
}

func TestVendorCapsAndTransportDecoding(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Flag(attrCapSpectral, true)
	ae.Flag(attrCapAdvanced, true)
	ae.Uint32(attrCapHWGen, 3)
	ae.Uint32(attrSpectralDataTransportMode, transportRelay)
	data, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := decodeVendorAttrs(data)
	if err != nil {
		t.Fatal(err)
	}
	caps := capsFromVendor(attrs)
	if !caps.Spectral || !caps.Advanced || caps.PhyDiag || caps.HardwareGeneration != 3 || caps.ControlPath != ControlPathVendor {
		t.Fatalf("unexpected caps %+v", caps)
	}
	if transportFromVendor(attrs) != TransportRelay {
		t.Fatal("relay transport not detected")
	}
}

func TestVendorErrorDetail(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(attrSpectralScanErrorCode, 1)
	data, _ := ae.Encode()
	attrs, _ := decodeVendorAttrs(data)
	if got := vendorErrorDetail(attrs); got != "mode unsupported" {
		t.Fatalf("error detail = %q", got)
	}
}
