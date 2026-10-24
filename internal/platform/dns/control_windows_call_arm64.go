//go:build windows && arm64

package dns

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ARM64: a 16-byte composite is passed in two consecutive registers.
func setInterfaceDNS(guid *windows.GUID, settings *dnsInterfaceSettings) uintptr {
	raw := (*[16]byte)(unsafe.Pointer(guid))
	lo, hi := binary.LittleEndian.Uint64(raw[0:]), binary.LittleEndian.Uint64(raw[8:])
	r, _, _ := procSetInterfaceDnsSettings.Call(uintptr(lo), uintptr(hi), uintptr(unsafe.Pointer(settings)))
	return r
}
