//go:build windows && 386

package dns

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 32-bit: the GUID is pushed by value as four 32-bit words.
func setInterfaceDNS(guid *windows.GUID, settings *dnsInterfaceSettings) uintptr {
	raw := (*[16]byte)(unsafe.Pointer(guid))
	w := func(i int) uintptr { return uintptr(binary.LittleEndian.Uint32(raw[4*i:])) }
	r, _, _ := procSetInterfaceDnsSettings.Call(w(0), w(1), w(2), w(3), uintptr(unsafe.Pointer(settings)))
	return r
}
