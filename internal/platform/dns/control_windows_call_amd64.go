//go:build windows && amd64

package dns

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// x64: a 16-byte struct argument is passed by reference to a caller copy.
func setInterfaceDNS(guid *windows.GUID, settings *dnsInterfaceSettings) uintptr {
	copyGUID := *guid
	r, _, _ := procSetInterfaceDnsSettings.Call(uintptr(unsafe.Pointer(&copyGUID)), uintptr(unsafe.Pointer(settings)))
	return r
}
