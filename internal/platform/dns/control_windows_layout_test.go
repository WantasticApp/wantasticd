//go:build windows

package dns

import (
	"testing"
	"unsafe"
)

// Offsets of DNS_INTERFACE_SETTINGS as MSVC lays it out.
func TestDNSInterfaceSettingsLayout(t *testing.T) {
	var s dnsInterfaceSettings
	ptr := unsafe.Sizeof(uintptr(0))
	if unsafe.Offsetof(s.FlagsLow) != 8 || unsafe.Offsetof(s.Domain) != 16 || unsafe.Offsetof(s.NameServer) != 16+ptr {
		t.Fatalf("layout: flags=%d domain=%d nameserver=%d", unsafe.Offsetof(s.FlagsLow), unsafe.Offsetof(s.Domain), unsafe.Offsetof(s.NameServer))
	}
}
