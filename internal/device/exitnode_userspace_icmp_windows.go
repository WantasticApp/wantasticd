//go:build windows

package device

import (
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = modIphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = modIphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
)

// windowsEchoer pings through the Windows ICMP API, which needs no raw
// socket and works for the service account.
type windowsEchoer struct{}

func newICMPEchoer() icmpEchoer {
	if procIcmpCreateFile.Find() != nil || procIcmpSendEcho.Find() != nil || procIcmpCloseHandle.Find() != nil {
		return nil
	}
	return windowsEchoer{}
}

func (windowsEchoer) echo(dst netip.Addr, payload []byte, timeout time.Duration) bool {
	if !dst.Is4() || len(payload) > 1472 {
		return false
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || windows.Handle(h) == windows.InvalidHandle {
		return false
	}
	defer procIcmpCloseHandle.Call(h)

	a := dst.As4()
	// IPAddr is the address in network byte order as laid out in memory.
	addr := binary.LittleEndian.Uint32(a[:])
	var data uintptr
	if len(payload) > 0 {
		data = uintptr(unsafe.Pointer(&payload[0]))
	}
	// ICMP_ECHO_REPLY (at most 40 bytes on 64-bit), the echoed data and room
	// for an ICMP error message.
	reply := make([]byte, 64+len(payload)+8)
	n, _, _ := procIcmpSendEcho.Call(h, uintptr(addr), data, uintptr(len(payload)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	// Status (offset 4) 0 is IP_SUCCESS: an echo reply, not an error.
	return n > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0
}

func (windowsEchoer) close() {}
