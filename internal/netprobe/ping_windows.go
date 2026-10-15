//go:build windows

package netprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ipHelperDLL     = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreateFile  = ipHelperDLL.NewProc("IcmpCreateFile")
	icmpSendEcho    = ipHelperDLL.NewProc("IcmpSendEcho")
	icmpCloseHandle = ipHelperDLL.NewProc("IcmpCloseHandle")
)

func ping(ctx context.Context, addr netip.Addr) (time.Duration, string, error) {
	if !addr.Is4() {
		return 0, "", errors.New("native Windows IPv6 echo is not implemented")
	}
	handle, _, createErr := icmpCreateFile.Call()
	if handle == 0 || handle == uintptr(windows.InvalidHandle) {
		return 0, "", fmt.Errorf("IcmpCreateFile: %w", createErr)
	}
	defer icmpCloseHandle.Call(handle)

	timeout := 4000 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return 0, "", context.DeadlineExceeded
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	payload := []byte("wantastic")
	reply := make([]byte, 64+len(payload))
	ip := addr.As4()
	destination := binary.LittleEndian.Uint32(ip[:])
	started := time.Now()
	count, _, callErr := icmpSendEcho.Call(
		handle,
		uintptr(destination),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeout.Milliseconds()),
	)
	if count == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_TIMEOUT
		}
		return 0, "", fmt.Errorf("IcmpSendEcho: %w", callErr)
	}
	latency := time.Since(started)
	return latency, fmt.Sprintf("native ICMP reply from %s in %s", addr, latency.Round(time.Millisecond)), nil
}
