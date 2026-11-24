// Package sysx holds the few raw-syscall primitives shared by the helper
// that differ between Linux (shipping) and Darwin (tests).
package sysx

import "syscall"

// Sleep blocks the calling thread for ns nanoseconds with nanosleep(2).
// It never arms a Go runtime timer (which would start the network poller).
func Sleep(ns int64) {
	ts := syscall.NsecToTimespec(ns)
	for syscall.Nanosleep(&ts, &ts) == syscall.EINTR {
	}
}
