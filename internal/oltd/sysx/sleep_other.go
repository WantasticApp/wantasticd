//go:build !linux

package sysx

import "golang.org/x/sys/unix"

// Sleep blocks for ns nanoseconds with select(2) (Darwin has no
// nanosleep wrapper in x/sys); never a Go runtime timer.
func Sleep(ns int64) {
	tv := unix.NsecToTimeval(ns)
	_, _ = unix.Select(0, nil, nil, nil, &tv)
}
