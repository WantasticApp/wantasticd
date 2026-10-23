//go:build linux

package platforms

import "golang.org/x/sys/unix"

// readKernelClockSync asks the kernel through adjtimex(2), as timedatectl's
// "System clock synchronized" does: synchronized when no NTP clock error is
// flagged (STA_UNSYNC clear, state not TIME_ERROR).
func readKernelClockSync() (bool, bool) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	return state != unix.TIME_ERROR && tx.Status&unix.STA_UNSYNC == 0, true
}
