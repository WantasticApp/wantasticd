//go:build !linux

package endpoints

import (
	"time"

	"golang.org/x/sys/unix"
)

func uptimeSeconds() (int64, bool) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, false
	}
	return int64(time.Since(time.Unix(tv.Unix())).Seconds()), true
}

func boardTemps(*Env) (int, int, bool) { return 0, 0, false }
