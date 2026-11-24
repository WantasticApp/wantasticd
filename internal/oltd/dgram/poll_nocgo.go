//go:build (linux && !cgo) || darwin

package dgram

import "golang.org/x/sys/unix"

func pollIn(fd, ms int) (bool, error) {
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(p, ms)
	if err == unix.EINTR {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n > 0 && p[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0, nil
}

// PollImpl names the poll(2) path compiled in (reported by --selftest).
const PollImpl = "x/sys/unix poll(2)"
