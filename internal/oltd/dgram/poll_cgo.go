//go:build linux && cgo

package dgram

/*
#include <poll.h>
#include <errno.h>

// oltd_poll_in waits up to ms milliseconds for fd to become readable using
// the C library's poll(2) (the "cgo used narrowly" primitive of the design;
// it never involves the Go network poller). Returns 1 ready, 0 timeout,
// -errno on error.
static int oltd_poll_in(int fd, int ms) {
	struct pollfd p;
	p.fd = fd;
	p.events = POLLIN;
	p.revents = 0;
	int r = poll(&p, 1, ms);
	if (r < 0) return -errno;
	if (r == 0) return 0;
	return (p.revents & (POLLIN | POLLERR | POLLHUP)) ? 1 : 0;
}
*/
import "C"

import "syscall"

func pollIn(fd, ms int) (bool, error) {
	r := C.oltd_poll_in(C.int(fd), C.int(ms))
	switch {
	case r == 1:
		return true, nil
	case r == 0:
		return false, nil
	case syscall.Errno(-r) == syscall.EINTR:
		return false, nil
	}
	return false, syscall.Errno(-r)
}

// PollImpl names the poll(2) path compiled in (reported by --selftest).
const PollImpl = "cgo poll(2)"
