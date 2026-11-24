//go:build linux

package netpollguard

import "syscall"

func probe() (bool, string) {
	fd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		if err == syscall.ENOSYS {
			return false, "epoll_create1: ENOSYS (no epoll): netpoll-free mode"
		}
		return false, "epoll_create1: " + err.Error() + ": netpoll-free mode"
	}
	syscall.Close(fd)
	return true, "epoll available"
}
