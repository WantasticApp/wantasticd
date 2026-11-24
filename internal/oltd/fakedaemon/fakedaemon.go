//go:build linux || darwin

// Package fakedaemon is a test double for a vendor daemon's AF_UNIX
// datagram "web service" socket (/tmp/sm_web, /tmp/pon_web, ...): it binds
// a path, reads requests like web_service_read (recv of at most 1024
// bytes), and answers like web_service_response (seq_push + sendto to the
// reply path carried in the request). Used by tests only.
package fakedaemon

import (
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/wire"
)

// Handler returns the reply payload for one request; reply=false drops it
// (simulates a wedged daemon).
type Handler func(code uint16, req []byte) (payload []byte, reply bool)

// Daemon is one fake daemon socket.
type Daemon struct {
	Path     string
	fd       int
	stop     atomic.Bool
	wg       sync.WaitGroup
	mu       sync.Mutex
	Requests [][]byte // every request as received (first 1024 bytes)
}

// Start binds path and serves h until Close.
func Start(path string, h Handler) (*Daemon, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	_ = unix.Unlink(path)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// pal_sock_set_sendbuf(fd, 0x80000) like the vendor; also lets Darwin
	// send datagrams larger than its 2 KiB default.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 0x80000)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 0x80000)
	d := &Daemon{Path: path, fd: fd}
	d.wg.Add(1)
	go d.loop(h)
	return d, nil
}

func (d *Daemon) loop(h Handler) {
	defer d.wg.Done()
	buf := make([]byte, wire.DaemonRecvLen)
	for !d.stop.Load() {
		p := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(p, 50)
		if err != nil || n == 0 {
			continue
		}
		m, _, err := unix.Recvfrom(d.fd, buf, 0)
		if err != nil || m < wire.QuickCountOff {
			continue
		}
		req := append([]byte(nil), buf[:m]...)
		d.mu.Lock()
		d.Requests = append(d.Requests, req)
		d.mu.Unlock()
		msg := wire.Msg(req)
		payload, ok := h(msg.Code(), req)
		if !ok {
			continue
		}
		_ = unix.Sendto(d.fd, wire.EncodeReply(msg.Code(), payload), 0, &unix.SockaddrUnix{Name: msg.ReplyPath()})
	}
}

// Seen returns a copy of the requests received so far.
func (d *Daemon) Seen() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.Requests...)
}

// Close stops the daemon and unlinks its path.
func (d *Daemon) Close() {
	d.stop.Store(true)
	d.wg.Wait()
	unix.Close(d.fd)
	_ = unix.Unlink(d.Path)
}

// Text is a helper Handler answering fixed text per code, like
// web_service_finish (text + four NULs); unknown codes are dropped.
func Text(replies map[uint16]string) Handler {
	return func(code uint16, _ []byte) ([]byte, bool) {
		s, ok := replies[code]
		if !ok {
			return nil, false
		}
		return wire.FinishText(s), true
	}
}
