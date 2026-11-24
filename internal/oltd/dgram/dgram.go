//go:build linux || darwin

// Package dgram is the AF_UNIX datagram client side of the vendor
// "web service" protocol, built only on raw syscalls (golang.org/x/sys/unix)
// so it never initializes the Go network poller: no package net, no
// os.File, no Go timers. Every wait is a poll(2) timeout.
//
// Each daemon socket gets its own client socket bound at a path unique to
// this process (never /tmp/web_service, which belongs to the webserver: the
// daemon replies to the path carried in the request). Requests to one
// daemon are serialized (one in flight per daemon socket). After a timeout
// the client socket is discarded and the next request binds a fresh path,
// so a late reply can never be mistaken for the answer to a later request.
package dgram

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/sysx"
	"wantastic-agent/internal/oltd/wire"
)

// ErrTimeout is returned when the daemon does not answer in time. It
// reports Timeout() == true.
var ErrTimeout error = timeoutError{}

// ErrBusy is returned when the daemon's receive queue stays full.
var ErrBusy = errors.New("dgram: daemon socket queue full")

type timeoutError struct{}

func (timeoutError) Error() string { return "dgram: daemon did not answer before the deadline" }
func (timeoutError) Timeout() bool { return true }

// Pool holds one Conn per daemon socket path.
type Pool struct {
	Dir string // directory for our reply sockets ("/tmp")
	Pid int
	// Epoch distinguishes processes that share a PID across a self
	// re-exec (the restart count), so a late reply addressed to a socket
	// of the previous process can never reach the new one.
	Epoch int
	mu    sync.Mutex
	next  int
	cons  map[string]*Conn
}

// NewPool returns a pool binding reply sockets in dir as
// wo<pid>_<epoch>_<n>_<gen> (numbers in base 36, path <= 31 bytes).
func NewPool(dir string, pid int) *Pool {
	return &Pool{Dir: dir, Pid: pid, cons: map[string]*Conn{}}
}

// Conn returns the (lazily created) client for one daemon socket.
func (p *Pool) Conn(dest string) *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cons[dest]
	if c == nil {
		p.next++
		c = &Conn{dest: dest, dir: p.Dir, pid: p.Pid, epoch: p.Epoch, idx: p.next, fd: -1}
		p.cons[dest] = c
	}
	return c
}

// Close closes every socket and unlinks every reply path.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.cons {
		c.mu.Lock()
		c.closeLocked()
		c.mu.Unlock()
	}
}

// Conn is the client socket for one daemon socket.
type Conn struct {
	mu    sync.Mutex
	dest  string
	dir   string
	pid   int
	epoch int
	idx   int
	gen   int
	fd    int
	path  string
	rbuf  []byte // receive buffer, reused across requests
}

// Path is the reply path the next request will carry.
func (c *Conn) replyPath() string {
	b36 := func(n int) string { return strconv.FormatInt(int64(n), 36) }
	return c.dir + "/wo" + b36(c.pid) + "_" + b36(c.epoch) + "_" + b36(c.idx) + "_" + b36(c.gen)
}

func (c *Conn) openLocked() error {
	if c.fd >= 0 {
		return nil
	}
	path := c.replyPath()
	if len(path) > wire.PathLen-1 {
		return fmt.Errorf("dgram: reply path %q exceeds %d bytes (use a shorter -sockdir)", path, wire.PathLen-1)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("dgram: socket: %w", err)
	}
	unix.CloseOnExec(fd)
	_ = unix.Unlink(path)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("dgram: bind %s: %w", path, err)
	}
	// Replies can be large (the vendor daemons send up to 512 KiB).
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 64<<10)
	c.fd, c.path = fd, path
	return nil
}

func (c *Conn) closeLocked() {
	if c.fd >= 0 {
		unix.Close(c.fd)
		_ = unix.Unlink(c.path)
		c.fd = -1
	}
}

// flushLocked drains stale datagrams (the vendor's fd_flush) and returns
// how many were dropped.
func (c *Conn) flushLocked() int {
	buf := make([]byte, 64)
	n := 0
	for {
		_, _, err := unix.Recvfrom(c.fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			return n
		}
		n++
	}
}

// Event is one step of a request, reported to Opts.Trace (diagnostics).
type Event struct {
	Kind      string // "send", "flush", "reply", "mismatch", "timeout", "late", "error"
	Sock      string // daemon socket path
	ReplyPath string // our reply socket path carried in the request
	Code      uint16 // request command code
	GotCode   uint16 // reply code (reply/mismatch/late)
	Bytes     int    // bytes sent / datagram bytes received / flushed count
	Elapsed   time.Duration
	Err       string
}

// Opts tunes one request.
type Opts struct {
	Timeout time.Duration
	// Grace keeps listening this long after a timeout, only to report a
	// late reply through Trace (the request still fails). Diagnostics only.
	Grace time.Duration
	Trace func(Event)
}

// Do sends one request (code + reply path filled in by build) and returns
// the reply payload as the webserver would see it with a bufSize buffer.
// build receives the reply path to embed (it must use wire.NewMsg).
func (c *Conn) Do(build func(replyPath string) (wire.Msg, error), bufSize int, o Opts) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	trace := o.Trace
	if trace == nil {
		trace = func(Event) {}
	}
	if err := c.openLocked(); err != nil {
		trace(Event{Kind: "error", Sock: c.dest, Err: err.Error()})
		return "", err
	}
	msg, err := build(c.path)
	if err != nil {
		trace(Event{Kind: "error", Sock: c.dest, ReplyPath: c.path, Err: err.Error()})
		return "", err
	}
	code := msg.Code()
	ev := Event{Sock: c.dest, ReplyPath: c.path, Code: code}
	if n := c.flushLocked(); n > 0 {
		e := ev
		e.Kind, e.Bytes = "flush", n
		trace(e)
	}
	start := time.Now()
	deadline := start.Add(o.Timeout)
	if err := c.sendLocked(msg.Bytes(), deadline); err != nil {
		e := ev
		e.Kind, e.Err, e.Elapsed = "error", err.Error(), time.Since(start)
		trace(e)
		return "", err
	}
	e := ev
	e.Kind, e.Bytes = "send", len(msg.Bytes())
	trace(e)
	if bufSize < wire.ReplyHdrLen+1 {
		bufSize = wire.ReplyHdrLen + 1
	}
	// Receive whole datagrams (up to the daemons' 512 KiB send buffer) so
	// diagnostics see real sizes; ParseReply applies the vendor buffer size.
	rbuf := bufSize + wire.ReplyHdrLen
	if rbuf < 0x80000 {
		rbuf = 0x80000
	}
	if len(c.rbuf) < rbuf {
		c.rbuf = make([]byte, rbuf)
	}
	buf := c.rbuf[:rbuf]
	for {
		left := time.Until(deadline)
		if left <= 0 {
			e := ev
			e.Kind, e.Elapsed = "timeout", time.Since(start)
			trace(e)
			if o.Grace > 0 {
				c.graceLocked(buf, ev, start, o.Grace, trace)
			}
			c.retireLocked()
			return "", ErrTimeout
		}
		ready, err := pollIn(c.fd, int(left/time.Millisecond)+1)
		if err != nil {
			c.retireLocked()
			return "", fmt.Errorf("dgram: poll: %w", err)
		}
		if !ready {
			continue // loop re-checks the deadline
		}
		n, _, err := unix.Recvfrom(c.fd, buf, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			e := ev
			e.Kind, e.Err, e.Elapsed = "error", err.Error(), time.Since(start)
			trace(e)
			c.retireLocked()
			return "", fmt.Errorf("dgram: recv: %w", err)
		}
		e := ev
		e.Bytes, e.Elapsed, e.GotCode = n, time.Since(start), replyCode(buf[:n])
		if payload, ok := wire.ParseReply(buf[:n], code, bufSize); ok {
			e.Kind = "reply"
			trace(e)
			return payload, nil
		}
		// Code mismatch: a stale reply to an older request. The vendor
		// would return an empty buffer; we keep waiting for ours.
		e.Kind = "mismatch"
		trace(e)
	}
}

// graceLocked listens a little longer after a timeout and reports any
// datagram that still arrives (diagnostics: slow daemon vs. no reply).
func (c *Conn) graceLocked(buf []byte, ev Event, start time.Time, grace time.Duration, trace func(Event)) {
	end := time.Now().Add(grace)
	for {
		left := time.Until(end)
		if left <= 0 {
			return
		}
		ready, err := pollIn(c.fd, int(left/time.Millisecond)+1)
		if err != nil {
			return
		}
		if !ready {
			continue
		}
		n, _, err := unix.Recvfrom(c.fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			continue
		}
		e := ev
		e.Kind, e.Bytes, e.Elapsed, e.GotCode = "late", n, time.Since(start), replyCode(buf[:n])
		trace(e)
		return
	}
}

func replyCode(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0]) | uint16(b[1])<<8
}

// retireLocked drops the socket after a failure and moves to a new reply
// path, so a late reply to this request lands on a dead path.
func (c *Conn) retireLocked() {
	c.closeLocked()
	c.gen++
}

func (c *Conn) sendLocked(b []byte, deadline time.Time) error {
	to := &unix.SockaddrUnix{Name: c.dest}
	backoff := int64(5e6) // 5 ms
	for {
		err := unix.Sendto(c.fd, b, unix.MSG_DONTWAIT, to)
		if err == nil {
			return nil
		}
		if err != unix.EAGAIN && err != unix.ENOBUFS && err != unix.EINTR {
			return fmt.Errorf("dgram: sendto %s: %w", c.dest, err)
		}
		if time.Now().After(deadline) {
			return ErrBusy
		}
		sleepNs(backoff)
		if backoff < 100e6 {
			backoff *= 2
		}
	}
}

// sleepNs is the design's back-pressure sleep: nanosleep(2), not a Go timer.
func sleepNs(ns int64) { sysx.Sleep(ns) }
