//go:build linux || darwin

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/endpoints"
)

// Config configures a Server.
type Config struct {
	Key      []byte
	Backend  endpoints.Backend
	Env      *endpoints.Env
	AllowSet bool
	// Workers caps concurrently served connections; extra connections get
	// one "busy" line and are closed.
	Workers int
	// CacheTTL is the coalescing window for hot getters.
	CacheTTL time.Duration
	// IdleTimeout is the per-connection SO_RCVTIMEO / SO_SNDTIMEO.
	IdleTimeout time.Duration
	Version     string
	Logf        func(format string, args ...any)
	// MaxHeap is the heap ceiling (bytes). The GC never runs in this
	// process (see memguard), so heap only grows; past MaxHeap the server
	// stops accepting, finishes the current requests, closes its
	// connections and Serve returns ErrRestart (the caller re-executes,
	// handing over the listening socket). 0 disables.
	MaxHeap uint64
	// HeapFn reads the current heap size (tests may override).
	HeapFn func() uint64
}

// ErrRestart is returned by Serve when the heap ceiling was reached and
// all connections are closed; the listener is still open (ListenerFD).
var ErrRestart = errors.New("server: heap ceiling reached, restart requested")

// Server is the helper API server.
type Server struct {
	cfg   Config
	sem   chan struct{}
	cache sync.Map // key -> *cacheEntry
	lfd   int
	wake  [2]int
	stop  sync.Once

	stopped    atomic.Bool
	restarting atomic.Bool
	connMu     sync.Mutex
	conns      map[int]bool // open client fds
}

type cacheEntry struct {
	mu   sync.Mutex
	at   time.Time
	data []byte
	err  error
	ok   bool
}

// New returns a server (not yet listening).
func New(cfg Config) *Server {
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Env == nil {
		cfg.Env = &endpoints.Env{}
	}
	return &Server{cfg: cfg, sem: make(chan struct{}, cfg.Workers), lfd: -1, wake: [2]int{-1, -1}, conns: map[int]bool{}}
}

// Adopt serves on an already listening TCP socket (inherited across a
// re-exec) and returns its port.
func (s *Server) Adopt(fd int) (port int, err error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, fmt.Errorf("adopt fd %d: %w", fd, err)
	}
	in4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return 0, fmt.Errorf("adopt fd %d: not an IPv4 socket", fd)
	}
	if runtime.GOOS == "linux" {
		if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || v == 0 {
			return 0, fmt.Errorf("adopt fd %d: not a listening socket", fd)
		}
	}
	unix.CloseOnExec(fd)
	if err := s.makeWake(); err != nil {
		return 0, err
	}
	s.lfd = fd
	return in4.Port, nil
}

// Addr returns the bound "ip:port" of the listener.
func (s *Server) Addr() string {
	sa, err := unix.Getsockname(s.lfd)
	if in4, ok := sa.(*unix.SockaddrInet4); err == nil && ok {
		return netip.AddrPortFrom(netip.AddrFrom4(in4.Addr), uint16(in4.Port)).String()
	}
	return ""
}

// ListenerFD is the listening socket (to hand over across a re-exec).
func (s *Server) ListenerFD() int { return s.lfd }

func (s *Server) makeWake() error {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		return fmt.Errorf("listen: pipe: %w", err)
	}
	unix.CloseOnExec(p[0])
	unix.CloseOnExec(p[1])
	_ = unix.SetNonblock(p[0], true)
	_ = unix.SetNonblock(p[1], true)
	s.wake = p
	return nil
}

// RequestRestart starts a drain: no new connections, open ones are closed
// after their current request, then Serve returns ErrRestart.
// It reports whether this call started the drain.
func (s *Server) RequestRestart() bool {
	if s.restarting.Swap(true) {
		return false
	}
	s.connMu.Lock()
	for fd := range s.conns {
		// Wakes a reader blocked between requests (read returns 0); a
		// request in progress still gets its reply written.
		_ = unix.Shutdown(fd, unix.SHUT_RD)
	}
	s.connMu.Unlock()
	s.kick()
	return true
}

func (s *Server) kick() {
	if s.wake[1] >= 0 {
		_, _ = unix.Write(s.wake[1], []byte{1})
	}
}

func (s *Server) heap() uint64 {
	if s.cfg.HeapFn != nil {
		return s.cfg.HeapFn()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func (s *Server) checkHeap() {
	if s.cfg.MaxHeap > 0 && !s.restarting.Load() && s.heap() > s.cfg.MaxHeap {
		if s.RequestRestart() {
			s.cfg.Logf("heap ceiling %d bytes reached: draining for restart", s.cfg.MaxHeap)
		}
	}
}

// Listen binds the TCP listener on addr ("ip:port", IPv4 only).
func (s *Server) Listen(addr string) (port int, err error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() {
		return 0, fmt.Errorf("listen: want IPv4 ip:port, got %q", addr)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, fmt.Errorf("listen: socket: %w", err)
	}
	unix.CloseOnExec(fd)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	sa := &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("listen: bind %s: %w", addr, err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("listen: %w", err)
	}
	got, err := unix.Getsockname(fd)
	if err == nil {
		if in4, ok := got.(*unix.SockaddrInet4); ok {
			port = in4.Port
		}
	}
	if err := s.makeWake(); err != nil {
		unix.Close(fd)
		return 0, err
	}
	s.lfd = fd
	return port, nil
}

// Stop wakes Serve and closes the listener.
func (s *Server) Stop() {
	s.stop.Do(func() {
		s.stopped.Store(true)
		s.kick()
	})
}

// Serve runs the accept loop until Stop (returns nil, listener closed) or
// a restart drain completes (returns ErrRestart, listener left open for
// the next process). The loop waits in poll(2) on the listener and a wake
// pipe; accepted connections use blocking reads with SO_RCVTIMEO.
func (s *Server) Serve() error {
	defer func() {
		unix.Close(s.wake[0])
		unix.Close(s.wake[1])
		s.wake = [2]int{-1, -1}
	}()
	drain := make([]byte, 16)
	for {
		if s.stopped.Load() {
			unix.Close(s.lfd)
			return nil
		}
		restarting := s.restarting.Load()
		if restarting && len(s.sem) == 0 {
			return ErrRestart
		}
		fds := []unix.PollFd{{Fd: int32(s.wake[0]), Events: unix.POLLIN}}
		timeout := -1
		if restarting {
			timeout = 100 // re-check the drain; new connections wait in the backlog
		} else {
			fds = append(fds, unix.PollFd{Fd: int32(s.lfd), Events: unix.POLLIN})
		}
		if _, err := unix.Poll(fds, timeout); err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("serve: poll: %w", err)
		}
		if fds[0].Revents != 0 {
			for {
				if n, err := unix.Read(s.wake[0], drain); n <= 0 || err != nil {
					break
				}
			}
			continue
		}
		if restarting || fds[1].Revents&unix.POLLIN == 0 {
			continue
		}
		cfd, peer, err := unix.Accept(s.lfd)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.ECONNABORTED {
				continue
			}
			return fmt.Errorf("serve: accept: %w", err)
		}
		unix.CloseOnExec(cfd)
		select {
		case s.sem <- struct{}{}:
			s.connMu.Lock()
			s.conns[cfd] = true
			s.connMu.Unlock()
			go func() {
				defer func() {
					s.connMu.Lock()
					delete(s.conns, cfd)
					s.connMu.Unlock()
					unix.Close(cfd)
					<-s.sem
					if s.restarting.Load() {
						s.kick()
					}
				}()
				s.handle(cfd, peer)
			}()
		default:
			s.writeLine(cfd, mustJSON(Envelope{Body: mustJSON(Reply{OK: false, Code: CodeBusy, Err: "too many connections"})}))
			unix.Close(cfd)
		}
	}
}

func peerString(sa unix.Sockaddr) string {
	if in4, ok := sa.(*unix.SockaddrInet4); ok {
		return netip.AddrPortFrom(netip.AddrFrom4(in4.Addr), uint16(in4.Port)).String()
	}
	return "?"
}

func (s *Server) writeLine(fd int, b []byte) bool {
	b = append(b, '\n')
	for len(b) > 0 {
		n, err := unix.SendmsgN(fd, b, nil, nil, sendFlags)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		b = b[n:]
	}
	return true
}

func (s *Server) handle(fd int, peer unix.Sockaddr) {
	tv := unix.NsecToTimeval(s.cfg.IdleTimeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	nonce := newNonce()
	if !s.writeLine(fd, mustJSON(Hello{Hello: ProtoName, V: ProtoVersion, Nonce: nonce})) {
		return
	}
	var lastSeq uint64
	var buf []byte
	tmp := make([]byte, 16<<10)
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			if len(buf) > MaxLine {
				return
			}
			n, err := unix.Read(fd, tmp)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n <= 0 {
				return // EOF, error, or SO_RCVTIMEO idle timeout
			}
			buf = append(buf, tmp[:n]...)
			continue
		}
		line := bytes.TrimSpace(buf[:i])
		buf = buf[i+1:]
		if len(line) == 0 {
			continue
		}
		var env Envelope
		var req Request
		if json.Unmarshal(line, &env) != nil || len(env.Body) == 0 ||
			!VerifyMAC(RequestMAC(s.cfg.Key, nonce, env.Body), env.MAC) ||
			json.Unmarshal(env.Body, &req) != nil || req.Seq <= lastSeq {
			s.cfg.Logf("auth failure from %s", peerString(peer))
			s.writeLine(fd, mustJSON(Envelope{Body: mustJSON(Reply{OK: false, Code: CodeAuth, Err: "authentication failed"})}))
			return
		}
		lastSeq = req.Seq
		rep := s.dispatch(&req)
		rep.Seq, rep.ID = req.Seq, req.ID
		body := mustJSON(rep)
		if !s.writeLine(fd, mustJSON(Envelope{Body: body, MAC: ReplyMAC(s.cfg.Key, nonce, body)})) {
			return
		}
		s.checkHeap()
		if s.restarting.Load() {
			return // close after a complete reply; the client reconnects
		}
	}
}

func (s *Server) dispatch(req *Request) Reply {
	switch req.Op {
	case "ping":
		return Reply{OK: true, Data: mustJSON(s.info())}
	case "cmd":
		// The /tmp/.imi_line framing is not confirmed on the device yet.
		return Reply{Code: CodeUnsupported, Err: endpoints.ErrUnsupported.Error() + ": cmd (IMI line socket not enabled)"}
	case "get", "set":
	default:
		return Reply{Code: CodeBadRequest, Err: "unknown op " + strconv.Quote(req.Op)}
	}
	ep, ok := endpoints.Lookup(req.Op, req.Path)
	if !ok {
		return Reply{Code: CodeUnsupported, Err: endpoints.ErrUnsupported.Error() + ": " + req.Op + " " + req.Path}
	}
	if req.Op == "set" && !s.cfg.AllowSet {
		return Reply{Code: CodeSetDisabled, Err: endpoints.ErrSetDisabled.Error()}
	}
	data, err := s.call(ep, req.Args)
	if err != nil {
		return Reply{Code: CodeDaemon, Err: err.Error()}
	}
	return Reply{OK: true, Data: data}
}

// call runs an endpoint; hot getters are coalesced: concurrent and
// back-to-back requests within CacheTTL share one daemon round trip.
func (s *Server) call(ep *endpoints.Endpoint, args map[string]any) ([]byte, error) {
	if !ep.Hot || ep.Op != "get" || s.cfg.CacheTTL <= 0 {
		return ep.Call(s.cfg.Backend, args, s.cfg.Env)
	}
	key := ep.Name + "?" + canonArgs(args)
	v, _ := s.cache.LoadOrStore(key, &cacheEntry{})
	e := v.(*cacheEntry)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ok && time.Since(e.at) < s.cfg.CacheTTL {
		return e.data, e.err
	}
	data, err := ep.Call(s.cfg.Backend, args, s.cfg.Env)
	if err != nil {
		e.ok = false
		return nil, err
	}
	e.data, e.err, e.at, e.ok = data, nil, time.Now(), true
	return data, nil
}

func canonArgs(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(endpoints.Params(args).Str(k))
		b.WriteByte('&')
	}
	return b.String()
}

// Info is the ping payload.
type Info struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Proto     int      `json:"proto"`
	AllowSet  bool     `json:"allowSet"`
	Get       []string `json:"get"`
	Set       []string `json:"set"`
	PollImpl  string   `json:"pollImpl,omitempty"`
	Workers   int      `json:"workers"`
	CacheTTLm int64    `json:"cacheTtlMs"`
}

func (s *Server) info() Info {
	in := Info{Name: ProtoName, Version: s.cfg.Version, Proto: ProtoVersion, AllowSet: s.cfg.AllowSet,
		Workers: s.cfg.Workers, CacheTTLm: s.cfg.CacheTTL.Milliseconds()}
	for _, e := range endpoints.Catalog() {
		if e.Op == "get" {
			in.Get = append(in.Get, e.Name)
		} else if s.cfg.AllowSet {
			in.Set = append(in.Set, e.Name)
		}
	}
	return in
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(Reply{Code: CodeBadRequest, Err: err.Error()})
	}
	return b
}

// newNonce returns 16 random bytes (hex) read from /dev/urandom with raw
// syscalls (crypto/rand may fall back to os.Open on old kernels without
// getrandom(2), which would start the network poller).
func newNonce() string {
	b := make([]byte, 16)
	if fd, err := syscall.Open("/dev/urandom", syscall.O_RDONLY|syscall.O_CLOEXEC, 0); err == nil {
		n, _ := syscall.Read(fd, b)
		syscall.Close(fd)
		if n == len(b) {
			return hex.EncodeToString(b)
		}
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%p", time.Now().UnixNano(), syscall.Getpid(), &b)))
	return hex.EncodeToString(h[:16])
}

// ErrStopped is returned by helpers when the server was stopped.
var ErrStopped = errors.New("server stopped")
