//go:build linux || darwin

// Command wantastic-oltd is the native OLT config/status helper: it runs on
// the CyberAntennas / Photon GP8X2G6 OLT, talks to the vendor daemons over
// their AF_UNIX datagram "web service" sockets exactly like the GoAhead
// webserver does (no web login, no HTTP load), and serves the companion
// agent over an HMAC-authenticated newline-JSON TCP API.
//
// The OLT kernel (3.6.5) has no epoll, so this binary must never start the
// Go network poller: no package net, no os.Open/os.File, no os/exec, no Go
// timers. See internal/oltd and the netpoll gate test.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/dgram"
	"wantastic-agent/internal/oltd/endpoints"
	"wantastic-agent/internal/oltd/memguard"
	"wantastic-agent/internal/oltd/netpollguard"
	"wantastic-agent/internal/oltd/server"
)

const version = "0.1.0"

// fdWriter writes straight to a file descriptor (no *os.File use).
type fdWriter int

func (w fdWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := syscall.Write(int(w), p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

var (
	stdout = fdWriter(1)
	stderr = fdWriter(2)
)

func logf(format string, args ...any) {
	fmt.Fprintf(stderr, "%s wantastic-oltd: %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func fatalf(code int, format string, args ...any) {
	logf(format, args...)
	os.Exit(code)
}

func main() {
	// Before anything else: the GC must never complete a cycle in this
	// process (its background scavenger would arm a runtime timer and
	// start the epoll netpoller, fatal on the OLT). Re-execs with GOGC=off.
	if err := memguard.Ensure(); err != nil {
		fatalf(3, "%v", err)
	}
	flag.CommandLine.SetOutput(stderr)
	listen := flag.String("listen", "", "TCP address to serve the helper API on, e.g. 192.168.130.179:7071 (required to serve; there is no default bind)")
	keyPath := flag.String("key", "/mnt/config/wantastic-oltd.key", "file holding the shared HMAC key (hex, >= 16 bytes)")
	allowSet := flag.Bool("allow-set", false, "serve set operations (off: writes are answered set_disabled and the agent uses the web UI)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request daemon reply timeout (poll(2))")
	cacheTTL := flag.Duration("cache", 3*time.Second, "coalescing window for hot getters (0 disables)")
	workers := flag.Int("workers", 3, "max concurrently served connections")
	sockDir := flag.String("sockdir", "/tmp", "directory for this process's reply sockets (path must stay under 32 bytes)")
	i2c := flag.Bool("i2c-sensors", false, "read board temperatures over /dev/i2c-1 for getSysStatus (like board_temp_get)")
	selftest := flag.Bool("selftest", false, "run read-only getters against the daemon sockets, print the results with per-sub-request diagnostics, exit (no listener)")
	selftestEPs := flag.String("selftest-endpoints", "", "comma separated read-only getters for -selftest (implies it), e.g. getSysStatus,getOntDetail?ontid=0/1/1; set*/del*/action names are refused")
	selftestGrace := flag.Duration("selftest-grace", 10*time.Second, "selftest only: after a sub-request timeout keep listening this long to report a late reply (0 disables)")
	maxHeap := flag.Int("max-heap-mb", 24, "heap ceiling in MiB; the GC is off, so past it the helper drains and re-executes itself keeping the listening socket (0 disables)")
	selftestGC := flag.Duration("selftest-gc", 0, "memory stress selftest for this duration: serve synthetic requests (fake daemon replies, no daemon load) over loopback TCP, verify no GC cycle ever runs, then exercise the restart handover by re-executing; exits")
	selftestGCChild := flag.String("selftest-gc-child", "", "internal: second stage of -selftest-gc after the re-exec (key hex)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintf(stdout, "wantastic-oltd %s (proto %d, %s)\n", version, server.ProtoVersion, dgram.PollImpl)
		return
	}
	hasEpoll, detail := netpollguard.Probe()
	heapNow, numGC := memguard.Stats()
	logf("startup: pid %d, %s; GOGC=%s numGC=%d heap=%d restarts=%s", syscall.Getpid(), detail,
		os.Getenv("GOGC"), numGC, heapNow, envOr(memguard.EnvRestarts, "0"))
	_ = hasEpoll
	if *selftestGCChild != "" {
		os.Exit(runSelftestGCChild(*selftestGCChild))
	}
	if *selftestGC > 0 {
		os.Exit(runSelftestGC(*selftestGC, uint64(*maxHeap)<<20))
	}

	env := &endpoints.Env{I2C: *i2c}
	pool := dgram.NewPool(strings.TrimRight(*sockDir, "/"), syscall.Getpid())
	pool.Epoch, _ = strconv.Atoi(envOr(memguard.EnvRestarts, "0"))
	defer pool.Close()
	backend := &dgram.Backend{Pool: pool, Timeout: *timeout}

	if *selftest || *selftestEPs != "" {
		calls, err := selftestPlan(*selftestEPs)
		if err != nil {
			fatalf(2, "%v", err)
		}
		backend.Grace = *selftestGrace
		code := runSelftest(backend, env, calls)
		pool.Close() // unlink our reply sockets
		os.Exit(code)
	}
	if *listen == "" {
		fatalf(2, "-listen is required (e.g. -listen 192.168.130.179:7071); refusing to pick a bind address")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		fatalf(2, "key: %v", err)
	}
	srv := server.New(server.Config{
		Key: key, Backend: backend, Env: env, AllowSet: *allowSet, Workers: *workers,
		CacheTTL: *cacheTTL, Version: version, Logf: logf, MaxHeap: uint64(*maxHeap) << 20,
	})
	port, err := listenOrAdopt(srv, *listen)
	if err != nil {
		fatalf(1, "%v", err)
	}
	logf("serving %s (port %d), allow-set=%v, workers=%d, cache=%s, timeout=%s, max-heap=%dMiB, %s",
		*listen, port, *allowSet, *workers, *cacheTTL, *timeout, *maxHeap, dgram.PollImpl)
	err = srv.Serve()
	if err == server.ErrRestart {
		pool.Close()
		heapNow, _ := memguard.Stats()
		logf("re-executing (heap %d bytes), listener fd %d handed over", heapNow, srv.ListenerFD())
		fatalf(1, "re-exec failed: %v", handOver(srv.ListenerFD()))
	}
	if err != nil {
		fatalf(1, "%v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// listenOrAdopt serves on the listening socket inherited from the previous
// process (WANTASTIC_OLTD_LISTEN_FD) when it is bound to addr, else binds.
func listenOrAdopt(srv *server.Server, addr string) (int, error) {
	if v := os.Getenv(memguard.EnvListenFD); v != "" {
		os.Unsetenv(memguard.EnvListenFD)
		if fd, err := strconv.Atoi(v); err == nil && fd > 2 {
			if bound := sockAddr(fd); bound == addr {
				port, err := srv.Adopt(fd)
				if err == nil {
					logf("adopted listening socket fd %d (%s) from the previous process", fd, addr)
					return port, nil
				}
				logf("inherited fd %d not usable: %v; binding anew", fd, err)
			} else {
				logf("inherited fd %d is bound to %q, not %q; binding anew", fd, bound, addr)
			}
			syscall.Close(fd)
		}
	}
	return srv.Listen(addr)
}

func sockAddr(fd int) string {
	sa, err := unix.Getsockname(fd)
	if in4, ok := sa.(*unix.SockaddrInet4); err == nil && ok {
		return netip.AddrPortFrom(netip.AddrFrom4(in4.Addr), uint16(in4.Port)).String()
	}
	return ""
}

// handOver re-executes this program keeping the listening socket open.
// It returns only on failure.
func handOver(lfd int) error {
	if _, err := unix.FcntlInt(uintptr(lfd), unix.F_SETFD, 0); err != nil {
		return fmt.Errorf("clear close-on-exec on fd %d: %w", lfd, err)
	}
	n, _ := strconv.Atoi(envOr(memguard.EnvRestarts, "0"))
	return memguard.Exec(memguard.EnvListenFD+"="+strconv.Itoa(lfd), memguard.EnvRestarts+"="+strconv.Itoa(n+1))
}

// readKey reads the shared secret with raw syscalls. The file holds hex
// (whitespace ignored); anything that is not valid hex is used as raw
// bytes.
func readKey(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer syscall.Close(fd)
	buf := make([]byte, 4096)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	raw := bytes.TrimSpace(buf[:n])
	key := raw
	if k, err := hex.DecodeString(string(raw)); err == nil {
		key = k
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("%s: key too short (%d bytes, need >= 16)", path, len(key))
	}
	return key, nil
}

// selftestCall is one read-only getter run by -selftest.
type selftestCall struct {
	path string
	args endpoints.Params
}

// defaultSelftest are read-only getters only; no set is ever issued here.
var defaultSelftest = []selftestCall{
	{"getSysStatus", nil},
	{"getPortBasicList", nil},
	{"getQvlanList", nil},
	{"getOntListBrife", endpoints.Params{"PonPortName": "all"}},
}

// selftestPlan parses -selftest-endpoints ("name" or "name?k=v&k2=v2",
// comma separated). Only registered getters are accepted; anything that
// looks like a write or an action is refused before anything runs.
func selftestPlan(list string) ([]selftestCall, error) {
	if strings.TrimSpace(list) == "" {
		return defaultSelftest, nil
	}
	var out []selftestCall
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, query, _ := strings.Cut(item, "?")
		name = strings.TrimPrefix(strings.TrimSpace(name), "/goform/")
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "set") || strings.HasPrefix(lower, "del") || strings.HasPrefix(lower, "add") || strings.Contains(lower, "action") {
			return nil, fmt.Errorf("-selftest-endpoints: refusing %q (selftest runs read-only getters only)", name)
		}
		if !strings.HasPrefix(name, "get") {
			return nil, fmt.Errorf("-selftest-endpoints: refusing %q (only get* endpoints)", name)
		}
		if _, ok := endpoints.Lookup("get", name); !ok {
			return nil, fmt.Errorf("-selftest-endpoints: %q is not served by the helper", name)
		}
		args := endpoints.Params{}
		for _, d := range defaultSelftest {
			if d.path == name {
				for k, v := range d.args {
					args[k] = v
				}
			}
		}
		if query != "" {
			for _, kv := range strings.Split(query, "&") {
				k, v, _ := strings.Cut(kv, "=")
				if k != "" {
					args[k] = v
				}
			}
		}
		out = append(out, selftestCall{name, args})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-selftest-endpoints: empty list")
	}
	return out, nil
}

// traceLine prints one daemon sub-request event.
func traceLine(e dgram.Event) {
	head := fmt.Sprintf("   [%s code %d]", e.Sock, e.Code)
	ms := e.Elapsed.Milliseconds()
	switch e.Kind {
	case "flush":
		fmt.Fprintf(stdout, "%s flushed %d stale datagram(s) before sending\n", head, e.Bytes)
	case "send":
		fmt.Fprintf(stdout, "%s sent %d B, reply path %s\n", head, e.Bytes, e.ReplyPath)
	case "reply":
		fmt.Fprintf(stdout, "%s reply code %d, %d B datagram, %d ms\n", head, e.GotCode, e.Bytes, ms)
	case "mismatch":
		fmt.Fprintf(stdout, "%s CODE MISMATCH: got code %d (%d B) after %d ms, still waiting\n", head, e.GotCode, e.Bytes, ms)
	case "timeout":
		fmt.Fprintf(stdout, "%s TIMEOUT after %d ms: no reply with code %d\n", head, ms, e.Code)
	case "late":
		fmt.Fprintf(stdout, "%s LATE reply code %d, %d B, %d ms after send (slow daemon, not dead)\n", head, e.GotCode, e.Bytes, ms)
	case "error":
		fmt.Fprintf(stdout, "%s ERROR after %d ms: %s\n", head, ms, e.Err)
	}
}

func runSelftest(b *dgram.Backend, env *endpoints.Env, calls []selftestCall) int {
	fmt.Fprintf(stdout, "wantastic-oltd %s selftest (read-only), poll=%s, epoll=%v, timeout=%s, grace=%s\n",
		version, dgram.PollImpl, netpollguard.HasEpoll(), b.Timeout, b.Grace)
	b.Trace = traceLine
	defer func() { b.Trace = nil }()
	failed := 0
	for _, c := range calls {
		ep, ok := endpoints.Lookup("get", c.path)
		if !ok {
			fmt.Fprintf(stdout, "== %s: not registered\n", c.path)
			failed++
			continue
		}
		fmt.Fprintf(stdout, "== %s args=%v\n", c.path, map[string]any(c.args))
		start := time.Now()
		data, err := ep.Call(b, c.args, env)
		ms := time.Since(start).Milliseconds()
		if err != nil {
			fmt.Fprintf(stdout, "== %s: ERROR after %d ms: %v\n", c.path, ms, err)
			failed++
			continue
		}
		valid := json.Valid(data)
		partial := ""
		if strings.Contains(string(data), `"_helperUnsupported"`) {
			partial = " (partial: see _helperUnsupported)"
		}
		fmt.Fprintf(stdout, "== %s: ok%s, %d bytes, %d ms, valid JSON=%v\n%s\n", c.path, partial, len(data), ms, valid, data)
		if !valid {
			failed++
		}
	}
	fmt.Fprintf(stdout, "selftest: %d/%d ok\n", len(calls)-failed, len(calls))
	if failed > 0 {
		return 1
	}
	return 0
}
