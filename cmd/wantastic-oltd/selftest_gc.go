//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/endpoints"
	"wantastic-agent/internal/oltd/memguard"
	"wantastic-agent/internal/oltd/server"
	"wantastic-agent/internal/oltd/sysx"
	"wantastic-agent/internal/oltd/wire"
)

// cannedBackend answers daemon requests from fixed text (no daemon load):
// the -selftest-gc stress exercises our code paths, not the daemons.
type cannedBackend struct{}

var cannedReplies = map[uint16]string{
	156:  "1.1.3.18(release-000530),V4.0,2026-11-23 00:05:30,1.3.6.1.4.1.48409.4",
	157:  "GPON-OLT,unused,0090.4C06.A427,123456790",
	417:  "lab",
	419:  "60,-30",
	387:  "192.168.100.100,255.255.255.0,static",
	386:  "192.168.100.1",
	272:  "pon1;pon1;1;2500;1;1\npon2;pon2;1;2500;1;1\nge1;ge1;1;1000;1;1\nge2;ge2;0;1000;1;1",
	662:  "1:01:00\n0:00:00",
	271:  "pon1,--,1,1,2500,1,0,0,0,0,1522,0,1\nge1,--,1,1,1000,1,0,0,0,0,1522,0,1",
	661:  "online enable 1 1 enable enable sn enable enable enable\noffline enable 0 1 enable enable sn enable enable enable",
	300:  "1,default,1,static,192.168.1.100,255.255.255.0:4000,VLAN4000,1,static,192.168.130.179,255.255.255.0",
	1011: "0/1/1,HWTC-93bb0308,online,0d20h11m,PTF2164Q,Normal,-,-\n0/1/2,HWTC-93bb0309,offline,0d00h00m,PTF2164Q,Normal,-,-",
}

func (cannedBackend) Query(_ string, build func(string) (wire.Msg, error), bufSize int) (string, error) {
	m, err := build("/tmp/wo-selftest")
	if err != nil {
		return "", err
	}
	text, ok := cannedReplies[m.Code()]
	if !ok {
		return "", fmt.Errorf("canned: no reply for code %d", m.Code())
	}
	got, _ := wire.ParseReply(wire.EncodeReply(m.Code(), wire.FinishText(text)), m.Code(), bufSize)
	return got, nil
}

// ---- raw-syscall loopback client (no package net) ------------------------

type rawClient struct {
	fd    int
	buf   []byte
	nonce string
	key   []byte
	seq   uint64
}

func dialRaw(addr string, key []byte, timeout time.Duration) (*rawClient, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	c := &rawClient{fd: fd, key: key}
	line, err := c.readLine()
	if err != nil {
		c.close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	var h server.Hello
	if json.Unmarshal(line, &h) != nil || h.Hello != server.ProtoName || h.Nonce == "" {
		c.close()
		return nil, fmt.Errorf("bad hello %q", line)
	}
	c.nonce = h.Nonce
	return c, nil
}

func (c *rawClient) close() { unix.Close(c.fd) }

func (c *rawClient) readLine() ([]byte, error) {
	tmp := make([]byte, 16<<10)
	for {
		if i := bytes.IndexByte(c.buf, '\n'); i >= 0 {
			line := c.buf[:i]
			c.buf = c.buf[i+1:]
			return line, nil
		}
		n, err := unix.Read(c.fd, tmp)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return nil, errors.New("connection closed")
		}
		c.buf = append(c.buf, tmp[:n]...)
	}
}

func (c *rawClient) call(op, path string, args map[string]any) (server.Reply, error) {
	c.seq++
	body, _ := json.Marshal(server.Request{Seq: c.seq, Op: op, Path: path, Args: args})
	line, _ := json.Marshal(server.Envelope{Body: body, MAC: server.RequestMAC(c.key, c.nonce, body)})
	line = append(line, '\n')
	for len(line) > 0 {
		n, err := unix.Write(c.fd, line)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return server.Reply{}, err
		}
		line = line[n:]
	}
	raw, err := c.readLine()
	if err != nil {
		return server.Reply{}, err
	}
	var env server.Envelope
	var rep server.Reply
	if json.Unmarshal(raw, &env) != nil || json.Unmarshal(env.Body, &rep) != nil {
		return rep, fmt.Errorf("bad reply %q", raw)
	}
	if !server.VerifyMAC(server.ReplyMAC(c.key, c.nonce, env.Body), env.MAC) || rep.Seq != c.seq {
		return rep, fmt.Errorf("reply signature/sequence mismatch")
	}
	return rep, nil
}

func randomKey() []byte {
	k := make([]byte, 32)
	if fd, err := syscall.Open("/dev/urandom", syscall.O_RDONLY|syscall.O_CLOEXEC, 0); err == nil {
		syscall.Read(fd, k)
		syscall.Close(fd)
	}
	return k
}

var stressCalls = []struct {
	op, path string
	args     map[string]any
}{
	{"get", "getSysStatus", nil},
	{"get", "getPortBasicList", nil},
	{"get", "getQvlanList", nil},
	{"get", "getOntListBrife", map[string]any{"PonPortName": "all"}},
	{"get", "getPonPortBasicList", nil},
	{"ping", "", nil},
}

// runSelftestGC starts the memory stress selftest (stage 0).
func runSelftestGC(d time.Duration, maxHeap uint64) int {
	if maxHeap == 0 {
		maxHeap = 24 << 20
	}
	st := gcStage{key: randomKey(), deadline: time.Now().Add(d).UnixNano(), maxHeap: maxHeap, fd: -1}
	fmt.Fprintf(stdout, "selftest-gc: %s of synthetic load (fake daemon replies, no daemon load), heap ceiling %d bytes; every ceiling hit drains and re-executes like production\n", d, maxHeap)
	return st.run()
}

// runSelftestGCChild continues the selftest after a re-exec.
func runSelftestGCChild(arg string) int {
	var st gcStage
	var keyHex string
	parts := strings.Split(arg, ":")
	if len(parts) != 5 {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: bad child argument\n")
		return 1
	}
	keyHex = parts[0]
	st.deadline, _ = strconv.ParseInt(parts[1], 10, 64)
	st.stage, _ = strconv.Atoi(parts[2])
	st.total, _ = strconv.ParseInt(parts[3], 10, 64)
	mh, _ := strconv.ParseUint(parts[4], 10, 64)
	st.maxHeap = mh
	var err error
	if st.key, err = hex.DecodeString(keyHex); err != nil {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: bad key\n")
		return 1
	}
	if st.fd, err = strconv.Atoi(os.Getenv(memguard.EnvListenFD)); err != nil {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: %s not set\n", memguard.EnvListenFD)
		return 1
	}
	os.Unsetenv(memguard.EnvListenFD)
	return st.run()
}

type gcStage struct {
	key      []byte
	deadline int64 // unix ns
	stage    int
	total    int64 // requests served by earlier stages
	maxHeap  uint64
	fd       int // inherited listener, -1 = bind 127.0.0.1:0
}

// run serves synthetic requests over loopback until the heap ceiling makes
// the server drain (production path) or the deadline passes, checking every
// second that no GC cycle ever completed; then it re-executes into the
// next stage with the listening socket, or reports PASS once the deadline
// has passed and at least one handover was verified.
func (st *gcStage) run() int {
	srv := server.New(server.Config{Key: st.key, Backend: cannedBackend{}, Env: &endpoints.Env{}, Workers: 3,
		Version: version, Logf: logf, MaxHeap: st.maxHeap})
	var port int
	var err error
	if st.fd >= 0 {
		port, err = srv.Adopt(st.fd)
	} else {
		port, err = srv.Listen("127.0.0.1:0")
	}
	if err != nil {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: stage %d listener: %v\n", st.stage, err)
		return 1
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()

	heap0, gc0 := memguard.Stats()
	fmt.Fprintf(stdout, "stage %d: pid %d, GOGC=%s, numGC=%d, heap=%d, listener %s (fd %d)\n",
		st.stage, syscall.Getpid(), os.Getenv("GOGC"), gc0, heap0, addr, srv.ListenerFD())
	if os.Getenv("GOGC") != "off" || gc0 != 0 {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: the GC is not off\n")
		return 1
	}
	final := time.Now().UnixNano() >= st.deadline && st.stage > 0

	var stop atomic.Bool
	var requests, failures atomic.Int64
	var firstErr atomic.Value
	var wg sync.WaitGroup
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for !stop.Load() {
				c, err := dialRaw(addr, st.key, 2*time.Second)
				if err != nil {
					sysx.Sleep(10e6)
					continue // server draining: retry until stop
				}
				for i := 0; i < 50 && !stop.Load(); i++ {
					sc := stressCalls[(w+i)%len(stressCalls)]
					rep, err := c.call(sc.op, sc.path, sc.args)
					if err != nil {
						break // closed by the drain: reconnect
					}
					requests.Add(1)
					if !rep.OK {
						failures.Add(1)
						firstErr.CompareAndSwap(nil, fmt.Sprintf("%s: %s %s", sc.path, rep.Code, rep.Err))
					}
					if final && requests.Load() >= 30 {
						stop.Store(true)
					}
				}
				c.close()
			}
		}(w)
	}

	fail := ""
	var serveErr error
	drained := false
	for !drained {
		select {
		case serveErr = <-served:
			drained = true // the server hit the ceiling and drained (production path)
			continue
		case <-afterNs(1e9):
		}
		heap, ngc := memguard.Stats()
		fmt.Fprintf(stdout, "  stage %d: requests=%d failures=%d heap=%d numGC=%d\n", st.stage, requests.Load(), failures.Load(), heap, ngc)
		if ngc != 0 {
			fail = "a GC cycle ran"
			break
		}
		if stop.Load() || time.Now().UnixNano() >= st.deadline {
			break
		}
	}
	stop.Store(true)
	if !drained {
		srv.RequestRestart()
	}
	wg.Wait()
	if !drained {
		select {
		case serveErr = <-served:
		case <-afterNs(10e9):
			serveErr = errors.New("drain did not finish within 10 s")
		}
	}
	if _, ngc := memguard.Stats(); ngc != 0 && fail == "" {
		fail = "a GC cycle ran"
	}
	if e, _ := firstErr.Load().(string); e != "" && fail == "" {
		fail = "request failed: " + e
	}
	if fail == "" && serveErr != server.ErrRestart {
		fail = fmt.Sprintf("Serve returned %v, want ErrRestart", serveErr)
	}
	if fail == "" && requests.Load() == 0 {
		fail = "no request served"
	}
	total := st.total + requests.Load()
	if fail != "" {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: stage %d: %s\n", st.stage, fail)
		return 1
	}
	if final {
		fmt.Fprintf(stdout, "selftest-gc: PASS: %d requests over %d re-executions, GOGC=off and numGC=0 in every stage, listener handed over each time\n",
			total, st.stage)
		return 0
	}
	fmt.Fprintf(stdout, "stage %d done: %d requests (total %d); re-executing with listener fd %d\n",
		st.stage, requests.Load(), total, srv.ListenerFD())
	if _, err := unix.FcntlInt(uintptr(srv.ListenerFD()), unix.F_SETFD, 0); err != nil {
		fmt.Fprintf(stdout, "selftest-gc: FAIL: %v\n", err)
		return 1
	}
	child := fmt.Sprintf("%s:%d:%d:%d:%d", hex.EncodeToString(st.key), st.deadline, st.stage+1, total, st.maxHeap)
	err = memguard.ExecArgs([]string{os.Args[0], "-selftest-gc-child", child},
		memguard.EnvListenFD+"="+strconv.Itoa(srv.ListenerFD()))
	fmt.Fprintf(stdout, "selftest-gc: FAIL: re-exec: %v\n", err)
	return 1
}

// afterNs is a channel closed after ns by a goroutine using nanosleep (no
// Go timer).
func afterNs(ns int64) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		sysx.Sleep(ns)
		close(ch)
	}()
	return ch
}
