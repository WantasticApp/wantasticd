//go:build linux || darwin

package server

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/oltd/dgram"
	"wantastic-agent/internal/oltd/endpoints"
	"wantastic-agent/internal/oltd/fakedaemon"
	"wantastic-agent/internal/oltd/wire"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

type rig struct {
	dir     string
	srv     *Server
	addr    string
	daemons map[string]*fakedaemon.Daemon
	pool    *dgram.Pool
}

// newRig starts fake nsm/pon daemons (AF_UNIX dgram in a short /tmp dir),
// the dgram backend, and the TCP server on 127.0.0.1:0.
func newRig(t *testing.T, cfg Config, handlers map[string]fakedaemon.Handler) *rig {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wot")
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{dir: dir, daemons: map[string]*fakedaemon.Daemon{}}
	for name, h := range handlers {
		d, err := fakedaemon.Start(dir+"/"+name, h)
		if err != nil {
			t.Fatal(err)
		}
		r.daemons[name] = d
	}
	r.pool = dgram.NewPool(dir, os.Getpid())
	cfg.Backend = &dgram.Backend{Pool: r.pool, Timeout: 300 * time.Millisecond,
		Map: func(s string) string { return dir + "/" + strings.TrimPrefix(s, "/tmp/") }}
	if cfg.Key == nil {
		cfg.Key = testKey
	}
	r.srv = New(cfg)
	port, err := r.srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = "127.0.0.1:" + strconv.Itoa(port)
	go r.srv.Serve()
	t.Cleanup(func() {
		r.srv.Stop()
		for _, d := range r.daemons {
			d.Close()
		}
		r.pool.Close()
		os.RemoveAll(dir)
	})
	return r
}

type client struct {
	c     net.Conn
	rd    *bufio.Reader
	nonce string
	key   []byte
	seq   uint64
}

func dial(t *testing.T, addr string, key []byte) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(c)
	line, err := rd.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var h Hello
	if err := json.Unmarshal(line, &h); err != nil || h.Hello != ProtoName || len(h.Nonce) != 32 {
		t.Fatalf("hello %s", line)
	}
	return &client{c: c, rd: rd, nonce: h.Nonce, key: key}
}

func (cl *client) send(t *testing.T, req Request) {
	t.Helper()
	body, _ := json.Marshal(req)
	line, _ := json.Marshal(Envelope{Body: body, MAC: RequestMAC(cl.key, cl.nonce, body)})
	if _, err := cl.c.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

func (cl *client) recv(t *testing.T) (Reply, bool) {
	t.Helper()
	line, err := cl.rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		t.Fatalf("envelope %s", line)
	}
	var rep Reply
	json.Unmarshal(env.Body, &rep)
	return rep, env.MAC != "" && VerifyMAC(ReplyMAC(cl.key, cl.nonce, env.Body), env.MAC)
}

func (cl *client) do(t *testing.T, op, path string, args map[string]any) Reply {
	t.Helper()
	cl.seq++
	cl.send(t, Request{Seq: cl.seq, ID: "t", Op: op, Path: path, Args: args})
	rep, signed := cl.recv(t)
	if !signed {
		t.Fatalf("reply not signed: %+v", rep)
	}
	if rep.Seq != cl.seq {
		t.Fatalf("seq %d want %d", rep.Seq, cl.seq)
	}
	return rep
}

const vlanText = "1,default,1,static,192.168.1.100,255.255.255.0:4000,VLAN4000,1,static,192.168.130.179,255.255.255.0"
const vlanJSON = `{"list":[{"vlanId":"1","remark":"default","ip":"192.168.1.100","mask":"255.255.255.0","ipType":"static","threeLayersEn":"1"},{"vlanId":"4000","remark":"VLAN4000","ip":"192.168.130.179","mask":"255.255.255.0","ipType":"static","threeLayersEn":"1"}]}`

func TestEndToEndGet(t *testing.T) {
	var portCalls atomic.Int32
	r := newRig(t, Config{CacheTTL: time.Minute}, map[string]fakedaemon.Handler{
		"sm_web": func(code uint16, req []byte) ([]byte, bool) {
			switch code {
			case 300:
				return wire.FinishText(vlanText), true
			case 271:
				portCalls.Add(1)
				return wire.FinishText("ge1,--,1,1,1000,1,0,0,0,0,1522,0,1"), true
			}
			return nil, false
		},
		"pon_web": func(code uint16, req []byte) ([]byte, bool) {
			switch code {
			case 662:
				return wire.FinishText(""), true
			case 1011:
				return wire.FinishText("0/1/1,HWTC-93bb0308,online,0d20h11m,PTF2164Q,Normal,-,-"), true
			}
			return nil, false
		},
	})
	cl := dial(t, r.addr, testKey)

	rep := cl.do(t, "get", "getQvlanList", nil)
	if !rep.OK || string(rep.Data) != vlanJSON {
		t.Fatalf("getQvlanList: %+v %s", rep, rep.Data)
	}
	rep = cl.do(t, "get", "/goform/getOntListBrife", map[string]any{"PonPortName": "all"})
	if !rep.OK || !strings.Contains(string(rep.Data), `"sn":"HWTC-93bb0308"`) {
		t.Fatalf("getOntListBrife: %+v", rep)
	}
	// The daemon replied to our own unique socket, never /tmp/web_service.
	reqs := r.daemons["pon_web"].Seen()
	path := wire.Msg(reqs[len(reqs)-1]).ReplyPath()
	if path == "/tmp/web_service" || !strings.HasPrefix(path, r.dir+"/wo"+strconv.FormatInt(int64(os.Getpid()), 36)+"_0_") || len(path) > 31 {
		t.Fatalf("reply path %q", path)
	}
	if p := wire.QuickParams(reqs[len(reqs)-1]); len(p) != 1 || p[0] != "all" {
		t.Fatalf("params %q", p)
	}
	// Hot getter coalescing: two reads inside the TTL = one daemon request.
	cl.do(t, "get", "getPortBasicList", nil)
	cl.do(t, "get", "getPortBasicList", nil)
	if n := portCalls.Load(); n != 1 {
		t.Fatalf("getPortBasicList hit the daemon %d times, want 1", n)
	}

	if rep := cl.do(t, "get", "getUserList", nil); rep.OK || rep.Code != CodeUnsupported {
		t.Fatalf("unsupported: %+v", rep)
	}
	if rep := cl.do(t, "set", "setOntListConfig", map[string]any{"onuid": "0/1/1"}); rep.OK || rep.Code != CodeSetDisabled {
		t.Fatalf("set disabled: %+v", rep)
	}
	if rep := cl.do(t, "cmd", "", map[string]any{"line": "show version"}); rep.OK || rep.Code != CodeUnsupported {
		t.Fatalf("cmd: %+v", rep)
	}
	ping := cl.do(t, "ping", "", nil)
	var info Info
	if err := json.Unmarshal(ping.Data, &info); err != nil || info.Name != ProtoName || len(info.Get) < 42 || len(info.Set) != 0 {
		t.Fatalf("ping %s", ping.Data)
	}
}

func TestDaemonTimeoutThenRecover(t *testing.T) {
	var drop atomic.Bool
	drop.Store(true)
	r := newRig(t, Config{}, map[string]fakedaemon.Handler{
		"sm_web": func(code uint16, req []byte) ([]byte, bool) {
			if drop.Load() {
				return nil, false
			}
			return wire.FinishText(vlanText), true
		},
	})
	cl := dial(t, r.addr, testKey)
	start := time.Now()
	rep := cl.do(t, "get", "getQvlanList", nil)
	if rep.OK || rep.Code != CodeDaemon || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %+v after %s", rep, time.Since(start))
	}
	drop.Store(false)
	if rep := cl.do(t, "get", "getQvlanList", nil); !rep.OK || string(rep.Data) != vlanJSON {
		t.Fatalf("recover: %+v", rep)
	}
	seen := r.daemons["sm_web"].Seen()
	if a, b := wire.Msg(seen[0]).ReplyPath(), wire.Msg(seen[len(seen)-1]).ReplyPath(); a == b {
		t.Fatalf("reply path not rotated after timeout: %s", a)
	}
}

func TestAuth(t *testing.T) {
	r := newRig(t, Config{}, map[string]fakedaemon.Handler{"sm_web": fakedaemon.Text(map[uint16]string{300: vlanText})})

	// Wrong key: one unsigned auth line, then the server closes.
	bad := dial(t, r.addr, []byte("wrong-key-wrong-key-wrong-key!!"))
	bad.seq++
	bad.send(t, Request{Seq: 1, Op: "get", Path: "getQvlanList"})
	rep, signed := bad.recv(t)
	if rep.OK || rep.Code != CodeAuth || signed {
		t.Fatalf("bad key: %+v signed=%v", rep, signed)
	}
	if _, err := bad.rd.ReadBytes('\n'); err == nil {
		t.Fatal("connection not closed after auth failure")
	}

	// Replay: reusing a seq is rejected.
	cl := dial(t, r.addr, testKey)
	if rep := cl.do(t, "get", "getQvlanList", nil); !rep.OK {
		t.Fatalf("first: %+v", rep)
	}
	cl.send(t, Request{Seq: cl.seq, Op: "get", Path: "getQvlanList"})
	if rep, _ := cl.recv(t); rep.Code != CodeAuth {
		t.Fatalf("replay accepted: %+v", rep)
	}

	// A MAC from another connection's nonce is rejected.
	c1 := dial(t, r.addr, testKey)
	c2 := dial(t, r.addr, testKey)
	body, _ := json.Marshal(Request{Seq: 1, Op: "get", Path: "getQvlanList"})
	line, _ := json.Marshal(Envelope{Body: body, MAC: RequestMAC(testKey, c1.nonce, body)})
	c2.c.Write(append(line, '\n'))
	if rep, _ := c2.recv(t); rep.Code != CodeAuth {
		t.Fatalf("cross-nonce MAC accepted: %+v", rep)
	}
}

func TestBusy(t *testing.T) {
	r := newRig(t, Config{Workers: 1}, map[string]fakedaemon.Handler{"sm_web": fakedaemon.Text(map[uint16]string{300: vlanText})})
	_ = dial(t, r.addr, testKey) // holds the only worker
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil || !strings.Contains(string(line), `"code":"busy"`) {
		t.Fatalf("busy: %s %v", line, err)
	}
}

func TestAllowSet(t *testing.T) {
	r := newRig(t, Config{AllowSet: true}, map[string]fakedaemon.Handler{
		"pon_web": func(code uint16, req []byte) ([]byte, bool) {
			if code != 1013 {
				return nil, false
			}
			if p := wire.QuickParams(req); len(p) != 7 || p[0] != "0/1/1" {
				return wire.FinishText("bad params"), true
			}
			return wire.FinishOK(), true
		},
	})
	cl := dial(t, r.addr, testKey)
	rep := cl.do(t, "set", "setOntListConfig", map[string]any{"onuid": "0/1/1", "mode": "sn"})
	if !rep.OK || string(rep.Data) != `{"errCode":"0"}` {
		t.Fatalf("set: %+v %s", rep, rep.Data)
	}
	_ = endpoints.ErrUnsupported
}
