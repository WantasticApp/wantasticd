//go:build linux || darwin

package server

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/oltd/dgram"
	"wantastic-agent/internal/oltd/fakedaemon"
)

// Heap ceiling: the request that crosses it still gets its reply, open
// connections are closed, Serve returns ErrRestart with the listener still
// open, and a new server adopting that fd serves a client that connected
// during the drain (it waited in the listen backlog).
func TestHeapCeilingRestartHandover(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wor")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	d, err := fakedaemon.Start(dir+"/sm_web", fakedaemon.Text(map[uint16]string{300: vlanText}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pool := dgram.NewPool(dir, os.Getpid())
	defer pool.Close()
	var heap atomic.Uint64
	heap.Store(1)
	cfg := Config{Key: testKey, MaxHeap: 100, HeapFn: heap.Load,
		Backend: &dgram.Backend{Pool: pool, Timeout: time.Second,
			Map: func(s string) string { return dir + "/" + strings.TrimPrefix(s, "/tmp/") }}}

	srv1 := New(cfg)
	port, err := srv1.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	done := make(chan error, 1)
	go func() { done <- srv1.Serve() }()

	idle := dial(t, addr, testKey)
	busy := dial(t, addr, testKey)
	if rep := busy.do(t, "get", "getQvlanList", nil); !rep.OK {
		t.Fatalf("before ceiling: %+v", rep)
	}
	heap.Store(1000)
	if rep := busy.do(t, "get", "getQvlanList", nil); !rep.OK || string(rep.Data) != vlanJSON {
		t.Fatalf("the request crossing the ceiling must still be answered: %+v", rep)
	}
	if _, err := busy.rd.ReadBytes('\n'); err == nil {
		t.Fatal("busy connection not closed after the ceiling")
	}
	if _, err := idle.rd.ReadBytes('\n'); err == nil {
		t.Fatal("idle connection not closed by the drain")
	}
	select {
	case err := <-done:
		if err != ErrRestart {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return ErrRestart")
	}
	// Connects while nobody accepts: queued in the backlog.
	late, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()

	heap.Store(1)
	srv2 := New(cfg)
	p2, err := srv2.Adopt(srv1.ListenerFD())
	if err != nil || p2 != port {
		t.Fatalf("adopt: %d %v", p2, err)
	}
	go srv2.Serve()
	defer srv2.Stop()
	late.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	if n, err := late.Read(buf); err != nil || !strings.Contains(string(buf[:n]), ProtoName) {
		t.Fatalf("backlogged client not served after handover: %q %v", buf[:n], err)
	}
	cl := dial(t, addr, testKey)
	if rep := cl.do(t, "get", "getQvlanList", nil); !rep.OK {
		t.Fatalf("after handover: %+v", rep)
	}
}
