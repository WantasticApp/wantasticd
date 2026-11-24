//go:build linux || darwin

package dgram

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"wantastic-agent/internal/oltd/fakedaemon"
	"wantastic-agent/internal/oltd/wire"
)

func kinds(ev []Event) string {
	var k []string
	for _, e := range ev {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

func TestTraceTimeoutLateMismatch(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wdg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	var mu sync.Mutex
	mode := "slow"
	d, err := fakedaemon.Start(dir+"/um_web", func(code uint16, req []byte) ([]byte, bool) {
		mu.Lock()
		m := mode
		mu.Unlock()
		path := wire.Msg(req).ReplyPath()
		switch m {
		case "slow": // answers after the client deadline
			go func() {
				fd, _ := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				defer unix.Close(fd)
				ts := unix.NsecToTimeval(300e6)
				unix.Select(0, nil, nil, nil, &ts)
				unix.Sendto(fd, wire.EncodeReply(code, wire.FinishText("late")), 0, &unix.SockaddrUnix{Name: path})
			}()
			return nil, false
		case "mismatch": // a stale reply first, then ours
			fd, _ := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			unix.Sendto(fd, wire.EncodeReply(code+1, wire.FinishText("stale")), 0, &unix.SockaddrUnix{Name: path})
			unix.Close(fd)
		}
		return wire.FinishText("v1,v2"), true
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var ev []Event
	b := &Backend{Pool: NewPool(dir, os.Getpid()), Timeout: 100 * time.Millisecond, Grace: time.Second,
		Trace: func(e Event) { ev = append(ev, e) }}
	defer b.Pool.Close()
	simple := func(p string) (wire.Msg, error) { return wire.NewMsg(156, p) }

	if _, err := b.Query(dir+"/um_web", simple, 2048); err != ErrTimeout {
		t.Fatalf("want timeout, got %v", err)
	}
	if kinds(ev) != "send,timeout,late" || ev[0].Bytes != wire.MsgLen || ev[2].GotCode != 156 || ev[0].Sock != dir+"/um_web" {
		t.Fatalf("events %+v", ev)
	}

	mu.Lock()
	mode = "mismatch"
	mu.Unlock()
	ev = nil
	got, err := b.Query(dir+"/um_web", simple, 2048)
	if err != nil || got != "v1,v2" {
		t.Fatalf("%q %v", got, err)
	}
	if kinds(ev) != "send,mismatch,reply" || ev[1].GotCode != 157 || ev[2].GotCode != 156 {
		t.Fatalf("events %+v", ev)
	}
	if ev[0].ReplyPath == "" || !strings.HasSuffix(ev[0].ReplyPath, "_1") {
		t.Fatalf("reply path not rotated after timeout: %q", ev[0].ReplyPath)
	}
}

// Reply socket names differ between processes sharing a PID across a
// re-exec (epoch) and stay within the 31-byte sun_path limit of the
// request even with large counters.
func TestReplyPathEpoch(t *testing.T) {
	a := NewPool("/tmp", 4194303)
	b := NewPool("/tmp", 4194303)
	b.Epoch = 1
	pa, pb := a.Conn("/tmp/um_web").replyPath(), b.Conn("/tmp/um_web").replyPath()
	if pa == pb {
		t.Fatalf("same reply path across epochs: %s", pa)
	}
	c := NewPool("/tmp", 4194303)
	c.Epoch = 1 << 30
	conn := c.Conn("/tmp/um_web")
	conn.idx, conn.gen = 99, 1<<31-1
	if p := conn.replyPath(); len(p) > wire.PathLen-1 {
		t.Fatalf("%q is %d bytes", p, len(p))
	}
}
