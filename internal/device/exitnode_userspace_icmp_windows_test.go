//go:build windows

package device

import (
	"net/netip"
	"testing"
	"time"
)

func TestWindowsICMPEcho(t *testing.T) {
	e := newICMPEchoer()
	if e == nil {
		t.Fatal("ICMP API unavailable")
	}
	if !e.echo(netip.MustParseAddr("127.0.0.1"), []byte("wantastic"), 2*time.Second) {
		t.Fatal("no echo reply from 127.0.0.1")
	}
}
