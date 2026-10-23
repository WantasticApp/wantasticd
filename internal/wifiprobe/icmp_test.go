package wifiprobe

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func TestSummarise(t *testing.T) {
	res := summarise(4, []time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 3 * time.Millisecond})
	if res.Received != 3 || res.Lost() != 1 || res.Min != 2*time.Millisecond || res.Max != 4*time.Millisecond || res.Avg != 3*time.Millisecond {
		t.Fatalf("unexpected %+v", res)
	}
	// |4-2| + |3-4| = 3ms over 2 gaps.
	if res.Jitter != 1500*time.Microsecond {
		t.Fatalf("jitter %s", res.Jitter)
	}
	if empty := summarise(3, nil); empty.Lost() != 3 || empty.Avg != 0 {
		t.Fatalf("unexpected empty %+v", empty)
	}
}

func TestProbeLoopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("loopback ICMP echo is only reliable on Linux, the agent's target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lo := netip.MustParseAddr("127.0.0.1")
	results, err := Probe(ctx, []netip.Addr{lo, lo, netip.MustParseAddr("::1")}, Options{Count: 3, Interval: 20 * time.Millisecond, Timeout: 500 * time.Millisecond})
	if errors.Is(err, ErrUnavailable) {
		t.Skip("no ICMP socket in this environment")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("IPv6 and duplicate targets must be skipped: %v", results)
	}
	res := results[lo]
	if res.Sent != 3 || res.Received != 3 || res.Avg <= 0 {
		t.Fatalf("loopback result %+v", res)
	}
}
