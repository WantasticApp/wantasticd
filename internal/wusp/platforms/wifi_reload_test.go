package platforms

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestWiFiReloadCoalescesBurstsAndNeverOverlaps(t *testing.T) {
	c := wifiReloadCoalescer{delay: 30 * time.Millisecond}
	var runs, active, overlap atomic.Int32
	run := func() {
		if active.Add(1) > 1 {
			overlap.Add(1)
		}
		runs.Add(1)
		time.Sleep(40 * time.Millisecond)
		active.Add(-1)
	}
	// Three writes from one Apply: one reload.
	for i := 0; i < 3; i++ {
		c.request(run)
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	// Writes while the reload runs: exactly one more reload afterwards.
	c.request(run)
	c.request(run)
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Fatalf("expected 2 reloads, got %d", got)
	}
	if overlap.Load() != 0 {
		t.Fatal("reloads overlapped")
	}
}
