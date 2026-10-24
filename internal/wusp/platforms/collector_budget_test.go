package platforms

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestBudgetedCollectorServesLastResultWhenSlow(t *testing.T) {
	name := "test.budget." + t.Name()
	var calls atomic.Int32
	release := make(chan struct{})
	slow := func(_ context.Context, m *wusp.Message) {
		n := calls.Add(1)
		if n == 1 {
			<-release // first run is stuck past the budget
		}
		m.Set("Device.Test.Run", wusp.Uint(uint64(n)))
	}

	first := wusp.NewMessage()
	runBudgetedCollector(context.Background(), name, 20*time.Millisecond, first, slow)
	if len(first.Fields) != 0 {
		t.Fatalf("cold overrun served %v", first.Fields)
	}
	// While the first run is still in flight, a second Get does not start a
	// duplicate run.
	second := wusp.NewMessage()
	runBudgetedCollector(context.Background(), name, 20*time.Millisecond, second, slow)
	if calls.Load() != 1 {
		t.Fatalf("duplicate run started: %d", calls.Load())
	}
	close(release)
	time.Sleep(50 * time.Millisecond)

	third := wusp.NewMessage()
	runBudgetedCollector(context.Background(), name, time.Second, third, slow)
	if v, ok := third.Get("Device.Test.Run"); !ok || wusp.ValueToString(v) != "2" {
		t.Fatalf("fresh result=%v ok=%v", v, ok)
	}
}
