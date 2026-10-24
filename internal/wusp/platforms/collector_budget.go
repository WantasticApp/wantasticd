package platforms

import (
	"context"
	"log"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"
)

// Collectors that talk to slow external sources (vendor consoles, driver
// CLIs, modems) get a time budget so one stuck source cannot push a Get past
// the controller's read deadline. A collector that overruns keeps running in
// the background; this Get uses its last good fields, and the next Get picks
// up the fresh ones.

const (
	slowCollectorLog          = 2 * time.Second
	backgroundCollectorBudget = 45 * time.Second
)

type collectorResult struct {
	fields []wusp.Field
	at     time.Time
}

type collectorCache struct {
	mu       sync.Mutex
	results  map[string]collectorResult
	inflight map[string]chan struct{}
}

var budgetedCollectors = &collectorCache{results: map[string]collectorResult{}, inflight: map[string]chan struct{}{}}

// runBudgetedCollector runs collect into its own message and merges the
// result into msg when it finishes within budget; otherwise it merges the
// previous result (if any) and lets the run finish in the background.
func runBudgetedCollector(ctx context.Context, name string, budget time.Duration, msg *wusp.Message, collect func(context.Context, *wusp.Message)) {
	c := budgetedCollectors
	c.mu.Lock()
	done, running := c.inflight[name]
	if !running {
		done = make(chan struct{})
		c.inflight[name] = done
		runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backgroundCollectorBudget)
		go func() {
			defer cancel()
			started := time.Now()
			out := wusp.NewMessage()
			_ = runCollector(name, func() error { collect(runCtx, out); return nil })
			if elapsed := time.Since(started); elapsed > slowCollectorLog {
				log.Printf("[USP] Slow collector: source=%s duration=%s fields=%d", name, elapsed.Round(time.Millisecond), len(out.Fields))
			}
			c.mu.Lock()
			c.results[name] = collectorResult{fields: out.Fields, at: time.Now()}
			delete(c.inflight, name)
			c.mu.Unlock()
			close(done)
		}()
	}
	c.mu.Unlock()

	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		log.Printf("[USP] Collector over budget: source=%s budget=%s; serving last result", name, budget)
	case <-ctx.Done():
	}
	c.mu.Lock()
	result, ok := c.results[name]
	c.mu.Unlock()
	if ok {
		for _, field := range result.fields {
			msg.Set(field.Path, field.Val)
		}
	}
}
