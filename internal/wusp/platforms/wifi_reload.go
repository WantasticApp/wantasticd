package platforms

import (
	"sync"
	"time"
)

const (
	// defaultWiFiReloadDelay groups radio writes sent together (an Apply
	// with channel + width + power) into a single wireless reload.
	defaultWiFiReloadDelay = 800 * time.Millisecond
	// wifiReloadTimeout bounds one background reload; QSDK can take ~30 s.
	wifiReloadTimeout = 90 * time.Second
)

// wifiReloadCoalescer runs at most one wireless reload at a time and folds
// every request made while one is pending or running into the next run, so
// N writes cost one or two reloads instead of N, and never overlap.
type wifiReloadCoalescer struct {
	delay   time.Duration
	mu      sync.Mutex
	timer   *time.Timer
	running bool
	again   bool
}

func (c *wifiReloadCoalescer) request(run func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		c.again = true
		return
	}
	if c.timer != nil {
		c.timer.Reset(c.delay)
		return
	}
	c.timer = time.AfterFunc(c.delay, func() { c.fire(run) })
}

func (c *wifiReloadCoalescer) fire(run func()) {
	c.mu.Lock()
	c.timer = nil
	c.running = true
	c.mu.Unlock()
	for {
		func() {
			defer func() { _ = recover() }()
			run()
		}()
		c.mu.Lock()
		if !c.again {
			c.running = false
			c.mu.Unlock()
			return
		}
		c.again = false
		c.mu.Unlock()
	}
}
