package device

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/exitnode"
)

// recordDefaultRoute captures ExternalDefaultRoute calls for one test.
func recordDefaultRoute(t *testing.T) func() []bool {
	var mu sync.Mutex
	var calls []bool
	prev := ExternalDefaultRoute
	ExternalDefaultRoute = func(on bool) {
		mu.Lock()
		calls = append(calls, on)
		mu.Unlock()
	}
	t.Cleanup(func() { ExternalDefaultRoute = prev })
	return func() []bool {
		time.Sleep(50 * time.Millisecond) // the engine calls it on a goroutine
		mu.Lock()
		defer mu.Unlock()
		return append([]bool(nil), calls...)
	}
}

func testExitEngine(t *testing.T, use string) (*Device, *exitEngine) {
	d := &Device{config: &config.Config{}, exitGuard: newExitGuard()}
	e := &exitEngine{
		d:         d,
		host:      exitnode.SystemHost("android"),
		statePath: filepath.Join(t.TempDir(), "exitnode.json"),
		phase:     exitnode.PhaseOff,
		st:        exitnode.State{Use: use},
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	close(e.done)
	d.exit = e
	return d, e
}

// The app restarts the engine to add the default route; stopping must not
// ask for it to be removed again, or the two restart each other forever.
func TestStopKeepsPlatformDefaultRoute(t *testing.T) {
	calls := recordDefaultRoute(t)
	d, e := testExitEngine(t, "10.255.255.36")
	e.platformOn, e.platformDefault = true, true
	d.stopExitEngine()
	if got := calls(); len(got) != 0 {
		t.Fatalf("stopping asked the platform for %v; want no call", got)
	}
}

// A restored exit keeps the platform's default route during the grace
// period, then gives the internet back if it never comes up.
func TestRestoredExitGraceThenDirect(t *testing.T) {
	calls := recordDefaultRoute(t)
	_, e := testExitEngine(t, "10.255.255.36")
	now := time.Now()
	e.platformDefault, e.platformGrace = true, now.Add(exitPlatformGrace)

	e.reconcileClient(now) // exit peer not listed yet
	if got := calls(); len(got) != 0 {
		t.Fatalf("within the grace period: got %v, want no call", got)
	}
	e.reconcileClient(now.Add(exitPlatformGrace + time.Second))
	if got := calls(); len(got) != 1 || got[0] {
		t.Fatalf("after the grace period: got %v, want [false]", got)
	}
}
