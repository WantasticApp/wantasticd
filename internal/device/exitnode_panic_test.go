package device

import (
	"path/filepath"
	"testing"
	"time"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
	"wantastic-agent/internal/exitnode"
)

// A panic on the reconcile path (here: a nil Device inside reconcileClient) must
// be recovered so the daemon stays up, and must be counted.
func TestRunTickRecoversPanic(t *testing.T) {
	e := &exitEngine{
		statePath: filepath.Join(t.TempDir(), "state.json"),
		st:        exitnode.State{Use: "10.255.255.36"}, // e.d is nil => reconcileClient derefs it and panics
	}
	var lastEnsure, lastQuery time.Time
	e.runTick(time.Now(), &lastEnsure, &lastQuery) // must not crash the test process
	if e.tickPanics != 1 {
		t.Fatalf("expected 1 recovered panic, got %d", e.tickPanics)
	}
}

// After exitTickPanicGiveup panics in a row the breaker disables the exit and
// restores normal routing, so a restored-but-unapplyable exit can't crash-loop.
func TestTickPanicBreakerDisablesExit(t *testing.T) {
	e := &exitEngine{
		d:         &Device{}, // device field nil => deactivate/release no-op safely
		statePath: filepath.Join(t.TempDir(), "state.json"),
		st:        exitnode.State{Use: "10.255.255.36"},
		useKey:    wgdevice.NoisePublicKey{1},
	}
	for i := 1; i < exitTickPanicGiveup; i++ {
		e.onTickPanic("boom", nil)
		if e.st.Use == "" {
			t.Fatalf("exit cleared too early at panic #%d", i)
		}
	}
	e.onTickPanic("boom", nil) // trips the breaker
	if e.st.Use != "" {
		t.Fatalf("breaker did not disable exit after %d panics (Use=%q)", exitTickPanicGiveup, e.st.Use)
	}
	if e.tickPanics != 0 {
		t.Fatalf("panic counter not reset after giveup, got %d", e.tickPanics)
	}
	if e.phase != exitnode.PhaseOff {
		t.Fatalf("expected phase Off after giveup, got %v", e.phase)
	}
	// The breaker must surface the auto-disable, not silently report "no exit".
	if e.disabledReason == "" {
		t.Fatalf("expected disabledReason to be set after giveup")
	}
	if u := e.useStatusLocked(); u == nil || u.State != "disabled" || u.Reason == "" {
		t.Fatalf("expected useStatus to surface the disabled state, got %+v", u)
	}
}

// A clean tick resets the counter so unrelated, transient panics never accumulate
// toward the breaker.
func TestResetTickPanicsClears(t *testing.T) {
	e := &exitEngine{tickPanics: 3}
	e.resetTickPanics()
	if e.tickPanics != 0 {
		t.Fatalf("expected counter reset to 0, got %d", e.tickPanics)
	}
}
