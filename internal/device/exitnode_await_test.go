package device

import (
	"testing"
	"time"

	"wantastic-agent/internal/exitnode"
)

// TestAwaitExitUsePokesUntilActive checks the jumpto wait loop pokes the
// reconciler before every wait and stops the instant the use goes Active —
// the fast-path that turns a same-LAN exit switch from "wait for the 2s tick"
// into "act within a step".
func TestAwaitExitUsePokesUntilActive(t *testing.T) {
	// Status is Standby for the first two polls, then Active on the third.
	states := []string{
		string(exitnode.PhaseStandby),
		string(exitnode.PhaseStandby),
		string(exitnode.PhaseActive),
	}
	var polls, pokes, sleeps int
	poll := func() (*ExitUse, bool) {
		s := states[min(polls, len(states)-1)]
		polls++
		return &ExitUse{State: s}, false
	}
	now := func() time.Time { return time.Unix(0, 0) } // never past the deadline
	deadline := time.Unix(10, 0)

	u, status := awaitExitUse(deadline, time.Millisecond, now,
		func(time.Duration) { sleeps++ }, func() { pokes++ }, poll)

	if status != exitWaitDone {
		t.Fatalf("status = %d, want exitWaitDone", status)
	}
	if u == nil || u.State != string(exitnode.PhaseActive) {
		t.Fatalf("returned use = %+v, want Active", u)
	}
	// Two Standby polls each poke-then-sleep; the Active poll returns at once.
	if polls != 3 {
		t.Fatalf("polls = %d, want 3", polls)
	}
	if pokes != 2 {
		t.Fatalf("pokes = %d, want 2 (one per non-terminal poll)", pokes)
	}
	if sleeps != 2 {
		t.Fatalf("sleeps = %d, want 2", sleeps)
	}
}

// TestAwaitExitUseRefusedStopsImmediately checks a refusal short-circuits
// without any further poke or sleep.
func TestAwaitExitUseRefusedStopsImmediately(t *testing.T) {
	var pokes, sleeps int
	poll := func() (*ExitUse, bool) {
		return &ExitUse{State: string(exitnode.PhaseStandby)}, true // refused
	}
	now := func() time.Time { return time.Unix(0, 0) }

	u, status := awaitExitUse(time.Unix(10, 0), time.Millisecond, now,
		func(time.Duration) { sleeps++ }, func() { pokes++ }, poll)

	if status != exitWaitRefused {
		t.Fatalf("status = %d, want exitWaitRefused", status)
	}
	if u == nil {
		t.Fatalf("returned use = nil, want the refusing status")
	}
	if pokes != 0 || sleeps != 0 {
		t.Fatalf("pokes=%d sleeps=%d, want 0/0 on refusal", pokes, sleeps)
	}
}

// TestAwaitExitUseClearedStopsImmediately checks a nil status (the exit was
// cleared) short-circuits as cleared.
func TestAwaitExitUseClearedStopsImmediately(t *testing.T) {
	var pokes int
	poll := func() (*ExitUse, bool) { return nil, false }
	now := func() time.Time { return time.Unix(0, 0) }

	u, status := awaitExitUse(time.Unix(10, 0), time.Millisecond, now,
		func(time.Duration) {}, func() { pokes++ }, poll)

	if status != exitWaitCleared {
		t.Fatalf("status = %d, want exitWaitCleared", status)
	}
	if u != nil {
		t.Fatalf("returned use = %+v, want nil", u)
	}
	if pokes != 0 {
		t.Fatalf("pokes = %d, want 0", pokes)
	}
}

// TestAwaitExitUseReturnsAtDeadline checks the loop gives up at the deadline
// even while still Standby, so a stuck switch cannot spin forever.
func TestAwaitExitUseReturnsAtDeadline(t *testing.T) {
	deadline := time.Unix(100, 0)
	// Advance the clock one step per poll; cross the deadline on the 4th.
	ticks := []time.Time{
		time.Unix(10, 0),
		time.Unix(40, 0),
		time.Unix(70, 0),
		time.Unix(200, 0), // past the deadline
	}
	var i, pokes int
	now := func() time.Time {
		tk := ticks[min(i, len(ticks)-1)]
		i++
		return tk
	}
	poll := func() (*ExitUse, bool) {
		return &ExitUse{State: string(exitnode.PhaseStandby)}, false
	}

	u, status := awaitExitUse(deadline, time.Millisecond, now,
		func(time.Duration) {}, func() { pokes++ }, poll)

	if status != exitWaitDone {
		t.Fatalf("status = %d, want exitWaitDone (deadline)", status)
	}
	if u == nil || u.State != string(exitnode.PhaseStandby) {
		t.Fatalf("returned use = %+v, want the last Standby status", u)
	}
	// now() is called 4 times (once per iteration); 3 non-terminal → 3 pokes.
	if pokes != 3 {
		t.Fatalf("pokes = %d, want 3", pokes)
	}
}
