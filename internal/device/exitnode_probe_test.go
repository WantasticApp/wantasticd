package device

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/exitnode"
)

// A failed reachability probe after activation must be surfaced in the status
// (it used to report a bare "active" while nothing loaded), and a passing
// probe must leave the status clean.
func TestExitProbeSurfacesFailure(t *testing.T) {
	done := make(chan struct{})
	e := &exitEngine{
		d:     &Device{},
		st:    exitnode.State{Use: "10.255.255.36"},
		phase: exitnode.PhaseActive,
		probe: func() error { defer close(done); return errors.New("dial tcp4 1.1.1.1:443: i/o timeout") },
	}
	e.mu.Lock()
	e.startProbeLocked()
	e.mu.Unlock()
	<-done
	waitFor(t, func() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.probeErr != "" })

	e.mu.Lock()
	u := e.useStatusLocked()
	e.mu.Unlock()
	if u == nil || u.State != string(exitnode.PhaseActive) || !strings.Contains(u.Reason, "not reachable through the exit") {
		t.Fatalf("probe failure not surfaced: %+v", u)
	}

	e.mu.Lock()
	e.finishProbeLocked(e.probeGen, e.st.Use, nil)
	u = e.useStatusLocked()
	e.mu.Unlock()
	if u.Reason != "" {
		t.Fatalf("passing probe should clear the reason, got %q", u.Reason)
	}
}

// A probe that finishes after routing changed (deactivated, or switched to
// another exit) must not touch the new state.
func TestExitProbeIgnoresStaleResult(t *testing.T) {
	e := &exitEngine{d: &Device{}, st: exitnode.State{Use: "10.255.255.36"}}
	e.probeGen = 3
	e.finishProbeLocked(2, "10.255.255.36", errors.New("old"))
	e.finishProbeLocked(3, "10.255.255.44", errors.New("other exit"))
	if e.probeErr != "" {
		t.Fatalf("stale probe result applied: %q", e.probeErr)
	}
}

func TestRouteSummary(t *testing.T) {
	rs := []exitnode.Route{
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Kind: exitnode.RouteBypass},
		{Dst: netip.MustParsePrefix("0.0.0.0/1"), Kind: exitnode.RouteTunnel},
		{Dst: netip.MustParsePrefix("128.0.0.0/1"), Kind: exitnode.RouteTunnel},
		{Dst: netip.MustParsePrefix("::/1"), Kind: exitnode.RouteReject},
	}
	if got := routeSummary(rs); got != "2 tunnel, 1 bypass, 1 ipv6-block" {
		t.Fatalf("got %q", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
