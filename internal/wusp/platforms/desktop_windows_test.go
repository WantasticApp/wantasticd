//go:build windows

package platforms

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"wantastic-agent/internal/wusp"
)

// TestDesktopProbeLive reads this machine and checks the result is complete
// and passes the data-model schema.
func TestDesktopProbeLive(t *testing.T) {
	if testing.Short() {
		t.Skip("reads the real system")
	}
	snap := newDesktopProbe(defaultCommandRunner).collect(context.Background())
	if snap == nil {
		t.Fatal("no snapshot")
	}
	t.Logf("%s %s / %s / %s / serial %q / %d interfaces / %d Wi-Fi / zone %s",
		snap.Manufacturer, snap.ModelName, snap.Description, snap.ProcessorModel, snap.SerialNumber, len(snap.Interfaces), len(snap.WiFi), snap.TimeZone)
	if snap.SoftwareVersion == "" || snap.ModelName == "" || snap.Description == "" {
		t.Errorf("identity missing: %+v", snap)
	}
	if snap.MemTotalKiB == 0 || snap.MemFreeKiB == 0 || snap.UptimeSeconds <= 0 {
		t.Errorf("memory/uptime missing: total=%d free=%d uptime=%d", snap.MemTotalKiB, snap.MemFreeKiB, snap.UptimeSeconds)
	}
	if len(snap.Interfaces) == 0 || snap.TimeZone == "" || snap.Hostname == "" {
		t.Errorf("interfaces/zone/hostname missing")
	}
	counted := false
	for _, info := range snap.Interfaces {
		counted = counted || info.StatsKnown && info.Stats.BytesReceived > 0
	}
	if !counted {
		t.Error("no interface reported traffic counters")
	}

	runner := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("not run in tests") }
	b := newHostBackend(KindWindows, Options{CommandRunner: runner, StatePath: filepath.Join(t.TempDir(), "state.json")})
	if err := wusp.ValidateMessageFast(b.collectDesktop(context.Background(), snap)); err != nil {
		t.Fatalf("live desktop fields fail validation: %v", err)
	}
}
