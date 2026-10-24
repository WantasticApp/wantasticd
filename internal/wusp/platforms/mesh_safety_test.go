package platforms

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Production must never act on the radios on a timer: active scans take the
// radio (and a relay's backhaul) off-channel, and spectral activation uses
// release-specific private ioctls. Both disrupted EasyMesh sites.
func TestPeriodicRadioWorkIsPassive(t *testing.T) {
	if !defaultWiFiScanCoordinator.passive {
		t.Fatal("timed Wi-Fi scans must be passive (kernel cache only)")
	}
	if !defaultSpectralCoordinator.passive {
		t.Fatal("timed spectral captures must stay disabled")
	}
}

func TestMeshConsoleReadsAreCachedAndSerialised(t *testing.T) {
	var calls, concurrent, peak atomic.Int32
	b := NewOpenWrtBackend(OpenWrtBackendOptions{})
	b.easyMeshConsole = easyMeshConsoleFunc(func(context.Context, easyMeshConsoleCommand) (string, error) {
		n := concurrent.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		concurrent.Add(-1)
		calls.Add(1)
		return "status", nil
	})
	ctx := context.Background()
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			_, _ = b.consoleRead(ctx, easyMeshConsoleDetailedStatus, time.Minute)
			_, _ = b.consoleRun(ctx, easyMeshConsoleDiscovery)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	if peak.Load() != 1 {
		t.Fatalf("console sessions overlapped: peak %d", peak.Load())
	}
	// 1 status read (then cached) + 4 explicit discovery runs.
	if calls.Load() != 5 {
		t.Fatalf("console calls=%d want 5", calls.Load())
	}
}
