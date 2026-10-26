package platforms

import (
	"sync/atomic"
	"testing"
	"time"

	modemPkg "wantastic-agent/internal/modem"
)

type countingModemController struct {
	fakeModemController
	calls *atomic.Int32
}

func (c countingModemController) GetInfo(devicePath string) (*modemPkg.Info, error) {
	c.calls.Add(1)
	return c.fakeModemController.GetInfo(devicePath)
}

func TestCellularInfoCacheAvoidsAModemSweepPerGet(t *testing.T) {
	var calls atomic.Int32
	ctl := countingModemController{
		fakeModemController: fakeModemController{infos: map[string]*modemPkg.Info{"/dev/cdc-wdm0": {Model: "RM520N-GL", Operator: "one"}}},
		calls:               &calls,
	}
	old := newModemController
	newModemController = func() modemPkg.Controller {
		return countingModemController{
			fakeModemController: fakeModemController{infos: map[string]*modemPkg.Info{"/dev/cdc-wdm0": {Model: "RM520N-GL", Operator: "two"}}},
			calls:               &calls,
		}
	}
	t.Cleanup(func() { newModemController = old })

	var cache cellularInfoCache
	for i := 0; i < 5; i++ {
		info, err := cache.get(ctl, "/dev/cdc-wdm0")
		if err != nil || info.Operator != "one" {
			t.Fatalf("get %d: %+v %v", i, info, err)
		}
		info.Operator = "mutated" // callers own their copy
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("modem queried %d times for 5 Gets", n)
	}

	// Once stale, the old value is served and one background refresh runs.
	cache.mu.Lock()
	cache.entries["/dev/cdc-wdm0"].at = time.Now().Add(-2 * cellularInfoTTL)
	cache.mu.Unlock()
	if info, _ := cache.get(ctl, "/dev/cdc-wdm0"); info.Operator != "one" {
		t.Fatalf("stale value not served: %+v", info)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, _ := cache.get(ctl, "/dev/cdc-wdm0"); info.Operator == "two" {
			if n := calls.Load(); n != 2 {
				t.Fatalf("modem queried %d times, want 2", n)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background refresh never landed")
}
