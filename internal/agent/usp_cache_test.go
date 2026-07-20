package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

type blockingCacheBackend struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
}

func (b *blockingCacheBackend) Collect(ctx context.Context, _ ...string) (*wusp.Message, error) {
	b.mu.Lock()
	b.calls++
	if b.calls == 1 {
		close(b.started)
	}
	b.mu.Unlock()

	select {
	case <-b.release:
		msg := wusp.NewMessage()
		msg.Set("Device.Cellular.Interface.1.IMEI", wusp.String("123456789012345"))
		msg.Set("Device.DeviceInfo.Manufacturer", wusp.String("Wantastic"))
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *blockingCacheBackend) Set(context.Context, string, wusp.Value) error { return nil }

func (b *blockingCacheBackend) Delete(context.Context, ...string) error { return nil }

func (b *blockingCacheBackend) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func TestPersistentDataModelCacheColdCollectSingleFlights(t *testing.T) {
	backend := &blockingCacheBackend{started: make(chan struct{}), release: make(chan struct{})}
	cache := newPersistentDataModelCache(backend, t.TempDir()+"/model.cache", time.Minute)

	const workers = 4
	start := make(chan struct{})
	ready := make(chan struct{}, workers)
	results := make(chan *wusp.Message, workers)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			ready <- struct{}{}
			<-start
			msg, err := cache.Collect(context.Background(), "Device.Cellular.")
			if err != nil {
				errs <- err
				return
			}
			results <- msg
		}()
	}
	for i := 0; i < workers; i++ {
		<-ready
	}
	close(start)

	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("cold cache never started a refresh")
	}
	close(backend.release)

	for i := 0; i < workers; i++ {
		select {
		case err := <-errs:
			t.Fatalf("Collect returned error: %v", err)
		case msg := <-results:
			if value, ok := msg.Get("Device.Cellular.Interface.1.IMEI"); !ok || wusp.ValueToString(value) != "123456789012345" {
				t.Fatalf("unexpected cellular response: %#v", msg.Fields)
			}
		case <-time.After(time.Second):
			t.Fatal("Collect did not finish after cache refresh")
		}
	}
	if calls := backend.callCount(); calls != 1 {
		t.Fatalf("backend Collect calls=%d want 1", calls)
	}
}

func TestPersistentDataModelCacheWaitHonorsContext(t *testing.T) {
	backend := &blockingCacheBackend{started: make(chan struct{}), release: make(chan struct{})}
	cache := newPersistentDataModelCache(backend, t.TempDir()+"/model.cache", time.Minute)

	ownerDone := make(chan error, 1)
	go func() {
		_, err := cache.Collect(context.Background(), "Device.Cellular.")
		ownerDone <- err
	}()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("cold cache never started a refresh")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := cache.Collect(ctx, "Device.DeviceInfo.")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting Collect error=%v want context deadline", err)
	}
	if calls := backend.callCount(); calls != 1 {
		t.Fatalf("backend Collect calls=%d want 1", calls)
	}

	close(backend.release)
	select {
	case err := <-ownerDone:
		if err != nil {
			t.Fatalf("owner Collect returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner Collect did not finish")
	}
}

func TestPreserveLastCompleteCellularSnapshot(t *testing.T) {
	previous := wusp.NewMessage()
	previous.Set("Device.DeviceInfo.HostName", wusp.String("before"))
	previous.Set("Device.Cellular.Interface.1.Name", wusp.String("rmnet_data0"))
	previous.Set("Device.Cellular.Interface.1.RSRP", wusp.Int(-96))
	previous.Set("Device.WUSP_CellularTelemetry.Interface.1.Model", wusp.String("RM520N-GL"))
	previous.Set("Device.WUSP_CellularControl.Interface.1.SupportedOperations", wusp.String("SendSMS"))
	previous.Set("Device.WUSP_GNSS.Receiver.1.Status", wusp.String("Fix3D"))

	partial := wusp.NewMessage()
	partial.Set("Device.DeviceInfo.HostName", wusp.String("after"))
	partial.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(0))
	partial.Set("Device.WUSP_CellularTelemetry.InterfaceNumberOfEntries", wusp.Uint(0))

	merged := preserveLastCompleteCellularSnapshot(previous, partial)
	if value, ok := merged.Get("Device.DeviceInfo.HostName"); !ok || wusp.ValueToString(value) != "after" {
		t.Fatalf("host update not preserved: %#v", merged.Fields)
	}
	for _, path := range []string{
		"Device.Cellular.Interface.1.RSRP",
		"Device.WUSP_CellularTelemetry.Interface.1.Model",
		"Device.WUSP_CellularControl.Interface.1.SupportedOperations",
		"Device.WUSP_GNSS.Receiver.1.Status",
	} {
		if _, ok := merged.Get(path); !ok {
			t.Fatalf("missing retained field %s", path)
		}
	}
}

func TestCompleteCellularSnapshotReplacesPreviousFields(t *testing.T) {
	previous := wusp.NewMessage()
	previous.Set("Device.Cellular.Interface.1.Name", wusp.String("rmnet_data0"))
	previous.Set("Device.Cellular.Interface.1.RSRP", wusp.Int(-96))

	current := wusp.NewMessage()
	current.Set("Device.Cellular.Interface.1.Name", wusp.String("rmnet_data0"))
	current.Set("Device.Cellular.Interface.1.RSRP", wusp.Int(-88))

	merged := preserveLastCompleteCellularSnapshot(previous, current)
	value, ok := merged.Get("Device.Cellular.Interface.1.RSRP")
	if !ok || value.AsInt() != -88 {
		t.Fatalf("RSRP=%v want -88", value)
	}
}
