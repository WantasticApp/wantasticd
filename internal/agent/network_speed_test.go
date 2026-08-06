package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

type networkSpeedTestBackend struct {
	downstream, upstream uint64
}

func (b *networkSpeedTestBackend) Collect(_ context.Context, _ ...string) (*wusp.Message, error) {
	msg := wusp.NewMessage()
	msg.Set("Device.DeviceInfo.SerialNumber", wusp.String("serial-1"))
	if b.downstream > 0 {
		msg.Set("Device.Cellular.Interface.1.DownstreamMaxBitRate", wusp.Uint(b.downstream))
	}
	if b.upstream > 0 {
		msg.Set("Device.Cellular.Interface.1.UpstreamMaxBitRate", wusp.Uint(b.upstream))
	}
	return msg, nil
}
func (*networkSpeedTestBackend) Set(context.Context, string, wusp.Value) error { return nil }
func (*networkSpeedTestBackend) Delete(context.Context, ...string) error       { return nil }

func TestNetworkSpeedManagerPersistsOnlyLastValidResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-speed.json")
	now := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	m := newNetworkSpeedManager(path)
	m.now = func() time.Time { return now }
	m.run = func(context.Context) (networkSpeedResult, error) {
		return networkSpeedResult{DownloadBPS: 100_000_000, UploadBPS: 20_000_000, LatencyMS: 12, Source: "speedtest.net"}, nil
	}
	if err := m.measure(context.Background()); err != nil {
		t.Fatalf("measure: %v", err)
	}
	restored := newNetworkSpeedManager(path)
	result, ok := restored.snapshot()
	if !ok || result.DownloadBPS != 100_000_000 || result.UploadBPS != 20_000_000 || !result.ObservedAt.Equal(now) {
		t.Fatalf("restored result = %+v, ok=%v", result, ok)
	}
}

func TestNetworkSpeedManagerRetainsLastResultAndPersistsRetryWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-speed.json")
	measuredAt := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	now := measuredAt
	m := newNetworkSpeedManager(path)
	m.now = func() time.Time { return now }
	m.run = func(context.Context) (networkSpeedResult, error) {
		return networkSpeedResult{DownloadBPS: 100_000_000, UploadBPS: 20_000_000}, nil
	}
	if err := m.measure(context.Background()); err != nil {
		t.Fatalf("initial measure: %v", err)
	}

	now = measuredAt.Add(networkSpeedInterval)
	m.run = func(context.Context) (networkSpeedResult, error) {
		return networkSpeedResult{}, errors.New("temporary public server failure")
	}
	if err := m.measure(context.Background()); err == nil {
		t.Fatal("failed measurement returned nil")
	}
	result, ok := m.snapshot()
	if !ok || result.DownloadBPS != 100_000_000 || !result.ObservedAt.Equal(measuredAt) {
		t.Fatalf("last successful result was not retained: %+v, ok=%v", result, ok)
	}

	restored := newNetworkSpeedManager(path)
	telemetry := restored.telemetry()
	if !telemetry.HasResult || telemetry.Status != "RetryScheduled" ||
		!telemetry.NextAttemptAt.Equal(now.Add(networkSpeedRetry)) {
		t.Fatalf("restored retry state = %+v", telemetry)
	}
}

func TestNetworkSpeedManagerDoesNotRunAgainBeforeDue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-speed.json")
	now := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	m := newNetworkSpeedManager(path)
	m.now = func() time.Time { return now }
	var calls atomic.Int32
	m.run = func(context.Context) (networkSpeedResult, error) {
		calls.Add(1)
		return networkSpeedResult{DownloadBPS: 100_000_000, UploadBPS: 20_000_000}, nil
	}
	if err := m.measure(context.Background()); err != nil {
		t.Fatalf("initial measure: %v", err)
	}
	for range 20 {
		if err := m.measure(context.Background()); err != nil {
			t.Fatalf("non-due measure: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("speed test executions = %d, want 1", got)
	}
	now = now.Add(networkSpeedInterval)
	if err := m.measure(context.Background()); err != nil {
		t.Fatalf("due measure: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("speed test executions after interval = %d, want 2", got)
	}
}

func TestNetworkSpeedManagerSchedulesExactNextCheck(t *testing.T) {
	now := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	m := &networkSpeedManager{
		now:       func() time.Time { return now },
		result:    networkSpeedResult{DownloadBPS: 10, UploadBPS: 5, ObservedAt: now},
		nextTryAt: now.Add(networkSpeedInterval),
	}
	if got := m.nextCheckDelay(); got != networkSpeedInterval {
		t.Fatalf("next check delay = %v, want %v", got, networkSpeedInterval)
	}
	now = now.Add(networkSpeedInterval)
	if got := m.nextCheckDelay(); got != 0 {
		t.Fatalf("due next check delay = %v, want 0", got)
	}
}

func TestNetworkTelemetryBackendExposesTypedSpeedFields(t *testing.T) {
	observedAt := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	m := &networkSpeedManager{result: networkSpeedResult{
		DownloadBPS: 80_000_000, UploadBPS: 10_000_000, Source: "speedtest.net",
		ObservedAt: observedAt,
	}, lastTryAt: observedAt, nextTryAt: observedAt.Add(networkSpeedInterval)}
	backend := &networkTelemetryBackend{backend: &networkSpeedTestBackend{}, speed: m}
	msg, err := backend.Collect(context.Background(), wusp.WUSPNetworkTelemetryPrefix)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if value, ok := msg.Get(wusp.WUSPNetworkTelemetryPrefix + "SpeedTest.DownloadBps"); !ok || value.AsUint() != 80_000_000 {
		t.Fatalf("download field = %v, present=%v", value.AsUint(), ok)
	}
	if value, ok := msg.Get(wusp.WUSPNetworkTelemetryPrefix + "SpeedTest.Status"); !ok || value.AsString() != "Ready" {
		t.Fatalf("status field = %q, present=%v", value.AsString(), ok)
	}
	if value, ok := msg.Get(wusp.WUSPNetworkTelemetryPrefix + "SpeedTest.IntervalSeconds"); !ok || value.AsUint() != uint64(networkSpeedInterval/time.Second) {
		t.Fatalf("interval field = %d, present=%v", value.AsUint(), ok)
	}
	if _, ok := msg.Get("Device.DeviceInfo.SerialNumber"); ok {
		t.Fatal("path-filtered telemetry response leaked an unrelated field")
	}
}

func TestNetworkSpeedInitialDelayIsDeterministicAndJittered(t *testing.T) {
	first := networkSpeedInitialDelay("device-a")
	if first != networkSpeedInitialDelay("device-a") || first < 5*time.Minute || first > 60*time.Minute {
		t.Fatalf("initial delay = %v", first)
	}
	if first == networkSpeedInitialDelay("device-b") {
		t.Fatal("two device identities unexpectedly received the same startup slot")
	}
}
