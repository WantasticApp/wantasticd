package agent

import (
	"context"
	"path/filepath"
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

func TestNetworkTelemetryBackendExposesTypedSpeedFields(t *testing.T) {
	m := &networkSpeedManager{result: networkSpeedResult{
		DownloadBPS: 80_000_000, UploadBPS: 10_000_000, Source: "speedtest.net",
		ObservedAt: time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC),
	}}
	backend := &networkTelemetryBackend{backend: &networkSpeedTestBackend{}, speed: m}
	msg, err := backend.Collect(context.Background(), wusp.WUSPNetworkTelemetryPrefix)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if value, ok := msg.Get(wusp.WUSPNetworkTelemetryPrefix + "SpeedTest.DownloadBps"); !ok || value.AsUint() != 80_000_000 {
		t.Fatalf("download field = %v, present=%v", value.AsUint(), ok)
	}
	if _, ok := msg.Get("Device.DeviceInfo.SerialNumber"); ok {
		t.Fatal("path-filtered telemetry response leaked an unrelated field")
	}
}

func TestNativeCapacityRequiresBothDirections(t *testing.T) {
	if hasNativeInternetCapacity(context.Background(), &networkSpeedTestBackend{downstream: 100_000_000}) {
		t.Fatal("one-sided native rate must not suppress the daily measurement")
	}
	if !hasNativeInternetCapacity(context.Background(), &networkSpeedTestBackend{downstream: 100_000_000, upstream: 20_000_000}) {
		t.Fatal("complete native rate was not detected")
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
