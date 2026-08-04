package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/showwin/speedtest-go/speedtest"

	"wantastic-agent/internal/wusp"
)

const (
	networkSpeedInterval = 24 * time.Hour
	networkSpeedRetry    = 6 * time.Hour
	networkSpeedTimeout  = 3 * time.Minute
)

type networkSpeedResult struct {
	DownloadBPS   uint64    `json:"download_bps"`
	UploadBPS     uint64    `json:"upload_bps"`
	LatencyMS     uint64    `json:"latency_ms"`
	JitterMS      uint64    `json:"jitter_ms"`
	ServerID      string    `json:"server_id"`
	ServerName    string    `json:"server_name"`
	ServerSponsor string    `json:"server_sponsor"`
	Source        string    `json:"source"`
	ObservedAt    time.Time `json:"observed_at"`
}

type networkSpeedManager struct {
	path string
	now  func() time.Time
	run  func(context.Context) (networkSpeedResult, error)

	mu        sync.RWMutex
	result    networkSpeedResult
	nextTryAt time.Time
	running   bool
}

func newNetworkSpeedManager(path string) *networkSpeedManager {
	m := &networkSpeedManager{path: path, now: time.Now, run: runPublicSpeedTest}
	m.load()
	return m
}

func runPublicSpeedTest(ctx context.Context) (networkSpeedResult, error) {
	httpClient := &http.Client{Timeout: networkSpeedTimeout}
	client := speedtest.New(
		speedtest.WithDoer(httpClient),
		speedtest.WithUserConfig(&speedtest.UserConfig{UserAgent: "wantasticd-network-capacity/1", MaxConnections: 4}),
	)
	servers, err := client.FetchServerListContext(ctx)
	if err != nil {
		return networkSpeedResult{}, fmt.Errorf("discover speedtest.net servers: %w", err)
	}
	targets, err := servers.FindServer(nil)
	if err != nil || len(targets) == 0 || targets[0] == nil {
		return networkSpeedResult{}, fmt.Errorf("select speedtest.net server: %w", err)
	}
	target := targets[0]
	if err := target.PingTestContext(ctx, nil); err != nil {
		return networkSpeedResult{}, fmt.Errorf("measure latency: %w", err)
	}
	if err := target.DownloadTestContext(ctx); err != nil {
		return networkSpeedResult{}, fmt.Errorf("measure download: %w", err)
	}
	if err := target.UploadTestContext(ctx); err != nil {
		return networkSpeedResult{}, fmt.Errorf("measure upload: %w", err)
	}
	if target.DLSpeed <= 0 || target.ULSpeed <= 0 {
		return networkSpeedResult{}, errors.New("public speed test returned an empty throughput result")
	}
	return networkSpeedResult{
		DownloadBPS: uint64(float64(target.DLSpeed) * 8),
		UploadBPS:   uint64(float64(target.ULSpeed) * 8),
		LatencyMS:   uint64(max(target.Latency.Milliseconds(), 0)),
		JitterMS:    uint64(max(target.Jitter.Milliseconds(), 0)),
		ServerID:    strings.TrimSpace(target.ID), ServerName: strings.TrimSpace(target.Name),
		ServerSponsor: strings.TrimSpace(target.Sponsor), Source: "speedtest.net", ObservedAt: time.Now().UTC(),
	}, nil
}

func (m *networkSpeedManager) snapshot() (networkSpeedResult, bool) {
	if m == nil {
		return networkSpeedResult{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.result, m.result.DownloadBPS > 0 && m.result.UploadBPS > 0 && !m.result.ObservedAt.IsZero()
}

func (m *networkSpeedManager) due() bool {
	now := m.now().UTC()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.running || (!m.nextTryAt.IsZero() && now.Before(m.nextTryAt)) {
		return false
	}
	return m.result.ObservedAt.IsZero() || now.Sub(m.result.ObservedAt) >= networkSpeedInterval
}

func (m *networkSpeedManager) measure(ctx context.Context) error {
	if m == nil || !m.due() {
		return nil
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()
	result, err := m.run(ctx)
	now := m.now().UTC()
	m.mu.Lock()
	m.running = false
	if err != nil {
		m.nextTryAt = now.Add(networkSpeedRetry)
		m.mu.Unlock()
		return err
	}
	result.ObservedAt = now
	result.Source = "speedtest.net"
	m.result = result
	m.nextTryAt = now.Add(networkSpeedInterval)
	m.mu.Unlock()
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeCacheAtomically(m.path, encoded)
}

func (m *networkSpeedManager) load() {
	data, err := osReadFile(m.path)
	if err != nil {
		return
	}
	var result networkSpeedResult
	if json.Unmarshal(data, &result) == nil && result.DownloadBPS > 0 && result.UploadBPS > 0 && !result.ObservedAt.IsZero() {
		m.result = result
		m.nextTryAt = result.ObservedAt.Add(networkSpeedInterval)
	}
}

var osReadFile = func(path string) ([]byte, error) { return os.ReadFile(path) }

type networkTelemetryBackend struct {
	backend wusp.DataBackend
	speed   *networkSpeedManager
}

func (b *networkTelemetryBackend) Collect(ctx context.Context, paths ...string) (*wusp.Message, error) {
	msg, err := b.backend.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if result, ok := b.speed.snapshot(); ok {
		appendNetworkSpeedFields(msg, result)
	}
	if len(paths) == 0 {
		return msg, nil
	}
	out := &wusp.Message{DeviceID: msg.DeviceID, Timestamp: msg.Timestamp}
	for _, field := range msg.Fields {
		for _, requested := range paths {
			requested = strings.TrimSpace(requested)
			if requested == field.Path || (strings.HasSuffix(requested, ".") && strings.HasPrefix(field.Path, requested)) {
				out.Fields = append(out.Fields, field)
				break
			}
		}
	}
	sort.Slice(out.Fields, func(i, j int) bool { return out.Fields[i].Path < out.Fields[j].Path })
	return out, nil
}

func appendNetworkSpeedFields(msg *wusp.Message, result networkSpeedResult) {
	if msg == nil {
		return
	}
	prefix := wusp.WUSPNetworkTelemetryPrefix + "SpeedTest."
	msg.Set(prefix+"DownloadBps", wusp.Uint(result.DownloadBPS))
	msg.Set(prefix+"UploadBps", wusp.Uint(result.UploadBPS))
	msg.Set(prefix+"LatencyMilliseconds", wusp.Uint(result.LatencyMS))
	msg.Set(prefix+"JitterMilliseconds", wusp.Uint(result.JitterMS))
	msg.Set(prefix+"ServerID", wusp.String(result.ServerID))
	msg.Set(prefix+"ServerName", wusp.String(result.ServerName))
	msg.Set(prefix+"ServerSponsor", wusp.String(result.ServerSponsor))
	msg.Set(prefix+"Source", wusp.String(result.Source))
	msg.Set(prefix+"ObservedAt", wusp.Time(result.ObservedAt))
}

func (b *networkTelemetryBackend) Set(ctx context.Context, path string, value wusp.Value) error {
	return b.backend.Set(ctx, path, value)
}
func (b *networkTelemetryBackend) Delete(ctx context.Context, paths ...string) error {
	return b.backend.Delete(ctx, paths...)
}
func (b *networkTelemetryBackend) Add(ctx context.Context, path string, initial *wusp.Message) ([]string, error) {
	adder, ok := b.backend.(wusp.DataAdder)
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	return adder.Add(ctx, path, initial)
}
func (b *networkTelemetryBackend) Warmup(ctx context.Context) error {
	if warmer, ok := b.backend.(interface{ Warmup(context.Context) error }); ok {
		return warmer.Warmup(ctx)
	}
	return nil
}

func hasNativeInternetCapacity(ctx context.Context, backend wusp.DataBackend) bool {
	msg, err := backend.Collect(ctx, "Device.Cellular.Interface.")
	if err != nil || msg == nil {
		return false
	}
	var downstream, upstream bool
	for _, field := range msg.Fields {
		if strings.HasSuffix(field.Path, ".DownstreamMaxBitRate") && field.Val.AsUint() > 0 {
			downstream = true
		}
		if strings.HasSuffix(field.Path, ".UpstreamMaxBitRate") && field.Val.AsUint() > 0 {
			upstream = true
		}
	}
	return downstream && upstream
}

func networkSpeedInitialDelay(deviceID string) time.Duration {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.TrimSpace(deviceID)))
	return 5*time.Minute + time.Duration(hash.Sum32()%56)*time.Minute
}

func (r *uspRuntime) runNetworkSpeedMonitor(ctx context.Context, stop <-chan struct{}) {
	if r == nil || r.networkSpeed == nil || r.rawBackend == nil {
		return
	}
	initial := time.NewTimer(networkSpeedInitialDelay(r.deviceID))
	defer initial.Stop()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	check := func() {
		if !r.networkSpeed.due() {
			return
		}
		capacityCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		hasNative := hasNativeInternetCapacity(capacityCtx, r.rawBackend)
		cancel()
		if hasNative {
			return
		}
		testCtx, testCancel := context.WithTimeout(ctx, networkSpeedTimeout)
		err := r.networkSpeed.measure(testCtx)
		testCancel()
		if err != nil {
			log.Printf("[USP] daily internet speed measurement failed; retained last valid result: %v", err)
			return
		}
		if result, ok := r.networkSpeed.snapshot(); ok {
			patch := wusp.NewMessage()
			appendNetworkSpeedFields(patch, result)
			_ = r.dataModelCache.Patch(patch)
			log.Printf("[USP] daily internet speed measurement complete: down=%d bps up=%d bps", result.DownloadBPS, result.UploadBPS)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-initial.C:
			check()
		case <-ticker.C:
			check()
		}
	}
}
