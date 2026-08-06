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

type networkSpeedCache struct {
	Version           int                `json:"version"`
	Result            networkSpeedResult `json:"result"`
	LastAttemptAt     time.Time          `json:"last_attempt_at,omitempty"`
	NextAttemptAt     time.Time          `json:"next_attempt_at,omitempty"`
	LastAttemptFailed bool               `json:"last_attempt_failed,omitempty"`
}

type networkSpeedTelemetry struct {
	Result        networkSpeedResult
	HasResult     bool
	Status        string
	LastAttemptAt time.Time
	NextAttemptAt time.Time
}

type networkSpeedManager struct {
	path string
	now  func() time.Time
	run  func(context.Context) (networkSpeedResult, error)

	mu         sync.RWMutex
	result     networkSpeedResult
	lastTryAt  time.Time
	nextTryAt  time.Time
	lastFailed bool
	running    bool
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

func (m *networkSpeedManager) telemetry() networkSpeedTelemetry {
	if m == nil {
		return networkSpeedTelemetry{Status: "Unavailable"}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	hasResult := validNetworkSpeedResult(m.result)
	status := "Scheduled"
	switch {
	case m.running:
		status = "Running"
	case m.lastFailed:
		status = "RetryScheduled"
	case hasResult:
		status = "Ready"
	}
	return networkSpeedTelemetry{
		Result:        m.result,
		HasResult:     hasResult,
		Status:        status,
		LastAttemptAt: m.lastTryAt,
		NextAttemptAt: m.nextTryAt,
	}
}

func validNetworkSpeedResult(result networkSpeedResult) bool {
	return result.DownloadBPS > 0 && result.UploadBPS > 0 && !result.ObservedAt.IsZero()
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

func (m *networkSpeedManager) nextCheckDelay() time.Duration {
	if m == nil {
		return networkSpeedInterval
	}
	now := m.now().UTC()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.running {
		return time.Minute
	}
	next := m.nextTryAt
	if next.IsZero() && !m.result.ObservedAt.IsZero() {
		next = m.result.ObservedAt.Add(networkSpeedInterval)
	}
	if next.IsZero() || !next.After(now) {
		return 0
	}
	return next.Sub(now)
}

func (m *networkSpeedManager) scheduleInitialAttempt(at time.Time) {
	if m == nil || at.IsZero() {
		return
	}
	m.mu.Lock()
	if m.nextTryAt.IsZero() {
		m.nextTryAt = at.UTC()
	}
	m.mu.Unlock()
}

func (m *networkSpeedManager) measure(ctx context.Context) error {
	if m == nil {
		return nil
	}
	now := m.now().UTC()
	m.mu.Lock()
	if m.running || (!m.nextTryAt.IsZero() && now.Before(m.nextTryAt)) ||
		(!m.result.ObservedAt.IsZero() && now.Sub(m.result.ObservedAt) < networkSpeedInterval) {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.lastTryAt = now
	m.mu.Unlock()
	result, err := m.run(ctx)
	now = m.now().UTC()
	m.mu.Lock()
	m.running = false
	if err != nil {
		m.lastFailed = true
		m.nextTryAt = now.Add(networkSpeedRetry)
		m.mu.Unlock()
		if persistErr := m.persist(); persistErr != nil {
			return errors.Join(err, fmt.Errorf("persist speed-test retry state: %w", persistErr))
		}
		return err
	}
	result.ObservedAt = now
	result.Source = "speedtest.net"
	m.result = result
	m.lastFailed = false
	m.nextTryAt = now.Add(networkSpeedInterval)
	m.mu.Unlock()
	return m.persist()
}

func (m *networkSpeedManager) load() {
	data, err := osReadFile(m.path)
	if err != nil {
		return
	}
	var cached networkSpeedCache
	if json.Unmarshal(data, &cached) == nil && cached.Version > 0 {
		if validNetworkSpeedResult(cached.Result) {
			m.result = cached.Result
		}
		m.lastTryAt = cached.LastAttemptAt
		m.nextTryAt = cached.NextAttemptAt
		m.lastFailed = cached.LastAttemptFailed
		if m.nextTryAt.IsZero() && validNetworkSpeedResult(m.result) {
			m.nextTryAt = m.result.ObservedAt.Add(networkSpeedInterval)
		}
		return
	}
	// Backward compatibility with the original cache, which stored the result
	// directly at the root of network-speed.json.
	var result networkSpeedResult
	if json.Unmarshal(data, &result) == nil && validNetworkSpeedResult(result) {
		m.result = result
		m.lastTryAt = result.ObservedAt
		m.nextTryAt = result.ObservedAt.Add(networkSpeedInterval)
	}
}

func (m *networkSpeedManager) persist() error {
	if m == nil || strings.TrimSpace(m.path) == "" {
		return nil
	}
	m.mu.RLock()
	cached := networkSpeedCache{
		Version:           1,
		Result:            m.result,
		LastAttemptAt:     m.lastTryAt,
		NextAttemptAt:     m.nextTryAt,
		LastAttemptFailed: m.lastFailed,
	}
	m.mu.RUnlock()
	encoded, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	return writeCacheAtomically(m.path, encoded)
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
	appendNetworkSpeedTelemetry(msg, b.speed.telemetry())
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

func appendNetworkSpeedTelemetry(msg *wusp.Message, telemetry networkSpeedTelemetry) {
	if msg == nil {
		return
	}
	prefix := wusp.WUSPNetworkTelemetryPrefix + "SpeedTest."
	msg.Set(prefix+"Status", wusp.String(telemetry.Status))
	msg.Set(prefix+"IntervalSeconds", wusp.Uint(uint64(networkSpeedInterval/time.Second)))
	if !telemetry.LastAttemptAt.IsZero() {
		msg.Set(prefix+"LastAttemptAt", wusp.Time(telemetry.LastAttemptAt))
	}
	if !telemetry.NextAttemptAt.IsZero() {
		msg.Set(prefix+"NextRunAt", wusp.Time(telemetry.NextAttemptAt))
	}
	if telemetry.HasResult {
		appendNetworkSpeedFields(msg, telemetry.Result)
	}
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

func networkSpeedInitialDelay(deviceID string) time.Duration {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.TrimSpace(deviceID)))
	return 5*time.Minute + time.Duration(hash.Sum32()%56)*time.Minute
}

func (r *uspRuntime) runNetworkSpeedMonitor(ctx context.Context, stop <-chan struct{}) {
	if r == nil || r.networkSpeed == nil {
		return
	}
	initialDelay := networkSpeedInitialDelay(r.deviceID)
	r.networkSpeed.scheduleInitialAttempt(time.Now().UTC().Add(initialDelay))
	initial := time.NewTimer(initialDelay)
	defer initial.Stop()
	check := func() {
		if !r.networkSpeed.due() {
			return
		}
		testCtx, testCancel := context.WithTimeout(ctx, networkSpeedTimeout)
		err := r.networkSpeed.measure(testCtx)
		testCancel()
		patch := wusp.NewMessage()
		appendNetworkSpeedTelemetry(patch, r.networkSpeed.telemetry())
		_ = r.dataModelCache.Patch(patch)
		if err != nil {
			log.Printf("[USP] daily internet speed measurement failed; retained last valid result: %v", err)
			return
		}
		if result, ok := r.networkSpeed.snapshot(); ok {
			log.Printf("[USP] daily internet speed measurement complete: down=%d bps up=%d bps", result.DownloadBPS, result.UploadBPS)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-stop:
		return
	case <-initial.C:
	}
	for {
		check()
		delay := r.networkSpeed.nextCheckDelay()
		if delay < time.Minute {
			delay = time.Minute
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
