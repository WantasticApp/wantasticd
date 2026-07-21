package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"
)

type persistentDataModelCache struct {
	backend  wusp.DataBackend
	path     string
	interval time.Duration

	mu             sync.RWMutex
	msg            *wusp.Message
	refreshing     bool
	refreshDone    chan struct{}
	lastRefreshErr error
	startOnce      sync.Once
}

type dataModelCacheRefreshStatus struct {
	UpdatedAt          time.Time `json:"updated_at"`
	State              string    `json:"state"`
	FieldCount         int       `json:"field_count"`
	CellularFieldCount int       `json:"cellular_field_count"`
	Error              string    `json:"error,omitempty"`
}

func newPersistentDataModelCache(backend wusp.DataBackend, path string, interval time.Duration) *persistentDataModelCache {
	c := &persistentDataModelCache{backend: backend, path: path, interval: interval}
	if c.interval <= 0 {
		c.interval = time.Minute
	}
	c.load()
	return c
}

func (c *persistentDataModelCache) Collect(ctx context.Context, paths ...string) (*wusp.Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.RLock()
	msg := cloneCachedMessage(c.msg)
	c.mu.RUnlock()
	if len(msg.Fields) > 0 {
		return subsetCachedMessage(msg, paths...), nil
	}

	// A cold cache must not fan out several simultaneous modem sweeps when the
	// controller asks for its sectioned WUSP snapshot. Join the active warm-up,
	// or become the single caller that populates the cache.
	if err := c.ensureSnapshot(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	msg = cloneCachedMessage(c.msg)
	c.mu.RUnlock()
	if len(msg.Fields) == 0 {
		return nil, fmt.Errorf("collect data model cache: empty snapshot")
	}
	return subsetCachedMessage(msg, paths...), nil
}

func (c *persistentDataModelCache) Set(ctx context.Context, path string, value wusp.Value) error {
	if err := c.backend.Set(ctx, path, value); err != nil {
		return err
	}
	c.refreshAfterMutation(ctx)
	return nil
}

func (c *persistentDataModelCache) Delete(ctx context.Context, paths ...string) error {
	if err := c.backend.Delete(ctx, paths...); err != nil {
		return err
	}
	c.refreshAfterMutation(ctx)
	return nil
}

func (c *persistentDataModelCache) Add(ctx context.Context, objectPath string, initial *wusp.Message) ([]string, error) {
	adder, ok := c.backend.(wusp.DataAdder)
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	paths, err := adder.Add(ctx, objectPath, initial)
	if err == nil {
		c.refreshAfterMutation(ctx)
	}
	return paths, err
}

func (c *persistentDataModelCache) Warmup(ctx context.Context) error {
	if warmer, ok := c.backend.(interface{ Warmup(context.Context) error }); ok {
		if err := warmer.Warmup(ctx); err != nil {
			return err
		}
	}
	return c.Refresh(ctx)
}

func (c *persistentDataModelCache) Patch(msg *wusp.Message) error {
	if c == nil || msg == nil || len(msg.Fields) == 0 {
		return nil
	}
	c.mu.Lock()
	merged := mergeCachedMessageFields(c.msg, msg.Fields)
	c.msg = cloneCachedMessage(merged)
	c.mu.Unlock()

	encoded, err := wusp.EncodeMessageLZ4(merged)
	if err != nil {
		return fmt.Errorf("encode data model cache patch: %w", err)
	}
	if err := writeCacheAtomically(c.path, encoded); err != nil {
		return err
	}
	return nil
}

func (c *persistentDataModelCache) Start(ctx context.Context) {
	c.startOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(c.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					c.refreshAsync()
				}
			}
		}()
	})
}

func (c *persistentDataModelCache) Refresh(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done, started := c.beginRefresh()
	if !started {
		return nil
	}
	return c.refreshOwned(ctx, done)
}

func (c *persistentDataModelCache) ensureSnapshot(ctx context.Context) error {
	done, started := c.beginRefresh()
	if started {
		return c.refreshOwned(ctx, done)
	}

	select {
	case <-done:
		c.mu.RLock()
		err := c.lastRefreshErr
		hasSnapshot := c.msg != nil && len(c.msg.Fields) > 0
		c.mu.RUnlock()
		if err != nil {
			return err
		}
		if !hasSnapshot {
			return fmt.Errorf("collect data model cache: empty snapshot")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *persistentDataModelCache) beginRefresh() (chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing {
		return c.refreshDone, false
	}
	done := make(chan struct{})
	c.refreshing = true
	c.refreshDone = done
	c.lastRefreshErr = nil
	return done, true
}

func (c *persistentDataModelCache) refreshOwned(ctx context.Context, done chan struct{}) (err error) {
	status := dataModelCacheRefreshStatus{UpdatedAt: time.Now().UTC(), State: "error"}
	defer func() {
		c.mu.Lock()
		c.refreshing = false
		c.lastRefreshErr = err
		close(done)
		c.mu.Unlock()
		if err != nil {
			status.Error = err.Error()
		} else {
			status.State = "ready"
		}
		writeDataModelCacheRefreshStatus(c.path, status)
	}()

	msg, err := c.backend.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect data model cache: %w", err)
	}
	if msg == nil || len(msg.Fields) == 0 {
		return fmt.Errorf("collect data model cache: empty snapshot")
	}
	c.mu.RLock()
	previous := cloneCachedMessage(c.msg)
	c.mu.RUnlock()
	msg = preserveLastCompleteCellularSnapshot(previous, msg)
	msg = preserveLastSMSInboxSnapshot(previous, msg)
	status.FieldCount = len(msg.Fields)
	status.CellularFieldCount = countCellularSnapshotFields(msg)
	encoded, err := wusp.EncodeMessageLZ4(msg)
	if err != nil {
		return fmt.Errorf("encode data model cache: %w", err)
	}
	if err := writeCacheAtomically(c.path, encoded); err != nil {
		return err
	}
	c.mu.Lock()
	c.msg = cloneCachedMessage(msg)
	c.mu.Unlock()
	objects, values := dataModelMessageCounts(msg)
	log.Printf("[USP] DataModel cache refreshed: objects=%d values=%d file=%s", objects, values, c.path)
	return nil
}

func countCellularSnapshotFields(msg *wusp.Message) int {
	if msg == nil {
		return 0
	}
	count := 0
	for _, field := range msg.Fields {
		if hasSnapshotPrefix(field.Path, cellularSnapshotPrefixes) {
			count++
		}
	}
	return count
}

func writeDataModelCacheRefreshStatus(cachePath string, status dataModelCacheRefreshStatus) {
	data, err := json.Marshal(status)
	if err != nil {
		return
	}
	path := cachePath + ".status.json"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

var cellularSnapshotPrefixes = []string{
	"Device.Cellular.",
	"Device.TrustedElements.SIM.",
	"Device.WUSP_CellularTelemetry.",
	"Device.WUSP_CellularControl.",
	"Device.WUSP_GNSS.",
	"Device.DeviceInfo.Location.1.",
}

// preserveLastCompleteCellularSnapshot avoids replacing a useful cellular
// model with the three standard Cellular root values while an embedded modem
// is rebooting, unavailable, or still being collected through a serialized AT
// bridge. The host fields continue to refresh; only missing indexed cellular
// objects are held until the next complete modem snapshot arrives.
func preserveLastCompleteCellularSnapshot(previous, current *wusp.Message) *wusp.Message {
	if current == nil || !hasIndexedCellularSnapshot(previous) || hasIndexedCellularSnapshot(current) {
		return current
	}
	merged := cloneCachedMessage(current)
	seen := make(map[string]struct{}, len(merged.Fields))
	for _, field := range merged.Fields {
		seen[field.Path] = struct{}{}
	}
	for _, field := range previous.Fields {
		if !hasSnapshotPrefix(field.Path, cellularSnapshotPrefixes) {
			continue
		}
		if _, exists := seen[field.Path]; exists {
			continue
		}
		merged.Fields = append(merged.Fields, field)
	}
	return merged
}

func preserveLastSMSInboxSnapshot(previous, current *wusp.Message) *wusp.Message {
	if previous == nil || current == nil {
		return current
	}
	previousInbox := make([]wusp.Field, 0)
	for _, field := range previous.Fields {
		if !isSMSInboxJSONPath(field.Path) {
			continue
		}
		if strings.TrimSpace(wusp.ValueToString(field.Val)) == "" {
			continue
		}
		previousInbox = append(previousInbox, field)
	}
	if len(previousInbox) == 0 {
		return current
	}

	merged := cloneCachedMessage(current)
	byPath := make(map[string]int, len(merged.Fields))
	for i, field := range merged.Fields {
		byPath[field.Path] = i
	}
	for _, previousField := range previousInbox {
		if i, ok := byPath[previousField.Path]; ok {
			if strings.TrimSpace(wusp.ValueToString(merged.Fields[i].Val)) == "" {
				merged.Fields[i] = previousField
			}
			continue
		}
		byPath[previousField.Path] = len(merged.Fields)
		merged.Fields = append(merged.Fields, previousField)
	}
	return merged
}

func isSMSInboxJSONPath(path string) bool {
	return strings.HasPrefix(path, "Device.WUSP_CellularControl.Interface.") && strings.HasSuffix(path, ".SMSInboxJSON")
}

func hasIndexedCellularSnapshot(msg *wusp.Message) bool {
	if msg == nil {
		return false
	}
	for _, field := range msg.Fields {
		if strings.HasPrefix(field.Path, "Device.Cellular.Interface.") ||
			strings.HasPrefix(field.Path, "Device.WUSP_CellularTelemetry.Interface.") ||
			strings.HasPrefix(field.Path, "Device.WUSP_CellularControl.Interface.") ||
			strings.HasPrefix(field.Path, "Device.WUSP_GNSS.Receiver.") {
			return true
		}
	}
	return false
}

func hasSnapshotPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (c *persistentDataModelCache) refreshAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.interval)
		defer cancel()
		if err := c.Refresh(ctx); err != nil {
			log.Printf("[USP] DataModel cache refresh warning: continue_on_error=true err=%v", err)
		}
	}()
}

// refreshAfterMutation keeps the file and in-memory snapshots coherent before
// the controller performs its immediate post-mutation sync. A refresh failure
// does not roll back an already successful device operation.
func (c *persistentDataModelCache) refreshAfterMutation(ctx context.Context) {
	if err := c.ensureSnapshot(ctx); err != nil {
		log.Printf("[USP] DataModel cache mutation refresh warning: continue_on_error=true err=%v", err)
	}
}

func (c *persistentDataModelCache) load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	msg, err := wusp.DecodeMessageLenient(data)
	if err != nil {
		log.Printf("[USP] DataModel cache ignored: file=%s err=%v", c.path, err)
		return
	}
	c.msg = msg
	objects, values := dataModelMessageCounts(msg)
	log.Printf("[USP] DataModel cache restored: objects=%d values=%d file=%s", objects, values, c.path)
}

func writeCacheAtomically(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create data model cache directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write data model cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit data model cache: %w", err)
	}
	return nil
}

func cloneCachedMessage(msg *wusp.Message) *wusp.Message {
	if msg == nil {
		return &wusp.Message{}
	}
	return &wusp.Message{DeviceID: msg.DeviceID, Timestamp: msg.Timestamp, Fields: append([]wusp.Field(nil), msg.Fields...)}
}

func mergeCachedMessageFields(msg *wusp.Message, fields []wusp.Field) *wusp.Message {
	out := cloneCachedMessage(msg)
	byPath := make(map[string]int, len(out.Fields))
	for i, field := range out.Fields {
		byPath[field.Path] = i
	}
	for _, field := range fields {
		field.Path = strings.TrimSpace(field.Path)
		if field.Path == "" {
			continue
		}
		if i, ok := byPath[field.Path]; ok {
			out.Fields[i] = field
			continue
		}
		byPath[field.Path] = len(out.Fields)
		out.Fields = append(out.Fields, field)
	}
	return out
}

func subsetCachedMessage(msg *wusp.Message, paths ...string) *wusp.Message {
	if len(paths) == 0 {
		return msg
	}
	out := &wusp.Message{DeviceID: msg.DeviceID, Timestamp: msg.Timestamp}
	seen := make(map[string]struct{})
	for _, requested := range paths {
		requested = strings.TrimSpace(requested)
		for _, field := range msg.Fields {
			if requested != field.Path && !(strings.HasSuffix(requested, ".") && strings.HasPrefix(field.Path, requested)) {
				continue
			}
			if _, exists := seen[field.Path]; exists {
				continue
			}
			seen[field.Path] = struct{}{}
			out.Fields = append(out.Fields, field)
		}
	}
	return out
}
