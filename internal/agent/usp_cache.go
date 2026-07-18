package agent

import (
	"context"
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

	mu         sync.RWMutex
	msg        *wusp.Message
	refreshing bool
	startOnce  sync.Once
}

func newPersistentDataModelCache(backend wusp.DataBackend, path string, interval time.Duration) *persistentDataModelCache {
	c := &persistentDataModelCache{backend: backend, path: path, interval: interval}
	if c.interval <= 0 {
		c.interval = 15 * time.Second
	}
	c.load()
	return c
}

func (c *persistentDataModelCache) Collect(_ context.Context, paths ...string) (*wusp.Message, error) {
	c.mu.RLock()
	msg := cloneCachedMessage(c.msg)
	c.mu.RUnlock()
	if len(msg.Fields) == 0 {
		// Preserve normal backend semantics for callers that intentionally use
		// the agent before startup warm-up (notably embedded/in-process users).
		return c.backend.Collect(context.Background(), paths...)
	}
	return subsetCachedMessage(msg, paths...), nil
}

func (c *persistentDataModelCache) Set(ctx context.Context, path string, value wusp.Value) error {
	if err := c.backend.Set(ctx, path, value); err != nil {
		return err
	}
	c.refreshAsync()
	return nil
}

func (c *persistentDataModelCache) Delete(ctx context.Context, paths ...string) error {
	if err := c.backend.Delete(ctx, paths...); err != nil {
		return err
	}
	c.refreshAsync()
	return nil
}

func (c *persistentDataModelCache) Add(ctx context.Context, objectPath string, initial *wusp.Message) ([]string, error) {
	adder, ok := c.backend.(wusp.DataAdder)
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	paths, err := adder.Add(ctx, objectPath, initial)
	if err == nil {
		c.refreshAsync()
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
	c.mu.Lock()
	if c.refreshing {
		c.mu.Unlock()
		return nil
	}
	c.refreshing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
	}()

	msg, err := c.backend.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect data model cache: %w", err)
	}
	if msg == nil || len(msg.Fields) == 0 {
		return fmt.Errorf("collect data model cache: empty snapshot")
	}
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

func (c *persistentDataModelCache) refreshAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.interval)
		defer cancel()
		if err := c.Refresh(ctx); err != nil {
			log.Printf("[USP] DataModel cache refresh warning: continue_on_error=true err=%v", err)
		}
	}()
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
