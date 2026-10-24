package platforms

import (
	"context"
	"sync"
	"time"
)

// The EasyMesh console (127.0.0.1:7777) is a debug port inside the vendor
// mesh daemon. Every command opens a session that the daemon serves on its
// own control loop, so frequent or overlapping sessions can stall mesh
// control traffic. All console use goes through this gate: one session at a
// time, and routine collection reuses recent output instead of asking again.
// Explicit operator actions always talk to the console directly.

const (
	meshStatusMaxAge = 60 * time.Second // td s1 for routine collection
	meshTreeMaxAge   = 5 * time.Minute  // td dtt detail for names / ghost pruning
)

type meshConsoleGate struct {
	mu    sync.Mutex
	cache map[easyMeshConsoleCommand]meshConsoleOutput
}

type meshConsoleOutput struct {
	text string
	at   time.Time
}

// consoleRun executes an explicit console command (serialised, uncached)
// and refreshes the cache with its output.
func (b *OpenWrtBackend) consoleRun(ctx context.Context, command easyMeshConsoleCommand) (string, error) {
	g := &b.meshConsole
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.runLocked(ctx, b, command)
}

// consoleRead returns output no older than maxAge, asking the console only
// when the cached copy is stale.
func (b *OpenWrtBackend) consoleRead(ctx context.Context, command easyMeshConsoleCommand, maxAge time.Duration) (string, error) {
	g := &b.meshConsole
	g.mu.Lock()
	defer g.mu.Unlock()
	if cached, ok := g.cache[command]; ok && time.Since(cached.at) < maxAge {
		return cached.text, nil
	}
	return g.runLocked(ctx, b, command)
}

// consoleInvalidate drops cached output so the next read asks again.
func (b *OpenWrtBackend) consoleInvalidate() {
	g := &b.meshConsole
	g.mu.Lock()
	g.cache = nil
	g.mu.Unlock()
}

func (g *meshConsoleGate) runLocked(ctx context.Context, b *OpenWrtBackend, command easyMeshConsoleCommand) (string, error) {
	output, err := b.easyMeshConsole.Run(ctx, command)
	if err != nil {
		return "", err
	}
	if g.cache == nil {
		g.cache = map[easyMeshConsoleCommand]meshConsoleOutput{}
	}
	g.cache[command] = meshConsoleOutput{text: output, at: time.Now()}
	return output, nil
}
