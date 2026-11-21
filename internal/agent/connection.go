package agent

import (
	"fmt"
	"log"
	"sync"
)

// tunnelMu serialises user connect/disconnect requests so two clicks can
// never race a Start against a Stop.
var tunnelMu sync.Mutex

// Disconnect takes the tunnel down while the daemon, its IPC API and the
// tray stay up, so the user can reconnect without a service restart.
func (a *Agent) Disconnect() error {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	if !a.device.IsRunning() {
		return nil
	}
	log.Println("[API] Disconnect requested via IPC")
	return a.device.Stop()
}

// Connect brings the tunnel back up after Disconnect, including the
// local-access routes a fresh start would have installed.
func (a *Agent) Connect() error {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	if !a.IsRunning() {
		return fmt.Errorf("agent is not running")
	}
	if a.device.IsRunning() {
		return nil
	}
	log.Println("[API] Connect requested via IPC")
	if err := a.device.Start(); err != nil {
		return err
	}
	if a.config.AllowLocalAccess {
		routes, err := a.device.EnableLocalAccess()
		if err != nil {
			log.Printf("[API] Warning: local access not restored: %v", err)
			return nil
		}
		// Turned on while disconnected: nothing advertises the routes yet.
		a.mu.RLock()
		ctx, active := a.workerCtx, a.localAccess != nil
		a.mu.RUnlock()
		if !active && ctx != nil {
			a.startLocalAccessAdvertiser(ctx, routes)
		}
	}
	return nil
}
