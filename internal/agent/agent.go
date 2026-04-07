package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"wantastic-agent/internal/stats"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/pkg/version"
)

// Agent manages the WireGuard device, local health workers, and optional auto-update.
type Agent struct {
	config  *config.Config
	device  *device.Device
	updater *update.Manager
	stats   *stats.Server

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	apiServer *APIServer
}

// New creates a new Agent with the provided configuration.
func New(cfg *config.Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg.GenerateDeviceID()

	dev, err := device.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}

	updater := update.NewManager(version.Version)

	statsServer := stats.NewServer(dev, version.Version)
	dev.SetStatsProvider(statsServer.GetSerializedMetrics)

	agt := &Agent{
		config:  cfg,
		device:  dev,
		updater: updater,
		stats:   statsServer,
		stopCh:  make(chan struct{}),
	}
	agt.apiServer = NewAPIServer(agt)
	return agt, nil
}

// Start starts the agent and its components.
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	a.running = true
	a.mu.Unlock()

	if err := a.device.Start(); err != nil {
		return fmt.Errorf("start device: %w", err)
	}

	if a.config.Verbose {
		if err := a.stats.Start(); err != nil {
			log.Printf("Warning: failed to start stats server: %v", err)
		}
	}

	workerCount := 3 // HealthCheck + DNSCheck + MetricsTicker
	if a.config.AutoUpdate {
		workerCount++
	}
	a.wg.Add(workerCount)

	go a.runHealthCheck(ctx)
	go a.runDNSCheck(ctx)
	go a.runMetricsTicker(ctx)

	if a.config.AutoUpdate {
		log.Println("Auto-update enabled")
		go a.runUpdateChecker(ctx)
	} else {
		log.Println("Auto-update disabled (use --auto-update to enable)")
	}

	if err := a.apiServer.Start(); err != nil {
		log.Printf("Warning: failed to start local IPC API: %v", err)
	}

	return nil
}

// Stop stops the agent and all its components.
func (a *Agent) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false

	select {
	case <-a.stopCh:
	default:
		close(a.stopCh)
	}
	a.mu.Unlock()

	a.wg.Wait()

	if a.stats != nil {
		a.stats.Stop()
	}

	if err := a.device.Stop(); err != nil {
		log.Printf("Error stopping device: %v", err)
	}

	if a.apiServer != nil {
		a.apiServer.Stop()
	}

	return nil
}

func (a *Agent) runMetricsTicker(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.device.SendStatsToServer()
		}
	}
}

func (a *Agent) runHealthCheck(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.device.HealthCheck(); err != nil {
				log.Printf("Device health check failed: %v", err)
			}
		}
	}
}

func (a *Agent) runDNSCheck(ctx context.Context) {
	defer a.wg.Done()

	// Only run on Linux
	if runtime.GOOS != "linux" {
		return
	}

	checkDNS := func() {
		// Read /etc/resolv.conf
		content, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return
		}
		s := string(content)

		// Check if reliable DNS exists
		if !strings.Contains(s, "1.1.1.1") && !strings.Contains(s, "8.8.8.8") {
			// Append if running as root/privileged
			f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				// Likely permission denied if not root; silent fail is okay as we can't do anything
				return
			}
			defer f.Close()

			log.Println("DNS Worker: Adding reliable nameservers (1.1.1.1, 8.8.8.8) to /etc/resolv.conf")
			if _, err := f.WriteString("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"); err != nil {
				log.Printf("Warning: DNS worker failed to update resolv.conf: %v", err)
			}
		}
	}

	// Initial check
	checkDNS()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			checkDNS()
		}
	}
}

func (a *Agent) runUpdateChecker(ctx context.Context) {
	defer a.wg.Done()

	// Initial check after short delay to let startup settle
	initial := time.NewTimer(1 * time.Minute)
	defer initial.Stop()

	// Daily check
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	check := func() {
		latest, err := a.updater.FetchLatestVersion(ctx)
		if err != nil {
			if a.config.Verbose {
				log.Printf("Update check failed: %v", err)
			}
			return
		}
		a.performSelfUpdate(ctx, latest)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-initial.C:
			check()
		case <-ticker.C:
			check()
		}
	}
}

func (a *Agent) performSelfUpdate(ctx context.Context, version string) {
	if version == "" {
		return
	}
	updated, err := a.updater.CheckAndUpdate(ctx, version)
	if err != nil {
		log.Printf("Self-update failed: %v", err)
		return
	}
	if updated {
		log.Printf("Self-update to %s completed successfully. Exiting to allow restart.", version)
		// Stop all components gracefully
		a.Stop()
		// Exit the process so supervisor (e.g. systemd) restarts it with new binary
		os.Exit(0)
	}
}

// IsRunning returns true if the agent is running, false otherwise.
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// SetExitNode instructs the server to route this device's traffic through the given peer exit node natively over WireGuard Noise.
func (a *Agent) SetExitNode(peerPubKey string) error {
	a.mu.RLock()
	serverPubKey := a.config.Server.PublicKey
	a.mu.RUnlock()

	if serverPubKey == "" {
		return fmt.Errorf("no server configured for exit node coordination")
	}

	data, err := device.EncodeExitNodeSelectionTUNControl(peerPubKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key for routing: %w", err)
	}

	log.Printf("[Agent] Sending Exit Node Routing request to peer %s via Noise Protocol TUN control", peerPubKey)
	return a.device.SendTUNControl(serverPubKey, data)
}

// ToggleOfferExitNode toggles whether this device offers itself as an exit node locally and informs the server natively over WireGuard Noise.
func (a *Agent) ToggleOfferExitNode() error {
	a.mu.Lock()
	enabled := !a.config.ExitNode.Enabled
	a.config.ExitNode.Enabled = enabled
	serverPubKey := a.config.Server.PublicKey
	a.mu.Unlock()

	if serverPubKey != "" && a.device != nil {
		data := device.EncodeExitNodeOfferTUNControl(enabled)
		log.Printf("[Agent] Sending Exit Node offer status (%v) to server via Noise Protocol", enabled)
		return a.device.SendTUNControl(serverPubKey, data)
	}

	return nil
}
