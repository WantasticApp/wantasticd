package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	platformdns "wantastic-agent/internal/platform/dns"
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
	usp     *uspRuntime

	mu           sync.RWMutex
	running      bool
	stopCh       chan struct{}
	workerCancel context.CancelFunc
	wg           sync.WaitGroup

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

	uspRuntime, err := newUSPRuntime(cfg, dev, version.Version)
	if err != nil {
		return nil, fmt.Errorf("create usp runtime: %w", err)
	}
	if uspRuntime != nil {
		dev.SetWUSPHandler(uspRuntime.HandlePeerPacket)
	}

	agt := &Agent{
		config:  cfg,
		device:  dev,
		updater: updater,
		usp:     uspRuntime,
		stopCh:  make(chan struct{}),
	}
	agt.apiServer = NewAPIServer(agt)
	return agt, nil
}

// Start starts the agent and its components.
func (a *Agent) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	workerCtx, workerCancel := context.WithCancel(ctx)
	a.workerCancel = workerCancel
	a.stopCh = make(chan struct{})
	a.running = true
	a.mu.Unlock()

	if err := a.device.Start(); err != nil {
		workerCancel()
		a.mu.Lock()
		a.running = false
		a.workerCancel = nil
		a.mu.Unlock()
		return fmt.Errorf("start device: %w", err)
	}

	var localAccessRoutes []string
	if a.config.AllowLocalAccess {
		var err error
		localAccessRoutes, err = a.device.EnableLocalAccess()
		if err != nil {
			_ = a.device.Stop()
			workerCancel()
			a.mu.Lock()
			a.running = false
			a.workerCancel = nil
			a.mu.Unlock()
			return fmt.Errorf("enable local access: %w", err)
		}
		log.Printf("Local access enabled for tenant routes: %v", localAccessRoutes)
	}

	workerCount := 2 // HealthCheck + DNSCheck
	if a.config.AutoUpdate {
		workerCount++
	}
	if a.usp != nil {
		workerCount += 2
	}
	if a.config.AllowLocalAccess {
		workerCount++
	}
	a.wg.Add(workerCount)

	go a.runHealthCheck(workerCtx)
	go a.runDNSCheck(workerCtx)

	if a.usp != nil {
		go a.runWUSPInit(workerCtx)
		go a.runNetworkSpeedMonitor(workerCtx)
	}
	if a.config.AllowLocalAccess {
		go a.runLocalAccessAdvertiser(workerCtx, localAccessRoutes)
	}

	if a.config.AutoUpdate {
		log.Println("Auto-update enabled")
		go a.runUpdateChecker(workerCtx)
	} else {
		log.Println("Auto-update disabled")
	}

	if err := a.apiServer.Start(); err != nil {
		log.Printf("Warning: failed to start local IPC API: %v", err)
	}

	return nil
}

func (a *Agent) runLocalAccessAdvertiser(ctx context.Context, routes []string) {
	defer a.wg.Done()
	defer func() {
		if err := a.sendLocalAccessAdvertisement(nil); err != nil {
			log.Printf("Local-access route revocation could not be delivered: %v", err)
		}
		if err := a.device.DisableLocalAccess(); err != nil {
			log.Printf("Failed to disable local-access forwarding: %v", err)
		}
	}()

	send := func() {
		if err := a.sendLocalAccessAdvertisement(routes); err != nil {
			log.Printf("Local-access route advertisement failed; will retry: %v", err)
		}
	}
	send()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			send()
		}
	}
}

func (a *Agent) sendLocalAccessAdvertisement(routes []string) error {
	if a.config.Server.PublicKey == "" {
		return fmt.Errorf("no tenant server configured")
	}
	payload, err := device.EncodeLocalAccessAdvertisement(routes)
	if err != nil {
		return err
	}
	return a.device.SendTUNControl(a.config.Server.PublicKey, payload)
}

// Stop stops the agent and all its components.
func (a *Agent) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	workerCancel := a.workerCancel
	a.workerCancel = nil

	select {
	case <-a.stopCh:
	default:
		close(a.stopCh)
	}
	a.mu.Unlock()

	if workerCancel != nil {
		workerCancel()
	}
	if a.usp != nil {
		a.usp.Close()
	}
	a.wg.Wait()

	if err := a.device.Stop(); err != nil {
		log.Printf("Error stopping device: %v", err)
	}

	if a.apiServer != nil {
		a.apiServer.Stop()
	}

	return nil
}

func (a *Agent) runWUSPInit(ctx context.Context) {
	defer a.wg.Done()
	a.usp.runInit(ctx)
}

func (a *Agent) runNetworkSpeedMonitor(ctx context.Context) {
	defer a.wg.Done()
	a.usp.runNetworkSpeedMonitor(ctx, a.stopCh)
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

	// Initial assertion + periodic re-assertion. Frequent enough to recover
	// quickly from external rewrites (DHCP, netifd, container restarts).
	platformdns.ApplyTunnel(ctx, a.config.Interface.DNS)

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			platformdns.ApplyTunnel(ctx, a.config.Interface.DNS)
		}
	}
}

func (a *Agent) runUpdateChecker(ctx context.Context) {
	defer a.wg.Done()

	// Initial check after short delay to let startup settle
	initial := time.NewTimer(1 * time.Minute)
	defer initial.Stop()

	// Keep the fleet current without requiring a service restart. Release
	// artifacts are immutable, so an hourly version-marker request is cheap and
	// avoids leaving long-running routers one day behind a control-plane fix.
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	check := func() {
		latest, err := a.updater.FetchLatestVersion(ctx)
		if err != nil {
			// Always log: a silent failure here leaves devices stuck on old
			// releases with nothing in the log to explain why.
			log.Printf("Update check failed; will retry in an hour: %v", err)
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
		log.Printf("Self-update failed; agent remains active and will retry on the next scheduled check: %v", err)
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
