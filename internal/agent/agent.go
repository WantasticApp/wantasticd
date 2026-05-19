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

	workerCount := 2 // HealthCheck + DNSCheck
	if a.config.AutoUpdate {
		workerCount++
	}
	if a.usp != nil {
		workerCount++
	}
	a.wg.Add(workerCount)

	go a.runHealthCheck(ctx)
	go a.runDNSCheck(ctx)

	if a.usp != nil {
		go a.runWUSPInit(ctx)
	}

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

	if runtime.GOOS != "linux" {
		return
	}

	// Initial assertion + periodic re-assertion. Frequent enough to recover
	// quickly from external rewrites (DHCP, netifd, container restarts).
	a.assertResolvConf()

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.assertResolvConf()
		}
	}
}

// assertResolvConf rewrites /etc/resolv.conf so that the DNS servers declared
// in wg.conf (Interface.DNS — typically the core server reachable through the
// WireGuard tunnel) are listed first, followed by any pre-existing nameservers
// and a public fallback (1.1.1.1 / 8.8.8.8) for bootstrap before the handshake
// completes. The function is idempotent and safe to run repeatedly.
func (a *Agent) assertResolvConf() {
	const path = "/etc/resolv.conf"

	configured := a.config.Interface.DNS

	existing := readResolvNameservers(path)

	desired := make([]string, 0, len(configured)+len(existing)+2)
	seen := make(map[string]struct{})
	add := func(ns string) {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			return
		}
		if _, ok := seen[ns]; ok {
			return
		}
		seen[ns] = struct{}{}
		desired = append(desired, ns)
	}

	for _, ns := range configured {
		add(ns)
	}
	for _, ns := range existing {
		add(ns)
	}
	add("1.1.1.1")
	add("8.8.8.8")

	if resolvNameserversEqual(existing, desired) {
		return
	}

	var b strings.Builder
	b.WriteString("# Managed by wantasticd — primary servers come from wg.conf DNS=\n")
	for _, ns := range desired {
		b.WriteString("nameserver ")
		b.WriteString(ns)
		b.WriteByte('\n')
	}
	b.WriteString("options timeout:1 attempts:1\n")

	// /etc/resolv.conf may be a symlink (OpenWrt → /tmp/resolv.conf.d/...) or
	// a Docker bind mount (rm fails with EBUSY). Only unlink if it's a
	// symlink; otherwise overwrite in place.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(path)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		log.Printf("DNS Worker: failed to update %s: %v", path, err)
		return
	}
	if len(configured) > 0 {
		log.Printf("DNS Worker: %s reasserted with primary DNS=%v", path, configured)
	} else {
		log.Printf("DNS Worker: %s reasserted (no DNS in wg.conf — fallback only)", path)
	}
}

func readResolvNameservers(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func resolvNameserversEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
