package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/claimkey"
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/netprobe"
	platformdns "wantastic-agent/internal/platform/dns"
	"wantastic-agent/pkg/version"

	"github.com/wailsapp/wails/v3/pkg/application"
)

const maxManualConfigBytes = 1 << 20

const desktopClaimPollInterval = 10 * time.Second

type claimConfigFetcher func(context.Context, string, string, string) (*auth.ClaimConfig, error)

type PeerInfo struct {
	PublicKey      string `json:"public_key"`
	AssignedIP     string `json:"assigned_ip"`
	Hostname       string `json:"hostname"`
	MagicName      string `json:"magic_name"`
	Endpoint       string `json:"endpoint"`
	RxBytes        uint64 `json:"rx_bytes"`
	TxBytes        uint64 `json:"tx_bytes"`
	P2PState       string `json:"p2p_state"`
	Connection     string `json:"connection"`
	OffersExitNode bool   `json:"offers_exit_node"`
	LastHandshake  int64  `json:"last_handshake"`
}

type StatusData struct {
	Configured        bool       `json:"configured"`
	Starting          bool       `json:"starting"`
	Running           bool       `json:"running"`
	DeviceRunning     bool       `json:"device_running"`
	TUNMode           bool       `json:"tun_mode"`
	TUNName           string     `json:"tun_name"`
	OfferExitNode     bool       `json:"offer_exit_node"`
	LocalAccess       bool       `json:"local_access"`
	LocalAccessRoutes []string   `json:"local_access_routes"`
	MagicDNS          bool       `json:"magic_dns"`
	DNSServers        []string   `json:"dns_servers"`
	IPs               []string   `json:"ips"`
	PubKey            string     `json:"pubkey"`
	RxBytes           uint64     `json:"rx_bytes"`
	TxBytes           uint64     `json:"tx_bytes"`
	Peers             []PeerInfo `json:"peers"`
}

type ClaimLink struct {
	PublicKey string `json:"public_key"`
	ServerURL string `json:"server_url"`
	ClaimURL  string `json:"claim_url"`
	Reused    bool   `json:"reused"`
}

type PingResult struct {
	Target     string       `json:"target"`
	IP         string       `json:"ip"`
	Reachable  bool         `json:"reachable"`
	LatencyMS  int64        `json:"latency_ms"`
	Connection string       `json:"connection"`
	Message    string       `json:"message"`
	Samples    []PingSample `json:"samples"`
	AverageMS  int64        `json:"average_ms"`
	PacketLoss int          `json:"packet_loss"`
}

type PingSample struct {
	LatencyMS int64 `json:"latency_ms"`
	Reachable bool  `json:"reachable"`
}

type App struct {
	ctx          context.Context
	desktop      *application.App
	window       application.Window
	tray         *application.SystemTray
	trayMenu     *application.Menu
	trayStatus   *application.MenuItem
	trayIP       *application.MenuItem
	trayToggle   *application.MenuItem
	trayDevices  *application.MenuItem
	trayNetwork  *application.MenuItem
	trayOpenApp  *application.MenuItem
	traySignIn   *application.MenuItem
	traySettings *application.MenuItem
	trayQuit     *application.MenuItem

	mu                  sync.RWMutex
	agt                 *agent.Agent
	agentCancel         context.CancelFunc
	claimCancel         context.CancelFunc
	claimEpoch          uint64
	cfg                 *config.Config
	configured          bool
	starting            bool
	externalOwned       bool
	helperEpoch         uint64
	helperMarker        string
	claimConnectPending bool
	language            string

	waitClaimConfig   claimConfigFetcher
	fetchClaimConfig  claimConfigFetcher
	hashedDeviceID    func() (string, error)
	applyDesktopClaim func(*claimkey.File, *auth.ClaimConfig) error
}

func NewApp(desktop *application.App) *App {
	return &App{
		desktop:          desktop,
		language:         "en",
		waitClaimConfig:  auth.WaitClaimConfig,
		fetchClaimConfig: auth.FetchClaimConfig,
		hashedDeviceID:   auth.HashedDeviceID,
	}
}

func (a *App) ServiceStartup(ctx context.Context, _ application.ServiceOptions) error {
	a.ctx = ctx
	if err := a.startEmbeddedAgent(); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.desktop.Event.Emit("app:error", err.Error())
	}
	status, statusErr := a.GetStatus()
	a.updateTray(status, statusErr)
	if !a.IsConfigured() {
		a.showMainWindow()
	}
	go a.pollStatus()
	return nil
}

func (a *App) ServiceShutdown() error {
	a.stopClaimWatcher()
	a.stopEmbeddedAgent()
	return nil
}

func (a *App) pollStatus() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			status, err := a.GetStatus()
			if err == nil {
				a.desktop.Event.Emit("status:update", status)
				a.updateTray(status, nil)
			} else {
				a.updateTray(nil, err)
			}
		}
	}
}

func (a *App) startEmbeddedAgent() error {
	cfg, err := config.LoadFromFile(auth.DefaultConfigPath())
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return fmt.Errorf("load desktop config: %w", err)
	}
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = config.DefaultTunName()
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		a.mu.Lock()
		a.cfg = cfg
		a.configured = true
		a.mu.Unlock()
		return nil
	}
	return a.startConfig(cfg)
}

func (a *App) startConfig(cfg *config.Config) error {
	if handled, err := a.startPrivilegedAgentIfNeeded(cfg); handled {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	agt, err := agent.New(cfg)
	if err != nil {
		cancel()
		return fmt.Errorf("create embedded agent: %w", err)
	}
	if err := agt.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("start embedded agent: %w", err)
	}
	a.mu.Lock()
	a.agt = agt
	a.agentCancel = cancel
	a.cfg = cfg
	a.configured = true
	a.starting = false
	a.externalOwned = false
	a.mu.Unlock()
	return nil
}

func (a *App) stopEmbeddedAgent() {
	a.mu.Lock()
	agt := a.agt
	cancel := a.agentCancel
	externalOwned := a.externalOwned
	marker := a.helperMarker
	a.agt = nil
	a.agentCancel = nil
	a.configured = false
	a.starting = false
	a.externalOwned = false
	a.helperMarker = ""
	a.helperEpoch++
	a.mu.Unlock()
	if externalOwned {
		_ = ipcPost("/api/shutdown")
	}
	if marker != "" {
		_ = os.Remove(marker)
	}
	if cancel != nil {
		cancel()
	}
	if agt != nil {
		_ = agt.Stop()
	}
}

func (a *App) restartConfig(cfg *config.Config) error {
	a.stopEmbeddedAgent()
	if err := a.startConfig(cfg); err != nil {
		return err
	}
	a.desktop.Event.Emit("service:ready", true)
	return nil
}

func (a *App) IsConfigured() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.configured
}

func (a *App) GetStatus() (*StatusData, error) {
	a.mu.RLock()
	configured := a.configured
	starting := a.starting
	cfg := a.cfg
	a.mu.RUnlock()
	if !configured || cfg == nil {
		return &StatusData{Configured: false, Starting: starting}, nil
	}

	var raw agent.StatusResponse
	if err := ipcGet("/api/status", &raw); err != nil {
		return &StatusData{Configured: true, Starting: starting}, nil
	}
	peers := make([]PeerInfo, 0, len(raw.Peers))
	for _, peer := range raw.Peers {
		// The coordinator is a transport peer, not a tenant device. It has no
		// overlay address and must not appear as a selectable "device".
		if net.ParseIP(strings.TrimSpace(peer.AssignedIP)) == nil {
			continue
		}
		peers = append(peers, PeerInfo{
			PublicKey: peer.PublicKey, AssignedIP: peer.AssignedIP, Hostname: peer.Hostname,
			MagicName: magicName(peer), Endpoint: peer.Endpoint, RxBytes: peer.RxBytes,
			TxBytes: peer.TxBytes, P2PState: peer.P2PState, Connection: peerConnection(peer),
			LastHandshake:  peer.LastHandshake,
			OffersExitNode: peer.OffersExitNode,
		})
	}
	ips := append([]string(nil), raw.IPs...)
	if len(ips) == 0 {
		for _, prefix := range cfg.Interface.Addresses {
			ips = append(ips, prefix.String())
		}
	}
	return &StatusData{
		Configured: true, Starting: starting, Running: raw.Running, DeviceRunning: raw.DeviceRunning,
		TUNMode: raw.TUNMode, TUNName: raw.TUNName, OfferExitNode: raw.ExitNode,
		LocalAccess: raw.LocalAccess, LocalAccessRoutes: append([]string(nil), cfg.LocalAccessRoutes...),
		MagicDNS: raw.MagicDNS, DNSServers: append([]string(nil), cfg.Interface.DNS...),
		IPs: ips, PubKey: raw.PubKey, RxBytes: raw.RxBytes, TxBytes: raw.TxBytes, Peers: peers,
	}, nil
}

func peerConnection(peer device.PeerInfo) string {
	if peer.IsP2P && peer.P2PState == "established" {
		return "direct"
	}
	if peer.IsP2P && peer.P2PState == "trying" {
		return "trying"
	}
	return "relay"
}

func magicName(peer device.PeerInfo) string {
	if host := sanitizeDNSLabel(peer.Hostname); host != "" {
		return host + ".wantastic"
	}
	ip := net.ParseIP(peer.AssignedIP)
	if ip != nil && ip.To4() != nil {
		return "node-" + strings.ReplaceAll(ip.To4().String(), ".", "-") + ".wantastic"
	}
	return ""
}

func sanitizeDNSLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	label := make([]byte, 0, min(len(value), 63))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			label = append(label, byte(r))
		} else if len(label) > 0 && label[len(label)-1] != '-' {
			label = append(label, '-')
		}
		if len(label) == 63 {
			break
		}
	}
	return strings.Trim(string(label), "-")
}

func (a *App) ToggleVPN() error {
	a.mu.RLock()
	cfg := a.cfg
	configured := a.configured
	starting := a.starting
	managedExternally := a.externalOwned || os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1"
	hasEmbeddedAgent := a.agt != nil
	a.mu.RUnlock()
	if starting {
		return errors.New("secure tunnel is still starting")
	}
	if runtime.GOOS == "darwin" && configured && cfg != nil && !managedExternally && !hasEmbeddedAgent {
		return a.restartConfig(cfg)
	}
	return ipcPost("/api/state/toggle")
}

func (a *App) SetOfferExitNode(enabled bool) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		return ipcPost(fmt.Sprintf("/api/exitnode/offer?enabled=%t", enabled))
	}
	if a.usesExternalAgent() {
		return a.persistExternalExitNodeOffer(enabled)
	}
	a.mu.RLock()
	agt := a.agt
	a.mu.RUnlock()
	if agt == nil {
		return errors.New("wantastic is not configured")
	}
	return agt.SetOfferExitNode(enabled)
}

func (a *App) persistExternalExitNodeOffer(enabled bool) error {
	path := auth.DefaultConfigPath()
	previous, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read exit-node preference: %w", err)
	}
	cfg, err := config.Parse(previous)
	if err != nil {
		return fmt.Errorf("parse exit-node preference: %w", err)
	}
	cfg.ExitNode.Enabled = enabled
	if err := cfg.SaveToFile(path); err != nil {
		return fmt.Errorf("persist exit-node preference: %w", err)
	}
	if err := ipcPost(fmt.Sprintf("/api/exitnode/offer/runtime?enabled=%t", enabled)); err != nil {
		if restoreErr := auth.WritePrivateFile(path, previous); restoreErr != nil {
			return fmt.Errorf("apply exit-node preference: %v; restore config: %w", err, restoreErr)
		}
		return fmt.Errorf("apply exit-node preference: %w", err)
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return nil
}

func (a *App) SetExitNode(publicKey string) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" || a.usesExternalAgent() {
		return ipcPost("/api/exitnode/use?peer=" + url.QueryEscape(strings.TrimSpace(publicKey)))
	}
	a.mu.RLock()
	agt := a.agt
	a.mu.RUnlock()
	if agt == nil {
		return errors.New("wantastic is not configured")
	}
	return agt.SetExitNode(strings.TrimSpace(publicKey))
}

func (a *App) usesExternalAgent() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.externalOwned
}

func (a *App) ConfigureLocalAccess(enabled bool, routes []string) error {
	normalized, err := config.ValidateLocalAccessRoutes(routes)
	if err != nil {
		return err
	}
	if len(normalized) > 0 {
		enabled = true
	}
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" || a.usesExternalAgent() {
		return a.persistExternalLocalAccess(enabled, normalized)
	}
	return a.updateConfig(func(cfg *config.Config) {
		cfg.AllowLocalAccess = enabled
		cfg.LocalAccessRoutes = normalized
	})
}

func (a *App) persistExternalLocalAccess(enabled bool, routes []string) error {
	path := auth.DefaultConfigPath()
	previous, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read local-access preference: %w", err)
	}
	cfg, err := config.Parse(previous)
	if err != nil {
		return fmt.Errorf("parse local-access preference: %w", err)
	}
	cfg.AllowLocalAccess = enabled
	cfg.LocalAccessRoutes = append([]string(nil), routes...)
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.SaveToFile(path); err != nil {
		return fmt.Errorf("persist local-access preference: %w", err)
	}
	query := url.Values{"enabled": []string{strconv.FormatBool(enabled)}}
	for _, route := range routes {
		query.Add("route", route)
	}
	if err := ipcPost("/api/local-access/runtime?" + query.Encode()); err != nil {
		if restoreErr := auth.WritePrivateFile(path, previous); restoreErr != nil {
			return fmt.Errorf("apply local-access preference: %v; restore config: %w", err, restoreErr)
		}
		return fmt.Errorf("apply local-access preference: %w", err)
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return nil
}

func (a *App) updateConfig(update func(*config.Config)) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		return errors.New("configuration changes require restarting the privileged development agent")
	}
	path := auth.DefaultConfigPath()
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return err
	}
	previous, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	update(cfg)
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.SaveToFile(path); err != nil {
		return err
	}
	if err := a.restartConfig(cfg); err == nil {
		return nil
	} else {
		startErr := err
		if restoreErr := os.WriteFile(path, previous, 0o600); restoreErr != nil {
			return fmt.Errorf("apply config: %v; restore previous config: %w", startErr, restoreErr)
		}
		if oldCfg, loadErr := config.LoadFromFile(path); loadErr == nil {
			_ = a.startConfig(oldCfg)
		}
		return startErr
	}
}

func (a *App) ImportManualConfig(raw string) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		return errors.New("manual import is disabled while using the privileged development agent")
	}
	if len(raw) == 0 {
		return errors.New("configuration is empty")
	}
	if len(raw) > maxManualConfigBytes {
		return fmt.Errorf("configuration exceeds %d bytes", maxManualConfigBytes)
	}
	dir := filepath.Dir(auth.DefaultConfigPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".manual-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cfg, err := config.LoadFromFile(tmpPath)
	if err != nil {
		return fmt.Errorf("invalid manual config: %w", err)
	}
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = config.DefaultTunName()
	return a.persistAndRestartConfig(cfg)
}

func (a *App) GenerateClaimLink(serverURL string, rotate bool) (*ClaimLink, error) {
	key, reused, err := claimkey.LoadOrCreate(claimkey.DefaultPath(), serverURL, rotate)
	if err != nil {
		return nil, err
	}
	a.startClaimWatcher(key)
	return &ClaimLink{PublicKey: key.PublicKey, ServerURL: key.ServerURL, ClaimURL: key.ClaimURL, Reused: reused}, nil
}

func (a *App) startClaimWatcher(key *claimkey.File) {
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)

	a.mu.Lock()
	previousCancel := a.claimCancel
	a.claimCancel = cancel
	a.claimEpoch++
	epoch := a.claimEpoch
	a.mu.Unlock()
	if previousCancel != nil {
		previousCancel()
	}

	go a.watchClaim(ctx, epoch, key)
}

func (a *App) stopClaimWatcher() {
	a.mu.Lock()
	cancel := a.claimCancel
	a.claimCancel = nil
	a.claimEpoch++
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) watchClaim(ctx context.Context, epoch uint64, key *claimkey.File) {
	deviceID, err := a.hashedDeviceID()
	if err != nil {
		a.emitError(fmt.Errorf("prepare device claim identity: %w", err))
		return
	}
	if parsed, parseErr := url.Parse(key.ServerURL); parseErr == nil {
		platformdns.EnsureBootstrapHost(ctx, parsed.Hostname())
	}

	ticker := time.NewTicker(desktopClaimPollInterval)
	defer ticker.Stop()
	for {
		claim, waitErr := a.waitClaimConfig(ctx, key.ServerURL, deviceID, key.PublicKey)
		if waitErr == nil {
			if a.applyClaimIfCurrent(ctx, epoch, key, claim) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}

		pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		claim, fetchErr := a.fetchClaimConfig(pollCtx, key.ServerURL, deviceID, key.PublicKey)
		cancel()
		if fetchErr == nil && a.applyClaimIfCurrent(ctx, epoch, key, claim) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if waitErr != nil && fetchErr != nil {
			a.emitError(fmt.Errorf("waiting for device claim: websocket: %v; polling: %w", waitErr, fetchErr))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) applyClaimIfCurrent(
	ctx context.Context,
	epoch uint64,
	key *claimkey.File,
	claim *auth.ClaimConfig,
) bool {
	if claim == nil || !claim.Claimed || ctx.Err() != nil {
		return false
	}
	a.mu.RLock()
	current := epoch == a.claimEpoch
	a.mu.RUnlock()
	if !current {
		return false
	}

	apply := a.applyDesktopClaim
	if apply == nil {
		apply = a.activateClaimedConfig
	}
	if err := apply(key, claim); err != nil {
		a.emitError(fmt.Errorf("activate claimed device: %w", err))
		return false
	}
	a.mu.Lock()
	if epoch == a.claimEpoch {
		a.claimCancel = nil
	}
	a.mu.Unlock()
	return true
}

func (a *App) activateClaimedConfig(key *claimkey.File, claim *auth.ClaimConfig) error {
	cfg, err := config.LoadFromClaimConfig(key.ServerURL, key.PrivateKey, key.PublicKey, claim)
	if err != nil {
		return fmt.Errorf("load claimed configuration: %w", err)
	}
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = config.DefaultTunName()
	if err := a.persistAndRestartConfig(cfg); err != nil {
		return fmt.Errorf("connect claimed device: %w", err)
	}
	a.mu.Lock()
	a.claimConnectPending = a.starting
	pending := a.claimConnectPending
	a.mu.Unlock()
	status, statusErr := a.GetStatus()
	if statusErr == nil && !pending {
		a.desktop.Event.Emit("status:update", status)
		a.desktop.Event.Emit("claim:connected", true)
	}
	a.updateTray(status, statusErr)
	return nil
}

func (a *App) persistAndRestartConfig(cfg *config.Config) error {
	path := auth.DefaultConfigPath()
	previous, previousErr := os.ReadFile(path)
	if previousErr != nil && !os.IsNotExist(previousErr) {
		return fmt.Errorf("read existing configuration: %w", previousErr)
	}
	if err := cfg.SaveToFile(path); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	startErr := a.restartConfig(cfg)
	if startErr == nil {
		return nil
	}
	if previousErr != nil {
		return startErr
	}
	if restoreErr := os.WriteFile(path, previous, 0o600); restoreErr != nil {
		return fmt.Errorf("connect: %v; restore previous configuration: %w", startErr, restoreErr)
	}
	if oldCfg, loadErr := config.LoadFromFile(path); loadErr == nil {
		_ = a.startConfig(oldCfg)
	}
	return startErr
}

func (a *App) emitError(err error) {
	if err != nil && a.desktop != nil {
		a.desktop.Event.Emit("app:error", err.Error())
	}
}

func (a *App) OpenURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost")) {
		return errors.New("refusing to open an invalid or insecure URL")
	}
	return a.desktop.Browser.OpenURL(rawURL)
}

func (a *App) PingPeer(reference string) (*PingResult, error) {
	status, err := a.GetStatus()
	if err != nil {
		return nil, err
	}
	reference = strings.TrimSpace(reference)
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if cfg == nil {
		return nil, errors.New("wantastic is not configured")
	}
	selected, err := selectPingTarget(reference, status.Peers, cfg.Server.AllowedIPs)
	if err != nil {
		return nil, err
	}
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	const sampleCount = 6
	samples := make([]PingSample, 0, sampleCount)
	var total time.Duration
	received := 0
	message := "No ICMP replies"
	for i := 0; i < sampleCount; i++ {
		sampleCtx, sampleCancel := context.WithTimeout(ctx, 750*time.Millisecond)
		latency, sampleMessage, runErr := netprobe.Ping(sampleCtx, selected.AssignedIP)
		sampleCancel()
		sample := PingSample{Reachable: runErr == nil}
		if runErr == nil {
			sample.LatencyMS = max(1, latency.Milliseconds())
			total += latency
			received++
			message = sampleMessage
		}
		samples = append(samples, sample)
		if i+1 < sampleCount {
			select {
			case <-ctx.Done():
				i = sampleCount
			case <-time.After(75 * time.Millisecond):
			}
		}
	}
	average := int64(0)
	if received > 0 {
		average = max(1, (total / time.Duration(received)).Milliseconds())
	}
	return &PingResult{
		Target: selected.MagicName, IP: selected.AssignedIP, Reachable: received > 0,
		LatencyMS: average, AverageMS: average, PacketLoss: (sampleCount - received) * 100 / sampleCount,
		Connection: selected.Connection, Message: message, Samples: samples,
	}, nil
}

func selectPingTarget(reference string, peers []PeerInfo, allowedRoutes []string) (*PeerInfo, error) {
	for i := range peers {
		peer := &peers[i]
		if strings.EqualFold(reference, peer.PublicKey) || strings.EqualFold(reference, peer.AssignedIP) ||
			strings.EqualFold(reference, peer.Hostname) || strings.EqualFold(reference, peer.MagicName) {
			if net.ParseIP(peer.AssignedIP) == nil {
				return nil, errors.New("peer does not have a usable overlay IP")
			}
			return peer, nil
		}
	}
	ip, err := netip.ParseAddr(reference)
	if err != nil {
		return nil, errors.New("peer was not found")
	}
	for _, raw := range allowedRoutes {
		prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(raw))
		if parseErr == nil && prefix.Contains(ip) {
			peer := device.PeerInfo{AssignedIP: ip.String()}
			return &PeerInfo{
				AssignedIP: ip.String(), MagicName: magicName(peer), Connection: "relay",
			}, nil
		}
	}
	return nil, errors.New("IP is outside the configured tenant routes")
}

func ipcGet(path string, target any) error {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := agent.NewIPCRequest(context.Background(), http.MethodGet, path)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local service returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(target)
}

func ipcPost(path string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := agent.NewIPCRequest(context.Background(), http.MethodPost, path)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		detail := strings.TrimSpace(string(message))
		if detail != "" {
			return errors.New(detail)
		}
		return fmt.Errorf("local service returned %s", resp.Status)
	}
	return nil
}

func (a *App) showMainWindow() {
	if a.window == nil {
		return
	}
	if a.tray != nil {
		a.tray.ShowWindow()
		return
	}
	a.window.Show().Focus()
}

func (a *App) setWindow(window application.Window) {
	a.window = window
}

func (a *App) setSystemTray(tray *application.SystemTray) {
	a.tray = tray
	text := trayStringsFor(a.language)
	tray.SetLabel(text.Offline)
	menu := a.desktop.NewMenu()
	a.trayStatus = menu.Add(text.Offline)
	a.trayStatus.SetEnabled(false)
	a.trayIP = menu.Add("IP: —")
	a.trayIP.SetEnabled(false)
	menu.AddSeparator()
	a.trayToggle = menu.Add(text.Connect)
	a.trayToggle.OnClick(func(*application.Context) {
		go func() {
			if err := a.ToggleVPN(); err != nil {
				a.desktop.Event.Emit("app:error", err.Error())
			}
		}()
	})
	a.trayDevices = menu.Add(text.Devices)
	a.trayDevices.OnClick(func(*application.Context) { a.showSection("devices") })
	a.trayNetwork = menu.Add(text.Network)
	a.trayNetwork.OnClick(func(*application.Context) { a.showSection("network") })
	a.trayOpenApp = menu.Add(text.OpenApp)
	a.trayOpenApp.OnClick(func(*application.Context) { a.showMainWindow() })
	menu.AddSeparator()
	a.traySignIn = menu.Add(text.SignIn)
	a.traySignIn.OnClick(func(*application.Context) {
		go func() {
			claim, err := a.GenerateClaimLink("https://console.wantastic.app", false)
			if err != nil {
				a.desktop.Event.Emit("app:error", err.Error())
				return
			}
			_ = a.OpenURL(claim.ClaimURL)
		}()
	})
	a.traySettings = menu.Add(text.Settings)
	a.traySettings.OnClick(func(*application.Context) { a.showSection("settings") })
	menu.AddSeparator()
	a.trayQuit = menu.Add(text.Quit)
	a.trayQuit.OnClick(func(*application.Context) { a.desktop.Quit() })
	a.trayMenu = menu
	tray.SetMenu(menu)
}

func (a *App) showSection(section string) {
	a.desktop.Event.Emit("navigate", section)
	a.showMainWindow()
}

func (a *App) updateTray(status *StatusData, statusErr error) {
	if a.trayMenu == nil || a.trayStatus == nil || a.trayIP == nil || a.trayToggle == nil {
		return
	}
	a.mu.RLock()
	language := a.language
	a.mu.RUnlock()
	presentation := makeTrayPresentationForLanguage(status, statusErr, language)
	a.tray.SetLabel(presentation.trayLabel)
	a.trayStatus.SetLabel(presentation.statusTitle)
	a.trayIP.SetLabel(presentation.ipTitle)
	a.trayToggle.SetLabel(presentation.toggleTitle)
	a.trayToggle.SetEnabled(presentation.toggleEnabled)
	a.tray.SetTooltip(presentation.tooltip)
	a.trayMenu.Update()
}

type trayPresentation struct {
	trayLabel     string
	statusTitle   string
	ipTitle       string
	toggleTitle   string
	toggleEnabled bool
	tooltip       string
}

func makeTrayPresentation(status *StatusData, statusErr error) trayPresentation {
	return makeTrayPresentationForLanguage(status, statusErr, "en")
}

func makeTrayPresentationForLanguage(status *StatusData, statusErr error, language string) trayPresentation {
	text := trayStringsFor(language)
	state := text.Offline
	toggle := text.Connect
	toggleEnabled := false
	ip := "–"
	if statusErr == nil && status != nil {
		toggleEnabled = status.Configured && !status.Starting
		switch {
		case status.Starting:
			state = text.Starting
			toggle = text.StartingAction
		case status.Running && status.DeviceRunning:
			state = text.Online
			toggle = text.Disconnect
		}
		if len(status.IPs) > 0 && status.IPs[0] != "" {
			ip = strings.SplitN(status.IPs[0], "/", 2)[0]
		}
	}
	tooltip := "Wantastic — " + state
	if ip != "–" {
		tooltip += " — " + ip
	}
	return trayPresentation{
		trayLabel:     state,
		statusTitle:   state,
		ipTitle:       "IP: " + ip,
		toggleTitle:   toggle,
		toggleEnabled: toggleEnabled,
		tooltip:       tooltip,
	}
}

// SetLanguage keeps the native tray menu aligned with the language selected in
// the desktop window. Unknown locale variants safely fall back to English.
func (a *App) SetLanguage(language string) {
	a.mu.Lock()
	a.language = normalizeDesktopLanguage(language)
	language = a.language
	a.mu.Unlock()
	if a.trayMenu == nil {
		return
	}
	text := trayStringsFor(language)
	a.trayDevices.SetLabel(text.Devices)
	a.trayNetwork.SetLabel(text.Network)
	a.trayOpenApp.SetLabel(text.OpenApp)
	a.traySignIn.SetLabel(text.SignIn)
	a.traySettings.SetLabel(text.Settings)
	a.trayQuit.SetLabel(text.Quit)
	status, err := a.GetStatus()
	a.updateTray(status, err)
}

func (a *App) OpenConsole() { _ = a.desktop.Browser.OpenURL("https://console.wantastic.app") }
func (a *App) WindowShow()  { a.showMainWindow() }
func (a *App) WindowHide() {
	if a.window != nil {
		a.window.Hide()
	}
}
func (a *App) WindowStartDrag()   {}
func (a *App) GetVersion() string { return version.Version }
