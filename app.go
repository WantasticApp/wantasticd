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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/claimkey"
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/pkg/version"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const maxManualConfigBytes = 1 << 20

type PeerInfo struct {
	PublicKey     string `json:"public_key"`
	AssignedIP    string `json:"assigned_ip"`
	Hostname      string `json:"hostname"`
	MagicName     string `json:"magic_name"`
	Endpoint      string `json:"endpoint"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	P2PState      string `json:"p2p_state"`
	Connection    string `json:"connection"`
	LastHandshake int64  `json:"last_handshake"`
}

type StatusData struct {
	Configured        bool       `json:"configured"`
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
	Target     string `json:"target"`
	IP         string `json:"ip"`
	Reachable  bool   `json:"reachable"`
	LatencyMS  int64  `json:"latency_ms"`
	Connection string `json:"connection"`
	Message    string `json:"message"`
}

type App struct {
	ctx context.Context

	mu          sync.RWMutex
	agt         *agent.Agent
	agentCancel context.CancelFunc
	cfg         *config.Config
	configured  bool
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	configureTrayOnlyApp()
	go a.startSystray()
	if err := a.startEmbeddedAgent(); err != nil && !errors.Is(err, os.ErrNotExist) {
		wailsruntime.EventsEmit(ctx, "app:error", err.Error())
	}
	if !a.IsConfigured() {
		a.showMainWindow()
	}
	go a.pollStatus()
}

func (a *App) shutdown(context.Context) { a.stopEmbeddedAgent() }

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
				wailsruntime.EventsEmit(a.ctx, "status:update", status)
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
	a.mu.Unlock()
	return nil
}

func (a *App) stopEmbeddedAgent() {
	a.mu.Lock()
	agt := a.agt
	cancel := a.agentCancel
	a.agt = nil
	a.agentCancel = nil
	a.configured = false
	a.mu.Unlock()
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
	wailsruntime.EventsEmit(a.ctx, "service:ready", true)
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
	cfg := a.cfg
	a.mu.RUnlock()
	if !configured || cfg == nil {
		return &StatusData{Configured: false}, nil
	}

	var raw agent.StatusResponse
	if err := ipcGet("/api/status", &raw); err != nil {
		return &StatusData{Configured: true}, nil
	}
	peers := make([]PeerInfo, 0, len(raw.Peers))
	for _, peer := range raw.Peers {
		peers = append(peers, PeerInfo{
			PublicKey: peer.PublicKey, AssignedIP: peer.AssignedIP, Hostname: peer.Hostname,
			MagicName: magicName(peer), Endpoint: peer.Endpoint, RxBytes: peer.RxBytes,
			TxBytes: peer.TxBytes, P2PState: peer.P2PState, Connection: peerConnection(peer),
			LastHandshake: peer.LastHandshake,
		})
	}
	return &StatusData{
		Configured: true, Running: raw.Running, DeviceRunning: raw.DeviceRunning,
		TUNMode: raw.TUNMode, TUNName: raw.TUNName, OfferExitNode: raw.ExitNode,
		LocalAccess: raw.LocalAccess, LocalAccessRoutes: append([]string(nil), cfg.LocalAccessRoutes...),
		MagicDNS: magicDNSActive(cfg.Interface.DNS), DNSServers: append([]string(nil), cfg.Interface.DNS...),
		IPs: raw.IPs, PubKey: raw.PubKey, RxBytes: raw.RxBytes, TxBytes: raw.TxBytes, Peers: peers,
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

func (a *App) ToggleVPN() error { return ipcPost("/api/state/toggle") }

func (a *App) SetOfferExitNode(enabled bool) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		return ipcPost(fmt.Sprintf("/api/exitnode/offer?enabled=%t", enabled))
	}
	a.mu.RLock()
	agt := a.agt
	a.mu.RUnlock()
	if agt == nil {
		return errors.New("wantastic is not configured")
	}
	return agt.SetOfferExitNode(enabled)
}

func (a *App) SetExitNode(publicKey string) error {
	if os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
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

func (a *App) ConfigureLocalAccess(enabled bool, routes []string) error {
	normalized, err := config.ValidateLocalAccessRoutes(routes)
	if err != nil {
		return err
	}
	if len(normalized) > 0 {
		enabled = true
	}
	return a.updateConfig(func(cfg *config.Config) {
		cfg.AllowLocalAccess = enabled
		cfg.LocalAccessRoutes = normalized
	})
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
	path := auth.DefaultConfigPath()
	previous, previousErr := os.ReadFile(path)
	if err := cfg.SaveToFile(path); err != nil {
		return err
	}
	if err := a.restartConfig(cfg); err == nil {
		return nil
	} else {
		startErr := err
		if previousErr == nil {
			_ = os.WriteFile(path, previous, 0o600)
			if oldCfg, loadErr := config.LoadFromFile(path); loadErr == nil {
				_ = a.startConfig(oldCfg)
			}
		}
		return startErr
	}
}

func (a *App) GenerateClaimLink(serverURL string, rotate bool) (*ClaimLink, error) {
	key, reused, err := claimkey.LoadOrCreate(claimkey.DefaultPath(), serverURL, rotate)
	if err != nil {
		return nil, err
	}
	return &ClaimLink{PublicKey: key.PublicKey, ServerURL: key.ServerURL, ClaimURL: key.ClaimURL, Reused: reused}, nil
}

func (a *App) OpenURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost")) {
		return errors.New("refusing to open an invalid or insecure URL")
	}
	wailsruntime.BrowserOpenURL(a.ctx, rawURL)
	return nil
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
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	started := time.Now()
	cmd := exec.CommandContext(ctx, "ping", pingArgs(selected.AssignedIP)...)
	output, runErr := cmd.CombinedOutput()
	message := strings.TrimSpace(string(output))
	if len(message) > 500 {
		message = message[:500]
	}
	return &PingResult{
		Target: selected.MagicName, IP: selected.AssignedIP, Reachable: runErr == nil,
		LatencyMS: time.Since(started).Milliseconds(), Connection: selected.Connection, Message: message,
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

func pingArgs(ip string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"-n", "1", "-w", "2000", ip}
	case "darwin":
		return []string{"-n", "-c", "1", "-W", "2000", ip}
	default:
		return []string{"-n", "-c", "1", "-W", "2", ip}
	}
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
		return fmt.Errorf("local service returned %s", resp.Status)
	}
	return nil
}

func magicDNSActive(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	// Native DNS application is currently implemented only by the Linux
	// adapter. macOS and Windows must not claim MagicDNS is active merely
	// because addresses were present in a config file.
	return runtime.GOOS == "linux"
}

func (a *App) showMainWindow() {
	if a.ctx == nil {
		return
	}
	activateDesktopApp()
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
}

func (a *App) OpenConsole()       { wailsruntime.BrowserOpenURL(a.ctx, "https://console.wantastic.app") }
func (a *App) WindowShow()        { a.showMainWindow() }
func (a *App) WindowHide()        { wailsruntime.WindowHide(a.ctx) }
func (a *App) WindowStartDrag()   {}
func (a *App) GetVersion() string { return version.Version }
