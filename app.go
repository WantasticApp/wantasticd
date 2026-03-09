package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/config"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ─── Data types (mirror agent.StatusResponse) ──────────────────────────────

type PeerInfo struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint"`
	AllowedIPs    string `json:"allowed_ips"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake"`
	IsRelay       bool   `json:"is_relay"`
	IsExitNode    bool   `json:"is_exit_node"`
	Latency       int64  `json:"latency_ms"`
}

type StatusData struct {
	Configured    bool       `json:"configured"` // true when the embedded VPN service is running
	Running       bool       `json:"running"`
	DeviceRunning bool       `json:"device_running"`
	TUNMode       bool       `json:"tun_mode"`
	TUNName       string     `json:"tun_name"`
	ExitNode      bool       `json:"exit_node"`
	IPs           []string   `json:"ips"`
	PubKey        string     `json:"pubkey"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxBytes       uint64     `json:"tx_bytes"`
	Peers         []PeerInfo `json:"peers"`
}

type AccountInfo struct {
	LoggedIn    bool   `json:"logged_in"`
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	AvatarURL   string `json:"avatar_url"`
}

// ─── App struct ─────────────────────────────────────────────────────────────

type App struct {
	ctx         context.Context
	auth        *Auth0Client
	agt         *agent.Agent
	agentCancel context.CancelFunc
	stopOnce    sync.Once
	configured  bool // true once the embedded VPN service has started successfully
}

func NewApp() *App {
	return &App{
		auth: NewAuth0Client(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.startEmbeddedAgent(); err != nil {
		log.Printf("Desktop mode: failed to start embedded agent: %v", err)
	}
	go a.pollStatus()
}

func (a *App) shutdown(ctx context.Context) {
	a.stopEmbeddedAgent()
}

// pollStatus emits "status:update" events to the frontend every 5 seconds
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
	configPath := defaultConfigPath()
	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		return fmt.Errorf("load config (%s): %w", configPath, err)
	}

	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = autoTUNName()

	agentCtx, cancel := context.WithCancel(context.Background())
	agt, err := startAgentWithRetry(agentCtx, cfg)
	if err != nil {
		cancel()
		return fmt.Errorf("start embedded agent: %w", err)
	}

	a.agentCancel = cancel
	a.agt = agt
	a.configured = true
	log.Printf("Embedded agent started: TUN=%s", cfg.Interface.TUNName)
	return nil
}

func (a *App) stopEmbeddedAgent() {
	a.stopOnce.Do(func() {
		if a.agentCancel != nil {
			a.agentCancel()
		}
		if a.agt != nil {
			if err := a.agt.Stop(); err != nil {
				log.Printf("Failed to stop embedded agent: %v", err)
			}
		}
	})
}

func defaultConfigPath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return filepath.Join(".", "wantastic", "config.conf")
	}
	return filepath.Join(base, "wantastic", "config.conf")
}

func saveConfigToAppStorage(cfg *config.Config) (string, error) {
	configPath := defaultConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	if err := cfg.SaveToFile(configPath); err != nil {
		return "", fmt.Errorf("save config file: %w", err)
	}
	return configPath, nil
}

func autoTUNName() string {
	if name := os.Getenv("WANTASTIC_TUN_NAME"); name != "" {
		return name
	}
	switch goruntime.GOOS {
	case "darwin":
		return "utun"
	case "linux":
		return findAvailableTUNName()
	default:
		return "wantastic0"
	}
}

func findAvailableTUNName() string {
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("wantastic%d", i)
		if !interfaceExists(name) {
			return name
		}
	}
	return "wantastic0"
}

func interfaceExists(name string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return true
		}
	}
	return false
}

func startAgentWithRetry(ctx context.Context, cfg *config.Config) (*agent.Agent, error) {
	maxRetries := 10
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		agt, err := agent.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("create agent: %w", err)
		}

		if err := agt.Start(ctx); err != nil {
			lastErr = err
			if strings.Contains(err.Error(), "address already in use") {
				_ = agt.Stop()
				cfg.Interface.ListenPort++
				continue
			}
			return nil, err
		}

		return agt, nil
	}

	return nil, fmt.Errorf("failed to start agent after %d attempts: %w", maxRetries, lastErr)
}

// ─── IPC helpers ────────────────────────────────────────────────────────────

// getIPCPort reads the port the embedded agent's IPC server is bound to.
// Priority: WTC_IPC_PORT env > $TMPDIR/wantasticd_ipc_port file > "9034".
func getIPCPort() string {
	if p := os.Getenv("WTC_IPC_PORT"); p != "" {
		return p
	}
	portFile := filepath.Join(os.TempDir(), "wantasticd_ipc_port")
	if b, err := os.ReadFile(portFile); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "9034"
}

func ipcURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%s%s", getIPCPort(), path)
}

func ipcGet(path string, out interface{}) error {
	resp, err := http.Get(ipcURL(path))
	if err != nil {
		return fmt.Errorf("service not reachable: %w", err)
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func ipcPost(path string) error {
	resp, err := http.Post(ipcURL(path), "application/json", nil)
	if err != nil {
		return fmt.Errorf("service not reachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

// ─── Wails-bound methods (callable from JS) ──────────────────────────────────

// IsConfigured reports whether the embedded VPN service started successfully.
func (a *App) IsConfigured() bool {
	return a.configured
}

// GetStatus fetches live VPN status from the embedded service.
// Returns a zero status (no error) when not yet configured so the frontend
// can render the onboarding flow rather than an error screen.
func (a *App) GetStatus() (*StatusData, error) {
	if !a.configured {
		return &StatusData{Configured: false}, nil
	}

	var raw struct {
		Running       bool     `json:"running"`
		DeviceRunning bool     `json:"device_running"`
		TUNMode       bool     `json:"tun_mode"`
		TUNName       string   `json:"tun_name"`
		ExitNode      bool     `json:"exit_node"`
		IPs           []string `json:"ips"`
		PubKey        string   `json:"pubkey"`
		RxBytes       uint64   `json:"rx_bytes"`
		TxBytes       uint64   `json:"tx_bytes"`
		Peers         []struct {
			PublicKey     string `json:"public_key"`
			Endpoint      string `json:"endpoint"`
			AllowedIPs    string `json:"allowed_ips"`
			RxBytes       uint64 `json:"rx_bytes"`
			TxBytes       uint64 `json:"tx_bytes"`
			LastHandshake string `json:"last_handshake"`
			IsRelay       bool   `json:"is_relay"`
			IsExitNode    bool   `json:"is_exit_node"`
			LatencyMs     int64  `json:"latency_ms"`
		} `json:"peers"`
	}

	if err := ipcGet("/api/status", &raw); err != nil {
		// Service still starting — return configured=true so UI shows a
		// loading indicator and retries on the next poll tick.
		return &StatusData{Configured: true, Running: false, DeviceRunning: false}, nil
	}

	peers := make([]PeerInfo, len(raw.Peers))
	for i, p := range raw.Peers {
		peers[i] = PeerInfo{
			PublicKey:     p.PublicKey,
			Endpoint:      p.Endpoint,
			AllowedIPs:    p.AllowedIPs,
			RxBytes:       p.RxBytes,
			TxBytes:       p.TxBytes,
			LastHandshake: p.LastHandshake,
			IsRelay:       p.IsRelay,
			IsExitNode:    p.IsExitNode,
			Latency:       p.LatencyMs,
		}
	}

	return &StatusData{
		Configured:    true,
		Running:       raw.Running,
		DeviceRunning: raw.DeviceRunning,
		TUNMode:       raw.TUNMode,
		TUNName:       raw.TUNName,
		ExitNode:      raw.ExitNode,
		IPs:           raw.IPs,
		PubKey:        raw.PubKey,
		RxBytes:       raw.RxBytes,
		TxBytes:       raw.TxBytes,
		Peers:         peers,
	}, nil
}

// ToggleVPN connects or disconnects the VPN tunnel
func (a *App) ToggleVPN() error {
	return ipcPost("/api/state/toggle")
}

// ToggleExitNode enables or disables offering this device as an exit node
func (a *App) ToggleExitNode() error {
	return ipcPost("/api/exitnode/toggle")
}

// SetExitNode routes all traffic through the peer with the given public key
func (a *App) SetExitNode(pubkey string) error {
	return ipcPost("/api/exitnode/use?peer=" + pubkey)
}

// GetIPCPort returns the active IPC port (for debug / diagnostics)
func (a *App) GetIPCPort() string {
	return getIPCPort()
}

// ─── Auth / Account ──────────────────────────────────────────────────────────

// GetAccount returns the current account state
func (a *App) GetAccount() (*AccountInfo, error) {
	tok := a.auth.StoredToken()
	if tok == "" {
		return &AccountInfo{LoggedIn: false}, nil
	}
	info := a.auth.ParseDisplayClaims(tok)
	info.LoggedIn = true
	info.Token = tok
	return info, nil
}

// StartLogin launches the gRPC Device Flow. Emits "auth:code" with the user_code
// and verification_uri as soon as they are available so the UI can display them.
// On approval, registers the device, fetches the WireGuard config, and starts
// the embedded VPN service. Emits "auth:complete" and "service:ready" on success.
func (a *App) StartLogin() {
	go func() {
		onVerification := func(userCode, uri string) {
			wailsruntime.EventsEmit(a.ctx, "auth:code",
				map[string]string{"code": userCode, "uri": uri})
			openBrowserURL(uri)
		}

		info, cfg, sessionToken, err := a.auth.RunDeviceFlow(a.ctx, onVerification)
		if err != nil {
			wailsruntime.EventsEmit(a.ctx, "auth:error", err.Error())
			return
		}
		wailsruntime.EventsEmit(a.ctx, "auth:complete", info)

		if !a.configured && cfg != nil {
			go a.initServiceWithConfig(cfg, sessionToken)
		}
	}()
}

// initServiceWithConfig persists a pre-fetched WireGuard config to app storage
// and starts the embedded VPN service. After a successful start, it performs
// the portal auto-login handoff by navigating the system browser to
// /api/device-handoff?t=<sessionToken> if a portal session token was returned.
func (a *App) initServiceWithConfig(cfg *config.Config, sessionToken string) {
	wailsruntime.EventsEmit(a.ctx, "service:configuring", true)
	log.Printf("Persisting VPN configuration and starting embedded service…")

	if _, err := saveConfigToAppStorage(cfg); err != nil {
		log.Printf("Failed to persist config in app storage: %v", err)
		wailsruntime.EventsEmit(a.ctx, "auth:error", fmt.Sprintf("Could not save VPN configuration: %v", err))
		return
	}

	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = autoTUNName()

	agentCtx, agentCancel := context.WithCancel(context.Background())
	agt, err := startAgentWithRetry(agentCtx, cfg)
	if err != nil {
		agentCancel()
		log.Printf("Failed to start embedded VPN service: %v", err)
		wailsruntime.EventsEmit(a.ctx, "auth:error", fmt.Sprintf("Could not start VPN service: %v", err))
		return
	}

	a.agentCancel = agentCancel
	a.agt = agt
	a.configured = true
	log.Printf("Embedded VPN service started via device flow: TUN=%s", cfg.Interface.TUNName)

	// Step 3 of the auth protocol: auto-login the console WebView
	if sessionToken != "" {
		handoffURL := portalBaseURL() + "/api/device-handoff?t=" + sessionToken
		log.Printf("Device-handoff: navigating to %s", handoffURL)
		wailsruntime.BrowserOpenURL(a.ctx, handoffURL)
	}

	wailsruntime.EventsEmit(a.ctx, "service:ready", true)
}

// initServiceFromToken registers this device with the Wantastic backend using
// the access token, fetches the WireGuard configuration, and starts the
// embedded VPN service. Emits "service:ready" on success.
func (a *App) initServiceFromToken(token string) {
	wailsruntime.EventsEmit(a.ctx, "service:configuring", true)
	log.Printf("Registering device with Wantastic backend (%s)…", apiServerAddr())

	ctx, cancel := context.WithTimeout(a.ctx, 45*time.Second)
	defer cancel()

	cfg, err := config.LoadFromToken(ctx, apiServerAddr(), token)
	if err != nil {
		log.Printf("Failed to load config from token: %v", err)
		wailsruntime.EventsEmit(a.ctx, "auth:error", fmt.Sprintf("Could not fetch VPN configuration: %v", err))
		return
	}
	if cfg.Auth.Token == "" {
		cfg.Auth.Token = token
	}

	configPath, err := saveConfigToAppStorage(cfg)
	if err != nil {
		log.Printf("Failed to persist config in app storage: %v", err)
		wailsruntime.EventsEmit(a.ctx, "auth:error", fmt.Sprintf("Could not save VPN configuration: %v", err))
		return
	}
	log.Printf("VPN configuration saved to app storage: %s", configPath)

	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = autoTUNName()

	agentCtx, agentCancel := context.WithCancel(context.Background())
	agt, err := startAgentWithRetry(agentCtx, cfg)
	if err != nil {
		agentCancel()
		log.Printf("Failed to start embedded VPN service: %v", err)
		wailsruntime.EventsEmit(a.ctx, "auth:error", fmt.Sprintf("Could not start VPN service: %v", err))
		return
	}

	a.agentCancel = agentCancel
	a.agt = agt
	a.configured = true
	log.Printf("Embedded VPN service started via token: TUN=%s", cfg.Interface.TUNName)
	wailsruntime.EventsEmit(a.ctx, "service:ready", true)
}

// Logout clears the stored token
func (a *App) Logout() error {
	return a.auth.ClearToken()
}

// OpenConsole opens the Wantastic console in the system browser.
// Uses portalBaseURL() so dev builds hit wantastic.local automatically.
func (a *App) OpenConsole() {
	tok := a.auth.StoredToken()
	target := portalBaseURL()
	if tok != "" {
		target += "/#access_token=" + tok
	}
	wailsruntime.BrowserOpenURL(a.ctx, target)
}

// GetPortalHost returns the current portal hostname for UI display.
func (a *App) GetPortalHost() string {
	u, err := url.Parse(portalBaseURL())
	if err != nil || u.Host == "" {
		return "console.wantastic.app"
	}
	return u.Host
}

// WindowShow brings the main window to the foreground
func (a *App) WindowShow() {
	wailsruntime.WindowShow(a.ctx)
}

// WindowHide hides the main window
func (a *App) WindowHide() {
	wailsruntime.WindowHide(a.ctx)
}

// WindowStartDrag is a no-op — dragging is handled via CSS -webkit-app-region
func (a *App) WindowStartDrag() {}

// ─── Utility ─────────────────────────────────────────────────────────────────

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// TruncateKey returns e.g. "ABCD1234…" for display
func (a *App) TruncateKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8] + "…"
}

// FormatBytes exposes the byte formatter to JS
func (a *App) FormatBytes(b uint64) string {
	return formatBytes(b)
}

// GetVersion returns the app version string
func (a *App) GetVersion() string {
	return "1.0.0"
}

// IsDaemonRunning checks whether the embedded service IPC is reachable
func (a *App) IsDaemonRunning() bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(ipcURL("/api/status"))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// PubKeyShort returns a display-friendly truncated pubkey
func (a *App) PubKeyShort(key string) string {
	key = strings.TrimRight(key, "=")
	if len(key) > 12 {
		return key[:6] + "…" + key[len(key)-4:]
	}
	return key
}
