// Command fiberagent-tiny is a tinygo-compatible Wantastic agent for
// embedded fiber devices (GPON ONUs and OLTs). It provides the device
// claim flow with a QR onboarding page, runs WUSP telemetry collection,
// and exposes setter/operate APIs over HTTP — no local WireGuard tunnel,
// no speedtest, no ICMP.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"rsc.io/qr"

	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/fiberolt"
	"wantastic-agent/internal/wusp/fiberonu"
	"wantastic-agent/pkg/version"
)

type claimKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ServerURL  string `json:"server_url"`
	ClaimURL   string `json:"claim_url"`
	CreatedAt  string `json:"created_at"`
}

type onboardingState struct {
	ClaimURL  string `json:"claim_url"`
	PublicKey string `json:"public_key"`
	Claimed   bool   `json:"claimed"`
	Message   string `json:"message,omitempty"`
}

var onboardingPage = template.Must(template.New("onboard").Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Onboard this device</title>
<style>
  body { font-family: sans-serif; background: #0f1115; color: #e6e8ec; margin: 0; display: flex; min-height: 100vh; align-items: center; justify-content: center; }
  .card { background: #171a21; border: 1px solid #2a2f3a; border-radius: 16px; padding: 40px; max-width: 420px; width: calc(100% - 48px); text-align: center; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { color: #9aa3b2; font-size: 14px; line-height: 1.5; }
  .qr { margin: 24px auto; display: block; image-rendering: pixelated; width: 240px; height: 240px; }
  .url { display: block; background: #0b0d11; border: 1px solid #2a2f3a; border-radius: 8px; padding: 10px; color: #7fd1ff; font-size: 12px; word-break: break-all; text-decoration: none; }
  .claimed { color: #5fd68b; font-weight: 600; }
</style>
</head>
<body>
  <div class="card">
    <h1>Wantastic</h1>
    {{if .Claimed}}
      <p class="claimed">This device is claimed and online.</p>
    {{else}}
      <p>Scan the QR code or open the link to claim this device.</p>
      <img class="qr" src="/qr.png" alt="Claim QR code">
      <a class="url" href="{{.ClaimURL}}">{{.ClaimURL}}</a>
    {{end}}
  </div>
</body>
</html>`))

func main() {
	claimKeyPath := flag.String("claim-key", defaultClaimKeyPath(), "Path to device claim key JSON")
	serverURL := flag.String("server-url", "", "Wantastic server URL/domain")
	onboardAddr := flag.String("onboard", ":9043", "Address for the QR onboarding page")
	oltURL := flag.String("olt-url", "", "FOS OLT web API base URL (e.g. http://192.168.100.100)")
	oltUser := flag.String("olt-user", "admin", "OLT web API user")
	oltPass := flag.String("olt-pass", "admin", "OLT web API password")
	devMode := flag.Bool("dev", false, "Skip claim wait, start collection immediately")
	corsOrigin := flag.String("cors-origin", "http://192.168.1.1", "Browser origin allowed to call the agent API (the native web UI)")
	_ = flag.String("config", "", "Reserved: path to an agent config file (accepted for factory rcS compatibility)")
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	log.Printf("fiberagent-tiny %s starting", version.Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received shutdown signal")
		cancel()
	}()

	kind := detectKind(*oltURL)
	log.Printf("Detected device kind: %s", kind)

	rt := &wuspRuntime{kind: kind}
	if kind == "olt" && *oltURL != "" {
		rt.oltClient = fiberolt.NewClient(*oltURL, *oltUser, *oltPass)
	}

	onboard := serveOnboarding(*onboardAddr, rt, *corsOrigin)

	portalURL := auth.NormalizeServerURL(*serverURL)
	keyFile, reused, err := loadOrCreateClaimKey(*claimKeyPath, portalURL, false)
	if err != nil {
		log.Fatalf("claim key: %v", err)
	}
	if reused {
		log.Printf("Reused existing device claim key: %s", *claimKeyPath)
	} else {
		log.Printf("Generated device claim key: %s", *claimKeyPath)
	}
	setOnboard(onboard, &onboardingState{
		ClaimURL:  keyFile.ClaimURL,
		PublicKey: keyFile.PublicKey,
	})
	log.Printf("Claim URL: %s", keyFile.ClaimURL)

	if *devMode {
		log.Printf("Dev mode — starting telemetry loop immediately (no claim wait)")
		go rt.collectLoop(ctx)
		<-ctx.Done()
		log.Println("fiberagent-tiny stopped")
		return
	}

	hashedDeviceID, err := auth.HashedDeviceID()
	if err != nil {
		log.Fatalf("device id: %v", err)
	}

	claim, err := auth.FetchClaimConfig(ctx, portalURL, hashedDeviceID, keyFile.PublicKey)
	if err != nil || claim == nil || !claim.Claimed {
		if err != nil {
			log.Printf("claim config not ready yet: %v", err)
		}
		for attempt := 1; ; attempt++ {
			claim, err = auth.WaitClaimConfig(ctx, portalURL, hashedDeviceID, keyFile.PublicKey)
			if err == nil && claim != nil && claim.Claimed {
				break
			}
			if ctx.Err() != nil {
				break
			}
			backoff := time.Duration(attempt) * 5 * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			log.Printf("claim wait attempt %d failed (%v); retrying in %s", attempt, err, backoff)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
		}
		if err != nil || claim == nil || !claim.Claimed {
			log.Fatalf("claim: %v", err)
		}
	}

	markClaimed(onboard, "")
	log.Printf("Device claimed — starting telemetry loop")

	go rt.collectLoop(ctx)

	<-ctx.Done()
	log.Println("fiberagent-tiny stopped")
}

// ---- device kind detection ------------------------------------------------

func detectKind(oltURL string) string {
	if oltURL != "" {
		return "olt"
	}
	if _, err := os.Stat("/proc/pon_phy"); err == nil {
		return "onu"
	}
	return "onu"
}

// ---- WUSP runtime: collect + set + operate --------------------------------

type wuspRuntime struct {
	kind       string
	oltClient  *fiberolt.Client
	onuEnabled bool
	oltEnabled bool

	mu      sync.Mutex
	lastMsg *wusp.Message
}

func (rt *wuspRuntime) collectLoop(ctx context.Context) {
	rt.onuEnabled = true
	rt.oltEnabled = true
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	rt.collect(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rt.collect(ctx)
		}
	}
}

func (rt *wuspRuntime) collect(ctx context.Context) {
	msg := wusp.NewMessage()
	switch rt.kind {
	case "onu":
		fiberonu.CollectONU(ctx, onuOpts(), rt.onuEnabled, msg)
	case "olt":
		if rt.oltClient != nil {
			fiberolt.CollectOLT(ctx, rt.oltClient, nil, rt.oltEnabled, msg)
		}
	}
	rt.mu.Lock()
	rt.lastMsg = msg
	rt.mu.Unlock()
	count := len(msg.Fields)
	log.Printf("[WUSP] collected %d fields (%s)", count, rt.kind)
}

func (rt *wuspRuntime) snapshot() *wusp.Message {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.lastMsg
}

func (rt *wuspRuntime) handleSet(path string, value wusp.Value) error {
	switch rt.kind {
	case "onu":
		return fiberonu.SetONUParam(onuOpts(), path, value, func(v bool) error {
			rt.onuEnabled = v
			return nil
		})
	case "olt":
		if rt.oltClient != nil {
			return fiberolt.SetOLTParam(context.Background(), rt.oltClient, path, value, func(v bool) error {
				rt.oltEnabled = v
				return nil
			})
		}
		return wusp.ErrUSPPathUnsupported
	}
	return wusp.ErrUSPPathUnsupported
}

func (rt *wuspRuntime) handleOperate(ctx context.Context, cmd string, input *wusp.Message) error {
	switch rt.kind {
	case "onu":
		return fiberonu.ONUOperate(ctx, onuOpts(), cmd, input)
	case "olt":
		if rt.oltClient != nil {
			return fiberolt.OLTOperate(ctx, rt.oltClient, cmd, input)
		}
		return wusp.ErrUSPPathUnsupported
	}
	return wusp.ErrUSPPathUnsupported
}

func onuOpts() fiberonu.Options {
	return fiberonu.Options{
		ProcPonPhyDir: envOrDefault("PROC_PON_PHY_DIR", ""),
		ProcXponDir:   envOrDefault("PROC_XPON_DIR", ""),
		CGIBaseURL:    envOrDefault("ONU_CGI_BASE_URL", ""),
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---- onboarding + API server ----------------------------------------------

type atomicState struct {
	mu sync.Mutex
	v  *onboardingState
}

func (a *atomicState) Load() *onboardingState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}

func (a *atomicState) Store(v *onboardingState) {
	a.mu.Lock()
	a.v = v
	a.mu.Unlock()
}

func serveOnboarding(addr string, rt *wuspRuntime, corsOrigin string) *atomicState {
	state := &atomicState{v: &onboardingState{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = onboardingPage.Execute(w, state.Load())
	})
	mux.HandleFunc("/qr.png", func(w http.ResponseWriter, r *http.Request) {
		claimURL := state.Load().ClaimURL
		if claimURL == "" {
			http.NotFound(w, r)
			return
		}
		code, err := qr.Encode(claimURL, qr.L)
		if err != nil {
			http.Error(w, "qr encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		_ = png.Encode(w, code.Image())
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Load())
	})

	mux.HandleFunc("/api/wusp/telemetry", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		msg := rt.snapshot()
		if msg == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"fields": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(msg)
	})

	mux.HandleFunc("/api/wusp/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Path  string `json:"path"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request", http.StatusBadRequest)
			return
		}
		err := rt.handleSet(req.Path, wusp.String(req.Value))
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	mux.HandleFunc("/api/wusp/operate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Command string         `json:"command"`
			Input   map[string]any `json:"input,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request", http.StatusBadRequest)
			return
		}
		var input *wusp.Message
		if len(req.Input) > 0 {
			input = wusp.NewMessage()
			for k, v := range req.Input {
				input.Set(k, wusp.String(fmt.Sprint(v)))
			}
		}
		err := rt.handleOperate(r.Context(), req.Command, input)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	server := &http.Server{Addr: addr, Handler: withCORS(mux, corsOrigin), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("onboarding page: %v", err)
		}
	}()
	log.Printf("Onboarding + WUSP API listening on %s (web-ui origin %s)", addr, corsOrigin)
	return state
}

// withCORS lets the device's own web UI (served by boa on :80) call the agent
// API on :9043. Only the configured origin is allowed, so arbitrary websites a
// user visits cannot drive the agent. A preflight is answered directly.
func withCORS(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && (origin == "*" || o == origin) {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func setOnboard(state *atomicState, next *onboardingState) {
	if state != nil {
		state.Store(next)
	}
}

func markClaimed(state *atomicState, message string) {
	if state == nil {
		return
	}
	prev := state.Load()
	setOnboard(state, &onboardingState{
		ClaimURL:  prev.ClaimURL,
		PublicKey: prev.PublicKey,
		Claimed:   true,
		Message:   message,
	})
}

// ---- claim key helpers ----------------------------------------------------

func defaultClaimKeyPath() string {
	return auth.PersistentFilePath("device-claim-key.json")
}

func loadOrCreateClaimKey(path, portalBaseURL string, force bool) (*claimKeyFile, bool, error) {
	if !force {
		if data, err := os.ReadFile(path); err == nil {
			var existing claimKeyFile
			if err := json.Unmarshal(data, &existing); err != nil {
				return nil, false, fmt.Errorf("parse existing key file: %w", err)
			}
			if existing.PrivateKey == "" || existing.PublicKey == "" {
				return nil, false, fmt.Errorf("existing key file missing private_key or public_key")
			}
			existing.ServerURL = portalBaseURL
			existing.ClaimURL = auth.BuildClaimURL(portalBaseURL, existing.PublicKey, "")
			if err := writeClaimKeyFile(path, &existing); err != nil {
				return nil, false, fmt.Errorf("update existing key file: %w", err)
			}
			return &existing, true, nil
		} else if !os.IsNotExist(err) {
			return nil, false, fmt.Errorf("read key file: %w", err)
		}
	}

	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, false, err
	}
	keyFile := &claimKeyFile{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ServerURL:  portalBaseURL,
		ClaimURL:   auth.BuildClaimURL(portalBaseURL, publicKey, ""),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeClaimKeyFile(path, keyFile); err != nil {
		return nil, false, err
	}
	return keyFile, false, nil
}

func writeClaimKeyFile(path string, keyFile *claimKeyFile) error {
	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func generateWireGuardKeyPair() (string, string, error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	privateBytes[0] &= 248
	privateBytes[31] = (privateBytes[31] & 127) | 64

	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(privateBytes), base64.StdEncoding.EncodeToString(publicBytes), nil
}

