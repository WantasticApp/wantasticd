package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/config"
	platformdns "wantastic-agent/internal/platform/dns"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/agent"
	"wantastic-agent/pkg/runner"
	"wantastic-agent/pkg/version"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/crypto/curve25519"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	if os.Args[1] == "--wait-claim" || os.Args[1] == "-wc" {
		os.Args = append([]string{os.Args[0], "connect"}, os.Args[1:]...)
	}

	switch os.Args[1] {
	case "genkey":
		handleGenKey()
	case "login":
		handleLogin()
	case "connect":
		handleConnect()
	case "status":
		handleStatus()
	case "tray":
		handleTray()
	case "update":
		handleUpdate()
	case "version":
		printVersion()
	default:
		printUsage()
		os.Exit(1)
	}
}

type claimKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ServerURL  string `json:"server_url"`
	ClaimURL   string `json:"claim_url"`
	CreatedAt  string `json:"created_at"`
}

func handleGenKey() {
	genCmd := flag.NewFlagSet("genkey", flag.ExitOnError)
	outPath := genCmd.String("out", defaultClaimKeyPath(), "Path to save/reuse the device claim key JSON")
	configPath := genCmd.String("config", auth.DefaultConfigPath(), "Path to save claimed configuration")
	serverURL := genCmd.String("server-url", "", "Wantastic server URL/domain used in the claim QR")
	server := genCmd.String("server", "", "Wantastic server domain shorthand for --server-url")
	portalURL := genCmd.String("portal-url", "", "Deprecated alias for --server-url")
	force := genCmd.Bool("force", false, "Generate a new key even if --out already exists")
	printQR := genCmd.Bool("qr", true, "Print a terminal QR code for the claim URL")
	showPrivate := genCmd.Bool("show-private", false, "Print the private key to stdout")
	noWait := genCmd.Bool("no-wait", false, "Generate the key and exit without waiting for claim")
	claimPoll := genCmd.Duration("claim-poll", 10*time.Second, "How often to poll for claim completion when websocket wait is unavailable")
	verbose := genCmd.Bool("v", false, "Enable verbose logging and debug output after claim")
	autoUpdate := genCmd.Bool("auto-update", false, "Enable automatic self-updates after claim")
	useTray := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	flagTray := genCmd.Bool("tray", useTray, "Enable system tray GUI after claim")
	genCmd.Parse(os.Args[2:])
	useTray = *flagTray

	claimServerURL := resolveClaimServerURL(*serverURL, *server, *portalURL)
	keyFile, reused, err := loadOrCreateClaimKey(*outPath, claimServerURL, *force)
	if err != nil {
		log.Fatalf("genkey failed: %v", err)
	}

	if reused {
		fmt.Printf("Reused existing device claim key: %s\n", *outPath)
	} else {
		fmt.Printf("Generated device claim key: %s\n", *outPath)
	}
	fmt.Printf("Public key: %s\n", keyFile.PublicKey)
	fmt.Printf("Server URL: %s\n", keyFile.ServerURL)
	fmt.Printf("Claim URL: %s\n", keyFile.ClaimURL)
	if *showPrivate {
		fmt.Printf("Private key: %s\n", keyFile.PrivateKey)
	}
	if *printQR {
		fmt.Println()
		qrterminal.GenerateWithConfig(keyFile.ClaimURL, qrterminal.Config{
			Level:      qrterminal.L,
			Writer:     os.Stdout,
			HalfBlocks: true,
		})
	}
	if *noWait {
		return
	}

	tunName := autoTUNName()
	log.Println("Waiting for claim. Press Ctrl+C to stop.")
	runner.RunServiceHook(func(ctx context.Context) {
		runWaitClaim(ctx, *outPath, *configPath, claimServerURL, *claimPoll, *verbose, *autoUpdate, tunName, useTray)
	})
}

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
			existing.ServerURL = normalizeClaimServerURL(portalBaseURL)
			existing.ClaimURL = buildClaimURL(portalBaseURL, existing.PublicKey)
			if err := auth.PersistPublicKey(existing.PublicKey); err != nil {
				log.Printf("Warning: could not persist public key copy: %v", err)
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
		ServerURL:  normalizeClaimServerURL(portalBaseURL),
		ClaimURL:   buildClaimURL(portalBaseURL, publicKey),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeClaimKeyFile(path, keyFile); err != nil {
		return nil, false, err
	}
	if err := auth.PersistPublicKey(publicKey); err != nil {
		log.Printf("Warning: could not persist public key copy: %v", err)
	}
	return keyFile, false, nil
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

func buildClaimURL(portalBaseURL, publicKey string) string {
	base := normalizeClaimServerURL(portalBaseURL)
	return base + "/#desktop?claim_public_key=" + url.QueryEscape(strings.TrimSpace(publicKey)) + "&wantastic_server=" + url.QueryEscape(base)
}

func resolveClaimServerURL(serverURL, server, portalURL string) string {
	for _, value := range []string{serverURL, server, portalURL} {
		if strings.TrimSpace(value) != "" {
			return normalizeClaimServerURL(value)
		}
	}
	return "https://" + auth.DefaultOAuth2Domain
}

func normalizeClaimServerURL(portalBaseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(portalBaseURL), "/")
	if base == "" {
		return "https://" + auth.DefaultOAuth2Domain
	}
	if !strings.HasPrefix(strings.ToLower(base), "http://") &&
		!strings.HasPrefix(strings.ToLower(base), "https://") {
		base = "https://" + base
	}
	if parsed, err := url.Parse(base); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host
	}
	return base
}

func writeClaimKeyFile(path string, keyFile *claimKeyFile) error {
	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key file: %w", err)
	}
	if err := auth.EnsureParentDir(path, 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

func loadClaimKeyFile(path string) (*claimKeyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var keyFile claimKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	if strings.TrimSpace(keyFile.PrivateKey) == "" || strings.TrimSpace(keyFile.PublicKey) == "" {
		return nil, fmt.Errorf("key file missing private_key or public_key")
	}
	return &keyFile, nil
}

func ensureConfigDir(path string) error {
	return auth.EnsureParentDir(path, 0o700)
}

func handleLogin() {
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	token := loginCmd.String("token", "", "Direct access token (skips browser auth)")
	portalURL := loginCmd.String("portal-url", "https://"+auth.DefaultOAuth2Domain, "Portal base URL")
	server := loginCmd.String("server", "", "Server hostname (shorthand for --portal-url https://HOST)")
	dev := loginCmd.Bool("dev", false, "Use local dev portal (https://"+auth.DefaultOAuth2DevDomain+")")
	loginCmd.Parse(os.Args[2:])

	// --server sets portal URL and disables TLS verification (local/dev servers
	// use self-signed certs or IP addresses without SANs).
	if *server != "" {
		*portalURL = "https://" + *server
		auth.SetInsecureSkipVerify()
	}

	if *dev {
		if *server == "" {
			*portalURL = "https://" + auth.DefaultOAuth2DevDomain
		}
		auth.SetInsecureSkipVerify()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var cfg *config.Config
	var err error
	if *token != "" {
		cfg, err = config.LoadFromToken(ctx, *portalURL, *token)
	} else {
		cfg, err = config.LoadFromDeviceFlow(ctx, *portalURL)
	}
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	// Log key config details so we can diagnose connection issues
	log.Printf("Login successful: endpoint=%s:%d, address=%v",
		cfg.Server.Endpoint, cfg.Server.Port, cfg.Interface.Addresses)

	configPath := auth.DefaultConfigPath()
	if err := ensureConfigDir(configPath); err != nil {
		log.Fatalf("Failed to prepare config path: %v", err)
	}

	if err := cfg.SaveToFile(configPath); err != nil {
		log.Fatalf("Failed to save configuration: %v", err)
	}
	log.Println("Configuration saved to", configPath)

	// Auto-connect after successful login.
	// On headless/embedded devices (OpenWrt), login is typically the only
	// interactive step — the user expects the tunnel to come up immediately.
	log.Println("Starting connection...")

	platformdns.EnsureBootstrap(ctx)
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = autoTUNName()

	runner.RunServiceHook(func(ctx context.Context) {
		runAgent(ctx, configPath, false, false, cfg.Interface.TUNName, false)
	})
}

func runAgentWithConfig(cfg *config.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	agt, err := startAgentWithRetry(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	log.Printf("Wantastic agent started successfully in TUN mode")

	select {
	case <-sigCh:
		log.Println("Received shutdown signal")
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	if err := agt.Stop(); err != nil {
		log.Fatalf("Failed to stop agent: %v", err)
	}

	log.Println("Agent stopped successfully")
}

func handleConnect() {
	connectCmd := flag.NewFlagSet("connect", flag.ExitOnError)
	configPath := connectCmd.String("config", "", "Path to configuration file")
	claimKeyPath := connectCmd.String("claim-key", defaultClaimKeyPath(), "Path to device claim key JSON")
	serverURL := connectCmd.String("server-url", "", "Wantastic server URL/domain used while waiting for claim")
	server := connectCmd.String("server", "", "Wantastic server domain shorthand for --server-url")
	portalURL := connectCmd.String("portal-url", "", "Deprecated alias for --server-url")
	waitClaim := connectCmd.Bool("wait-claim", false, "Wait until the factory claim public key is claimed, then connect")
	waitClaimShort := connectCmd.Bool("wc", false, "Alias for --wait-claim")
	claimPoll := connectCmd.Duration("claim-poll", 10*time.Second, "How often to poll for claim completion")
	verbose := connectCmd.Bool("v", false, "Enable verbose logging and debug output")
	autoUpdate := connectCmd.Bool("auto-update", false, "Enable automatic self-updates")

	useTray := false
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		useTray = true // Always start the systray component simultaneously on Desktop OSs
	}

	// Still parse flags in case the user explicitly sets --tray=false or --tray=true
	flagTray := connectCmd.Bool("tray", useTray, "Enable system tray GUI")
	connectCmd.Parse(os.Args[2:])

	useTray = *flagTray
	if *waitClaimShort {
		*waitClaim = true
	}

	// Auto-determine TUN name based on platform
	tunName := autoTUNName()

	if *configPath == "" {
		// If positional argument provided, use it as config path
		if connectCmd.NArg() > 0 {
			*configPath = connectCmd.Arg(0)
		} else {
			candidates := auth.ConfigPathCandidates()
			*configPath = candidates[0] // default if none found
			for _, p := range candidates {
				if _, err := os.Stat(p); err == nil {
					*configPath = p
					break
				}
			}
		}
	}
	if _, err := os.Stat(*configPath); err != nil {
		if os.IsNotExist(err) && claimKeyExists(*claimKeyPath) {
			log.Printf("Config not found at %s; waiting for claim using %s", *configPath, *claimKeyPath)
			*waitClaim = true
		} else if os.IsNotExist(err) && !*waitClaim {
			log.Fatalf("Config not found at %s. Run `wantasticd genkey --out %s` to create a claim key and wait for claim, or pass --wait-claim with an existing key.", *configPath, *claimKeyPath)
		}
	}

	runner.RunServiceHook(func(ctx context.Context) {
		if *waitClaim {
			runWaitClaim(ctx, *claimKeyPath, *configPath, resolveClaimServerURL(*serverURL, *server, *portalURL), *claimPoll, *verbose, *autoUpdate, tunName, useTray)
			return
		}
		runAgent(ctx, *configPath, *verbose, *autoUpdate, tunName, useTray)
	})
}

func claimKeyExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func runWaitClaim(parentCtx context.Context, claimKeyPath, configPath, serverURL string, pollInterval time.Duration, verbose bool, autoUpdate bool, tunName string, useTray bool) {
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	keyFile, err := loadClaimKeyFile(claimKeyPath)
	if err != nil {
		log.Fatalf("Failed to load claim key: %v", err)
	}
	if serverURL == "" {
		serverURL = keyFile.ServerURL
	}
	serverURL = resolveClaimServerURL(serverURL, "", "")
	log.Printf("Waiting for Wantastic device claim: public_key=%s server=%s", keyFile.PublicKey, serverURL)
	log.Printf("Claim URL: %s", buildClaimURL(serverURL, keyFile.PublicKey))

	hashedDeviceID, err := auth.HashedDeviceID()
	if err != nil {
		log.Fatalf("Failed to get device id: %v", err)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		claim, waitErr := auth.WaitClaimConfig(parentCtx, serverURL, hashedDeviceID, keyFile.PublicKey)
		if waitErr == nil && claim != nil && claim.Claimed {
			if applyClaimedConfig(parentCtx, configPath, serverURL, keyFile, claim, verbose, autoUpdate, tunName, useTray) {
				return
			}
		} else if waitErr != nil && parentCtx.Err() == nil {
			log.Printf("Claim websocket unavailable, falling back to signed polling: %v", waitErr)
		}

		pollCtx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
		claim, fetchErr := auth.FetchClaimConfig(pollCtx, serverURL, hashedDeviceID, keyFile.PublicKey)
		cancel()
		if fetchErr == nil && claim != nil && claim.Claimed {
			if applyClaimedConfig(parentCtx, configPath, serverURL, keyFile, claim, verbose, autoUpdate, tunName, useTray) {
				return
			}
		} else if fetchErr != nil && parentCtx.Err() == nil {
			log.Printf("Claim polling not ready: %v", fetchErr)
		} else if parentCtx.Err() == nil {
			log.Printf("Claim not ready yet")
		}

		select {
		case <-parentCtx.Done():
			log.Println("Stopped waiting for claim")
			return
		case <-ticker.C:
		}
	}
}

func applyClaimedConfig(parentCtx context.Context, configPath, serverURL string, keyFile *claimKeyFile, claim *auth.ClaimConfig, verbose bool, autoUpdate bool, tunName string, useTray bool) bool {
	cfg, cfgErr := config.LoadFromClaimConfig(serverURL, keyFile.PrivateKey, keyFile.PublicKey, claim)
	if cfgErr != nil {
		log.Printf("Claim found but config is not ready: %v", cfgErr)
		return false
	}
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = tunName
	if verbose || os.Getenv("DEBUG_LEVEL") == "debug" {
		cfg.Verbose = true
	}
	cfg.AutoUpdate = autoUpdate
	if err := ensureConfigDir(configPath); err != nil {
		log.Fatalf("Failed to prepare config path: %v", err)
	}
	if err := cfg.SaveToFile(configPath); err != nil {
		log.Fatalf("Failed to save claimed configuration: %v", err)
	}
	log.Printf("Device claimed. Configuration saved to %s", configPath)
	runAgent(parentCtx, configPath, verbose, autoUpdate, tunName, useTray)
	return true
}

func runAgent(parentCtx context.Context, configPath string, verbose bool, autoUpdate bool, tunName string, useTray bool) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if verbose || os.Getenv("DEBUG_LEVEL") == "debug" {
		cfg.Verbose = true
	}

	cfg.AutoUpdate = autoUpdate

	// Ensure bootstrap DNS resolution is sane before connecting. The platform
	// DNS package avoids direct resolver-file writes unless that is safe.
	platformdns.EnsureBootstrap(ctx)

	// Enforce TUN mode config natively
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = tunName

	agt, err := startAgentWithRetry(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	log.Printf("Wantastic agent started successfully")
	log.Printf("Mode: System TUN (%s)", cfg.Interface.TUNName)

	go func() {
		select {
		case <-sigCh:
			log.Println("Received shutdown signal (Interrupt)")
			cancel()
		case <-ctx.Done():
		}
	}()

	if useTray {
		log.Println("Starting system tray client...")
		// systray.Run MUST block the main thread on macOS
		runner.RunSystray(ctx, cancel)
	} else {
		<-ctx.Done()
	}

	if err := agt.Stop(); err != nil {
		log.Fatalf("Failed to stop agent: %v", err)
	}
	log.Println("Agent stopped successfully")
}

func printVersion() {
	fmt.Printf("wantasticd version %s\n", version.Version)
	fmt.Printf("commit: %s\n", version.Commit)
	fmt.Printf("build date: %s\n", version.BuildDate)
}

func handleTray() {
	log.Println("Starting Wantastic system tray client...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			log.Println("Received shutdown signal (Interrupt)")
			cancel()
		case <-ctx.Done():
		}
	}()

	// systray.Run MUST block the main thread on macOS
	runner.RunSystray(ctx, cancel)
	log.Println("Tray app exiting")
}

func handleStatus() {
	resp, err := http.Get("http://127.0.0.1:" + agent.GetIPCPort() + "/api/status")
	if err != nil {
		fmt.Println("Status: Offline (Daemon is not running or not reachable)")
		return
	}
	defer resp.Body.Close()

	var status struct {
		TUNMode bool   `json:"tun_mode"`
		TUNName string `json:"tun_name"`
		Running bool   `json:"running"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		fmt.Printf("Status: Error parsing response: %v\n", err)
		return
	}

	state := "Stopped"
	if status.Running {
		state = "Running"
	}
	modeStr := "Userspace"
	if status.TUNMode {
		modeStr = fmt.Sprintf("TUN (%s)", status.TUNName)
	}
	fmt.Printf("Status: %s\nMode: %s\n", state, modeStr)
}

func handleUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	mgr := update.NewManager(version.Version)
	latest, err := mgr.FetchLatestVersion(ctx)
	if err != nil {
		log.Fatalf("Failed to fetch latest version: %v", err)
	}

	if latest == version.Version {
		fmt.Printf("Already running latest version: %s\n", version.Version)
		return
	}

	fmt.Printf("Updating from %s to %s...\n", version.Version, latest)
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to determine executable path: %v", err)
	}
	if err := mgr.RunUpdateScript(ctx, latest, execPath); err != nil {
		log.Fatalf("Update failed: %v", err)
	}
}

func handlePeers() {
	resp, err := http.Get("http://127.0.0.1:" + agent.GetIPCPort() + "/peers")
	if err != nil {
		log.Fatalf("Failed to reach daemon: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		Peers []struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
			Alive    bool   `json:"alive"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatalf("Failed to decode discovery results: %v", err)
	}

	fmt.Printf("%-18s %-20s %-25s\n", "IP ADDRESS", "HOSTNAME", "OS / DEVICE TYPE")
	fmt.Println(strings.Repeat("-", 65))
	for _, p := range data.Peers {
		hostname := p.Hostname
		if hostname == "" {
			hostname = "unknown"
		}
		osInfo := p.OS
		if osInfo == "" {
			osInfo = "unknown"
		}
		fmt.Printf("%-18s %-20s %-25s\n", p.IP, hostname, osInfo)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "\nAvailable commands:")
	fmt.Fprintln(os.Stderr, "  genkey     Generate a fixed device claim key and QR URL")
	fmt.Fprintln(os.Stderr, "  login      Authenticate and configure client")
	fmt.Fprintln(os.Stderr, "  connect    Connect using a configuration file")
	fmt.Fprintln(os.Stderr, "  update     Self-update to the latest version")
	fmt.Fprintln(os.Stderr, "  version    Show version information")
	fmt.Fprintln(os.Stderr, "\nEnvironment Variables:")
	fmt.Fprintln(os.Stderr, "  WANTASTIC_TUN_NAME=X   Override auto TUN name selection")
}

// autoTUNName returns an automatic TUN interface name based on the platform
func autoTUNName() string {
	// Check if user specified a custom name via environment variable
	if name := os.Getenv("WANTASTIC_TUN_NAME"); name != "" {
		return name
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "darwin":
		// On macOS, use "utun" to let the system assign an available number
		return "utun"
	case "linux":
		// On Linux, try to find an available wantasticX interface
		return findAvailableTUNName()
	default:
		return "wantastic0"
	}
}

// findAvailableTUNName finds an available TUN interface name on Linux
func findAvailableTUNName() string {
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("wantastic%d", i)
		// Check if interface exists by trying to open it
		if !interfaceExists(name) {
			return name
		}
	}
	return "wantastic0"
}

// interfaceExists checks if a network interface exists
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
		if i > 0 {
			log.Printf("Port %d in use, retrying with port %d...", cfg.Interface.ListenPort-1, cfg.Interface.ListenPort)
		}

		agt, err := agent.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("create agent: %w", err)
		}

		if err := agt.Start(ctx); err != nil {
			lastErr = err
			// Check for "address already in use"
			if strings.Contains(err.Error(), "bind: address already in use") || strings.Contains(err.Error(), "address already in use") {
				agt.Stop()
				cfg.Interface.ListenPort++
				continue
			}
			return nil, err
		}

		return agt, nil
	}

	return nil, fmt.Errorf("failed to start agent after %d attempts: %w", maxRetries, lastErr)
}
