package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/agent"
	"wantastic-agent/pkg/runner"
	"wantastic-agent/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
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

	configPath := "/etc/wantastic/config.conf"
	// Check if /etc/wantastic already exists as a plain file (e.g. from bulk_install).
	// If so, use it directly instead of trying to create a subdirectory.
	if info, err := os.Stat("/etc/wantastic"); err == nil && !info.IsDir() {
		configPath = "/etc/wantastic"
	} else if err := os.MkdirAll("/etc/wantastic", 0700); err != nil {
		// Can't create directory — fall back to flat file
		configPath = "/etc/wantastic"
	}

	if err := cfg.SaveToFile(configPath); err != nil {
		log.Fatalf("Failed to save configuration: %v", err)
	}
	log.Println("Configuration saved to", configPath)
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

	// Auto-determine TUN name based on platform
	tunName := autoTUNName()

	if *configPath == "" {
		// If positional argument provided, use it as config path
		if connectCmd.NArg() > 0 {
			*configPath = connectCmd.Arg(0)
		} else {
			// Try paths in priority order: dir-based, flat file, local fallback
			candidates := []string{
				"/etc/wantastic/config.conf",
				"/etc/wantastic",
				"wantastic.conf",
			}
			*configPath = candidates[0] // default if none found
			for _, p := range candidates {
				if _, err := os.Stat(p); err == nil {
					*configPath = p
					break
				}
			}
		}
	}

	runner.RunServiceHook(func(ctx context.Context) {
		runAgent(ctx, *configPath, *verbose, *autoUpdate, tunName, useTray)
	})
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

	// Ensure system has working public DNS before connecting.
	ensureSystemDNS()

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

// ensureSystemDNS checks /etc/resolv.conf for a reliable public DNS server
// (1.1.1.1 or 8.8.8.8) and appends both if neither is present. This prevents
// WireGuard endpoint resolution failures on devices with missing or broken DNS.
// No-op on non-Linux platforms.
func ensureSystemDNS() {
	if runtime.GOOS != "linux" {
		return
	}
	const resolvConf = "/etc/resolv.conf"
	data, err := os.ReadFile(resolvConf)
	if err != nil {
		return
	}
	content := string(data)
	has1111 := strings.Contains(content, "1.1.1.1")
	has8888 := strings.Contains(content, "8.8.8.8")
	if has1111 || has8888 {
		return
	}

	// Neither reliable DNS present — check existing nameservers still respond.
	hasWorking := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				if _, err := net.LookupHost("one.one.one.one"); err == nil {
					hasWorking = true
					break
				}
			}
		}
	}
	if hasWorking {
		return
	}

	log.Println("No reliable DNS found — adding 1.1.1.1 and 8.8.8.8 to /etc/resolv.conf")
	f, err := os.OpenFile(resolvConf, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Warning: could not update /etc/resolv.conf: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")
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
