package main

import (
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
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/daemon"
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
	token := loginCmd.String("token", "", "Direct authentication token")
	serverURL := loginCmd.String("server-url", "auth.wantastic.app:443", "Authentication server URL")
	installService := loginCmd.Bool("d", false, "Install and run as system service (daemon)")
	loginCmd.Parse(os.Args[2:])

	// Auto-determine TUN name based on platform
	tunName := autoTUNName()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfg *config.Config
	var err error

	if *token != "" {
		cfg, err = config.LoadFromToken(ctx, *serverURL, *token)
	} else {
		cfg, err = config.LoadFromDeviceFlow(ctx, *serverURL)
	}

	if err != nil {
		log.Fatalf("Failed to configure agent: %v", err)
	}

	// Default to new standard path
	configPath := "/etc/wantastic/config.conf"
	configDir := "/etc/wantastic"

	// If running as non-root/daemon setup request validation
	if *installService && os.Geteuid() != 0 {
		log.Printf("Warning: Service installation (-d) requires root privileges.")
	}

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("Warning: failed to create config directory %s: %v", configDir, err)
		// Fallback to local directory if system directory fails (e.g. non-root)
		configPath = "wantastic.conf"
		log.Printf("Falling back to local file: %s", configPath)
	}

	if err := cfg.SaveToFile(configPath); err != nil {
		log.Printf("Warning: could not save configuration file: %v", err)
		if *installService {
			log.Fatalf("Error: Cannot install service without saving configuration file.")
		}
		log.Println("Running with in-memory configuration only.")
		runAgentWithConfig(cfg)
	} else {
		log.Println("Login successful. Configuration saved to", configPath)

		if *installService {
			log.Println("Setting up system service...")
			if err := daemon.SetupService(configPath); err != nil {
				log.Fatalf("Failed to setup service: %v", err)
			}
			log.Println("Service installed and started successfully.")
			return
		}

		log.Println("Connecting...")
		useTray := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
		runner.RunServiceHook(func(ctx context.Context) {
			runAgent(ctx, configPath, false, false, tunName, useTray)
		})
	}
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
	installService := connectCmd.Bool("d", false, "Install and run as system service (daemon)")
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
			// Use default if not specified
			*configPath = "/etc/wantastic/config.conf"
			if _, err := os.Stat(*configPath); os.IsNotExist(err) {
				// Check for old default for backward compatibility or local fallback
				altPath := "wantastic.conf"
				if _, err := os.Stat(altPath); err == nil {
					*configPath = altPath
				} else {
					// If neither exists, and no flag provided, we can't proceed but let's try to load default anyway
					// and let LoadFromFile error out with a nice message if it fails
				}
			}
		}
	}

	if *installService {
		log.Println("Setting up system service...")
		if err := daemon.SetupService(*configPath); err != nil {
			log.Fatalf("Failed to setup service: %v", err)
		}
		log.Println("Service installed and started successfully.")
		return
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
