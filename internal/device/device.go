package device

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/config"
	pb "wantastic-agent/internal/grpc/proto"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"

	"wantastic-agent/internal/device/wireguard-go/conn"
	"wantastic-agent/internal/device/wireguard-go/tun"
	virtstack "wantastic-agent/internal/device/wireguard-go/tun/netstack"

	"golang.org/x/crypto/curve25519"
)

type Device struct {
	config *config.Config
	device *wgdevice.Device
	tunDev tun.Device

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}

	tunName     string
	addedRoutes []string

	PortForwarder func(string, int) bool

	statsProvider func() []byte

	// TUN mode fields
	nativeTun    tun.Device // Native system TUN device (when TUNMode is enabled)
	originalTun  tun.Device // Original TUN device from wireguard-go
	systemRoutes []string   // System routes added for TUN mode

	// Exit node routes installed dynamically
	exitNodeRoutes []string

	// Device netstack for P2P connection handling
	netstack *virtstack.Net

	// export support (set via SetGRPCClient before device receives P2P messages)
	grpcClient   exportGRPCClient // interface defined in export.go
	backupConfig *config.Config   // saved before a config switch; cleared on success/rollback
}

func New(cfg *config.Config) (*Device, error) {
	return &Device{
		config: cfg,
		stopCh: make(chan struct{}),
	}, nil
}

// IsRunning safely returns whether the WireGuard device tunnel is currently active
func (d *Device) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

func (d *Device) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = true
	d.mu.Unlock()

	var tunDev tun.Device
	var err error

	addrs := make([]netip.Addr, len(d.config.Interface.Addresses))
	for i, prefix := range d.config.Interface.Addresses {
		addrs[i] = prefix.Addr()
	}

	tunDev, err = d.startTUNMode(addrs)

	if err != nil {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return fmt.Errorf("create tun: %w", err)
	}

	d.tunDev = tunDev

	// 4. Start WireGuard
	logger := wgdevice.NewLogger(wgdevice.LogLevelError, fmt.Sprintf("(%s) ", d.config.DeviceID))
	if os.Getenv("LOG_LEVEL") == "debug" || d.config.Verbose {
		logger = wgdevice.NewLogger(wgdevice.LogLevelVerbose, fmt.Sprintf("(%s) ", d.config.DeviceID))
	}

	wd := wgdevice.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	wd.DisableSomeRoamingForBrokenMobileSemantics()
	wd.SetStatsHandler(d.handleStats)
	wd.SetPunchHandler(d.handlePunch)
	wd.SetTUNControlHandler(d.handleTUNControl)
	wd.SetAddPeerRouteHandler(d.addPeerRoute)
	if d.statsProvider != nil {
		wd.SetStatsProvider(d.statsProvider)
	}
	d.device = wd

	if err := d.applyConfig(); err != nil {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return err
	}

	if err := wd.Up(); err != nil {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return fmt.Errorf("device up: %w", err)
	}

	// Add static routes to the OS networking table for the server's AllowedIPs
	// This ensures responses to pings (and other traffic) correctly route back through the TUN
	for _, ip := range d.config.Server.AllowedIPs {
		if ip == "0.0.0.0/0" || ip == "::/0" {
			// Skip adding global routes here automatically to avoid infinite routing loops
			// with the endpoint. Exit nodes handles this explicitly with endpoint exclusions.
			continue
		}
		if err := d.addRoute(ip); err != nil {
			log.Printf("Warning: failed to add OS route for AllowedIP %s: %v", ip, err)
		} else {
			// Track it so it doesn't get infinitely added by P2P later
			d.mu.Lock()
			d.systemRoutes = append(d.systemRoutes, ip)
			d.mu.Unlock()
		}
	}

	// Start P2P hole-punching subsystem after first handshake confirms connectivity
	go func() {
		// Wait for the first successful handshake before starting P2P
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			if d.HasActiveHandshake() {
				logger.Verbosef("[P2P] Handshake detected, starting P2P client subsystem")
				wd.StartP2P()
				return
			}
		}
		// Start anyway after 30s even without handshake (will retry registration)
		logger.Verbosef("[P2P] Starting P2P client subsystem (no handshake yet)")
		wd.StartP2P()
	}()

	// Diagnostic: dump device state after Up() to verify configuration
	if ipcState, err := wd.IpcGet(); err == nil {
		log.Printf("WireGuard device up. Peer endpoint: %s:%d, Listen port: %d",
			d.config.Server.Endpoint, d.config.Server.Port, d.config.Interface.ListenPort)

		// Check if peer is actually configured
		if !strings.Contains(ipcState, "public_key=") {
			log.Printf("WARNING: No peers configured in WireGuard device!")
		}
		if d.config.Verbose {
			log.Printf("IPC state:\n%s", ipcState)
		}
	} else {
		log.Printf("Warning: failed to get IPC state for diagnostics: %v", err)
	}

	return nil
}

func (d *Device) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false

	wg := d.device
	td := d.tunDev
	d.mu.Unlock()

	d.cleanupTUNMode()

	if wg != nil {
		wg.Close()
	} else if td != nil {
		td.Close()
	}

	log.Printf("Stopped device")
	return nil
}

func (d *Device) Close() error { return d.Stop() }

func (d *Device) applyConfig() error {
	privHex, err := base64ToHex(d.config.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Resolve endpoint hostname to IP if needed.
	// WireGuard's ParseEndpoint uses netip.ParseAddrPort which only accepts literal ip:port.
	endpointHost := d.config.Server.Endpoint
	if endpointHost != "" {
		if _, err := netip.ParseAddr(endpointHost); err != nil {
			// Not a literal IP — resolve DNS
			ips, err := net.LookupHost(endpointHost)
			if err != nil {
				return fmt.Errorf("resolve endpoint %q: %w", endpointHost, err)
			}
			if len(ips) == 0 {
				return fmt.Errorf("no addresses found for endpoint %q", endpointHost)
			}
			log.Printf("Resolved endpoint %s -> %s", endpointHost, ips[0])
			endpointHost = ips[0]
		}
	}

	// Helper to generate the full configuration string for a given port
	genConfig := func(port int) (string, error) {
		var conf strings.Builder
		fmt.Fprintf(&conf, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", privHex, port)

		if d.config.Server.PublicKey != "" {
			pubHex, err := base64ToHex(d.config.Server.PublicKey)
			if err != nil {
				return "", fmt.Errorf("invalid public key: %w", err)
			}
			fmt.Fprintf(&conf, "public_key=%s\nendpoint=%s:%d\n", pubHex, endpointHost, d.config.Server.Port)
			if len(d.config.Server.AllowedIPs) > 0 {
				for _, ip := range d.config.Server.AllowedIPs {
					fmt.Fprintf(&conf, "allowed_ip=%s\n", ip)
				}
			} else {
				conf.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
			}
			conf.WriteString("persistent_keepalive_interval=20\n")
		}
		return conf.String(), nil
	}

	// Check if the configured port is available before passing it to WireGuard.
	// This avoids noisy ERROR logs from the WireGuard library when the port is in use.
	port := d.config.Interface.ListenPort
	if port != 0 {
		probe, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("Port %d in use, using random port", port)
			port = 0
			d.config.Interface.ListenPort = 0
		} else {
			probe.Close()
		}
	}

	// Apply the full configuration with the available port
	cfgStr, err := genConfig(port)
	if err != nil {
		return err
	}

	if err := d.device.IpcSet(cfgStr); err != nil {
		return err
	}

	// Restore custom stats enabling for the server peer if configured
	if d.config.Server.SendStats && d.config.Server.PublicKey != "" {
		if pubKey, err := base64ToHex(d.config.Server.PublicKey); err == nil {
			if pk, err := hex.DecodeString(pubKey); err == nil && len(pk) == 32 {
				var noiseKey [32]byte
				copy(noiseKey[:], pk)
				if peer := d.device.LookupPeer(noiseKey); peer != nil {
					peer.SendStatsEnabled.Store(true)
				}
			}
		}
	}

	return nil
}

func (d *Device) UpdateConfig(cfg *pb.DeviceConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(cfg.Addresses) > 0 {
		d.config.Interface.Addresses = nil
		for _, a := range cfg.Addresses {
			p, _ := netip.ParsePrefix(a)
			d.config.Interface.Addresses = append(d.config.Interface.Addresses, p)
		}
	}
	if cfg.ListenPort > 0 {
		d.config.Interface.ListenPort = int(cfg.ListenPort)
	}
	return d.applyConfig()
}

func (d *Device) UpdateServerConfig(cfg *pb.ServerConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config.Server.Endpoint = cfg.Endpoint
	d.config.Server.Port = int(cfg.Port)
	if cfg.PublicKey != "" {
		d.config.Server.PublicKey = cfg.PublicKey
	}
	return d.applyConfig()
}

// UpdateExitNodeConfig updates the device's exit node configuration
func (d *Device) UpdateExitNodeConfig(cfg *pb.ExitNodeConfiguration) error {
	d.mu.Lock()
	d.config.ExitNode.Enabled = cfg.Enabled
	d.config.ExitNode.ExitRoutes = cfg.ExitRoutes
	d.config.ExitNode.ExitDNS = cfg.ExitDns
	d.config.ExitNode.AllowLAN = cfg.AllowLan
	d.mu.Unlock()

	// If the server connection exists, send the exit node config to the peers
	// Note: We use SendTUNControl for Message Type 7 coordination.
	//
	// The specification for Message Type 7 payload could just be a JSON struct,
	// or another binary format, depending on what the Coordinator expects.
	// For now we will serialize it to JSON.

	bytesPayload, err := json.Marshal(d.config.ExitNode)
	if err != nil {
		return fmt.Errorf("failed to marshal exit node config for TUN control: %w", err)
	}

	if d.config.Server.PublicKey != "" {
		err := d.SendTUNControl(d.config.Server.PublicKey, bytesPayload)
		if err != nil {
			log.Printf("Debug: SendTUNControl for ExitNode failed (might not be online yet): %v", err)
			return nil // Don't fail the whole update just because we couldn't dispatch yet
		}
	}

	return nil
}

func (d *Device) HealthCheck() error {
	if d.device == nil {
		return fmt.Errorf("off")
	}
	return nil
}

func (d *Device) GetPublicKey() string {
	b, _ := base64.StdEncoding.DecodeString(d.config.PrivateKey)
	var priv [32]byte
	copy(priv[:], b)
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(pub[:])
}

func (d *Device) SetStatsHandler(handler func(*wgdevice.Peer, []byte)) {
	d.device.SetStatsHandler(handler)
}

func (d *Device) SetPunchHandler(handler func(*wgdevice.Peer, []byte)) {
	d.device.SetPunchHandler(handler)
}

func (d *Device) SetStatsProvider(provider func() []byte) {
	d.statsProvider = provider
	// If device is already running, apply immediately
	d.mu.RLock()
	if d.device != nil {
		d.device.SetStatsProvider(provider)
	}
	d.mu.RUnlock()
}

func (d *Device) handleTUNControl(peer *wgdevice.Peer, data []byte) {
	// Handle P2P TUN control messages (message type 7)
	// Base format: [Action:1 byte][...]
	// Actions 0,1,2,5 use [Action:1][TargetPubKey:32].
	// Action 8 (ExportDevice) uses a variable-length payload.
	// Action 10 (ExportComplete) carries no payload.
	if len(data) < 1 {
		return
	}

	action := data[0]

	// Export actions use different payload formats — dispatch before the
	// fixed-size peer-key check that guards the other actions.
	switch action {
	case SubtypeExportDevice:
		go d.handleExportDevice(data[1:])
		return
	case SubtypeExportComplete:
		log.Printf("[Export] Export acknowledged by server")
		return
	}

	// All remaining actions require at least [action:1][pubkey:32].
	if len(data) < 33 {
		return
	}
	var targetPubKey [32]byte
	copy(targetPubKey[:], data[1:33])

	targetPeer := d.device.LookupPeer(targetPubKey)
	if targetPeer == nil {
		log.Printf("[TUN] TUN control: target peer not found")
		return
	}

	// Action 1: Server tells us we can now use this peer as an exit node
	if action == 1 {
		log.Printf("[TUN] Server designated peer %x as exit node", targetPubKey[:4])

		// Map the default route to this specific WireGuard peer natively
		peerHex := hex.EncodeToString(targetPubKey[:])
		cfg := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=false\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", peerHex)
		d.device.IpcSet(cfg)

		// Add os-level default route to route all traffic into the TUN interface
		d.mu.Lock()
		if err := d.addExitNodeRoute("0.0.0.0/0"); err != nil {
			log.Printf("[TUN] Failed adding IPv4 exit route: %v", err)
		}
		if err := d.addExitNodeRoute("::/0"); err != nil {
			log.Printf("[TUN] Failed adding IPv6 exit route: %v", err)
		}
		d.mu.Unlock()
	} else if action == 0 {
		log.Printf("[TUN] Server revoked exit node routing")

		// Re-assign 0.0.0.0/0 back to the server if needed, or simply remove OS routes (WG ignores it if OS route is gone)
		if srvPubKey, err := base64ToHex(d.config.Server.PublicKey); err == nil {
			cfg := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=false\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", srvPubKey)
			d.device.IpcSet(cfg)
		}

		d.mu.Lock()
		d.removeExitNodeRoutes()
		d.mu.Unlock()
	} else if action == 2 {
		// Action 2: Server asks us to become an exit node for others
		d.mu.RLock()
		enabled := d.config.ExitNode.Enabled
		d.mu.RUnlock()

		if enabled {
			log.Printf("[TUN] Server requested this device to become an exit node")
			d.enableOnDemandNAT()
		} else {
			log.Printf("[TUN] Server requested exit node, but local exit node sharing is disabled")
		}
	} else if action == 5 {
		// Action 5: Server revokes our duties to be an exit node
		log.Printf("[TUN] Server revoked our duties to be an exit node")
		d.disableOnDemandNAT()
	}
}

func (d *Device) enableOnDemandNAT() {
	switch runtime.GOOS {
	case "linux":
		os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
		os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0644)
		exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE").Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding & NAT enabled via procfs/iptables on Linux")
	case "darwin":
		exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
		exec.Command("sysctl", "-w", "net.inet6.ip6.forwarding=1").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding enabled via sysctl on macOS")
	case "windows":
		exec.Command("powershell", "-Command", "Set-NetIPInterface -Forwarding Enabled").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding enabled via PowerShell on Windows")
	default:
		log.Printf("[TUN] On-demand Exit Node IP forwarding not implemented for %s", runtime.GOOS)
	}
}

func (d *Device) disableOnDemandNAT() {
	switch runtime.GOOS {
	case "linux":
		os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644)
		os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("0\n"), 0644)
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE").Run()
		exec.Command("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding & NAT disabled via procfs/iptables on Linux")
	case "darwin":
		exec.Command("sysctl", "-w", "net.inet.ip.forwarding=0").Run()
		exec.Command("sysctl", "-w", "net.inet6.ip6.forwarding=0").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding disabled via sysctl on macOS")
	case "windows":
		exec.Command("powershell", "-Command", "Set-NetIPInterface -Forwarding Disabled").Run()
		log.Printf("[TUN] On-demand Exit Node IP forwarding disabled via PowerShell on Windows")
	}
}

// addRoute adds a system route dynamically
func (d *Device) addRoute(network string) error {
	return addRouteOS(d.tunName, network)
}

// removeRoute removes a system route dynamically
func (d *Device) removeRoute(network string) error {
	return removeRouteOS(d.tunName, network)
}

// addExitNodeRoute adds a route dynamically during runtime for exit node behavior
func (d *Device) addExitNodeRoute(network string) error {
	if err := d.addRoute(network); err != nil {
		return err
	}
	// Track it so we can remove it later
	found := false
	for _, r := range d.exitNodeRoutes {
		if r == network {
			found = true
			break
		}
	}
	if !found {
		d.exitNodeRoutes = append(d.exitNodeRoutes, network)
	}
	log.Printf("[TUN] Added exit node route: %s", network)
	return nil
}

// removeExitNodeRoutes removes dynamically added exit node routes
func (d *Device) removeExitNodeRoutes() {
	for _, route := range d.exitNodeRoutes {
		d.removeRoute(route)
		log.Printf("[TUN] Removed exit node route: %s", route)
	}
	d.exitNodeRoutes = nil
}

// addPeerRoute adds a route for a dynamically discovered P2P peer
func (d *Device) addPeerRoute(ip net.IP) {
	route := fmt.Sprintf("%s/32", ip.String())
	d.mu.Lock()
	defer d.mu.Unlock()

	// Dedup check to prevent infinite OS route addition loops
	for _, existing := range d.systemRoutes {
		if existing == route {
			return
		}
	}

	if err := d.addRoute(route); err != nil {
		log.Printf("[TUN] Failed adding P2P peer route %s: %v", route, err)
	} else {
		log.Printf("[TUN] Added P2P peer route: %s", route)
		// We add it to system routes so it gets cleaned up properly
		d.systemRoutes = append(d.systemRoutes, route)
	}
}

// SendTUNControl sends a Message Type 7 control payload to a specific peer
func (d *Device) SendTUNControl(peerPubKey string, data []byte) error {
	pk, err := base64ToHex(peerPubKey)
	if err != nil {
		return fmt.Errorf("invalid pubkey encoding: %w", err)
	}

	pkBytes, err := hex.DecodeString(pk)
	if err != nil || len(pkBytes) != 32 {
		return fmt.Errorf("invalid pubkey format/length: %w", err)
	}

	var noiseKey [32]byte
	copy(noiseKey[:], pkBytes)

	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()

	if wd == nil {
		return fmt.Errorf("device not started")
	}

	peer := wd.LookupPeer(noiseKey)
	if peer == nil {
		return fmt.Errorf("peer not found: %s", peerPubKey)
	}

	peer.SendTUNControl(data)
	return nil
}

// SendStatsToServer pushes a stats message (Message Type 5) to the server peer.
// Safe to call from any goroutine; no-ops if the device is not started or the
// server peer is not found / not stats-enabled.
func (d *Device) SendStatsToServer() {
	if !d.config.Server.SendStats || d.config.Server.PublicKey == "" {
		return
	}

	pubHex, err := base64ToHex(d.config.Server.PublicKey)
	if err != nil {
		return
	}
	pkBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pkBytes) != 32 {
		return
	}

	var noiseKey [32]byte
	copy(noiseKey[:], pkBytes)

	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return
	}

	peer := wd.LookupPeer(noiseKey)
	if peer == nil {
		return
	}

	go peer.SendStats()
}

func (d *Device) GetStats() (map[string]any, error) {
	return map[string]any{
		"id":        d.config.DeviceID,
		"connected": d.HasActiveHandshake(),
	}, nil
}

func (d *Device) HasActiveHandshake() bool {
	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return false
	}

	res, err := wd.IpcGet()
	if err != nil {
		return false
	}
	lines := strings.Split(res, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ts, _ := strconv.ParseInt(parts[1], 10, 64)
				if ts > 0 && time.Since(time.Unix(ts, 0)) < 3*time.Minute {
					return true
				}
			}
		}
	}
	return false
}

func (d *Device) GetTransferStats() (uint64, uint64, error) {
	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return 0, 0, fmt.Errorf("device not started")
	}

	res, err := wd.IpcGet()
	if err != nil {
		return 0, 0, err
	}

	var rx, tx uint64
	lines := strings.SplitSeq(res, "\n")
	for line := range lines {
		if strings.HasPrefix(line, "rx_bytes=") {
			parts := strings.Split(line, "=")
			if n, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				rx += n
			}
		}
		if strings.HasPrefix(line, "tx_bytes=") {
			parts := strings.Split(line, "=")
			if n, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				tx += n
			}
		}
	}
	return rx, tx, nil
}

// startTUNMode creates a native system TUN device for exit node functionality
// This allows the system to route all traffic through the WireGuard tunnel
func (d *Device) startTUNMode(addrs []netip.Addr) (tun.Device, error) {
	log.Printf("Initializing system TUN mode for exit node functionality...")

	tunName := d.config.Interface.TUNName
	if tunName == "" {
		tunName = "wantastic0"
	}

	// Create native TUN device
	nativeTun, err := tun.CreateTUN(tunName, d.config.Interface.MTU)
	if err != nil {
		return nil, fmt.Errorf("create native TUN device: %w", err)
	}

	d.nativeTun = nativeTun
	actualName, _ := nativeTun.Name()
	d.tunName = actualName
	log.Printf("Created TUN interface: %s", actualName)

	if err := setupTUNInterface(actualName, d.config.Interface.Addresses); err != nil {
		log.Printf("Warning: failed to setup TUN interface networking: %v", err)
	}

	// Create a parallel Userspace Netstack bound to the native TUN IP
	// This ensures P2P hole-punching and internal WireGuard routing is accelerated in Go userspace
	ns, err := d.createMinimalNetstack(addrs)
	if err != nil {
		log.Printf("Warning: hybrid virtstack creation failed: %v", err)
	} else {
		d.netstack = ns
		log.Printf("Initialized secondary userspace virtstack for P2P acceleration")
	}

	log.Printf("TUN mode initialized successfully on %s", actualName)
	return nativeTun, nil
}

// cleanupTUNMode cleans up system routes and TUN interface
func (d *Device) cleanupTUNMode() {
	log.Printf("Cleaning up TUN mode...")

	// Close native TUN device
	if d.nativeTun != nil {
		d.nativeTun.Close()
		d.nativeTun = nil
	}

	log.Printf("TUN mode cleanup complete")
}

// createMinimalNetstack creates a minimal netstack for DNS resolution in TUN mode
// This is needed because some code paths expect a netstack for DNS lookups
func (d *Device) createMinimalNetstack(addrs []netip.Addr) (*virtstack.Net, error) {
	// We create a minimal netstack that can forward DNS queries, using virtstack
	// We bind it strictly to the TUN interface's IP payload for any DNS requests
	// made by the CLI. CreateNetTUN returns the TUN interface and the Netstack.
	// Since we already created a TUN interface organically in startTUNMode, building another
	// overlapping structure will result in 2 interfaces, but we discard the extra one for now:
	_, ns, err := virtstack.CreateNetTUN(addrs, nil, d.config.Interface.MTU)
	if err != nil {
		return nil, fmt.Errorf("could not create virtstack: %v", err)
	}
	return ns, nil
}

// GetTUNName returns the name of the TUN interface (if in TUN mode)
func (d *Device) GetTUNName() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tunName
}

func base64ToHex(b64 string) (string, error) {
	db, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(db), nil
}

type PeerInfo struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	IsP2P         bool   `json:"is_p2p"`
	LastHandshake int64  `json:"last_handshake"`
}

// GetDetailedPeers queries the native WireGuard UAPI to gather live topology metadata
func (d *Device) GetDetailedPeers() []PeerInfo {
	d.mu.RLock()
	wd := d.device
	srvHex, _ := base64ToHex(d.config.Server.PublicKey)
	d.mu.RUnlock()

	if wd == nil {
		return nil
	}

	ipcState, err := wd.IpcGet()
	if err != nil {
		return nil
	}

	var infos []PeerInfo
	var current PeerInfo

	scanner := bufio.NewScanner(strings.NewReader(ipcState))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, val := parts[0], parts[1]
		switch key {
		case "public_key":
			if current.PublicKey != "" {
				// Finalize previous peer
				if current.PublicKey != srvHex {
					current.IsP2P = true
				}
				infos = append(infos, current)
			}
			current = PeerInfo{PublicKey: val}
		case "endpoint":
			current.Endpoint = val
		case "rx_bytes":
			current.RxBytes, _ = strconv.ParseUint(val, 10, 64)
		case "tx_bytes":
			current.TxBytes, _ = strconv.ParseUint(val, 10, 64)
		case "last_handshake_time_sec":
			current.LastHandshake, _ = strconv.ParseInt(val, 10, 64)
		}
	}
	if current.PublicKey != "" {
		if current.PublicKey != srvHex {
			current.IsP2P = true
		}
		infos = append(infos, current)
	}

	return infos
}
