package device

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/config"

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
	statsHook     func(*wgdevice.Peer, []byte)
	wuspHook      func(*wgdevice.Peer, []byte)
	punchHook     func(*wgdevice.Peer, []byte)

	peerHostnamesMu sync.RWMutex
	peerHostnames   map[string]string

	// TUN mode fields
	nativeTun    tun.Device // Native system TUN device (when TUNMode is enabled)
	originalTun  tun.Device // Original TUN device from wireguard-go
	systemRoutes []string   // System routes added for TUN mode

	// Exit node routes installed dynamically
	exitNodeRoutes  []string
	exitNodePeerKey [32]byte
	exitNodeActive  bool
	exitNodeShared  bool

	// Device netstack for P2P connection handling
	netstack *virtstack.Net
}

func New(cfg *config.Config) (*Device, error) {
	return &Device{
		config:        cfg,
		stopCh:        make(chan struct{}),
		peerHostnames: make(map[string]string),
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
	wd.SetWUSPHandler(d.handleWUSP)
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
	routes := d.systemRoutes
	exitRoutes := d.exitNodeRoutes
	sharedExitNode := d.exitNodeShared
	d.systemRoutes = nil
	d.exitNodeRoutes = nil
	d.exitNodePeerKey = [32]byte{}
	d.exitNodeActive = false
	d.mu.Unlock()

	// Remove all OS routes before closing the TUN interface so the
	// kernel doesn't leave stale entries pointing at a dead utun index.
	for _, route := range append(routes, exitRoutes...) {
		if err := d.removeRoute(route); err != nil {
			log.Printf("[TUN] Warning: failed to remove route %s on stop: %v", route, err)
		}
	}

	if sharedExitNode {
		if err := d.disableExitNodeSharing(); err != nil {
			log.Printf("[TUN] Warning: failed to disable exit node sharing on stop: %v", err)
		}
	}

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
	d.mu.Lock()
	d.statsHook = handler
	d.mu.Unlock()
}

func (d *Device) SetWUSPHandler(handler func(*wgdevice.Peer, []byte)) {
	d.mu.Lock()
	d.wuspHook = handler
	d.mu.Unlock()
}

func (d *Device) SetPunchHandler(handler func(*wgdevice.Peer, []byte)) {
	d.mu.Lock()
	d.punchHook = handler
	d.mu.Unlock()
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

// addRoute adds a system route dynamically
func (d *Device) addRoute(network string) error {
	return addRouteOS(d.tunName, network)
}

// removeRoute removes a system route dynamically
func (d *Device) removeRoute(network string) error {
	return removeRouteOS(d.tunName, network)
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

// SendWUSP sends an encrypted Message Type 8 payload to a specific peer.
func (d *Device) SendWUSP(peerPubKey string, data []byte) error {
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

	peer.SendWUSP(data)
	return nil
}

// SendWUSPToServer sends an encrypted Message Type 8 payload to the configured server peer.
func (d *Device) SendWUSPToServer(data []byte) error {
	if d.config.Server.PublicKey == "" {
		return fmt.Errorf("server public key not configured")
	}
	return d.SendWUSP(d.config.Server.PublicKey, data)
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
	AssignedIP    string `json:"assigned_ip"` // VPN IP (e.g. "172.16.0.12")
	Hostname      string `json:"hostname"`
	Endpoint      string `json:"endpoint"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	IsP2P         bool   `json:"is_p2p"`
	P2PState      string `json:"p2p_state"` // "discovered"|"trying"|"established"|"failed"|""
	LastHandshake int64  `json:"last_handshake"`
}

// GetDetailedPeers returns live peer topology: WireGuard IPC data merged with
// P2P-discovered peers so the systray always shows all network participants,
// even before a P2P punch succeeds (relay-only peers).
func (d *Device) GetDetailedPeers() []PeerInfo {
	d.mu.RLock()
	wd := d.device
	srvHex, _ := base64ToHex(d.config.Server.PublicKey)
	d.mu.RUnlock()

	if wd == nil {
		return nil
	}

	// --- Phase 1: read WireGuard IPC state (server + punched P2P peers) ---
	byPubKey := make(map[string]*PeerInfo)

	if ipcState, err := wd.IpcGet(); err == nil {
		var cur *PeerInfo
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
				if cur != nil {
					byPubKey[cur.PublicKey] = cur
				}
				cur = &PeerInfo{
					PublicKey: val,
					Hostname:  d.getPeerHostname(val),
				}
				if val != srvHex {
					cur.IsP2P = true
					cur.P2PState = "established"
				}
			case "endpoint":
				if cur != nil {
					cur.Endpoint = val
				}
			case "rx_bytes":
				if cur != nil {
					cur.RxBytes, _ = strconv.ParseUint(val, 10, 64)
				}
			case "tx_bytes":
				if cur != nil {
					cur.TxBytes, _ = strconv.ParseUint(val, 10, 64)
				}
			case "last_handshake_time_sec":
				if cur != nil {
					cur.LastHandshake, _ = strconv.ParseInt(val, 10, 64)
				}
			case "allowed_ip":
				// First /32 allowed_ip on a non-server peer is its VPN IP
				if cur != nil && cur.IsP2P && cur.AssignedIP == "" {
					if strings.HasSuffix(val, "/32") {
						cur.AssignedIP = strings.TrimSuffix(val, "/32")
					}
				}
			}
		}
		if cur != nil {
			byPubKey[cur.PublicKey] = cur
		}
	}

	// --- Phase 2: merge P2P-discovered peers (pre-punch and relay peers) ---
	p2pClient := wd.GetP2PClient()
	if p2pClient != nil {
		for _, dp := range p2pClient.GetDiscoveredPeers() {
			pubHex := fmt.Sprintf("%x", dp.PublicKey[:])
			if pubHex == srvHex {
				continue // skip the server
			}

			stateStr := p2pStateString(dp.State)
			assignedIP := ""
			if len(dp.AssignedIP) == 4 {
				assignedIP = dp.AssignedIP.String()
			}

			if info, ok := byPubKey[pubHex]; ok {
				// Already in WireGuard IPC — just enrich with P2P state and IP
				info.P2PState = stateStr
				if info.AssignedIP == "" {
					info.AssignedIP = assignedIP
				}
				if info.Hostname == "" {
					info.Hostname = d.getPeerHostname(pubHex)
				}
			} else {
				// Relay-only peer: not yet in WireGuard, add it
				byPubKey[pubHex] = &PeerInfo{
					PublicKey:  pubHex,
					AssignedIP: assignedIP,
					Hostname:   d.getPeerHostname(pubHex),
					IsP2P:      true,
					P2PState:   stateStr,
				}
			}
		}
	}

	// Collect and return — server first, then peers sorted by VPN IP
	infos := make([]PeerInfo, 0, len(byPubKey))
	for _, info := range byPubKey {
		infos = append(infos, *info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return peerInfoSortLess(infos[i], infos[j])
	})
	return infos
}

func (d *Device) getPeerHostname(publicKey string) string {
	if publicKey == "" {
		return ""
	}
	d.peerHostnamesMu.RLock()
	defer d.peerHostnamesMu.RUnlock()
	return d.peerHostnames[publicKey]
}

func (d *Device) setPeerHostname(publicKey, hostname string) {
	hostname = strings.TrimSpace(hostname)
	if publicKey == "" || hostname == "" {
		return
	}
	d.peerHostnamesMu.Lock()
	d.peerHostnames[publicKey] = hostname
	d.peerHostnamesMu.Unlock()
}

func peerInfoSortLess(a, b PeerInfo) bool {
	aAddr, aErr := netip.ParseAddr(a.AssignedIP)
	bAddr, bErr := netip.ParseAddr(b.AssignedIP)
	switch {
	case aErr == nil && bErr == nil:
		if cmp := aAddr.Compare(bAddr); cmp != 0 {
			return cmp < 0
		}
	case aErr == nil:
		return true
	case bErr == nil:
		return false
	}

	if a.Hostname != b.Hostname {
		if a.Hostname == "" {
			return false
		}
		if b.Hostname == "" {
			return true
		}
		return a.Hostname < b.Hostname
	}
	if a.AssignedIP != b.AssignedIP {
		if a.AssignedIP == "" {
			return false
		}
		if b.AssignedIP == "" {
			return true
		}
		return a.AssignedIP < b.AssignedIP
	}
	return a.PublicKey < b.PublicKey
}

func p2pStateString(s wgdevice.P2PState) string {
	switch s {
	case wgdevice.P2PStateDiscovered:
		return "discovered"
	case wgdevice.P2PStateTrying:
		return "trying"
	case wgdevice.P2PStateEstablished:
		return "established"
	case wgdevice.P2PStateFailed:
		return "failed"
	default:
		return ""
	}
}
