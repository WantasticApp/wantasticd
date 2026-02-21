package device

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
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
	config   *config.Config
	device   *wgdevice.Device
	tunDev   tun.Device
	netstack *virtstack.Net

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}

	tunName     string
	addedRoutes []string

	PortForwarder func(string, int) bool

	statsProvider func() []byte
}

func New(cfg *config.Config) (*Device, error) {
	return &Device{
		config: cfg,
		stopCh: make(chan struct{}),
	}, nil
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
	var netstackInst *virtstack.Net
	var err error

	addrs := make([]netip.Addr, len(d.config.Interface.Addresses))
	for i, prefix := range d.config.Interface.Addresses {
		addrs[i] = prefix.Addr()
	}

	// Force Userspace Netstack
	// We no longer attempt to creating a real system TUN device.
	// This ensures "busybox" behavior where the application is entirely self-contained.
	log.Printf("Initializing userspace netstack...")
	tunDev, netstackInst, err = virtstack.CreateNetTUN(addrs, nil, d.config.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create netstack tun: %w", err)
	}
	d.netstack = netstackInst
	d.tunName = "userspace-tun"
	d.tunDev = tunDev
	// Wrap TUN for JIT Port Forwarding
	tunDev = NewTunWrapper(tunDev, d.PortForwarder)

	// 4. Start WireGuard
	logger := wgdevice.NewLogger(wgdevice.LogLevelError, fmt.Sprintf("(%s) ", d.config.DeviceID))
	if os.Getenv("LOG_LEVEL") == "debug" || d.config.Verbose {
		logger = wgdevice.NewLogger(wgdevice.LogLevelVerbose, fmt.Sprintf("(%s) ", d.config.DeviceID))
	}

	wd := wgdevice.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	wd.DisableSomeRoamingForBrokenMobileSemantics()
	wd.SetStatsHandler(d.handleStats)
	wd.SetPunchHandler(d.handlePunch)
	if d.statsProvider != nil {
		wd.SetStatsProvider(d.statsProvider)
	}
	d.device = wd

	if err := d.applyConfig(); err != nil {
		return err
	}

	if err := wd.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}

	// Start P2P hole-punching subsystem after first handshake confirms connectivity
	go func() {
		// Wait for the first successful handshake before starting P2P
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			if d.HasActiveHandshake() {
				log.Printf("[P2P] Handshake detected, starting P2P client subsystem")
				wd.StartP2P()
				return
			}
		}
		// Start anyway after 30s even without handshake (will retry registration)
		log.Printf("[P2P] Starting P2P client subsystem (no handshake yet)")
		wd.StartP2P()
	}()

	// Configure SendStats for the server peer if enabled
	if d.config.Server.SendStats && d.config.Server.PublicKey != "" {
		if pubKey, err := base64ToHex(d.config.Server.PublicKey); err == nil {
			if pk, err := hex.DecodeString(pubKey); err == nil && len(pk) == 32 {
				var noiseKey [32]byte
				copy(noiseKey[:], pk)
				if peer := wd.LookupPeer(noiseKey); peer != nil {
					peer.SendStatsEnabled.Store(true)
					log.Printf("Enabled custom stats for peer %s", d.config.Server.PublicKey)
				} else {
					log.Printf("Warning: Peer %s not found to enable stats", d.config.Server.PublicKey)
				}
			} else {
				log.Printf("Error decoding hex public key: %v", err)
			}
		} else {
			log.Printf("Error converting base64 public key to hex: %v", err)
		}
	}

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

	// No system cleanup needed for userspace netstack

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
	return d.device.IpcSet(cfgStr)
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
	lines := strings.Split(res, "\n")
	for _, line := range lines {
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

func (d *Device) GetNetstack() *virtstack.Net { return d.netstack }

// GetWireGuardStatus returns a human-readable status of the userspace WireGuard device
// including peer endpoints (to prove P2P vs relay/VPN mode), handshake times, and transfer stats.
func (d *Device) GetWireGuardStatus() string {
	d.mu.RLock()
	wd := d.device
	cfg := d.config
	d.mu.RUnlock()

	if wd == nil {
		return "device not started\n"
	}

	res, err := wd.IpcGet()
	if err != nil {
		return fmt.Sprintf("error reading device status: %v\n", err)
	}

	var sb strings.Builder
	sb.WriteString("=== WireGuard Userspace Device Status ===\n")

	// Configured server endpoint for comparison
	serverEndpoint := ""
	if cfg != nil && cfg.Server.Endpoint != "" {
		serverEndpoint = cfg.Server.Endpoint
	}

	lines := strings.Split(res, "\n")
	var localPubKey, localListenPort string
	peerIdx := 0

	type peerInfo struct {
		pubKey        string
		endpoint      string
		allowedIPs    []string
		lastHandshake int64
		txBytes       uint64
		rxBytes       uint64
		keepalive     int
	}
	var peers []peerInfo
	var current *peerInfo

	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch key {
		case "public_key":
			if current != nil {
				peers = append(peers, *current)
			}
			// Decode hex to base64 for display
			hexBytes, _ := hex.DecodeString(val)
			b64 := base64.StdEncoding.EncodeToString(hexBytes)
			if peerIdx == 0 && localPubKey == "" {
				// First public_key could be device or peer depending on IPC format
			}
			current = &peerInfo{pubKey: b64}
			peerIdx++
		case "listen_port":
			localListenPort = val
		case "endpoint":
			if current != nil {
				current.endpoint = val
			}
		case "allowed_ip":
			if current != nil {
				current.allowedIPs = append(current.allowedIPs, val)
			}
		case "last_handshake_time_sec":
			if current != nil {
				current.lastHandshake, _ = strconv.ParseInt(val, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.txBytes, _ = strconv.ParseUint(val, 10, 64)
			}
		case "rx_bytes":
			if current != nil {
				current.rxBytes, _ = strconv.ParseUint(val, 10, 64)
			}
		case "persistent_keepalive_interval":
			if current != nil {
				current.keepalive, _ = strconv.Atoi(val)
			}
		}
	}
	if current != nil {
		peers = append(peers, *current)
	}

	// Device info
	if d.config != nil && len(d.config.Interface.Addresses) > 0 {
		addrs := make([]string, len(d.config.Interface.Addresses))
		for i, a := range d.config.Interface.Addresses {
			addrs[i] = a.String()
		}
		sb.WriteString(fmt.Sprintf("  Local Address: %s\n", strings.Join(addrs, ", ")))
	}
	if localPubKey != "" {
		sb.WriteString(fmt.Sprintf("  Public Key:    %s\n", localPubKey))
	}
	if localListenPort != "" {
		sb.WriteString(fmt.Sprintf("  Listen Port:   %s\n", localListenPort))
	}
	if serverEndpoint != "" {
		sb.WriteString(fmt.Sprintf("  Hub Endpoint:  %s (configured)\n", serverEndpoint))
	}
	sb.WriteString(fmt.Sprintf("  Peers:         %d\n", len(peers)))
	sb.WriteString("\n")

	for i, p := range peers {
		sb.WriteString(fmt.Sprintf("  Peer #%d\n", i+1))
		sb.WriteString(fmt.Sprintf("    Public Key:  %s\n", p.pubKey))

		if p.endpoint != "" {
			sb.WriteString(fmt.Sprintf("    Endpoint:    %s\n", p.endpoint))

			// Determine connection mode by checking:
			// 1. If this peer's public key matches the Hub's configured key → Relay
			// 2. If this peer's endpoint IP matches the Hub IP → Relay
			isHubPeer := false

			// Check public key match (most reliable)
			if cfg != nil && cfg.Server.PublicKey != "" && p.pubKey == cfg.Server.PublicKey {
				isHubPeer = true
			}

			// Check endpoint IP match (Server.Endpoint is just IP, no port)
			if !isHubPeer && serverEndpoint != "" {
				peerHost, _, _ := net.SplitHostPort(p.endpoint)
				if peerHost == serverEndpoint {
					isHubPeer = true
				}
			}

			if isHubPeer {
				sb.WriteString("    Mode:        🔄 VPN/Relay (via Hub)\n")
			} else {
				sb.WriteString("    Mode:        ⚡ P2P Direct (hole-punched)\n")
			}
		} else {
			sb.WriteString("    Endpoint:    (none - no connection)\n")
			sb.WriteString("    Mode:        ❌ Disconnected\n")
		}

		if p.lastHandshake > 0 {
			t := time.Unix(p.lastHandshake, 0)
			ago := time.Since(t).Round(time.Second)
			sb.WriteString(fmt.Sprintf("    Handshake:   %s ago (%s)\n", ago, t.Format("15:04:05")))
		} else {
			sb.WriteString("    Handshake:   never\n")
		}

		sb.WriteString(fmt.Sprintf("    Transfer:    ↓ %s received, ↑ %s sent\n",
			formatBytes(p.rxBytes), formatBytes(p.txBytes)))

		if len(p.allowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("    Allowed IPs: %s\n", strings.Join(p.allowedIPs, ", ")))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func base64ToHex(b64 string) (string, error) {
	db, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(db), nil
}
