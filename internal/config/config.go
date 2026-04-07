package config

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"wantastic-agent/internal/auth"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

// resolveEndpoint resolves a hostname to an IP address using the system's default DNS resolver.
// This respects /etc/hosts, mDNS (.local), and all system DNS configuration.
func resolveEndpoint(hostname string) (string, error) {
	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	// Use the system's default resolver
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("resolve hostname %s: %w", hostname, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname %s", hostname)
	}

	// Return the first IPv4 address if available, otherwise first IPv6
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			log.Printf("Resolved endpoint %s -> %s", hostname, ip.IP.String())
			return ip.IP.String(), nil
		}
	}

	// If no IPv4, return the first IPv6
	log.Printf("Resolved endpoint %s -> %s", hostname, ips[0].IP.String())
	return ips[0].IP.String(), nil
}

type ExitNode struct {
	Enabled    bool     `json:"enabled"`
	ExitRoutes []string `json:"exit_routes"`
	ExitDNS    []string `json:"exit_dns"`
	AllowLAN   bool     `json:"allow_lan"`
}

type Config struct {
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	Server     Server    `json:"server"`
	Interface  Interface `json:"interface"`
	Auth       Auth      `json:"auth"`
	ExitNode   ExitNode  `json:"exit_node"`
	Verbose    bool      `json:"verbose"`
	AutoUpdate bool      `json:"auto_update"`

	filePath   string // path this config was loaded from; not serialised
	HandoffURL string // confirmation URL returned by register; not serialised
}

type Server struct {
	Endpoint            string   `json:"endpoint"`
	Port                int      `json:"port"`
	PublicKey           string   `json:"public_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	SendStats           bool     `json:"send_stats"`
}

type Interface struct {
	Addresses  []netip.Prefix `json:"addresses"`
	ListenPort int            `json:"listen_port"`
	MTU        int            `json:"mtu"`
	DNS        []string       `json:"dns"`
	TUNMode    bool           `json:"tun_mode"` // Use system TUN device instead of userspace netstack
	TUNName    string         `json:"tun_name"` // Name of the TUN interface (e.g., "wantastic0")
}

// Auth holds the authentication credentials for the agent.
type Auth struct {
	// PortalURL is the HTTPS portal base used for re-registration
	// (e.g. "https://console.wantastic.app").
	PortalURL string `json:"portal_url,omitempty"`

	// ServerURL is the gRPC runtime server for GetConfiguration / RefreshAuth
	// (e.g. "auth.wantastic.app:443").  Populated from the portal register response.
	ServerURL string `json:"server_url,omitempty"`

	// Token is the long-lived session token for gRPC runtime calls.
	Token string `json:"token"`

	RefreshTime time.Duration `json:"refresh_time"`
}

// LoadFromFile loads the configuration from a file.
// It first attempts to parse the file as JSON.
// If that fails, it tries to parse it as a traditional WireGuard configuration file.
// Returns a pointer to the Config struct if successful, or an error if any step fails.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Try to parse as JSON first
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err == nil {
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		cfg.filePath = path
		return &cfg, nil
	}

	// If JSON parsing fails, try to parse as traditional WireGuard config
	cfg, err = parseTraditionalWireGuardConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	cfg.filePath = path
	return &cfg, nil
}

// parseTraditionalWireGuardConfig parses traditional WireGuard INI-style configuration
func parseTraditionalWireGuardConfig(configData string) (Config, error) {
	var cfg Config
	scanner := bufio.NewScanner(strings.NewReader(configData))

	currentSection := ""
	peerPublicKey := ""
	peerEndpoint := ""
	peerAllowedIPs := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "Interface":
			switch key {
			case "PrivateKey":
				cfg.PrivateKey = value
			case "Address":
				// Convert CIDR address to netip.Prefix
				if prefix, err := netip.ParsePrefix(value); err == nil {
					cfg.Interface.Addresses = []netip.Prefix{prefix}
				}
			case "ListenPort":
				if port, err := fmt.Sscanf(value, "%d", &cfg.Interface.ListenPort); err == nil && port == 1 {
					// Port parsed successfully
				}
			case "MTU":
				if mtu, err := fmt.Sscanf(value, "%d", &cfg.Interface.MTU); err == nil && mtu == 1 {
					// MTU parsed successfully
				}
			case "DNS":
				// Parse DNS servers from traditional WireGuard config
				dnsServers := strings.Split(value, ",")
				for i := range dnsServers {
					dnsServers[i] = strings.TrimSpace(dnsServers[i])
				}
				// Store DNS servers in Interface configuration for netstack to use
				cfg.Interface.DNS = dnsServers
				log.Printf("Configured DNS servers: %v", dnsServers)
			}

		case "Peer":
			switch key {
			case "PublicKey":
				peerPublicKey = value
			case "Endpoint":
				peerEndpoint = value
			case "AllowedIPs":
				peerAllowedIPs = strings.Split(value, ",")
				for i := range peerAllowedIPs {
					peerAllowedIPs[i] = strings.TrimSpace(peerAllowedIPs[i])
				}
			case "PersistentKeepalive":
				if keepalive, err := fmt.Sscanf(value, "%d", &cfg.Server.PersistentKeepalive); err == nil && keepalive == 1 {
					// Keepalive parsed successfully
				}
			}
		}
	}

	// Extract server information from peer section
	if peerPublicKey != "" {
		cfg.Server.PublicKey = peerPublicKey
	}

	if peerEndpoint != "" {
		// Parse endpoint (format: host:port)
		if parts := strings.Split(peerEndpoint, ":"); len(parts) == 2 {
			cfg.Server.Endpoint = parts[0]
			if port, err := fmt.Sscanf(parts[1], "%d", &cfg.Server.Port); err == nil && port == 1 {
				// Port parsed successfully
			}
		} else {
			cfg.Server.Endpoint = peerEndpoint
			cfg.Server.Port = 51820 // Default WireGuard port
		}
	}

	if len(peerAllowedIPs) > 0 {
		cfg.Server.AllowedIPs = peerAllowedIPs
	}

	// Generate device ID if not set
	if cfg.DeviceID == "" {
		cfg.GenerateDeviceID()
	}

	// Default to sending stats for traditional configs (users can opt-out if we add a flag later)
	cfg.Server.SendStats = true

	return cfg, nil
}

// LoadFromDeviceFlow runs the RFC 8628 HTTP device authorization flow:
//
//  1. Shows a QR code + user code and polls until the user approves.
//  2. Calls POST /api/agent/register with the access token.
//  3. Decrypts the returned WireGuard config (ChaCha20-Poly1305).
//
// portalURL is the HTTPS portal base (e.g. "https://console.wantastic.app").
func LoadFromDeviceFlow(ctx context.Context, portalURL string) (*Config, error) {
	accessToken, err := auth.RunDeviceFlow(ctx, portalURL, auth.DefaultOAuth2ClientID)
	if err != nil {
		return nil, fmt.Errorf("device flow: %w", err)
	}
	return registerAndDecryptConfig(ctx, portalURL, accessToken)
}

// LoadFromToken registers the device using a direct access token (skips OAuth2).
// portalURL is the HTTPS portal base (e.g. "https://console.wantastic.app").
func LoadFromToken(ctx context.Context, portalURL, token string) (*Config, error) {
	return registerAndDecryptConfig(ctx, portalURL, token)
}

// registerAndDecryptConfig calls POST /api/agent/register over HTTPS, decrypts
// the returned WireGuard config, and returns a ready-to-use Config.
//
// No gRPC is used in this path — the portal is the only network endpoint.
func registerAndDecryptConfig(ctx context.Context, portalURL, accessToken string) (*Config, error) {
	hashedID, err := auth.HashedDeviceID()
	if err != nil {
		return nil, fmt.Errorf("get device id: %w", err)
	}

	regResp, nonce, err := auth.RegisterDevice(ctx, portalURL, accessToken, hashedID)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	// Derive decryption key: SHA256(access_token)
	hash := sha256.Sum256([]byte(accessToken))
	// Nonce: little-endian uint64 zero-padded to 12 bytes
	nonceBytes := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonceBytes[:8], nonce)

	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	decrypted, err := aead.Open(nil, nonceBytes, regResp.EncryptedConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}

	cfgStruct, err := parseTraditionalWireGuardConfig(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("parse decrypted config: %w", err)
	}

	cfg := &cfgStruct
	cfg.Auth.PortalURL = portalURL
	cfg.Auth.Token = regResp.Token
	if regResp.ServerURL != "" {
		cfg.Auth.ServerURL = regResp.ServerURL
	}
	cfg.HandoffURL = regResp.HandoffURL
	cfg.GenerateDeviceID()
	return cfg, nil
}

// Validate validates the configuration.
// It checks if the private key, server endpoint, and server port are set.
// If the server endpoint is not an IP address, it attempts to resolve it.
// If any validation fails, it returns an error with a descriptive message.
func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private key required")
	}
	if c.Server.Endpoint == "" {
		return fmt.Errorf("server endpoint required")
	}

	// Resolve hostname to IP address if it's not already an IP
	if net.ParseIP(c.Server.Endpoint) == nil {
		resolvedIP, err := resolveEndpoint(c.Server.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint %s: %w", c.Server.Endpoint, err)
		}
		c.Server.Endpoint = resolvedIP
	}

	if c.Server.Port == 0 {
		c.Server.Port = 51820
	}
	if c.Interface.MTU == 0 {
		c.Interface.MTU = 1420
	}
	if c.Interface.ListenPort == 0 {
		// Standard client behavior: use random port to avoid conflicts
		c.Interface.ListenPort = 0
	}
	if c.Interface.TUNName == "" {
		c.Interface.TUNName = DefaultTunName()
	}
	if c.Auth.RefreshTime == 0 {
		c.Auth.RefreshTime = 24 * time.Hour
	}
	return nil
}

// DefaultTunName returns the default tun device name for the platform.
func DefaultTunName() string {
	switch runtime.GOOS {
	case "openbsd":
		return "tun"
	case "windows":
		return "Wantastic"
	case "darwin":
		// "utun" is recognized by wireguard-go/tun/tun_darwin.go
		// as a magic value that uses/creates any free number.
		return "utun"
	case "linux":
		return "wantastic0"
	default:
		return "wantastic0"
	}
}

func (c *Config) GenerateDeviceID() {
	if c.DeviceID != "" {
		return
	}

	// Generate a stable, anonymous device ID.
	id, err := machineid.ProtectedID("wantastic")
	if err != nil {
		// usage of machine-id is optional, don't scare the user
		log.Printf("System machine-id not available (%v); falling back to MAC address for device ID.", err)

		// Fallback: Try to find a stable MAC address (common for embedded devices)
		useMac := false
		if ifaces, err := net.Interfaces(); err == nil {
			// Sort interfaces by name for deterministic selection
			sort.Slice(ifaces, func(i, j int) bool {
				return ifaces[i].Name < ifaces[j].Name
			})

			for _, iface := range ifaces {
				// Skip loopback, down interfaces, or those with no MAC
				if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 || len(iface.HardwareAddr) == 0 {
					continue
				}

				// Use the first valid MAC address found (e.g. eth0, wlan0)
				id = iface.HardwareAddr.String()
				log.Printf("Using MAC address of interface '%s' (%s) as stable device ID source.", iface.Name, id)
				useMac = true
				break
			}
		}

		if !useMac {
			log.Printf("Warning: no stable hardware identifier (machine-id or MAC) found.")
			log.Printf("Falling back to a random device ID. This device may be re-registered if the configuration is lost.")
			c.DeviceID = uuid.New().String()
			return
		}
	}

	// Hash the ID to protect privacy (either machine-id or MAC).
	hash := sha256.Sum256([]byte(id))
	c.DeviceID = hex.EncodeToString(hash[:])
}

// SaveToFile saves the configuration to a file.
// It marshals the configuration to JSON with indentation and writes it to the specified path.
// The file is created with permissions 0600, which restricts access to the owner only.
// Returns an error if any step of the process fails.
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// CheckWritable returns an error if the config file cannot be written to.
// Used as a pre-flight check before performing irreversible operations.
func (c *Config) CheckWritable() error {
	if c.filePath == "" {
		return fmt.Errorf("config has no file path")
	}
	f, err := os.OpenFile(c.filePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("config file not writable: %w", err)
	}
	f.Close()
	return nil
}

// Clone returns a deep copy of the Config for use as a rollback backup.
// The filePath is preserved so the clone can be saved to the same location.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	backup := *c // value copy of all scalar fields

	if len(c.Server.AllowedIPs) > 0 {
		backup.Server.AllowedIPs = make([]string, len(c.Server.AllowedIPs))
		copy(backup.Server.AllowedIPs, c.Server.AllowedIPs)
	}
	if len(c.Interface.Addresses) > 0 {
		backup.Interface.Addresses = make([]netip.Prefix, len(c.Interface.Addresses))
		copy(backup.Interface.Addresses, c.Interface.Addresses)
	}
	if len(c.Interface.DNS) > 0 {
		backup.Interface.DNS = make([]string, len(c.Interface.DNS))
		copy(backup.Interface.DNS, c.Interface.DNS)
	}
	if len(c.ExitNode.ExitRoutes) > 0 {
		backup.ExitNode.ExitRoutes = make([]string, len(c.ExitNode.ExitRoutes))
		copy(backup.ExitNode.ExitRoutes, c.ExitNode.ExitRoutes)
	}
	if len(c.ExitNode.ExitDNS) > 0 {
		backup.ExitNode.ExitDNS = make([]string, len(c.ExitNode.ExitDNS))
		copy(backup.ExitNode.ExitDNS, c.ExitNode.ExitDNS)
	}
	return &backup
}

// Save atomically persists the config to the file it was loaded from.
// Returns an error if the config has no known file path (e.g. created from a
// gRPC response); callers should use SaveToFile(path) in that case.
func (c *Config) Save() error {
	if c.filePath == "" {
		return fmt.Errorf("config has no file path; use SaveToFile(path) instead")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := c.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	return os.Rename(tmp, c.filePath)
}
