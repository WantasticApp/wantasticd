package device

// export.go — handles P2P device export messages (subtypes 8, 9, 10).
//
// Message flow:
//
//	Server                           Device
//	  |-- TUN ctrl action=8 -------->|  ExportDevice  (variable payload)
//	  |                              |  validate token
//	  |                              |  generate new keypair
//	  |                              |  register with target server
//	  |                              |  switch WireGuard config
//	  |<-- TUN ctrl action=9 --------|  ExportConfirm (status + pubkey + message)
//	  |-- TUN ctrl action=10 ------->|  ExportComplete (acknowledgement)

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	wantasticgrpc "wantastic-agent/internal/grpc"
)

// P2P export action bytes (carried in the first byte of TUN control message data).
const (
	SubtypeExportDevice   = uint8(8)  // Server → Client: export request
	SubtypeExportConfirm  = uint8(9)  // Client → Server: export confirmation
	SubtypeExportComplete = uint8(10) // Server → Client: export acknowledged
)

// exportConfirmSleep controls the backoff between sendExportConfirm retries.
// Overridden to 0 in tests to avoid slow sleeps.
var exportConfirmSleep = time.Second

// maxExportPayloadSize is the maximum number of bytes accepted in a subtype-8
// TUN control message body. Payloads larger than this are rejected to prevent
// memory exhaustion from a malicious server.
const maxExportPayloadSize = 1024

// maxExportFieldLen is the maximum length of a single TLV field in the payload.
// Fields longer than this are rejected.
const maxExportFieldLen = 255

// exportInProgress guards against concurrent export attempts.
// 0 = idle, 1 = in-progress.
var exportInProgress atomic.Int32

// exportGRPCClient is the subset of *wantasticgrpc.Client needed for export.
// Defined as an interface so the device package does not take a hard compile-time
// dependency on a concrete gRPC client in its struct definition.
type exportGRPCClient interface {
	ValidateExportToken(ctx context.Context, token string) (bool, error)
	RegisterPeer(ctx context.Context, accountID, pubKeyHex string) (*wantasticgrpc.ExportPeerInfo, error)
}

// SetGRPCClient provides export capabilities to the device.
// Must be called by the Agent after the gRPC client is created, before the
// device can receive export requests.
func (d *Device) SetGRPCClient(client exportGRPCClient) {
	d.grpcClient = client
}

// ── Payload types ─────────────────────────────────────────────────────────

// ExportDevicePayload is the decoded body of a subtype-8 message.
//
//	[account_len:1][account]
//	[network_len:1][network]
//	[endpoint_len:1][endpoint]
//	[token_len:1][token]
type ExportDevicePayload struct {
	TargetAccountID string
	TargetNetwork   string
	ServerEndpoint  string
	ExportToken     string
}

func decodeExportDevicePayload(data []byte) (*ExportDevicePayload, error) {
	if len(data) > maxExportPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", len(data), maxExportPayloadSize)
	}

	p := &ExportDevicePayload{}
	offset := 0

	readField := func(name string) (string, error) {
		if offset >= len(data) {
			return "", fmt.Errorf("payload truncated before %s field", name)
		}
		l := int(data[offset])
		offset++
		if l > maxExportFieldLen {
			return "", fmt.Errorf("%s field too long: %d bytes (max %d)", name, l, maxExportFieldLen)
		}
		if offset+l > len(data) {
			return "", fmt.Errorf("invalid %s length %d", name, l)
		}
		s := string(data[offset : offset+l])
		offset += l
		return s, nil
	}

	var err error
	if p.TargetAccountID, err = readField("account_id"); err != nil {
		return nil, err
	}
	if p.TargetNetwork, err = readField("network"); err != nil {
		return nil, err
	}
	if p.ServerEndpoint, err = readField("endpoint"); err != nil {
		return nil, err
	}
	if p.ExportToken, err = readField("token"); err != nil {
		return nil, err
	}
	return p, nil
}

// exportConfirmPayload is the body of a subtype-9 confirmation message.
//
//	[status:1]
//	[new_pubkey:32]  (zero-filled on failure)
//	[token_len:1][token]
//	[msg_len:1][message]
type exportConfirmPayload struct {
	Status      uint8
	NewPubKey   [32]byte
	ExportToken string
	Message     string
}

func (p *exportConfirmPayload) encode() []byte {
	token := p.ExportToken
	if len(token) > maxExportFieldLen {
		token = token[:maxExportFieldLen]
	}
	msg := p.Message
	if len(msg) > maxExportFieldLen {
		msg = msg[:maxExportFieldLen]
	}
	buf := make([]byte, 1+32+1+len(token)+1+len(msg))
	offset := 0
	buf[offset] = p.Status
	offset++
	copy(buf[offset:], p.NewPubKey[:])
	offset += 32
	buf[offset] = byte(len(token))
	offset++
	copy(buf[offset:], token)
	offset += len(token)
	buf[offset] = byte(len(msg))
	offset++
	copy(buf[offset:], msg)
	return buf
}

// ── Handler ───────────────────────────────────────────────────────────────

// handleExportDevice processes a subtype-8 export request received from the server.
// Called as a goroutine from handleTUNControl; always sends a subtype-9
// confirmation back (unless the payload itself cannot be decoded).
func (d *Device) handleExportDevice(data []byte) {
	// Reject concurrent export attempts — only one migration at a time.
	if !exportInProgress.CompareAndSwap(0, 1) {
		log.Printf("[Export] Ignoring export request: another export is already in progress")
		return
	}
	defer exportInProgress.Store(0)

	payload, err := decodeExportDevicePayload(data)
	if err != nil {
		// No token available — server will time out and may retry.
		log.Printf("[Export] Cannot decode payload: %v", err)
		return
	}

	log.Printf("[Export] Received export request: account=%s server=%s",
		payload.TargetAccountID, payload.ServerEndpoint)

	// Step 1: Validate the export token with the current server.
	if d.grpcClient == nil {
		msg := "no gRPC client available; cannot validate export token"
		log.Printf("[Export] %s", msg)
		d.sendExportConfirm(1, [32]byte{}, payload.ExportToken, msg)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	valid, err := d.grpcClient.ValidateExportToken(ctx, payload.ExportToken)
	cancel()
	if err != nil || !valid {
		msg := "token validation failed"
		if err != nil {
			msg = "token validation error: " + err.Error()
		}
		log.Printf("[Export] %s", msg)
		d.sendExportConfirm(1, [32]byte{}, payload.ExportToken, msg)
		return
	}

	// Steps 2-5: generate keys, register, switch config.
	newPubKey, err := d.performExport(payload)
	if err != nil {
		log.Printf("[Export] Export failed: %v", err)
		d.sendExportConfirm(1, [32]byte{}, payload.ExportToken, err.Error())
		return
	}

	d.sendExportConfirm(0, newPubKey, payload.ExportToken, "export completed successfully")
	log.Printf("[Export] Export completed successfully")
}

// performExport generates a new keypair, registers with the target server,
// and atomically switches the WireGuard configuration.
// Returns the new public key on success. Any failure triggers a full rollback
// so the device remains connected to the original server.
func (d *Device) performExport(payload *ExportDevicePayload) ([32]byte, error) {
	// 0. Check that we can write the config file before making any changes.
	//    This prevents a situation where the WG config is switched but the
	//    on-disk config cannot be updated, which would cause a desync on restart.
	d.mu.RLock()
	cfg := d.config
	d.mu.RUnlock()
	if err := cfg.CheckWritable(); err != nil {
		return [32]byte{}, fmt.Errorf("config file not writable, refusing export: %w", err)
	}

	// 1. Generate a new Curve25519 private key (clamped per RFC 7748).
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return [32]byte{}, fmt.Errorf("keygen failed: %w", err)
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey) //nolint:staticcheck
	pubKeyHex := hex.EncodeToString(pubKey[:])

	// 2. Back up the current config before making any changes.
	d.mu.Lock()
	d.backupConfig = d.config.Clone()
	d.mu.Unlock()

	// All steps below must succeed together; any error rolls back to backup.

	// 3. Register with the target server using the new public key.
	peerInfo, err := d.registerWithTargetServer(payload, pubKeyHex)
	if err != nil {
		d.mu.Lock()
		d.backupConfig = nil
		d.mu.Unlock()
		return [32]byte{}, fmt.Errorf("registration failed: %w", err)
	}

	// 4. Switch the WireGuard config to the new server/keypair.
	privKeyHex := hex.EncodeToString(privKey[:])
	if err := d.switchWireGuardConfig(privKeyHex, peerInfo); err != nil {
		if rbErr := d.rollbackConfig(); rbErr != nil {
			return [32]byte{}, fmt.Errorf("config switch failed: %w; rollback also failed: %v", err, rbErr)
		}
		return [32]byte{}, fmt.Errorf("config switch failed (rollback ok): %w", err)
	}

	// 5. Finalise in-memory config: public key and account ID not set by switchWireGuardConfig.
	d.mu.Lock()
	d.config.PublicKey = base64.StdEncoding.EncodeToString(pubKey[:])
	d.config.DeviceID = payload.TargetAccountID
	newCfg := d.config
	d.backupConfig = nil
	d.mu.Unlock()

	// 6. Persist the updated config. On failure, roll back the WG device too
	//    so the on-disk and in-memory state stay consistent.
	if err := newCfg.Save(); err != nil {
		log.Printf("[Export] Config save failed, rolling back WireGuard device: %v", err)
		if rbErr := d.rollbackConfig(); rbErr != nil {
			return [32]byte{}, fmt.Errorf("config save failed: %w; rollback also failed: %v", err, rbErr)
		}
		return [32]byte{}, fmt.Errorf("config save failed (rollback ok): %w", err)
	}

	return pubKey, nil
}

// switchWireGuardConfig updates the in-memory config to point at the new server,
// re-applies the full WireGuard configuration (private key, peer, routes, stats),
// removes old OS routes, adds new ones, and waits for the first handshake.
func (d *Device) switchWireGuardConfig(privKeyHex string, info *wantasticgrpc.ExportPeerInfo) error {
	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return fmt.Errorf("device not started")
	}

	// Update in-memory config fields for the new server.
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("decode priv key hex: %w", err)
	}
	d.mu.Lock()
	d.config.PrivateKey = base64.StdEncoding.EncodeToString(privBytes)
	d.config.Server.Endpoint = info.ServerIP
	d.config.Server.Port = info.ServerPort
	d.config.Server.PublicKey = base64.StdEncoding.EncodeToString([]byte(info.ServerPubKey))
	// If server pub key is hex, store as-is; applyConfig converts base64→hex internally.
	// Detect hex vs base64 and normalise to base64 for consistent storage.
	if b, err2 := hex.DecodeString(info.ServerPubKey); err2 == nil && len(b) == 32 {
		d.config.Server.PublicKey = base64.StdEncoding.EncodeToString(b)
	} else {
		d.config.Server.PublicKey = info.ServerPubKey
	}
	d.config.Server.AllowedIPs = []string{info.AssignedIP}
	d.mu.Unlock()

	// Remove old OS routes, then apply the full WireGuard config via applyConfig
	// (handles private key, peer, listen port, stats enabling).
	d.mu.Lock()
	for _, r := range d.systemRoutes {
		if removeErr := d.removeRoute(r); removeErr != nil {
			log.Printf("[Export] Warning: failed to remove old OS route %s: %v", r, removeErr)
		}
	}
	d.systemRoutes = d.systemRoutes[:0]
	err = d.applyConfig()
	d.mu.Unlock()
	if err != nil {
		return fmt.Errorf("apply config: %w", err)
	}

	// Add OS routes for the new server's AllowedIPs (skip default routes).
	d.mu.RLock()
	newAllowedIPs := d.config.Server.AllowedIPs
	d.mu.RUnlock()
	for _, ip := range newAllowedIPs {
		if ip == "0.0.0.0/0" || ip == "::/0" {
			continue
		}
		if err := d.addRoute(ip); err != nil {
			log.Printf("[Export] Warning: failed to add OS route for %s: %v", ip, err)
		} else {
			d.mu.Lock()
			d.systemRoutes = append(d.systemRoutes, ip)
			d.mu.Unlock()
		}
	}

	// Wait for handshake with the new server.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return d.waitForHandshake(ctx)
}

// waitForHandshake polls HasActiveHandshake until it returns true or ctx expires.
func (d *Device) waitForHandshake(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for handshake with new server")
		default:
		}
		if d.HasActiveHandshake() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// rollbackConfig restores the WireGuard device to the backed-up configuration.
func (d *Device) rollbackConfig() error {
	d.mu.RLock()
	backup := d.backupConfig
	d.mu.RUnlock()
	if backup == nil {
		return fmt.Errorf("no backup config available")
	}

	log.Printf("[Export] Rolling back to previous config")

	privHex, err := base64ToHex(backup.PrivateKey)
	if err != nil {
		return fmt.Errorf("rollback: invalid private key: %w", err)
	}
	srvHex, err := base64ToHex(backup.Server.PublicKey)
	if err != nil {
		return fmt.Errorf("rollback: invalid server key: %w", err)
	}

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "private_key=%s\nreplace_peers=true\n", privHex)
	fmt.Fprintf(&cfg, "public_key=%s\nendpoint=%s:%d\n",
		srvHex, backup.Server.Endpoint, backup.Server.Port)
	for _, ip := range backup.Server.AllowedIPs {
		fmt.Fprintf(&cfg, "allowed_ip=%s\n", ip)
	}
	cfg.WriteString("persistent_keepalive_interval=20\n")

	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return fmt.Errorf("device not started")
	}

	if err := wd.IpcSet(cfg.String()); err != nil {
		return fmt.Errorf("rollback ipc set: %w", err)
	}

	d.mu.Lock()
	d.config = backup
	d.backupConfig = nil
	d.mu.Unlock()

	log.Printf("[Export] Rollback completed")
	return nil
}

// registerWithTargetServer opens a temporary gRPC connection to the target server
// and registers the device's new public key under the target account.
func (d *Device) registerWithTargetServer(payload *ExportDevicePayload, pubKeyHex string) (*wantasticgrpc.ExportPeerInfo, error) {
	d.mu.RLock()
	token := d.config.Auth.Token
	deviceID := d.config.DeviceID
	d.mu.RUnlock()

	newClient, err := wantasticgrpc.New(payload.ServerEndpoint, deviceID, token)
	if err != nil {
		return nil, fmt.Errorf("connect to target server %s: %w", payload.ServerEndpoint, err)
	}
	defer newClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return newClient.RegisterPeer(ctx, payload.TargetAccountID, pubKeyHex)
}

// sendExportConfirm sends a subtype-9 (ExportConfirm) TUN control message to
// the server. Retries up to 3 times with linear back-off.
// status=0 means success; status=1 means failure.
func (d *Device) sendExportConfirm(status uint8, pubKey [32]byte, token, message string) {
	payload := &exportConfirmPayload{
		Status:      status,
		NewPubKey:   pubKey,
		ExportToken: token,
		Message:     message,
	}
	// TUN control data: [action:1][payload bytes]
	data := append([]byte{SubtypeExportConfirm}, payload.encode()...)

	d.mu.RLock()
	serverPubKey := d.config.Server.PublicKey
	d.mu.RUnlock()

	for i := 0; i < 3; i++ {
		if err := d.SendTUNControl(serverPubKey, data); err == nil {
			log.Printf("[Export] Confirmation sent (attempt=%d status=%d)", i+1, status)
			return
		}
		time.Sleep(time.Duration(i+1) * exportConfirmSleep)
	}
	log.Printf("[Export] Failed to send confirmation after 3 attempts (status=%d)", status)
}
