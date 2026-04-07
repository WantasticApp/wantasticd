package device

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

type TUNControlAction uint8

const (
	TUNControlActionRevokeExitNodeRouting  TUNControlAction = 0
	TUNControlActionUseExitNodeRouting     TUNControlAction = 1
	TUNControlActionEnableExitNodeSharing  TUNControlAction = 2
	TUNControlActionRequestExitNodeRouting TUNControlAction = 3
	TUNControlActionSetExitNodeOffer       TUNControlAction = 4
	TUNControlActionDisableExitNodeSharing TUNControlAction = 5
)

const tunControlPeerPayloadSize = 1 + 32

func (a TUNControlAction) String() string {
	switch a {
	case TUNControlActionRevokeExitNodeRouting:
		return "revoke-exit-node-routing"
	case TUNControlActionUseExitNodeRouting:
		return "use-exit-node-routing"
	case TUNControlActionEnableExitNodeSharing:
		return "enable-exit-node-sharing"
	case TUNControlActionRequestExitNodeRouting:
		return "request-exit-node-routing"
	case TUNControlActionSetExitNodeOffer:
		return "set-exit-node-offer"
	case TUNControlActionDisableExitNodeSharing:
		return "disable-exit-node-sharing"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(a))
	}
}

func EncodeExitNodeSelectionTUNControl(peerPubKeyHex string) ([]byte, error) {
	data := make([]byte, tunControlPeerPayloadSize)
	data[0] = byte(TUNControlActionRequestExitNodeRouting)

	peerPubKeyHex = strings.TrimSpace(peerPubKeyHex)
	if peerPubKeyHex == "" || strings.EqualFold(peerPubKeyHex, "none") {
		return data, nil
	}

	pubKey, err := decodePeerPublicKeyHex(peerPubKeyHex)
	if err != nil {
		return nil, err
	}
	copy(data[1:], pubKey[:])
	return data, nil
}

func EncodeExitNodeOfferTUNControl(enabled bool) []byte {
	data := []byte{byte(TUNControlActionSetExitNodeOffer), 0}
	if enabled {
		data[1] = 1
	}
	return data
}

func decodePeerPublicKeyHex(peerPubKeyHex string) ([32]byte, error) {
	var pubKey [32]byte

	raw, err := hex.DecodeString(strings.TrimSpace(peerPubKeyHex))
	if err != nil {
		return pubKey, fmt.Errorf("decode peer public key: %w", err)
	}
	if len(raw) != len(pubKey) {
		return pubKey, fmt.Errorf("invalid peer public key length: got %d want %d", len(raw), len(pubKey))
	}

	copy(pubKey[:], raw)
	return pubKey, nil
}

func decodeTUNControlPeerKey(data []byte) ([32]byte, error) {
	var pubKey [32]byte
	if len(data) < tunControlPeerPayloadSize {
		return pubKey, errors.New("payload too short for peer-targeted action")
	}
	copy(pubKey[:], data[1:tunControlPeerPayloadSize])
	return pubKey, nil
}

func (d *Device) handleTUNControl(peer *wgdevice.Peer, data []byte) {
	if len(data) == 0 {
		return
	}

	action := TUNControlAction(data[0])
	switch action {
	case TUNControlActionUseExitNodeRouting:
		targetPubKey, err := decodeTUNControlPeerKey(data)
		if err != nil {
			log.Printf("[TUN] Invalid %s message from %s: %v", action, peer, err)
			return
		}
		if err := d.activateExitNodeRouting(targetPubKey); err != nil {
			log.Printf("[TUN] Failed to activate exit node routing: %v", err)
		}
	case TUNControlActionRevokeExitNodeRouting:
		log.Printf("[TUN] Server revoked exit node routing")
		if err := d.deactivateExitNodeRouting(); err != nil {
			log.Printf("[TUN] Failed to revoke exit node routing: %v", err)
		}
	case TUNControlActionEnableExitNodeSharing:
		d.mu.RLock()
		enabled := d.config.ExitNode.Enabled
		d.mu.RUnlock()

		if !enabled {
			log.Printf("[TUN] Server requested exit node sharing, but local exit node sharing is disabled")
			return
		}
		if err := d.enableExitNodeSharing(); err != nil {
			log.Printf("[TUN] Failed to enable exit node sharing: %v", err)
		}
	case TUNControlActionDisableExitNodeSharing:
		log.Printf("[TUN] Server revoked our duties to be an exit node")
		if err := d.disableExitNodeSharing(); err != nil {
			log.Printf("[TUN] Failed to disable exit node sharing: %v", err)
		}
	default:
		log.Printf("[TUN] Ignoring unsupported TUN control action %d (%s) from %s", uint8(action), action, peer)
	}
}

func (d *Device) activateExitNodeRouting(targetPubKey [32]byte) error {
	if d.device == nil {
		return errors.New("device not started")
	}
	if d.device.LookupPeer(targetPubKey) == nil {
		return fmt.Errorf("target peer %x not found", targetPubKey[:4])
	}

	routes, err := d.exitRouteTargets()
	if err != nil {
		return err
	}

	if err := d.applyAllowedIPsToPeer(hex.EncodeToString(targetPubKey[:]), routes); err != nil {
		return err
	}
	if err := d.syncExitNodeRoutes(routes); err != nil {
		return err
	}

	d.mu.Lock()
	d.exitNodePeerKey = targetPubKey
	d.exitNodeActive = true
	d.mu.Unlock()

	log.Printf("[TUN] Server designated peer %x as exit node for routes %s", targetPubKey[:4], strings.Join(routes, ", "))
	return nil
}

func (d *Device) deactivateExitNodeRouting() error {
	routes, err := d.exitRouteTargets()
	if err != nil {
		return err
	}

	d.mu.RLock()
	serverPubKey := d.config.Server.PublicKey
	d.mu.RUnlock()

	if serverPubKey != "" {
		serverPubKeyHex, err := base64ToHex(serverPubKey)
		if err != nil {
			return fmt.Errorf("decode server public key: %w", err)
		}
		if err := d.applyAllowedIPsToPeer(serverPubKeyHex, routes); err != nil {
			return err
		}
	}

	if err := d.clearExitNodeRoutes(); err != nil {
		return err
	}

	d.mu.Lock()
	d.exitNodePeerKey = [32]byte{}
	d.exitNodeActive = false
	d.mu.Unlock()
	return nil
}

func (d *Device) enableExitNodeSharing() error {
	d.mu.RLock()
	if d.exitNodeShared {
		d.mu.RUnlock()
		return nil
	}
	tunName := d.tunName
	d.mu.RUnlock()

	note, err := enableExitNodeSharingOS(tunName)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.exitNodeShared = true
	d.mu.Unlock()

	if note != "" {
		log.Printf("[TUN] Exit node sharing enabled with platform note: %s", note)
	} else {
		log.Printf("[TUN] Exit node sharing enabled")
	}

	return nil
}

func (d *Device) disableExitNodeSharing() error {
	d.mu.RLock()
	if !d.exitNodeShared {
		d.mu.RUnlock()
		return nil
	}
	tunName := d.tunName
	d.mu.RUnlock()

	if err := disableExitNodeSharingOS(tunName); err != nil {
		return err
	}

	d.mu.Lock()
	d.exitNodeShared = false
	d.mu.Unlock()
	log.Printf("[TUN] Exit node sharing disabled")
	return nil
}

func (d *Device) exitRouteTargets() ([]string, error) {
	d.mu.RLock()
	addresses := append([]netip.Prefix(nil), d.config.Interface.Addresses...)
	configuredRoutes := append([]string(nil), d.config.ExitNode.ExitRoutes...)
	d.mu.RUnlock()

	return effectiveExitRoutes(addresses, configuredRoutes)
}

func effectiveExitRoutes(addresses []netip.Prefix, configuredRoutes []string) ([]string, error) {
	if len(configuredRoutes) > 0 {
		return canonicalizeExitRoutes(configuredRoutes)
	}

	hasIPv4 := false
	hasIPv6 := false
	for _, address := range addresses {
		switch {
		case address.Addr().Is4():
			hasIPv4 = true
		case address.Addr().Is6():
			hasIPv6 = true
		}
	}

	routes := make([]string, 0, 2)
	if hasIPv4 || (!hasIPv4 && !hasIPv6) {
		routes = append(routes, "0.0.0.0/0")
	}
	if hasIPv6 || (!hasIPv4 && !hasIPv6) {
		routes = append(routes, "::/0")
	}
	return routes, nil
}

func canonicalizeExitRoutes(routes []string) ([]string, error) {
	canonical := make([]string, 0, len(routes))
	seen := make(map[string]struct{}, len(routes))

	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return nil, fmt.Errorf("invalid exit route %q: %w", route, err)
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		canonical = append(canonical, key)
	}

	return canonical, nil
}

func (d *Device) applyAllowedIPsToPeer(peerPubKeyHex string, routes []string) error {
	if d.device == nil {
		return errors.New("device not started")
	}

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "public_key=%s\nreplace_allowed_ips=false\n", peerPubKeyHex)
	for _, route := range routes {
		fmt.Fprintf(&cfg, "allowed_ip=%s\n", route)
	}

	if err := d.device.IpcSet(cfg.String()); err != nil {
		return fmt.Errorf("update allowed IPs for peer %s: %w", peerPubKeyHex, err)
	}
	return nil
}

func (d *Device) syncExitNodeRoutes(routes []string) error {
	d.mu.RLock()
	currentRoutes := append([]string(nil), d.exitNodeRoutes...)
	d.mu.RUnlock()

	current := make(map[string]struct{}, len(currentRoutes))
	for _, route := range currentRoutes {
		current[route] = struct{}{}
	}

	desired := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		desired[route] = struct{}{}
	}

	var firstErr error
	for _, route := range currentRoutes {
		if _, ok := desired[route]; ok {
			continue
		}
		if err := d.removeRoute(route); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("remove route %s: %w", route, err)
		} else if err == nil {
			log.Printf("[TUN] Removed exit node route: %s", route)
		}
	}

	for _, route := range routes {
		if _, ok := current[route]; ok {
			continue
		}
		if err := d.addRoute(route); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("add route %s: %w", route, err)
		} else if err == nil {
			log.Printf("[TUN] Added exit node route: %s", route)
		}
	}

	d.mu.Lock()
	d.exitNodeRoutes = append([]string(nil), routes...)
	d.mu.Unlock()
	return firstErr
}

func (d *Device) clearExitNodeRoutes() error {
	d.mu.RLock()
	routes := append([]string(nil), d.exitNodeRoutes...)
	d.mu.RUnlock()

	var firstErr error
	for _, route := range routes {
		if err := d.removeRoute(route); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("remove route %s: %w", route, err)
		} else if err == nil {
			log.Printf("[TUN] Removed exit node route: %s", route)
		}
	}

	d.mu.Lock()
	d.exitNodeRoutes = nil
	d.mu.Unlock()
	return firstErr
}
