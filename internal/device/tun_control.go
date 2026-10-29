package device

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

type TUNControlAction uint8

const (
	TUNControlActionRevokeExitNodeRouting   TUNControlAction = 0
	TUNControlActionUseExitNodeRouting      TUNControlAction = 1
	TUNControlActionEnableExitNodeSharing   TUNControlAction = 2
	TUNControlActionRequestExitNodeRouting  TUNControlAction = 3
	TUNControlActionSetExitNodeOffer        TUNControlAction = 4
	TUNControlActionDisableExitNodeSharing  TUNControlAction = 5
	TUNControlActionSetLocalAccessRoutes    TUNControlAction = 6
	TUNControlActionApplyLocalAccessRoutes  TUNControlAction = 7
	TUNControlActionRemoveLocalAccessRoutes TUNControlAction = 8
	TUNControlActionSyncLocalAccessRoutes   TUNControlAction = 9
	// Peer-to-peer exit-node negotiation, sent over the direct WireGuard
	// session between two devices of the same tenant (never via the hub).
	TUNControlActionExitRequest TUNControlAction = 10 // [10, op]
	TUNControlActionExitStatus  TUNControlAction = 11 // [11, flags]
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
	case TUNControlActionSetLocalAccessRoutes:
		return "set-local-access-routes"
	case TUNControlActionApplyLocalAccessRoutes:
		return "apply-local-access-routes"
	case TUNControlActionRemoveLocalAccessRoutes:
		return "remove-local-access-routes"
	case TUNControlActionSyncLocalAccessRoutes:
		return "sync-local-access-routes"
	case TUNControlActionExitRequest:
		return "exit-request"
	case TUNControlActionExitStatus:
		return "exit-status"
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
	// Coordinator commands change routing and forwarding state. Accept them
	// only from the configured tenant server, never from a dynamically
	// discovered peer.
	switch action {
	case TUNControlActionRevokeExitNodeRouting,
		TUNControlActionUseExitNodeRouting,
		TUNControlActionEnableExitNodeSharing,
		TUNControlActionDisableExitNodeSharing,
		TUNControlActionApplyLocalAccessRoutes,
		TUNControlActionRemoveLocalAccessRoutes,
		TUNControlActionSyncLocalAccessRoutes:
		if !d.isServerTUNControlPeer(peer.PublicKeyHex()) {
			log.Printf("[TUN] Ignoring unauthorized %s message from %s", action, peer)
			return
		}
	}
	switch action {
	case TUNControlActionUseExitNodeRouting:
		// Portal "assign exit node": select the exit like `jumpto` would.
		// The exit itself must still have opted in locally and confirm.
		targetPubKey, err := decodeTUNControlPeerKey(data)
		if err != nil {
			log.Printf("[TUN] Invalid %s message from %s: %v", action, peer, err)
			return
		}
		if e := d.exitEngine(); e != nil {
			if ip := e.ipForKey(targetPubKey); ip != "" {
				if _, err := d.UseExitNode(ip, 0); err != nil {
					log.Printf("[TUN] Coordinator exit-node assignment to %s failed: %v", ip, err)
				}
			} else {
				log.Printf("[TUN] Coordinator assigned unknown exit peer %x", targetPubKey[:4])
			}
		}
	case TUNControlActionRevokeExitNodeRouting:
		log.Printf("[TUN] Coordinator revoked exit-node routing")
		_ = d.ClearExitNode()
	case TUNControlActionEnableExitNodeSharing, TUNControlActionDisableExitNodeSharing:
		// Being an exit is a local opt-in (`wantasticd exit-node on`); the
		// coordinator cannot turn it on or off.
		log.Printf("[TUN] Ignoring coordinator %s: exit-node sharing is controlled locally", action)
	case TUNControlActionExitRequest, TUNControlActionExitStatus:
		if e := d.exitEngine(); e != nil {
			e.handleControl(peer, action, data)
		}
	case TUNControlActionApplyLocalAccessRoutes:
		owner, routes, err := decodeLocalAccessRouteUpdate(data)
		if err != nil {
			log.Printf("[TUN] Invalid local-access route update: %v", err)
			return
		}
		if err := d.applyLocalAccessRouteUpdate(owner, routes); err != nil {
			log.Printf("[TUN] Failed to apply local-access routes: %v", err)
		}
	case TUNControlActionRemoveLocalAccessRoutes:
		owner, err := decodeLocalAccessRouteRemoval(data)
		if err != nil {
			log.Printf("[TUN] Invalid local-access route removal: %v", err)
			return
		}
		if err := d.removeLocalAccessRouteUpdate(owner); err != nil {
			log.Printf("[TUN] Failed to remove local-access routes: %v", err)
		}
	case TUNControlActionSyncLocalAccessRoutes:
		routesByOwner, err := decodeLocalAccessSnapshot(data)
		if err != nil {
			log.Printf("[TUN] Invalid local-access route snapshot: %v", err)
			return
		}
		if err := d.applyLocalAccessSnapshot(routesByOwner); err != nil {
			log.Printf("[TUN] Failed to sync local-access routes: %v", err)
		}
	default:
		log.Printf("[TUN] Ignoring unsupported TUN control action %d (%s) from %s", uint8(action), action, peer)
	}
}
