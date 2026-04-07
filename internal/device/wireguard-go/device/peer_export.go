package device

import "encoding/hex"

// PublicKeyHex exposes the peer's remote WireGuard public key in hex form.
func (peer *Peer) PublicKeyHex() string {
	return hex.EncodeToString(peer.handshake.remoteStatic[:])
}
