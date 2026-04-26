package device

import (
	"log"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

func (d *Device) handlePunch(peer *wgdevice.Peer, data []byte) {
	log.Printf("[P2P] Received HOLE PUNCH from %v (Internal Endpoint Updated)", peer)
	d.mu.RLock()
	hook := d.punchHook
	d.mu.RUnlock()
	if hook != nil {
		hook(peer, data)
	}
}

func (d *Device) handleWUSP(peer *wgdevice.Peer, data []byte) {
	d.mu.RLock()
	hook := d.wuspHook
	d.mu.RUnlock()
	if hook != nil {
		hook(peer, data)
	}
}
