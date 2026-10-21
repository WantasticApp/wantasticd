package device

import (
	"fmt"
	"time"
	"unsafe"

	"wantastic-agent/internal/wusp"
)

const (
	wuspFragmentAssemblyTTL = 30 * time.Second

	// maxWUSPFragmentBytesPerPeer bounds memory held for one peer's incomplete
	// messages. Fragment counts are sender-declared, so without a byte budget
	// a peer could stream fragments for messages that never complete.
	maxWUSPFragmentBytesPerPeer = 2 * wusp.MaxUSPControlMessageSize
	// wuspFragmentSlotCost approximates the per-slot overhead of an assembly
	// (one USPControlFragment header), charged when the slots are allocated.
	wuspFragmentSlotCost = int(unsafe.Sizeof(wusp.USPControlFragment{}))
)

type wuspFragmentKey struct {
	peer      *Peer
	messageID uint64
}

type wuspFragmentAssembly struct {
	updated   time.Time
	fragments []wusp.USPControlFragment
	received  uint32
	bytes     int // slot overhead + buffered payload, for the per-peer budget
}

func (device *Device) nextWUSPFragmentMessageID() uint64 {
	return device.wuspFragments.nextID.Add(1)
}

func (device *Device) consumeWUSPPayload(peer *Peer, payload []byte) ([]byte, bool, error) {
	fragment, ok, err := wusp.DecodeUSPControlFragment(payload)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return payload, true, nil
	}

	now := time.Now()
	key := wuspFragmentKey{peer: peer, messageID: fragment.MessageID}

	device.wuspFragments.Lock()
	defer device.wuspFragments.Unlock()
	device.pruneExpiredWUSPFragmentsLocked(now)

	assembly := device.wuspFragments.pending[key]
	if assembly == nil {
		slots := int(fragment.Count) * wuspFragmentSlotCost
		if device.wuspFragments.bytesByPeer[peer]+slots > maxWUSPFragmentBytesPerPeer {
			return nil, false, fmt.Errorf("%w: peer fragment buffer exceeds %d bytes", wusp.ErrUSPTransportMalformed, maxWUSPFragmentBytesPerPeer)
		}
		assembly = &wuspFragmentAssembly{
			updated:   now,
			fragments: make([]wusp.USPControlFragment, fragment.Count),
		}
		device.wuspFragments.pending[key] = assembly
		device.chargeWUSPFragmentsLocked(peer, assembly, slots)
	}
	if len(assembly.fragments) != int(fragment.Count) {
		device.dropWUSPAssemblyLocked(key, assembly)
		return nil, false, fmt.Errorf("%w: mismatched control fragment count", wusp.ErrUSPTransportMalformed)
	}

	if len(assembly.fragments[fragment.Index].Data) == 0 {
		if device.wuspFragments.bytesByPeer[peer]+len(fragment.Data) > maxWUSPFragmentBytesPerPeer {
			device.dropWUSPAssemblyLocked(key, assembly)
			return nil, false, fmt.Errorf("%w: peer fragment buffer exceeds %d bytes", wusp.ErrUSPTransportMalformed, maxWUSPFragmentBytesPerPeer)
		}
		fragment.Data = append([]byte(nil), fragment.Data...)
		assembly.fragments[fragment.Index] = fragment
		assembly.received++
		device.chargeWUSPFragmentsLocked(peer, assembly, len(fragment.Data))
	}
	assembly.updated = now

	if assembly.received != fragment.Count {
		return nil, false, nil
	}

	device.dropWUSPAssemblyLocked(key, assembly)
	assembled, err := wusp.ReassembleUSPControlFragments(assembly.fragments)
	if err != nil {
		return nil, false, err
	}
	return assembled, true, nil
}

func (device *Device) pruneExpiredWUSPFragmentsLocked(now time.Time) {
	for key, assembly := range device.wuspFragments.pending {
		if now.Sub(assembly.updated) > wuspFragmentAssemblyTTL {
			device.dropWUSPAssemblyLocked(key, assembly)
		}
	}
}

func (device *Device) chargeWUSPFragmentsLocked(peer *Peer, assembly *wuspFragmentAssembly, n int) {
	assembly.bytes += n
	device.wuspFragments.bytesByPeer[peer] += n
}

func (device *Device) dropWUSPAssemblyLocked(key wuspFragmentKey, assembly *wuspFragmentAssembly) {
	delete(device.wuspFragments.pending, key)
	remaining := device.wuspFragments.bytesByPeer[key.peer] - assembly.bytes
	if remaining <= 0 {
		delete(device.wuspFragments.bytesByPeer, key.peer)
		return
	}
	device.wuspFragments.bytesByPeer[key.peer] = remaining
}
