package device

import (
	"fmt"
	"time"

	"wantastic-agent/internal/wusp"
)

const wuspFragmentAssemblyTTL = 30 * time.Second

type wuspFragmentKey struct {
	peer      *Peer
	messageID uint64
}

type wuspFragmentAssembly struct {
	updated   time.Time
	fragments []wusp.USPControlFragment
	received  uint32
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
		assembly = &wuspFragmentAssembly{
			updated:   now,
			fragments: make([]wusp.USPControlFragment, fragment.Count),
		}
		device.wuspFragments.pending[key] = assembly
	}
	if len(assembly.fragments) != int(fragment.Count) {
		delete(device.wuspFragments.pending, key)
		return nil, false, fmt.Errorf("%w: mismatched control fragment count", wusp.ErrUSPTransportMalformed)
	}

	if len(assembly.fragments[fragment.Index].Data) == 0 {
		fragment.Data = append([]byte(nil), fragment.Data...)
		assembly.fragments[fragment.Index] = fragment
		assembly.received++
	}
	assembly.updated = now

	if assembly.received != fragment.Count {
		return nil, false, nil
	}

	delete(device.wuspFragments.pending, key)
	assembled, err := wusp.ReassembleUSPControlFragments(assembly.fragments)
	if err != nil {
		return nil, false, err
	}
	return assembled, true, nil
}

func (device *Device) pruneExpiredWUSPFragmentsLocked(now time.Time) {
	for key, assembly := range device.wuspFragments.pending {
		if now.Sub(assembly.updated) > wuspFragmentAssemblyTTL {
			delete(device.wuspFragments.pending, key)
		}
	}
}
