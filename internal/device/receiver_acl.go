package device

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

// Receiver-ACL wire format (phase 3), mirrored from the hub encoder
// (ISPApp-TunnelHub coordinator receiver_acl.go):
//
//	[0]        action = 12 (TUNControlActionApplyReceiverACL)
//	[1]        version = 1
//	[2]        flags: bit0 FIRST (reset pending), bit1 LAST (commit)
//	[3]        gen: batch generation; a chunk whose gen differs from the pending
//	           batch (without FIRST) is discarded
//	[4:6]      denyCount (uint16 LE): # deny entries IN THIS CHUNK
//	[6:]       denyCount entries, each: [family(1): 4 or 6][addr: 4 or 16 bytes]
//	[x:x+2]    relayCount (uint16 LE): # relay-only entries IN THIS CHUNK
//	[x+2:]     relayCount entries, same encoding
//
// DENY entries are source overlay /32 (or /128) IPs this client must DROP inbound
// from. RELAY-ONLY entries are permitted peers that must NOT use a direct tunnel
// (scoped allow) — their live direct tunnel is torn down and re-promotion is
// pinned off, but their traffic is NOT dropped (it flows via the hub relay).
// Both counts 0 with FIRST|LAST clears everything — the revocation path.
//
// Backward-compat: the relay list sits AFTER the deny list, so a client that only
// understands the deny list reads denyCount entries and ignores the trailing
// bytes (version stays 1) — it still drops denied, just won't relay-pin.
const (
	receiverACLVersion    = 1
	receiverACLFlagFirst  = 1 << 0
	receiverACLFlagLast   = 1 << 1
	receiverACLHeaderSize = 6
)

// applyReceiverACL decodes one ApplyReceiverACL frame, reassembles the batch
// across chunks, and on the committing (LAST) frame installs the new deny set and
// tears down now-denied/relay-only direct tunnels. Returns an error only for a
// malformed frame, in which case the caller keeps the previous sets.
func (d *Device) applyReceiverACL(data []byte) error {
	denyKeys, relayKeys, commit, err := d.ingestReceiverACLChunk(data)
	if err != nil {
		return err
	}
	if !commit {
		return nil // mid-batch; wait for the LAST chunk
	}

	serverKey, err := d.serverNoiseKey()
	if err != nil {
		// Without the server key the carve-out can't be enforced; refuse rather
		// than install a set that might drop relayed/control traffic.
		return fmt.Errorf("receiver-acl: server key unavailable: %w", err)
	}

	wg := d.wg.Load()
	if wg == nil {
		return errors.New("receiver-acl: device not running")
	}

	// Swap the drop set FIRST so there is no window where a direct tunnel exists
	// unfiltered, THEN tear down denied/relay-only direct tunnels.
	wg.SetReceiverACLDenySet(denyKeys, serverKey)

	denied := keySet(denyKeys)
	relayOnly := keySet(relayKeys)

	// If the current exit node became denied OR relay-only, clear exit routing
	// before its direct tunnel is torn down so the default route is not
	// black-holed. (An exit needs a direct session, so a relay-only exit must be
	// cleared too; in steady state this only fires during a policy transition.)
	d.clearExitIfDenied(denied)
	d.clearExitIfDenied(relayOnly)

	if p2p := wg.GetP2PClient(); p2p != nil {
		if torn := p2p.TearDownDeniedDirectPeers(denied); len(torn) > 0 {
			log.Printf("[TUN] Receiver ACL: tore down %d now-denied direct tunnel(s)", len(torn))
		}
		// Relay-only peers: pin them off a direct path and tear down any live
		// direct tunnel so traffic falls back to the hub relay (where the stateful
		// filter enforces port/protocol). Their traffic is NOT dropped.
		if torn := p2p.ApplyRelayOnly(relayOnly); len(torn) > 0 {
			log.Printf("[TUN] Receiver ACL: relay-pinned %d peer(s), tore down their direct tunnel(s)", len(torn))
		}
	}
	return nil
}

func keySet(keys [][]byte) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[string(k)] = struct{}{}
	}
	return m
}

// ingestReceiverACLChunk parses one frame and folds it into the pending batch.
// It returns the fully reassembled deny and relay-only key sets with commit=true
// only on the LAST chunk of a batch; otherwise commit=false and they are buffered.
func (d *Device) ingestReceiverACLChunk(data []byte) (denyKeys, relayKeys [][]byte, commit bool, err error) {
	deny, relay, flags, gen, err := decodeReceiverACLFrame(data)
	if err != nil {
		return nil, nil, false, err
	}

	d.aclMu.Lock()
	defer d.aclMu.Unlock()

	if flags&receiverACLFlagFirst != 0 {
		// Start (or restart) a batch. FIRST is the only thing that resets pending
		// state, so a newer batch cleanly supersedes an abandoned one.
		d.aclPendingDeny = nil
		d.aclPendingRelay = nil
		d.aclPendingGen = gen
		d.aclPendingHasGen = true
	} else if !d.aclPendingHasGen || d.aclPendingGen != gen {
		// A continuation whose batch we never saw the start of (lost FIRST) or
		// that belongs to a different/superseded generation: ignore it WITHOUT
		// disturbing the batch currently in progress. Fail safe — the previous
		// committed sets stay in place until a batch commits on its LAST chunk.
		return nil, nil, false, nil
	}

	d.aclPendingDeny = append(d.aclPendingDeny, deny...)
	d.aclPendingRelay = append(d.aclPendingRelay, relay...)

	if flags&receiverACLFlagLast == 0 {
		return nil, nil, false, nil
	}
	// Commit: hand back the accumulated sets and reset the buffer.
	denyKeys = d.aclPendingDeny
	relayKeys = d.aclPendingRelay
	d.aclPendingDeny = nil
	d.aclPendingRelay = nil
	d.aclPendingHasGen = false
	return denyKeys, relayKeys, true, nil
}

// decodeReceiverACLFrame validates one frame and returns its deny and relay-only
// entries (raw address bytes), flags and generation.
func decodeReceiverACLFrame(data []byte) (deny, relay [][]byte, flags, gen uint8, err error) {
	if len(data) < receiverACLHeaderSize {
		return nil, nil, 0, 0, errors.New("frame too short")
	}
	if TUNControlAction(data[0]) != TUNControlActionApplyReceiverACL {
		return nil, nil, 0, 0, fmt.Errorf("wrong action byte %d", data[0])
	}
	if data[1] != receiverACLVersion {
		return nil, nil, 0, 0, fmt.Errorf("unsupported version %d", data[1])
	}
	flags = data[2]
	gen = data[3]

	readList := func(off, count int) ([][]byte, int, error) {
		var out [][]byte
		for i := 0; i < count; i++ {
			if off >= len(data) {
				return nil, 0, errors.New("truncated entries")
			}
			fam := data[off]
			off++
			var n int
			switch fam {
			case 4:
				n = net.IPv4len
			case 6:
				n = net.IPv6len
			default:
				return nil, 0, fmt.Errorf("bad family tag %d", fam)
			}
			if off+n > len(data) {
				return nil, 0, errors.New("truncated address")
			}
			out = append(out, append([]byte(nil), data[off:off+n]...))
			off += n
		}
		return out, off, nil
	}

	denyCount := int(binary.LittleEndian.Uint16(data[4:6]))
	deny, off, err := readList(receiverACLHeaderSize, denyCount)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	// Relay-only list follows the deny list. Absent (old-format-style frame with
	// no trailing count) ⇒ empty relay list, which is valid.
	if off+2 > len(data) {
		return deny, nil, flags, gen, nil
	}
	relayCount := int(binary.LittleEndian.Uint16(data[off : off+2]))
	relay, _, err = readList(off+2, relayCount)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	return deny, relay, flags, gen, nil
}

// serverNoiseKey decodes the configured tenant server's public key (base64) into
// the raw 32-byte form used to carve the hub/relay peer out of the receiver ACL.
func (d *Device) serverNoiseKey() (wgdevice.NoisePublicKey, error) {
	var key wgdevice.NoisePublicKey
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(d.config.Server.PublicKey))
	if err != nil {
		return key, err
	}
	if len(raw) != len(key) {
		return key, fmt.Errorf("server key length %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// clearExitIfDenied clears exit-node routing when the active exit's overlay IP is
// in the denied set, so tearing down that direct peer does not black-hole the
// default route.
func (d *Device) clearExitIfDenied(denied map[string]struct{}) {
	e := d.exitEngine()
	if e == nil {
		return
	}
	ip := e.currentUseIP()
	if ip == "" {
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return
	}
	if _, ok := denied[denyKeyForIPString(parsed)]; ok {
		if err := d.ClearExitNode(); err != nil {
			log.Printf("[TUN] Receiver ACL: failed to clear denied exit node %s: %v", ip, err)
		}
	}
}

// denyKeyForIPString returns the deny-set map key (raw address bytes) for an IP.
func denyKeyForIPString(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return string(ip4)
	}
	if len(ip) == net.IPv6len {
		return string(ip)
	}
	return ""
}
