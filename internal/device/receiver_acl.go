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
//	[0]      action = 12 (TUNControlActionApplyReceiverACL)
//	[1]      version = 1
//	[2]      flags: bit0 FIRST (reset pending), bit1 LAST (commit)
//	[3]      gen: batch generation; a chunk whose gen differs from the pending
//	         batch (without FIRST) is discarded
//	[4:6]    count (uint16 LE): number of entries IN THIS CHUNK
//	[6:]     count entries, each: [family(1): 4 or 6][addr: 4 or 16 bytes]
//
// Entries are source overlay /32 (or /128) IPs this client must drop inbound
// from. A single-frame set has FIRST|LAST both set. An empty set (count 0,
// FIRST|LAST) clears the filter — the revocation path.
const (
	receiverACLVersion    = 1
	receiverACLFlagFirst  = 1 << 0
	receiverACLFlagLast   = 1 << 1
	receiverACLHeaderSize = 6
)

// applyReceiverACL decodes one ApplyReceiverACL frame, reassembles the batch
// across chunks, and on the committing (LAST) frame installs the new deny set
// and tears down any now-denied direct tunnel. Returns an error only for a
// malformed frame, in which case the caller keeps the previous set.
func (d *Device) applyReceiverACL(data []byte) error {
	keys, commit, err := d.ingestReceiverACLChunk(data)
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

	// Swap the set FIRST so there is no window where a direct tunnel exists
	// unfiltered, THEN tear down denied direct tunnels.
	wg.SetReceiverACLDenySet(keys, serverKey)

	denied := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		denied[string(k)] = struct{}{}
	}

	// If the current exit node became denied, clear exit routing before removing
	// the peer so the default route is not black-holed. (In steady state an exit
	// requires an allow, so this only fires during an allow→deny transition.)
	d.clearExitIfDenied(denied)

	if p2p := wg.GetP2PClient(); p2p != nil {
		if torn := p2p.TearDownDeniedDirectPeers(denied); len(torn) > 0 {
			log.Printf("[TUN] Receiver ACL: tore down %d now-denied direct tunnel(s)", len(torn))
		}
	}
	return nil
}

// ingestReceiverACLChunk parses one frame and folds it into the pending batch.
// It returns the fully reassembled key set and commit=true only on the LAST
// chunk of a batch; otherwise commit=false and the keys are buffered.
func (d *Device) ingestReceiverACLChunk(data []byte) (keys [][]byte, commit bool, err error) {
	entries, flags, gen, err := decodeReceiverACLFrame(data)
	if err != nil {
		return nil, false, err
	}

	d.aclMu.Lock()
	defer d.aclMu.Unlock()

	if flags&receiverACLFlagFirst != 0 {
		// Start (or restart) a batch. FIRST is the only thing that resets pending
		// state, so a newer batch cleanly supersedes an abandoned one.
		d.aclPendingKeys = nil
		d.aclPendingGen = gen
		d.aclPendingHasGen = true
	} else if !d.aclPendingHasGen || d.aclPendingGen != gen {
		// A continuation whose batch we never saw the start of (lost FIRST) or
		// that belongs to a different/superseded generation: ignore it WITHOUT
		// disturbing the batch currently in progress. Fail safe — the previous
		// committed set stays in place until a batch commits on its LAST chunk.
		return nil, false, nil
	}

	d.aclPendingKeys = append(d.aclPendingKeys, entries...)

	if flags&receiverACLFlagLast == 0 {
		return nil, false, nil
	}
	// Commit: hand back the accumulated set and reset the buffer.
	keys = d.aclPendingKeys
	d.aclPendingKeys = nil
	d.aclPendingHasGen = false
	return keys, true, nil
}

// decodeReceiverACLFrame validates one frame and returns its entries (raw
// address bytes), flags and generation.
func decodeReceiverACLFrame(data []byte) (entries [][]byte, flags, gen uint8, err error) {
	if len(data) < receiverACLHeaderSize {
		return nil, 0, 0, errors.New("frame too short")
	}
	if TUNControlAction(data[0]) != TUNControlActionApplyReceiverACL {
		return nil, 0, 0, fmt.Errorf("wrong action byte %d", data[0])
	}
	if data[1] != receiverACLVersion {
		return nil, 0, 0, fmt.Errorf("unsupported version %d", data[1])
	}
	flags = data[2]
	gen = data[3]
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	off := receiverACLHeaderSize
	for i := 0; i < count; i++ {
		if off >= len(data) {
			return nil, 0, 0, errors.New("truncated entries")
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
			return nil, 0, 0, fmt.Errorf("bad family tag %d", fam)
		}
		if off+n > len(data) {
			return nil, 0, 0, errors.New("truncated address")
		}
		entries = append(entries, append([]byte(nil), data[off:off+n]...))
		off += n
	}
	return entries, flags, gen, nil
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
