package exitnode

import (
	"net/netip"
	"time"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsInternet reports whether a is a public unicast address, i.e. traffic to
// it from a peer is exit-node traffic rather than tenant/LAN traffic.
func IsInternet(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	if a.Is4() {
		return !cgnat.Contains(a)
	}
	return true
}

// PacketAddrs returns the source and destination of an IP packet.
func PacketAddrs(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return
}

// Client-side health thresholds.
const (
	// HandshakeStaleAfter: a direct exit path whose last handshake is older
	// than this is treated as dead (keepalive 25s + rekey 120s + slack).
	HandshakeStaleAfter = 200 * time.Second
)

// ClientPhase is the client-side exit-node state.
type ClientPhase string

const (
	PhaseOff     ClientPhase = "off"
	PhasePending ClientPhase = "pending" // waiting for the exit to confirm
	PhaseActive  ClientPhase = "active"  // internet goes through the exit
	PhaseStandby ClientPhase = "standby" // chosen, but routing is normal (fail-open)
)

// PathHealth is what the reconciler knows about the exit peer right now.
type PathHealth struct {
	Listed        bool // the coordinator lists the peer (same tenant, recently online)
	Direct        bool // P2P state established and a WireGuard peer exists
	LastHandshake time.Time
	Offered       *bool // last ExitStatus from the peer, nil = unknown
	Granted       bool  // the peer confirmed our use request
}

// NextPhase decides the client phase. Fail-open: anything short of a live,
// confirmed direct path means normal routing with a reason.
func NextPhase(h PathHealth, now time.Time) (ClientPhase, string) {
	switch {
	case !h.Listed:
		return PhaseStandby, "exit peer is offline or no longer in this network"
	case h.Offered != nil && !*h.Offered:
		return PhaseStandby, "exit peer has not enabled exit-node (run `sudo wantasticd exit-node on` there)"
	case !h.Direct:
		return PhaseStandby, "no direct path to the exit peer yet (relayed exit traffic needs hub support); routing normally"
	case h.LastHandshake.IsZero() || now.Sub(h.LastHandshake) > HandshakeStaleAfter:
		return PhaseStandby, "direct path to the exit peer is stale; routing normally"
	case !h.Granted:
		return PhasePending, "waiting for the exit peer to confirm"
	}
	return PhaseActive, ""
}
