package device

import (
	"net"
	"sync/atomic"
	"time"
)

// natClass is what the coordinator's reflection says about the NAT in front
// of an endpoint. The coordinator is the only reflector, so mapping behaviour
// is inferred rather than measured: a NAT that kept the WireGuard port
// (Linux-style masquerade, most home routers) reuses one mapping for every
// destination in practice. One that rewrote it (carrier-grade NAT on mobile
// and much broadband, e.g. China Unicom/Mobile/Telecom) may allocate a new
// port per destination: endpoint-dependent mapping, "symmetric", NAT type 4.
type natClass uint8

const (
	natClassUnknown    natClass = iota
	natClassPublic              // the observed address is on the device itself
	natClassMapped              // a router port mapping (NAT-PMP/UPnP) is announced
	natClassPreserving          // the NAT kept the WireGuard port
	natClassRewriting           // the NAT rewrote the port; mapping may be endpoint-dependent
)

func (n natClass) String() string {
	switch n {
	case natClassPublic:
		return "public"
	case natClassMapped:
		return "port-mapped"
	case natClassPreserving:
		return "port-preserving"
	case natClassRewriting:
		return "port-rewriting"
	default:
		return "unknown"
	}
}

// easy reports whether the endpoint the coordinator saw is the one this side
// uses towards any peer, so a peer can aim at it directly.
func (n natClass) easy() bool {
	return n == natClassPublic || n == natClassMapped || n == natClassPreserving
}

// stableSource reports whether every packet this side sends leaves from the
// same public endpoint, so sending to many destinations costs no NAT ports.
// Only such a side may spray: a spray from behind an endpoint-dependent NAT
// would allocate one carrier port per packet and could exhaust its block.
func (n natClass) stableSource() bool {
	return n == natClassPublic || n == natClassPreserving
}

const (
	// p2pSprayFirstPorts and p2pSprayPorts bound the spray of an easy side
	// towards a port-rewriting peer: the first attempt guesses a sequential
	// allocator (mostly above the peer's observed port), later attempts a
	// port block centred on it.
	p2pSprayFirstPorts = 128
	p2pSprayPorts      = 256
	// p2pSprayMaxAttempts stops spraying after this many failed attempts
	// until the peer's address changes (which resets the attempt count).
	p2pSprayMaxAttempts = 4
	// p2pSprayDelay leaves the plain punch time to succeed first.
	p2pSprayDelay = 1500 * time.Millisecond
	// p2pSprayInterval separates sweeps; filter entries opened by a sweep
	// outlive it (UDP conntrack keeps unreplied entries ~30s).
	p2pSprayInterval = 6 * time.Second
	p2pSpraySweeps   = 2
	// p2pSprayPerRound paces a sweep over several punch rounds
	// (at most ~700 packets/s at the fastest round interval).
	p2pSprayPerRound = 32
	// p2pSprayMinPort excludes ports carrier NATs do not allocate.
	p2pSprayMinPort = 1024

	// p2pDirectKeepalive is the longest a direct path may go without this
	// side sending. Carrier NATs commonly drop idle UDP mappings after
	// 30s or less, and many refresh a mapping only on outbound packets.
	// WireGuard's persistent keepalive is reset by received packets, so on
	// an idle path only one side keeps transmitting; this keeps both sides'
	// mappings alive.
	p2pDirectKeepalive = 12 * time.Second
)

// p2pIsPublicIPv4 decides whether an address is a public IPv4 endpoint;
// tests substitute loopback.
var p2pIsPublicIPv4 = isPublicIPv4PunchAddr

func isPublicIPv4PunchAddr(addr net.UDPAddr) bool {
	return addr.IP.To4() != nil && isPublicInternetPunchAddr(addr)
}

// classifyNAT infers the NAT in front of an endpoint from the coordinator's
// observation, the endpoint's reported default-route address (which carries
// its WireGuard listen port) and its other candidates.
func classifyNAT(observed, local net.UDPAddr, candidates []net.UDPAddr) natClass {
	observed = normalizeUDPAddr(observed)
	if !p2pIsPublicIPv4(observed) {
		return natClassUnknown
	}
	local = normalizeUDPAddr(local)
	if local.IP.Equal(observed.IP) && local.Port == observed.Port {
		return natClassPublic
	}
	listenPort := local.Port
	for _, candidate := range candidates {
		candidate = normalizeUDPAddr(candidate)
		if candidate.Port <= 0 || (candidate.IP.Equal(observed.IP) && candidate.Port == observed.Port) {
			continue
		}
		if p2pIsPublicIPv4(candidate) {
			// A second public endpoint is a router port mapping (or a
			// public interface address): reachable without punching.
			return natClassMapped
		}
		if listenPort <= 0 {
			// Interface candidates (LAN, IPv6) carry the listen port.
			listenPort = candidate.Port
		}
	}
	switch {
	case listenPort <= 0:
		return natClassUnknown
	case observed.Port == listenPort:
		return natClassPreserving
	default:
		return natClassRewriting
	}
}

// punchPlan is how one side punches towards a peer.
type punchPlan struct {
	self, peer natClass
	// targets are punched every round.
	targets []net.UDPAddr
	// spray is swept a few times, paced, after p2pSprayDelay.
	spray  []net.UDPAddr
	sweeps int
}

// planPunch picks the punch strategy for session. Roles follow the NAT
// classes: towards an easy peer only its known endpoint matters, and a
// port-rewriting side sends there first so its fresh mapping is the next
// allocation. An easy side whose own source is stable sprays a bounded
// window of ports around a port-rewriting peer's observed port; that opens
// its own NAT's filter for the port the peer's NAT picked towards it, so the
// peer's punches (aimed at the easy side's stable endpoint) get through and
// are answered at their real source.
func planPunch(session *P2PSession, self natClass, attempts int) punchPlan {
	plan := punchPlan{
		self: self,
		peer: classifyNAT(session.ObservedAddr, session.LocalAddr, session.CandidateAddrs),
	}
	spray := plan.peer == natClassRewriting && self.stableSource() && attempts < p2pSprayMaxAttempts
	// Small port predictions are kept for peers of unknown behaviour; they
	// are pointless towards an easy peer and the spray covers them.
	plan.targets = buildPunchTargets(session, !plan.peer.easy() && !spray)
	if spray {
		n, back := p2pSprayFirstPorts, p2pSprayFirstPorts/4
		if attempts > 0 {
			n, back = p2pSprayPorts, p2pSprayPorts/2
		}
		plan.spray = sprayPorts(session.ObservedAddr, n, back, plan.targets)
		if len(plan.spray) > 0 {
			plan.sweeps = p2pSpraySweeps
		}
	}
	return plan
}

// sprayPorts lists up to n ports on base's IP near base's port, nearest
// first, at most back of them below it, skipping exclude.
func sprayPorts(base net.UDPAddr, n, back int, exclude []net.UDPAddr) []net.UDPAddr {
	base = normalizeUDPAddr(base)
	skip := make(map[int]struct{}, len(exclude)+1)
	skip[base.Port] = struct{}{}
	for _, addr := range exclude {
		if addr.IP.Equal(base.IP) {
			skip[addr.Port] = struct{}{}
		}
	}
	out := make([]net.UDPAddr, 0, n)
	add := func(port int) {
		if port < p2pSprayMinPort || port > 65535 || len(out) >= n {
			return
		}
		if _, ok := skip[port]; ok {
			return
		}
		skip[port] = struct{}{}
		out = append(out, net.UDPAddr{IP: base.IP, Port: port})
	}
	below := 0
	for d := 1; len(out) < n && d <= 65535; d++ {
		add(base.Port + d)
		if below < back && base.Port-d >= p2pSprayMinPort {
			before := len(out)
			add(base.Port - d)
			below += len(out) - before
		}
	}
	return out
}

// punchSpray paces a plan's spray across punch rounds. One spray runs at a
// time per client (limiter) so several peers never multiply the rate.
type punchSpray struct {
	size    int
	sweeps  int
	next    int
	nextAt  time.Time
	active  bool
	limiter *atomic.Bool
}

func newPunchSpray(size, sweeps int, start time.Time, limiter *atomic.Bool) *punchSpray {
	if size == 0 {
		sweeps = 0
	}
	return &punchSpray{size: size, sweeps: sweeps, nextAt: start.Add(p2pSprayDelay), limiter: limiter}
}

// step returns the spray indexes [lo, hi) to send this round. promoted stops
// any further sweeps: the peer already answered.
func (s *punchSpray) step(now time.Time, promoted bool) (lo, hi int) {
	if s == nil || s.sweeps <= 0 {
		return 0, 0
	}
	if promoted {
		s.sweeps = 0
		s.release()
		return 0, 0
	}
	if !s.active {
		if now.Before(s.nextAt) || !s.limiter.CompareAndSwap(false, true) {
			return 0, 0
		}
		s.active, s.next = true, 0
	}
	lo = s.next
	hi = min(lo+p2pSprayPerRound, s.size)
	s.next = hi
	if hi == s.size {
		s.sweeps--
		s.nextAt = now.Add(p2pSprayInterval)
		s.release()
	}
	return lo, hi
}

func (s *punchSpray) release() {
	if s != nil && s.active {
		s.active = false
		s.limiter.Store(false)
	}
}
