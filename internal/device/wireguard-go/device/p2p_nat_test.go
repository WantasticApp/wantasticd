package device

import (
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func udp(s string) net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return normalizeUDPAddr(*addr)
}

func TestClassifyNAT(t *testing.T) {
	for _, tc := range []struct {
		name       string
		observed   string
		local      string
		candidates []string
		want       natClass
	}{
		{"no observation", "", "192.168.1.2:51820", nil, natClassUnknown},
		{"public interface", "198.51.100.7:51820", "198.51.100.7:51820", nil, natClassPublic},
		{"port kept", "198.51.100.7:51820", "192.168.1.2:51820", nil, natClassPreserving},
		{"port rewritten (CGNAT)", "198.51.100.7:40123", "10.42.0.9:51820", nil, natClassRewriting},
		{"router port mapping", "198.51.100.7:40123", "192.168.1.2:51820",
			[]string{"198.51.100.7:40123", "198.51.100.7:51820"}, natClassMapped},
		{"listen port from IPv6 candidate", "198.51.100.7:40123", "",
			[]string{"198.51.100.7:40123", "[2408:8207::1]:51820"}, natClassRewriting},
		{"no listen port", "198.51.100.7:40123", "", nil, natClassUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observed, local net.UDPAddr
			if tc.observed != "" {
				observed = udp(tc.observed)
			}
			if tc.local != "" {
				local = udp(tc.local)
			}
			var candidates []net.UDPAddr
			for _, c := range tc.candidates {
				candidates = append(candidates, udp(c))
			}
			if got := classifyNAT(observed, local, candidates); got != tc.want {
				t.Fatalf("classifyNAT = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSprayPortsIsBoundedAndNearestFirst(t *testing.T) {
	base := udp("198.51.100.7:40000")
	exclude := []net.UDPAddr{udp("198.51.100.7:40001")}
	got := sprayPorts(base, p2pSprayFirstPorts, p2pSprayFirstPorts/4, exclude)
	if len(got) != p2pSprayFirstPorts {
		t.Fatalf("spray has %d ports, want %d", len(got), p2pSprayFirstPorts)
	}
	if got[0].Port != 39999 || got[1].Port != 40002 {
		t.Fatalf("spray does not start next to the observed port: %v %v", got[0], got[1])
	}
	below := 0
	seen := map[int]bool{}
	for _, addr := range got {
		if !addr.IP.Equal(base.IP) || addr.Port == 40000 || addr.Port == 40001 || seen[addr.Port] {
			t.Fatalf("bad spray target %v", addr)
		}
		seen[addr.Port] = true
		if addr.Port < 40000 {
			below++
		}
	}
	if below != p2pSprayFirstPorts/4 {
		t.Fatalf("%d ports below the observed one, want %d", below, p2pSprayFirstPorts/4)
	}

	// Near the bottom of the range no privileged port is sprayed.
	for _, addr := range sprayPorts(udp("198.51.100.7:1030"), p2pSprayPorts, p2pSprayPorts/2, nil) {
		if addr.Port < p2pSprayMinPort {
			t.Fatalf("sprayed privileged port %d", addr.Port)
		}
	}
}

func TestPunchSprayPacing(t *testing.T) {
	var limiter atomic.Bool
	start := time.Unix(1000, 0)
	s := newPunchSpray(70, 2, start, &limiter)
	if lo, hi := s.step(start, false); hi != lo {
		t.Fatalf("spray started before the plain punch had its head start")
	}
	now := start.Add(p2pSprayDelay)
	var sent int
	for i := 0; i < 3; i++ {
		lo, hi := s.step(now, false)
		if hi-lo > p2pSprayPerRound {
			t.Fatalf("round sent %d spray packets", hi-lo)
		}
		sent += hi - lo
	}
	if sent != 70 || limiter.Load() {
		t.Fatalf("first sweep sent %d, limiter held=%v", sent, limiter.Load())
	}
	if lo, hi := s.step(now.Add(time.Second), false); hi != lo {
		t.Fatalf("second sweep started before p2pSprayInterval")
	}

	// Another spray holding the limiter defers this one.
	limiter.Store(true)
	if lo, hi := s.step(now.Add(p2pSprayInterval), false); hi != lo {
		t.Fatalf("spray ran while another one held the limiter")
	}
	limiter.Store(false)
	if _, hi := s.step(now.Add(p2pSprayInterval), false); hi == 0 {
		t.Fatalf("second sweep did not start")
	}
	// A promotion stops the spray and frees the limiter.
	if lo, hi := s.step(now.Add(p2pSprayInterval), true); hi != lo || limiter.Load() {
		t.Fatalf("spray continued after the peer answered")
	}
	if lo, hi := s.step(now.Add(time.Minute), false); hi != lo {
		t.Fatalf("spray resumed after promotion")
	}
}

func TestBuildPunchTargetsPutsIPv6FirstWithoutPrediction(t *testing.T) {
	session := &P2PSession{
		ObservedAddr: udp("198.51.100.7:40000"),
		LocalAddr:    udp("10.42.0.9:51820"),
		CandidateAddrs: []net.UDPAddr{
			udp("198.51.100.7:40000"), udp("10.42.0.9:51820"), udp("[2408:8207::1]:51820"),
		},
		AssignedIP: net.IPv4(10, 255, 0, 2).To4(),
	}
	targets := buildPunchTargets(session, true)
	if targets[0].String() != "[2408:8207::1]:51820" {
		t.Fatalf("IPv6 is not punched first: %v", targets)
	}
	for _, target := range targets[1:] {
		if target.IP.To4() == nil {
			t.Fatalf("port prediction on IPv6: %v", targets)
		}
	}
	// IPv6, the two IPv4 bases and 12 predictions around the public one.
	if len(targets) != 1+2+12 {
		t.Fatalf("%d targets: %v", len(targets), targets)
	}
	if plain := buildPunchTargets(session, false); len(plain) != 3 {
		t.Fatalf("targets without prediction = %v", plain)
	}
}

func TestFilterLocalCandidatesIPv6AndPPPoE(t *testing.T) {
	skipPPP := p2pSkipPPP
	t.Cleanup(func() { p2pSkipPPP = skipPPP })
	ifaces := []p2pLocalInterface{
		// OpenWrt on PPPoE broadband: CGNAT IPv4, global IPv6 on the WAN.
		{name: "pppoe-wan", flags: net.FlagUp, ips: []net.IP{net.ParseIP("100.70.1.2"), net.ParseIP("2408:8207::1")}},
		{name: "br-lan", flags: net.FlagUp, ips: []net.IP{
			net.ParseIP("192.168.1.1"), net.ParseIP("fd12::1"), net.ParseIP("2408:8207:1::1"),
		}},
		// Android 464XLAT.
		{name: "v4-rmnet_data0", flags: net.FlagUp, ips: []net.IP{net.ParseIP("192.0.0.4")}},
	}
	names := func(addrs []net.UDPAddr) []string {
		var out []string
		for _, a := range addrs {
			out = append(out, a.String())
		}
		return out
	}

	p2pSkipPPP = false // Linux
	got := names(filterLocalCandidates(net.ParseIP("100.70.1.2").To4(), net.ParseIP("2408:8207::1"), ifaces, "wantastic", 51820))
	want := []string{"192.168.1.1:51820", "[2408:8207::1]:51820", "[2408:8207:1::1]:51820"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("linux candidates = %v, want %v", got, want)
	}

	// Unique-local addresses only take a slot no global address wants.
	p2pSkipPPP = true // macOS/Windows: ppp is a VPN
	got = names(filterLocalCandidates(nil, nil, ifaces, "wantastic", 51820))
	want = []string{"192.168.1.1:51820", "[2408:8207:1::1]:51820", "[fd12::1]:51820"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

func TestDirectKeepaliveDue(t *testing.T) {
	peer := &DiscoveredPeer{}
	now := time.Unix(1000, 0)
	if directKeepaliveDue(peer, 100, now) {
		t.Fatal("keepalive on first observation")
	}
	if directKeepaliveDue(peer, 100, now.Add(p2pDirectKeepalive-time.Second)) {
		t.Fatal("keepalive before the interval")
	}
	if !directKeepaliveDue(peer, 100, now.Add(p2pDirectKeepalive)) {
		t.Fatal("no keepalive after the interval without sending")
	}
	// Received traffic does not matter; only what this side sent does.
	if directKeepaliveDue(peer, 200, now.Add(2*p2pDirectKeepalive)) {
		t.Fatal("keepalive although this side just sent")
	}
}

// --- NAT simulation ---------------------------------------------------------

type simFilter int

const (
	filterEndpointIndependent simFilter = iota // full cone
	filterAddress                              // restricted cone
	filterAddressPort                          // port-restricted cone, stateful firewall
)

// simNAT is a NAT (or, with preserve and no translation, a stateful IPv6
// firewall) in front of one WireGuard socket.
type simNAT struct {
	ip       net.IP
	edm      bool // endpoint-dependent mapping ("symmetric")
	filter   simFilter
	preserve bool // a new mapping keeps the internal port when free
	alloc    func() int

	mappings map[string]int
	ports    map[int]bool
	sent     map[string]bool
}

func newSimNAT(ip string, edm bool, filter simFilter, preserve bool, alloc func() int) *simNAT {
	return &simNAT{
		ip: net.ParseIP(ip), edm: edm, filter: filter, preserve: preserve, alloc: alloc,
		mappings: map[string]int{}, ports: map[int]bool{}, sent: map[string]bool{},
	}
}

func (n *simNAT) out(internalPort int, dst net.UDPAddr) net.UDPAddr {
	key := "*"
	if n.edm {
		key = dst.String()
	}
	port, ok := n.mappings[key]
	if !ok {
		if n.preserve && !n.ports[internalPort] {
			port = internalPort
		} else {
			for port = n.alloc(); n.ports[port]; port = n.alloc() {
			}
		}
		n.mappings[key] = port
		n.ports[port] = true
	}
	n.sent[fmt.Sprintf("%d|%s", port, dst.String())] = true
	n.sent[fmt.Sprintf("%d|%s", port, dst.IP)] = true
	return net.UDPAddr{IP: n.ip, Port: port}
}

func (n *simNAT) in(src, dst net.UDPAddr) bool {
	if !dst.IP.Equal(n.ip) || !n.ports[dst.Port] {
		return false
	}
	switch n.filter {
	case filterAddress:
		return n.sent[fmt.Sprintf("%d|%s", dst.Port, src.IP)]
	case filterAddressPort:
		return n.sent[fmt.Sprintf("%d|%s", dst.Port, src.String())]
	}
	return true
}

func sequentialPorts(start, step int) func() int {
	next := start
	return func() int { p := next; next += step; return p }
}

func randomPorts(seed int64, lo, hi int) func() int {
	r := rand.New(rand.NewSource(seed))
	return func() int { return lo + r.Intn(hi-lo) }
}

type simSide struct {
	listen   int
	lan      string
	v4, v6   *simNAT
	observed net.UDPAddr
	sent     int
}

var simHub = udp("203.0.113.1:51820")

// connect maps the side's WireGuard socket to the coordinator, then lets
// background traffic take background new mappings.
func (s *simSide) connect(background int) {
	s.observed = s.v4.out(s.listen, simHub)
	for i := 0; i < background; i++ {
		s.v4.out(s.listen, net.UDPAddr{IP: net.IPv4(198, 18, byte(i>>8), byte(i)), Port: 443})
	}
}

func (s *simSide) local() net.UDPAddr {
	return udp(fmt.Sprintf("%s:%d", s.lan, s.listen))
}

func (s *simSide) candidates() []net.UDPAddr {
	out := []net.UDPAddr{s.local()}
	if s.v6 != nil {
		out = append(out, net.UDPAddr{IP: s.v6.ip, Port: s.listen})
	}
	return out
}

// sessionAbout is the session the coordinator's relay about s creates.
func (s *simSide) sessionAbout() *P2PSession {
	return &P2PSession{
		ObservedAddr:   s.observed,
		LocalAddr:      s.local(),
		CandidateAddrs: append([]net.UDPAddr{s.observed}, s.candidates()...),
		AssignedIP:     net.IPv4(10, 255, 0, 9).To4(),
	}
}

func (s *simSide) selfNAT() natClass {
	return classifyNAT(s.observed, s.local(), s.candidates())
}

func (s *simSide) natFor(dst net.UDPAddr) *simNAT {
	if dst.IP.To4() != nil {
		return s.v4
	}
	return s.v6
}

// punch sends one punch from x to dst; when it reaches y, y answers at its
// source as HandlePunch does. It reports whether that answer reached x.
func punch(x, y *simSide, dst net.UDPAddr) bool {
	x.sent++
	nx, ny := x.natFor(dst), y.natFor(dst)
	if nx == nil || ny == nil {
		return false
	}
	src := nx.out(x.listen, dst)
	if !ny.in(src, dst) {
		return false
	}
	return nx.in(ny.out(y.listen, src), src)
}

// simulatePunch runs both sides' plans with the real round cadence and spray
// scheduler for one punch timeout. It returns the family of the first
// working path ("" when none).
func simulatePunch(a, b *simSide, planA, planB punchPlan) string {
	var limA, limB atomic.Bool
	start := time.Unix(1000, 0)
	sprayA := newPunchSpray(len(planA.spray), planA.sweeps, start, &limA)
	sprayB := newPunchSpray(len(planB.spray), planB.sweeps, start, &limB)
	type side struct {
		x, y  *simSide
		plan  punchPlan
		spray *punchSpray
	}
	sides := []side{{a, b, planA, sprayA}, {b, a, planB, sprayB}}
	now := start
	for round := 0; now.Before(start.Add(p2pPunchTimeout)); round++ {
		for _, s := range sides {
			send := append([]net.UDPAddr(nil), s.plan.targets...)
			lo, hi := s.spray.step(now, false)
			send = append(send, s.plan.spray[lo:hi]...)
			for _, dst := range send {
				if punch(s.x, s.y, dst) {
					if dst.IP.To4() == nil {
						return "ipv6"
					}
					return "ipv4"
				}
			}
		}
		now = now.Add(p2pPunchInterval(round))
	}
	return ""
}

func homeRouter(ip string) *simSide {
	return &simSide{listen: 51820, lan: "192.168.1.20",
		v4: newSimNAT(ip, false, filterAddressPort, true, randomPorts(7, 1024, 65535))}
}

func carrierNAT(ip string, edm bool, alloc func() int) *simSide {
	return &simSide{listen: 51820, lan: "10.42.0.9",
		v4: newSimNAT(ip, edm, filterAddressPort, false, alloc)}
}

func withIPv6(s *simSide, ip string) *simSide {
	s.v6 = newSimNAT(ip, false, filterAddressPort, true, nil)
	return s
}

// TestPunchStrategyAgainstSimulatedNATs shows which pairs get a direct path
// with the strategy (and which the previous fixed target list missed).
func TestPunchStrategyAgainstSimulatedNATs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		a, b       func() *simSide
		background int // mappings b's NAT made after its coordinator mapping
		attempt    int
		want       string // path the strategy finds
		legacy     string // path the previous target list found
	}{
		{
			name:       "home router vs CGNAT symmetric sequential",
			a:          func() *simSide { return homeRouter("198.51.100.7") },
			b:          func() *simSide { return carrierNAT("112.96.1.1", true, sequentialPorts(30000, 1)) },
			background: 40,
			want:       "ipv4", legacy: "",
		},
		{
			name:       "home router vs CGNAT symmetric random in a 128-port block, retry",
			a:          func() *simSide { return homeRouter("198.51.100.7") },
			b:          func() *simSide { return carrierNAT("112.96.1.1", true, randomPorts(3, 30080, 30208)) },
			background: 20, attempt: 1,
			want: "ipv4", legacy: "",
		},
		{
			name:   "home router vs CGNAT cone with a rewritten port (NAT3)",
			a:      func() *simSide { return homeRouter("198.51.100.7") },
			b:      func() *simSide { return carrierNAT("112.96.1.1", false, randomPorts(5, 1024, 65535)) },
			want:   "ipv4",
			legacy: "ipv4",
		},
		{
			name: "two symmetric CGNATs with IPv6",
			a: func() *simSide {
				return withIPv6(carrierNAT("112.96.1.1", true, randomPorts(1, 1024, 65535)), "2408:8207::1")
			},
			b: func() *simSide {
				return withIPv6(carrierNAT("117.136.2.2", true, randomPorts(2, 1024, 65535)), "2409:8a00::2")
			},
			want: "ipv6", legacy: "ipv6",
		},
		{
			name: "two symmetric CGNATs, IPv4 only (relay)",
			a:    func() *simSide { return carrierNAT("112.96.1.1", true, randomPorts(1, 1024, 65535)) },
			b:    func() *simSide { return carrierNAT("117.136.2.2", true, randomPorts(2, 1024, 65535)) },
			want: "", legacy: "",
		},
		{
			name: "home router vs CGNAT symmetric random over the whole range (relay)",
			a:    func() *simSide { return homeRouter("198.51.100.7") },
			b:    func() *simSide { return carrierNAT("112.96.1.1", true, randomPorts(9, 1024, 65535)) },
			want: "", legacy: "",
		},
		{
			name: "two home routers",
			a:    func() *simSide { return homeRouter("198.51.100.7") },
			b: func() *simSide {
				s := homeRouter("203.0.113.50")
				s.lan = "192.168.0.5"
				return s
			},
			want: "ipv4", legacy: "ipv4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(legacy bool) (string, *simSide, *simSide, punchPlan, punchPlan) {
				a, b := tc.a(), tc.b()
				a.connect(0)
				b.connect(tc.background)
				var planA, planB punchPlan
				if legacy {
					planA = punchPlan{targets: buildPunchTargets(b.sessionAbout(), true)}
					planB = punchPlan{targets: buildPunchTargets(a.sessionAbout(), true)}
				} else {
					planA = planPunch(b.sessionAbout(), a.selfNAT(), tc.attempt)
					planB = planPunch(a.sessionAbout(), b.selfNAT(), tc.attempt)
				}
				return simulatePunch(a, b, planA, planB), a, b, planA, planB
			}
			got, a, b, planA, planB := run(false)
			if got != tc.want {
				t.Fatalf("strategy path = %q, want %q (a=%s/%s spray=%d, b=%s/%s spray=%d)",
					got, tc.want, planA.self, planA.peer, len(planA.spray), planB.self, planB.peer, len(planB.spray))
			}
			if legacy, _, _, _, _ := run(true); legacy != tc.legacy {
				t.Fatalf("previous target list path = %q, want %q", legacy, tc.legacy)
			}
			// Bounded: a port-rewriting side never sprays (each packet
			// would cost it a carrier port), and no side sends more than
			// its rounds of plain targets plus the bounded sweeps.
			for _, p := range []punchPlan{planA, planB} {
				if len(p.spray) > 0 && !p.self.stableSource() {
					t.Fatalf("%s side sprays", p.self)
				}
				if len(p.spray) > p2pSprayPorts || p.sweeps > p2pSpraySweeps {
					t.Fatalf("spray %d ports x %d sweeps exceeds bounds", len(p.spray), p.sweeps)
				}
			}
			for _, s := range []*simSide{a, b} {
				if limit := 200*(1+p2pMaxPredictedTargets+2) + p2pSpraySweeps*p2pSprayPorts; s.sent > limit {
					t.Fatalf("side sent %d punches, more than %d", s.sent, limit)
				}
			}
		})
	}
}

func TestPlanPunchRoles(t *testing.T) {
	cgnat := carrierNAT("112.96.1.1", true, sequentialPorts(30000, 1))
	home := homeRouter("198.51.100.7")
	cgnat.connect(0)
	home.connect(0)

	// The strict side aims only at the easy side's endpoints, observed
	// first, and predicts nothing (each extra destination would cost it a
	// fresh carrier port).
	strict := planPunch(home.sessionAbout(), cgnat.selfNAT(), 0)
	if strict.self != natClassRewriting || strict.peer != natClassPreserving || len(strict.spray) != 0 {
		t.Fatalf("strict plan: %s/%s spray=%d", strict.self, strict.peer, len(strict.spray))
	}
	if len(strict.targets) != 2 || strict.targets[0].String() != home.observed.String() {
		t.Fatalf("strict targets = %v", strict.targets)
	}

	// The easy side sprays the strict side's port neighbourhood.
	easy := planPunch(cgnat.sessionAbout(), home.selfNAT(), 0)
	if len(easy.spray) != p2pSprayFirstPorts || easy.sweeps != p2pSpraySweeps {
		t.Fatalf("easy plan spray=%d sweeps=%d", len(easy.spray), easy.sweeps)
	}
	if retry := planPunch(cgnat.sessionAbout(), home.selfNAT(), 1); len(retry.spray) != p2pSprayPorts {
		t.Fatalf("retry spray = %d", len(retry.spray))
	}
	// Spraying stops after p2pSprayMaxAttempts failures.
	if late := planPunch(cgnat.sessionAbout(), home.selfNAT(), p2pSprayMaxAttempts); len(late.spray) != 0 {
		t.Fatalf("spray after %d attempts", p2pSprayMaxAttempts)
	}
	// Unknown own NAT (no RegisterAck yet): no spray.
	if unknown := planPunch(cgnat.sessionAbout(), natClassUnknown, 0); len(unknown.spray) != 0 {
		t.Fatal("spray without knowing this side's NAT")
	}
}
