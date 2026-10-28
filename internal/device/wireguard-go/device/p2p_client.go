package device

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"

	"golang.org/x/crypto/blake2s"
)

const (
	p2pPunchTimeout        = 18 * time.Second
	p2pStalledAttemptTTL   = 30 * time.Second
	p2pRetryBaseDelay      = 15 * time.Second
	p2pRetryMaxDelay       = 2 * time.Minute
	p2pMaxPredictedTargets = 16
	p2pMaxPeerListEntries  = 4096
	p2pControlQueueSize    = 256
	p2pAttemptQueueSize    = 256
	p2pPunchQueueSize      = 128
	p2pPromotionQueueSize  = 128
	p2pPunchWorkers        = 4
	p2pPromotionWorkers    = 2
	p2pAttemptGateInterval = 2 * time.Second
	p2pHandshakeTimeout    = 20 * time.Second
	p2pHandshakePoll       = 50 * time.Millisecond
	p2pDirectStaleAfter    = 4 * time.Minute

	// p2pPeerForgetAfter drops discovery entries the coordinator stopped
	// listing; it lists peers seen within 5 minutes.
	p2pPeerForgetAfter = 10 * time.Minute
	// p2pReregisterInterval re-announces candidates so a restarted
	// coordinator relearns them without waiting for an ID change.
	p2pReregisterInterval = 60 * time.Second
	// p2pPunchReplyInterval rate-limits answers to authenticated punches.
	p2pPunchReplyInterval = 100 * time.Millisecond
	// p2pResponderFallback is how long the side that waits for the peer's
	// handshake initiation waits before initiating itself.
	p2pResponderFallback = 3 * time.Second
	// p2pNonceGrace is the window in which a second relay for the same peer
	// (both sides asked at once) joins the running session instead of
	// restarting it.
	p2pNonceGrace = 2 * time.Second
	// p2pEstablishedRelayGrace ignores a relay that races the promotion it
	// belongs to; a later relay means the peer lost the direct path.
	p2pEstablishedRelayGrace = 5 * time.Second
	p2pMaxIPv6Candidates     = 2
)

type P2PClient struct {
	device *Device

	// extraCandidates are reachable addresses found outside the interface
	// list (a router port mapping); reregister asks the maintenance loop to
	// announce a changed set.
	extraCandidates atomic.Pointer[[]net.UDPAddr]
	reregister      atomic.Bool
	lastRegister    atomic.Int64

	myID          uint32
	myPublicKey   NoisePublicKey
	serverPeerKey NoisePublicKey
	localAddr     net.UDPAddr
	observedAddr  net.UDPAddr

	peers    map[uint32]*DiscoveredPeer
	mu       sync.RWMutex
	sessions map[uint32]*P2PSession

	peerKeyIndex   map[NoisePublicKey]uint32
	attemptGates   map[uint32]*atomic.Int64
	sessionByNonce map[[8]byte]*P2PSession
	destinations   atomic.Pointer[p2pDestinationIndex]

	ctx       context.Context
	cancel    context.CancelFunc
	startOnce sync.Once
	closeOnce sync.Once
	workers   sync.WaitGroup

	controlQueue   chan p2pControlEvent
	attemptQueue   chan uint32
	punchQueue     chan p2pPunchJob
	promotionQueue chan p2pPromotionJob

	droppedControl  atomic.Uint64
	droppedAttempts atomic.Uint64
}

type DiscoveredPeer struct {
	ID             uint32
	PublicKey      NoisePublicKey
	LocalAddr      net.UDPAddr
	ObservedAddr   net.UDPAddr
	CandidateAddrs []net.UDPAddr
	NATType        NATType
	P2PCapable     bool

	State         P2PState
	DirectConn    *net.UDPConn
	Endpoint      conn.Endpoint
	RelayPeer     *Peer
	LastUsed      time.Time
	LastSeen      time.Time
	EstablishedAt time.Time
	AssignedIP    net.IP
	PunchAttempts int
}

type P2PState int

const (
	P2PStateDiscovered P2PState = iota
	P2PStateTrying
	P2PStateEstablished
	P2PStateFailed
)

type NATType int

const (
	NATUnknown NATType = iota
	NATNone
	NATFullCone
	NATRestricted
	NATPortRestricted
	NATSymmetric
)

type P2PSession struct {
	TargetID       uint32
	TargetPubKey   NoisePublicKey
	LocalAddr      net.UDPAddr
	ObservedAddr   net.UDPAddr
	CandidateAddrs []net.UDPAddr
	AssignedIP     net.IP
	Nonce          [8]byte
	Established    bool
	Promoting      bool
	done           chan struct{}
	doneOnce       sync.Once

	// altNonce is the nonce of a second relay for the same pair that arrived
	// within p2pNonceGrace; punches carrying it are accepted too.
	altNonce    [8]byte
	hasAltNonce bool
	createdAt   time.Time
	promotedAt  time.Time
	lastReply   time.Time
}

func (s *P2PSession) acceptsNonce(nonce [8]byte) bool {
	return nonce == s.Nonce || (s.hasAltNonce && nonce == s.altNonce)
}

type p2pDestinationIndex struct {
	byIP map[netip.Addr]p2pDestination
}

type p2pDestination struct {
	peerID uint32
	gate   *atomic.Int64
}

type p2pControlEvent struct {
	message *P2PMessage
	punch   [41]byte
	addr    net.UDPAddr
}

type p2pPunchJob struct {
	peerID  uint32
	session *P2PSession
	packet  []byte
	targets []conn.Endpoint
}

type p2pPromotionJob struct {
	peerID     uint32
	session    *P2PSession
	publicKey  NoisePublicKey
	assignedIP net.IP
	endpoint   conn.Endpoint
	relayPeer  *Peer
	startedAt  time.Time
}

func normalizeUDPAddr(addr net.UDPAddr) net.UDPAddr {
	if ip4 := addr.IP.To4(); ip4 != nil {
		addr.IP = append(net.IP(nil), ip4...)
		return addr
	}
	if ip16 := addr.IP.To16(); ip16 != nil {
		addr.IP = append(net.IP(nil), ip16...)
	}
	return addr
}

func isUsablePunchAddr(addr net.UDPAddr) bool {
	if addr.Port <= 0 || addr.IP == nil {
		return false
	}
	ip := addr.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return !ip.IsUnspecified()
}

func NewP2PClient(device *Device, serverKeys ...NoisePublicKey) *P2PClient {
	ctx, cancel := context.WithCancel(context.Background())
	client := &P2PClient{
		device:         device,
		peers:          make(map[uint32]*DiscoveredPeer),
		sessions:       make(map[uint32]*P2PSession),
		peerKeyIndex:   make(map[NoisePublicKey]uint32),
		attemptGates:   make(map[uint32]*atomic.Int64),
		sessionByNonce: make(map[[8]byte]*P2PSession),
		ctx:            ctx,
		cancel:         cancel,
		controlQueue:   make(chan p2pControlEvent, p2pControlQueueSize),
		attemptQueue:   make(chan uint32, p2pAttemptQueueSize),
		punchQueue:     make(chan p2pPunchJob, p2pPunchQueueSize),
		promotionQueue: make(chan p2pPromotionJob, p2pPromotionQueueSize),
		myPublicKey:    device.staticIdentity.publicKey,
	}
	if len(serverKeys) > 0 {
		client.serverPeerKey = serverKeys[0]
	}
	client.destinations.Store(&p2pDestinationIndex{byIP: make(map[netip.Addr]p2pDestination)})
	return client
}

func (c *P2PClient) Start() {
	c.startOnce.Do(func() {
		c.startWorker(c.controlWorker)
		c.startWorker(c.attemptWorker)
		for range p2pPunchWorkers {
			c.startWorker(c.punchWorker)
		}
		for range p2pPromotionWorkers {
			c.startWorker(c.promotionWorker)
		}
		c.startWorker(c.maintenanceLoop)
		c.register()
	})
}

func (c *P2PClient) startWorker(worker func()) {
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		worker()
	}()
}

// Close stops every P2P goroutine. It is safe to call more than once.
func (c *P2PClient) Close() {
	c.closeOnce.Do(func() {
		c.cancel()
		c.mu.Lock()
		for _, session := range c.sessions {
			session.signalDone()
		}
		c.mu.Unlock()
		c.workers.Wait()
	})
}

func (s *P2PSession) signalDone() {
	if s == nil || s.done == nil {
		return
	}
	s.doneOnce.Do(func() { close(s.done) })

}

// EnqueueMessage bounds untrusted control-plane work instead of creating one
// goroutine per datagram.
func (c *P2PClient) EnqueueMessage(msg *P2PMessage) bool {
	if msg == nil {
		return false
	}
	select {
	case <-c.ctx.Done():
		return false
	case c.controlQueue <- p2pControlEvent{message: msg}:
		return true
	default:
		c.droppedControl.Add(1)
		return false
	}
}

// EnqueuePunch copies the fixed-size authenticated punch into a bounded queue.
func (c *P2PClient) EnqueuePunch(packet []byte, addr *net.UDPAddr) bool {
	if len(packet) != 41 || addr == nil {
		return false
	}
	event := p2pControlEvent{addr: normalizeUDPAddr(*addr)}
	copy(event.punch[:], packet)
	select {
	case <-c.ctx.Done():
		return false
	case c.controlQueue <- event:
		return true
	default:
		c.droppedControl.Add(1)
		return false
	}

}

func (c *P2PClient) controlWorker() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case event := <-c.controlQueue:
			if event.message != nil {
				c.HandleMessage(event.message)
				continue
			}
			c.HandlePunch(event.punch[:], &event.addr)
		}
	}

}

func (c *P2PClient) attemptWorker() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case peerID := <-c.attemptQueue:
			c.tryP2PByID(peerID)
		}
	}
}

func (c *P2PClient) getDefaultLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if ip4 := localAddr.IP.To4(); ip4 != nil {
			return append(net.IP(nil), ip4...)
		}
		return append(net.IP(nil), localAddr.IP...)
	}
	return nil
}

// p2pLocalInterface is the subset of an interface candidate collection needs.
type p2pLocalInterface struct {
	name  string
	flags net.Flags
	ips   []net.IP
}

// p2pSkippedInterfacePrefixes are tunnels and bridges whose addresses are
// unreachable for a peer on another network: announcing them only spends
// punch targets.
var p2pSkippedInterfacePrefixes = []string{"utun", "ipsec", "ppp", "bridge", "tailscale", "wg"}

var p2pSharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func (c *P2PClient) collectLocalCandidates(port int) []net.UDPAddr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	local := make([]p2pLocalInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := p2pLocalInterface{name: iface.Name, flags: iface.Flags}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				entry.ips = append(entry.ips, v.IP)
			case *net.IPAddr:
				entry.ips = append(entry.ips, v.IP)
			}
		}
		local = append(local, entry)
	}
	return filterLocalCandidates(c.getDefaultLocalIP(), local, c.tunName(), port)
}

func (c *P2PClient) tunName() string {
	if c.device == nil || c.device.tun.device == nil {
		return ""
	}
	name, err := c.device.tun.device.Name()
	if err != nil {
		return ""
	}
	return name
}

// filterLocalCandidates keeps addresses a peer could plausibly reach: the
// default-route address first (when it belongs to an eligible interface),
// then other interface addresses, with at most p2pMaxIPv6Candidates IPv6.
func filterLocalCandidates(defaultIP net.IP, ifaces []p2pLocalInterface, ownTun string, port int) []net.UDPAddr {
	eligible := make([]net.IP, 0, 4)
	for _, iface := range ifaces {
		if iface.flags&net.FlagUp == 0 || iface.flags&net.FlagLoopback != 0 || isSkippedCandidateInterface(iface.name, ownTun) {
			continue
		}
		for _, ip := range iface.ips {
			if isUsefulLocalCandidateIP(ip) {
				eligible = append(eligible, ip)
			}
		}
	}

	candidates := make([]net.UDPAddr, 0, 4)
	if defaultIP != nil {
		for _, ip := range eligible {
			if ip.Equal(defaultIP) {
				appendPunchCandidate(&candidates, net.UDPAddr{IP: ip, Port: port}, nil)
				break
			}
		}
	}
	ipv6 := 0
	for _, candidate := range candidates {
		if candidate.IP.To4() == nil {
			ipv6++
		}
	}
	for _, ip := range eligible {
		if ip.To4() == nil {
			if ipv6 >= p2pMaxIPv6Candidates {
				continue
			}
			before := len(candidates)
			appendPunchCandidate(&candidates, net.UDPAddr{IP: ip, Port: port}, nil)
			if len(candidates) > before {
				ipv6++
			}
			continue
		}
		appendPunchCandidate(&candidates, net.UDPAddr{IP: ip, Port: port}, nil)
	}
	return candidates
}

func isSkippedCandidateInterface(name, ownTun string) bool {
	if name == "" {
		return false
	}
	if ownTun != "" && name == ownTun {
		return true
	}
	lower := strings.ToLower(name)
	for _, prefix := range p2pSkippedInterfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isUsefulLocalCandidateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		ip = ip.To16()
	}
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Carrier-grade NAT and overlay (Tailscale-style) space is never a path
	// another site can reach directly.
	if addr, ok := netip.AddrFromSlice(ip); ok && p2pSharedAddressSpace.Contains(addr.Unmap()) {
		return false
	}
	return true
}

// SetExtraCandidates replaces the extra reachable addresses (e.g. a router
// port mapping) and announces them on the next maintenance tick.
func (c *P2PClient) SetExtraCandidates(addrs []net.UDPAddr) {
	copied := append([]net.UDPAddr(nil), addrs...)
	c.extraCandidates.Store(&copied)
	c.reregister.Store(true)
}

func (c *P2PClient) register() {
	c.device.net.RLock()
	port := int(c.device.net.port)
	c.device.net.RUnlock()

	candidates := c.collectLocalCandidates(port)
	if extra := c.extraCandidates.Load(); extra != nil {
		for _, candidate := range *extra {
			appendPunchCandidate(&candidates, candidate, nil)
		}
	}
	var localAddr net.UDPAddr
	if len(candidates) > 0 {
		localAddr = candidates[0]
	} else {
		localAddr = net.UDPAddr{IP: net.IPv4zero, Port: port}
	}
	c.mu.Lock()
	c.localAddr = localAddr
	c.mu.Unlock()

	msg := &P2PMessage{
		Subtype: P2PSubtypeRegister,
		Payload: EncodeP2PCandidatePayload(candidates),
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	msg.SetLocalAddr(&localAddr)

	c.device.log.Verbosef("[P2P] Registering with server using local=%v candidates=%d", localAddr, len(candidates))
	c.lastRegister.Store(time.Now().UnixNano())
	c.sendToServer(msg)
}

// registerDue reports whether the maintenance loop should register again:
// until the coordinator assigned an ID, when the candidate set changed, and
// periodically so a restarted coordinator relearns LAN and port-mapped
// candidates (Register is idempotent on the hub).
func (c *P2PClient) registerDue(now time.Time) bool {
	c.mu.RLock()
	myID := c.myID
	c.mu.RUnlock()
	if myID == 0 {
		return true
	}
	if c.reregister.Swap(false) {
		return true
	}
	return now.Sub(time.Unix(0, c.lastRegister.Load())) >= p2pReregisterInterval
}

func (c *P2PClient) HandleMessage(msg *P2PMessage) {
	switch msg.Subtype {
	case P2PSubtypeRegisterAck:
		c.handleRegisterAck(msg)
	case P2PSubtypePeerList:
		c.handlePeerList(msg)
	case P2PSubtypePunchRelay:
		c.handlePunchRelay(msg)
	case P2PSubtypeHeartbeat:
	}
}

func (c *P2PClient) handleRegisterAck(msg *P2PMessage) {
	c.mu.Lock()
	previousID := c.myID
	c.myID = msg.TargetID
	c.observedAddr = normalizeUDPAddr(msg.ObservedAddr())
	observedAddr := c.observedAddr
	c.mu.Unlock()

	if previousID != 0 && previousID != msg.TargetID {
		c.device.log.Verbosef("[P2P] Coordinator renumbered this device %d -> %d (coordinator restart)", previousID, msg.TargetID)
	}
	c.device.log.Verbosef("[P2P] Registered with server. My ID: %d observed=%v", msg.TargetID, observedAddr)
	c.requestPeerList()
}

func (c *P2PClient) requestPeerList() {
	msg := &P2PMessage{Subtype: P2PSubtypePeerList}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	c.sendToServer(msg)
}

func (c *P2PClient) handlePeerList(msg *P2PMessage) {
	if len(msg.Payload) < 4 {
		return
	}
	count := binary.BigEndian.Uint32(msg.Payload[0:4])
	if count > p2pMaxPeerListEntries || uint64(len(msg.Payload)) < 4+uint64(count)*78 {
		return
	}

	now := time.Now()
	c.mu.Lock()
	if c.peers == nil {
		c.peers = make(map[uint32]*DiscoveredPeer)
	}
	if c.peerKeyIndex == nil {
		c.peerKeyIndex = make(map[NoisePublicKey]uint32)
	}
	if c.attemptGates == nil {
		c.attemptGates = make(map[uint32]*atomic.Int64)
	}
	renumbered := false
	offset := 4
	for i := uint32(0); i < count; i++ {
		peerID := binary.BigEndian.Uint32(msg.Payload[offset:])
		var publicKey NoisePublicKey
		copy(publicKey[:], msg.Payload[offset+4:offset+36])
		localAddr := normalizeUDPAddr(net.UDPAddr{
			IP:   append(net.IP(nil), msg.Payload[offset+36:offset+52]...),
			Port: int(binary.BigEndian.Uint16(msg.Payload[offset+52:])),
		})
		observedAddr := normalizeUDPAddr(net.UDPAddr{
			IP:   append(net.IP(nil), msg.Payload[offset+54:offset+70]...),
			Port: int(binary.BigEndian.Uint16(msg.Payload[offset+70:])),
		})
		assignedIP := append(net.IP(nil), msg.Payload[offset+74:offset+78]...)

		// Do not let a recycled ID silently replace an active authenticated
		// session. A later maintenance refresh can rediscover it safely.
		if peer := c.peers[peerID]; peer != nil && !peer.PublicKey.IsZero() && !publicKey.IsZero() &&
			!peer.PublicKey.Equals(publicKey) && (peer.State == P2PStateTrying || peer.State == P2PStateEstablished) {
			offset += 78
			continue
		}
		if c.renumberPeerLocked(publicKey, peerID) {
			renumbered = true
		}

		peer, ok := c.peers[peerID]
		if !ok {
			peer = &DiscoveredPeer{
				ID:       peerID,
				State:    P2PStateDiscovered,
				LastUsed: now,
			}
			c.peers[peerID] = peer
		}

		peer.PublicKey = publicKey
		peer.LocalAddr = localAddr
		peer.ObservedAddr = observedAddr
		peer.NATType = NATType(msg.Payload[offset+72])
		peer.P2PCapable = msg.Payload[offset+73] == 1
		peer.AssignedIP = assignedIP
		peer.LastSeen = now
		if _, ok := c.attemptGates[peerID]; !ok {
			c.attemptGates[peerID] = new(atomic.Int64)
		}
		if !publicKey.IsZero() {
			c.peerKeyIndex[publicKey] = peerID
		}
		offset += 78
	}

	c.rebuildIndexesLocked()
	c.mu.Unlock()

	if renumbered {
		// Peers moving to new IDs means the coordinator restarted and lost
		// our candidates as well.
		c.reregister.Store(true)
	}
	c.device.log.Verbosef("[P2P] Discovered %d peers", count)
}

// renumberPeerLocked moves the entry known for publicKey to newID when the
// coordinator assigned that key a new ID (it renumbers after a restart or an
// idle expiry). The stale ID is dropped: punch requests to it would be
// silently discarded by the coordinator, and two entries for one VPN IP make
// the destination index pick either. An established direct path survives the
// move because the WireGuard peer is keyed by public key, not coordinator ID.
func (c *P2PClient) renumberPeerLocked(publicKey NoisePublicKey, newID uint32) bool {
	if publicKey.IsZero() {
		return false
	}
	oldID, ok := c.peerKeyIndex[publicKey]
	if !ok || oldID == newID {
		return false
	}
	old := c.peers[oldID]
	delete(c.peerKeyIndex, publicKey)
	if old == nil || !old.PublicKey.Equals(publicKey) {
		return false
	}
	c.discardSessionLocked(oldID)
	if replaced := c.peers[newID]; replaced != nil {
		c.discardSessionLocked(newID)
	}
	delete(c.peers, oldID)
	if old.State == P2PStateTrying {
		// The attempt was addressed to the stale ID; let traffic start a new
		// one against the current ID.
		old.State = P2PStateDiscovered
	}
	old.ID = newID
	c.peers[newID] = old
	if gate := c.attemptGates[oldID]; gate != nil {
		c.attemptGates[newID] = gate
		delete(c.attemptGates, oldID)
	}
	c.peerKeyIndex[publicKey] = newID
	c.device.log.Verbosef("[P2P] Peer %d renumbered to %d by the coordinator", oldID, newID)
	return true
}

// forgetUnlistedPeersLocked drops discovery entries the coordinator has not
// listed for p2pPeerForgetAfter. Active attempts and direct paths are left to
// their own timeouts.
func (c *P2PClient) forgetUnlistedPeersLocked(now time.Time) bool {
	changed := false
	for id, peer := range c.peers {
		if peer.State == P2PStateTrying || peer.State == P2PStateEstablished ||
			peer.LastSeen.IsZero() || now.Sub(peer.LastSeen) <= p2pPeerForgetAfter {
			continue
		}
		c.discardSessionLocked(id)
		delete(c.peers, id)
		delete(c.attemptGates, id)
		changed = true
	}
	return changed
}

// rebuildIndexesLocked publishes immutable lookup tables for packet-path
// readers. Peers already negotiating or established are intentionally absent
// from destinations: their packets must not pay for time reads, atomics, or
// redundant negotiation attempts.
func (c *P2PClient) rebuildIndexesLocked() {
	if c.attemptGates == nil {
		c.attemptGates = make(map[uint32]*atomic.Int64)
	}
	peerKeyIndex := make(map[NoisePublicKey]uint32, len(c.peers))
	destinationIndex := &p2pDestinationIndex{
		byIP: make(map[netip.Addr]p2pDestination, len(c.peers)),
	}
	for _, peer := range c.peers {
		if !peer.PublicKey.IsZero() {
			peerKeyIndex[peer.PublicKey] = peer.ID
		}
		if !peer.P2PCapable || peer.State == P2PStateTrying || peer.State == P2PStateEstablished ||
			(!c.serverPeerKey.IsZero() && peer.PublicKey.Equals(c.serverPeerKey)) {
			continue
		}
		addr, ok := ipv4Netip(peer.AssignedIP)
		if !ok {
			continue
		}
		gate := c.attemptGates[peer.ID]
		if gate == nil {
			gate = new(atomic.Int64)
			c.attemptGates[peer.ID] = gate
		}
		destinationIndex.byIP[addr] = p2pDestination{peerID: peer.ID, gate: gate}
	}
	c.peerKeyIndex = peerKeyIndex
	c.destinations.Store(destinationIndex)
}

func (c *P2PClient) setRetryGateLocked(peer *DiscoveredPeer) {
	if peer == nil || c.attemptGates == nil {
		return
	}
	if gate := c.attemptGates[peer.ID]; gate != nil {
		gate.Store(peer.LastUsed.Add(p2pRetryDelay(peer.PunchAttempts)).UnixNano())
	}
}

func ipv4Netip(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ip4)), true
}

func (c *P2PClient) TryP2P(peerID uint32) bool {
	return c.tryP2PByID(peerID)
}

// ObserveDestination is called from the TUN hot path. It performs only a
// lock-free immutable-map lookup and an atomic cooldown check. The first
// packet keeps using the relay while a bounded worker negotiates a direct
// path; it is never delayed by hole punching.
func (c *P2PClient) ObserveDestination(dst []byte) {
	index := c.destinations.Load()
	if index == nil {
		return
	}
	var addr netip.Addr
	switch len(dst) {
	case net.IPv4len:
		addr = netip.AddrFrom4([4]byte(dst))
	case net.IPv6len:
		addr = netip.AddrFrom16([16]byte(dst))
	default:
		return
	}
	destination, ok := index.byIP[addr]
	if !ok || destination.gate == nil {
		return
	}

	now := time.Now()
	next := destination.gate.Load()
	if next > now.UnixNano() || !destination.gate.CompareAndSwap(next, now.Add(p2pAttemptGateInterval).UnixNano()) {
		return
	}
	if !c.queueP2PAttempt(destination.peerID) {
		destination.gate.Store(now.UnixNano())
	}
}

func (c *P2PClient) queueP2PAttempt(peerID uint32) bool {
	if c.ctx == nil || c.attemptQueue == nil {
		return false
	}
	select {
	case <-c.ctx.Done():
		return false
	case c.attemptQueue <- peerID:
		return true
	default:
		c.droppedAttempts.Add(1)
		return false
	}
}

func (c *P2PClient) tryP2PByID(peerID uint32) bool {
	c.mu.Lock()
	peer, ok := c.peers[peerID]
	if !ok || !peer.P2PCapable || peer.PublicKey.IsZero() ||
		len(peer.AssignedIP.To4()) != net.IPv4len || peer.PublicKey.Equals(c.serverPeerKey) {
		c.mu.Unlock()
		return false
	}
	now := time.Now()
	switch peer.State {
	case P2PStateEstablished, P2PStateTrying:
		c.mu.Unlock()
		return true
	case P2PStateFailed:
		retryAt := peer.LastUsed.Add(p2pRetryDelay(peer.PunchAttempts))
		if now.Before(retryAt) {
			if gate := c.attemptGates[peer.ID]; gate != nil {
				gate.Store(retryAt.UnixNano())
			}
			c.mu.Unlock()
			return false
		}
	}
	peer.State = P2PStateTrying
	peer.LastUsed = now
	c.rebuildIndexesLocked()
	c.mu.Unlock()

	msg := &P2PMessage{
		Subtype:  P2PSubtypePunchRequest,
		TargetID: peerID,
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	c.sendToServer(msg)
	return true
}

func (c *P2PClient) handlePunchRelay(msg *P2PMessage) {
	targetID := msg.TargetID
	now := time.Now()

	var relayedPubKey NoisePublicKey
	copy(relayedPubKey[:], msg.PublicKey[:])

	c.mu.Lock()
	if c.peers == nil {
		c.peers = make(map[uint32]*DiscoveredPeer)
	}
	if c.sessions == nil {
		c.sessions = make(map[uint32]*P2PSession)
	}
	if c.sessionByNonce == nil {
		c.sessionByNonce = make(map[[8]byte]*P2PSession)
	}
	if c.peerKeyIndex == nil {
		c.peerKeyIndex = make(map[NoisePublicKey]uint32)
	}
	if existing := c.peers[targetID]; !relayedPubKey.IsZero() &&
		(existing == nil || existing.PublicKey.IsZero() || existing.PublicKey.Equals(relayedPubKey)) {
		c.renumberPeerLocked(relayedPubKey, targetID)
	}
	peer, ok := c.peers[targetID]
	if !ok {
		peer = &DiscoveredPeer{ID: targetID, P2PCapable: true}
		c.peers[targetID] = peer
	}
	peer.LastSeen = now

	var teardown *p2pDirectTeardown
	if peer.State == P2PStateEstablished {
		// A relay racing the promotion it belongs to (both sides asked at
		// once) is noise. A later one means the peer lost the direct path
		// and is punching again: answering from a direct peer it no longer
		// reaches would leave both sides stuck, so return to the relay and
		// join the new attempt.
		if now.Sub(peer.EstablishedAt) < p2pEstablishedRelayGrace ||
			(!relayedPubKey.IsZero() && !peer.PublicKey.Equals(relayedPubKey)) {
			c.mu.Unlock()
			return
		}
		teardown = &p2pDirectTeardown{
			publicKey:  peer.PublicKey,
			assignedIP: append(net.IP(nil), peer.AssignedIP...),
			relayPeer:  peer.RelayPeer,
		}
		peer.Endpoint = nil
		peer.RelayPeer = nil
		peer.State = P2PStateTrying
	}

	if !relayedPubKey.IsZero() {
		if peer.PublicKey.IsZero() {
			peer.PublicKey = relayedPubKey
		} else if !peer.PublicKey.Equals(relayedPubKey) {
			peer.State = P2PStateFailed
			peer.LastUsed = now
			peer.PunchAttempts++
			c.setRetryGateLocked(peer)
			c.rebuildIndexesLocked()
			c.mu.Unlock()
			c.device.log.Errorf("[P2P] Punch relay key mismatch for target %d", targetID)
			return
		}
	}
	if peer.PublicKey.IsZero() {
		peer.State = P2PStateFailed
		peer.LastUsed = now
		peer.PunchAttempts++
		c.setRetryGateLocked(peer)
		c.rebuildIndexesLocked()
		c.mu.Unlock()
		c.device.log.Verbosef("[P2P] Punch relay missing public key for target %d", targetID)
		return
	}
	if !c.serverPeerKey.IsZero() && peer.PublicKey.Equals(c.serverPeerKey) {
		peer.State = P2PStateFailed
		peer.LastUsed = now
		peer.PunchAttempts++
		c.setRetryGateLocked(peer)
		c.rebuildIndexesLocked()
		c.mu.Unlock()
		c.device.log.Errorf("[P2P] Refusing punch relay that targets the coordinator key")
		return
	}

	// When both sides request a punch at once the coordinator relays twice,
	// possibly with different nonces, and the two relays may arrive in either
	// order on each side. Keep the young session running and accept the
	// second nonce as well, so whichever nonce the peer settles on still
	// authenticates here.
	if current := c.sessions[targetID]; teardown == nil && current != nil &&
		now.Sub(current.createdAt) < p2pNonceGrace && current.TargetPubKey.Equals(peer.PublicKey) {
		if current.Nonce != msg.Nonce && !(current.hasAltNonce && current.altNonce == msg.Nonce) {
			if current.hasAltNonce {
				delete(c.sessionByNonce, current.altNonce)
			}
			current.altNonce = msg.Nonce
			current.hasAltNonce = true
			c.sessionByNonce[current.altNonce] = current
		}
		peer.LastUsed = now
		c.mu.Unlock()
		c.device.log.Verbosef("[P2P] Punch relay for target %d joined the running attempt", targetID)
		return
	}

	if len(msg.Payload) >= net.IPv4len {
		assignedIP := append(net.IP(nil), msg.Payload[:net.IPv4len]...)
		if !assignedIP.Equal(net.IPv4zero) {
			peer.AssignedIP = assignedIP
		}
	}

	peer.LocalAddr = normalizeUDPAddr(msg.LocalAddr())
	peer.ObservedAddr = normalizeUDPAddr(msg.ObservedAddr())
	peer.CandidateAddrs = sanitizePunchTargets(DecodeP2PCandidatePayload(msg.Payload, net.IPv4len), peer.AssignedIP)
	peer.LastUsed = now
	peer.State = P2PStateTrying

	session := &P2PSession{
		TargetID:       targetID,
		TargetPubKey:   peer.PublicKey,
		LocalAddr:      peer.LocalAddr,
		ObservedAddr:   peer.ObservedAddr,
		CandidateAddrs: append([]net.UDPAddr(nil), peer.CandidateAddrs...),
		AssignedIP:     append(net.IP(nil), peer.AssignedIP...),
		createdAt:      now,
		done:           make(chan struct{}),
	}
	copy(session.Nonce[:], msg.Nonce[:])
	c.discardSessionLocked(targetID)
	c.sessions[targetID] = session
	c.sessionByNonce[session.Nonce] = session
	c.peerKeyIndex[peer.PublicKey] = targetID
	c.rebuildIndexesLocked()
	c.mu.Unlock()

	if teardown != nil {
		c.device.log.Verbosef("[P2P] Peer %d is punching again; leaving the direct path for the relay", targetID)
		c.teardownDirect(*teardown)
	}

	targets := buildPunchTargets(session)
	c.device.log.Verbosef("[P2P] Punch relay target=%d observed=%v local=%v candidates=%d targets=%d",
		targetID, session.ObservedAddr, session.LocalAddr, len(session.CandidateAddrs), len(targets))

	job := p2pPunchJob{
		peerID:  targetID,
		session: session,
		packet:  c.makeOuterPunchPacket(session),
		targets: c.parsePunchTargets(targets),
	}
	if len(job.packet) == 0 || len(job.targets) == 0 || !c.enqueuePunchJob(job) {
		c.mu.Lock()
		failed := c.failPunchSessionIfCurrentLocked(peer, session, time.Now())
		c.mu.Unlock()
		if failed {
			c.device.log.Verbosef("[P2P] Punch relay for peer %d could not be scheduled", targetID)
		}
	}
}

// p2pDirectTeardown is what is needed to drop a direct WireGuard peer and
// hand its VPN address back to the relay, outside c.mu.
type p2pDirectTeardown struct {
	publicKey  NoisePublicKey
	assignedIP net.IP
	relayPeer  *Peer
}

func (c *P2PClient) teardownDirect(t p2pDirectTeardown) {
	if t.publicKey.IsZero() {
		return
	}
	c.device.RemovePeer(t.publicKey)
	relayPeer := t.relayPeer
	if relayPeer == nil {
		relayPeer = c.relayPeerForIP(t.assignedIP)
	}
	c.restoreRelayRoute(t.assignedIP, relayPeer)
}

func (c *P2PClient) parsePunchTargets(targets []net.UDPAddr) []conn.Endpoint {
	endpoints := make([]conn.Endpoint, 0, len(targets))
	for _, target := range targets {
		endpoint, err := c.device.net.bind.ParseEndpoint(target.String())
		if err == nil {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

func (c *P2PClient) enqueuePunchJob(job p2pPunchJob) bool {
	select {
	case <-c.ctx.Done():
		return false
	case c.punchQueue <- job:
		return true
	default:
		return false
	}
}

func (c *P2PClient) punchWorker() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case job := <-c.punchQueue:
			c.holePunch(job)
		}
	}
}

func (c *P2PClient) holePunch(job p2pPunchJob) {
	deadline := time.Now().Add(p2pPunchTimeout)
	buffers := [][]byte{job.packet}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for round := 0; ; round++ {
		select {
		case <-c.ctx.Done():
			return
		case <-job.session.done:
			return
		case <-timer.C:
		}

		if now := time.Now(); now.After(deadline) {
			c.mu.Lock()
			if job.session.Promoting {
				// Keep punching while the handshake is validated: the peer may
				// still need a punch to authenticate this side, and the open
				// NAT mapping carries the handshake. Validation always ends
				// (and stops this loop) before the extended deadline.
				deadline = job.session.promotedAt.Add(p2pHandshakeTimeout + time.Second)
				c.mu.Unlock()
				if now.After(deadline) {
					return
				}
			} else {
				peer := c.peers[job.peerID]
				if c.failPunchSessionIfCurrentLocked(peer, job.session, now) {
					c.device.log.Verbosef("[P2P] Punch timeout for peer %d after %d targets — retry in ~%s",
						job.peerID, len(job.targets), p2pRetryDelay(peer.PunchAttempts))
				}
				c.mu.Unlock()
				return
			}
		}
		for _, target := range job.targets {
			_ = c.device.net.bind.Send(buffers, target)
		}
		timer.Reset(p2pPunchInterval(round))
	}
}

// failPunchSessionIfCurrentLocked marks a punch attempt failed only when the
// timed-out session is still the active session for that peer. Punch attempts
// can overlap when both peers retry or the coordinator relays fresh endpoints;
// an older goroutine must not clobber a newer successful attempt.
func (c *P2PClient) failPunchSessionIfCurrentLocked(peer *DiscoveredPeer, session *P2PSession, now time.Time) bool {
	if peer == nil || session == nil || session.Established || peer.State == P2PStateEstablished {
		return false
	}
	current := c.sessions[peer.ID]
	if current != session {
		return false
	}
	peer.State = P2PStateFailed
	peer.LastUsed = now
	peer.PunchAttempts++
	c.setRetryGateLocked(peer)
	c.forgetSessionLocked(peer.ID, session)
	session.signalDone()
	c.rebuildIndexesLocked()
	return true
}

func buildPunchTargets(session *P2PSession) []net.UDPAddr {
	if session == nil {
		return nil
	}
	targets := make([]net.UDPAddr, 0, len(session.CandidateAddrs)+8)
	for _, candidate := range session.CandidateAddrs {
		appendPunchCandidate(&targets, candidate, session.AssignedIP)
	}
	appendPunchCandidate(&targets, session.ObservedAddr, session.AssignedIP)
	appendPunchCandidate(&targets, session.LocalAddr, session.AssignedIP)

	baseLen := len(targets)
	for i := 0; i < baseLen && len(targets) < p2pMaxPredictedTargets; i++ {
		appendPortPredictionCandidates(&targets, targets[i], session.AssignedIP)
	}
	return targets
}

func sanitizePunchTargets(candidates []net.UDPAddr, assignedIP net.IP) []net.UDPAddr {
	out := make([]net.UDPAddr, 0, len(candidates))
	for _, candidate := range candidates {
		appendPunchCandidate(&out, candidate, assignedIP)
	}
	return out
}

func appendPunchCandidate(candidates *[]net.UDPAddr, candidate net.UDPAddr, assignedIP net.IP) {
	candidate = normalizeUDPAddr(candidate)
	if !isUsablePunchAddr(candidate) || isAssignedOverlayAddr(candidate, assignedIP) {
		return
	}
	key := candidate.String()
	for _, existing := range *candidates {
		if existing.String() == key {
			return
		}
	}
	*candidates = append(*candidates, candidate)
}

func appendPortPredictionCandidates(candidates *[]net.UDPAddr, base net.UDPAddr, assignedIP net.IP) {
	if !isPublicInternetPunchAddr(base) {
		return
	}
	for _, delta := range []int{1, -1, 2, -2, 3, -3, 5, -5, 8, -8, 13, -13} {
		if len(*candidates) >= p2pMaxPredictedTargets {
			return
		}
		port := base.Port + delta
		if port <= 0 || port > 65535 {
			continue
		}
		appendPunchCandidate(candidates, net.UDPAddr{IP: base.IP, Port: port}, assignedIP)
	}
}

func isAssignedOverlayAddr(candidate net.UDPAddr, assignedIP net.IP) bool {
	if len(assignedIP) == 0 || assignedIP.Equal(net.IPv4zero) {
		return false
	}
	candidateIP := candidate.IP
	if ip4 := candidateIP.To4(); ip4 != nil {
		candidateIP = ip4
	}
	assigned := assignedIP
	if ip4 := assigned.To4(); ip4 != nil {
		assigned = ip4
	}
	return candidateIP.Equal(assigned)
}

func isPublicInternetPunchAddr(addr net.UDPAddr) bool {
	if !isUsablePunchAddr(addr) {
		return false
	}
	ip := addr.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func p2pPunchInterval(round int) time.Duration {
	switch {
	case round < 5:
		return 45 * time.Millisecond
	case round < 25:
		return time.Duration(90+(round*17)%45) * time.Millisecond
	default:
		return time.Duration(220+(round*29)%90) * time.Millisecond
	}
}

func p2pRetryDelay(attempts int) time.Duration {
	if attempts <= 0 {
		return p2pRetryBaseDelay
	}
	delay := p2pRetryBaseDelay << min(attempts, 3)
	if delay > p2pRetryMaxDelay {
		return p2pRetryMaxDelay
	}
	return delay
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *P2PClient) makePunchPacket(session *P2PSession) []byte {
	if session.TargetPubKey.IsZero() {
		return nil
	}

	packet := make([]byte, 1+8+32)
	packet[0] = P2PSubtypePunchPacket
	copy(packet[1:9], session.Nonce[:])

	c.device.staticIdentity.RLock()
	ss, err := c.device.staticIdentity.privateKey.sharedSecret(session.TargetPubKey)
	c.device.staticIdentity.RUnlock()
	if err != nil {
		return nil
	}

	mac, _ := blake2s.New256(ss[:])
	mac.Write(session.Nonce[:])
	sum := mac.Sum(nil)
	copy(packet[9:], sum)
	return packet
}

func (c *P2PClient) makeOuterPunchPacket(session *P2PSession) []byte {
	rawPacket := c.makePunchPacket(session)
	if len(rawPacket) == 0 {
		return nil
	}
	packet := make([]byte, 4+len(rawPacket))
	binary.LittleEndian.PutUint32(packet[:4], MessageP2PType)
	copy(packet[4:], rawPacket)
	return packet
}

func (c *P2PClient) verifyPunchPacket(packet []byte, session *P2PSession) bool {
	if len(packet) != 41 || packet[0] != P2PSubtypePunchPacket {
		return false
	}
	var nonce [8]byte
	copy(nonce[:], packet[1:9])
	if !session.acceptsNonce(nonce) {
		return false
	}
	return c.verifyPunchMAC(packet, session.TargetPubKey)
}

// verifyPunchMAC checks the punch MAC, keyed by the static-static shared
// secret, over the nonce the packet carries.
func (c *P2PClient) verifyPunchMAC(packet []byte, targetPubKey NoisePublicKey) bool {
	if len(packet) != 41 || packet[0] != P2PSubtypePunchPacket {
		return false
	}
	c.device.staticIdentity.RLock()
	ss, err := c.device.staticIdentity.privateKey.sharedSecret(targetPubKey)
	c.device.staticIdentity.RUnlock()
	if err != nil {
		return false
	}

	mac, _ := blake2s.New256(ss[:])
	mac.Write(packet[1:9])
	sum := mac.Sum(nil)
	return subtle.ConstantTimeCompare(sum, packet[9:]) == 1
}

func (c *P2PClient) GetEndpoint(peerID uint32) conn.Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if peer, ok := c.peers[peerID]; ok && peer.State == P2PStateEstablished {
		return peer.Endpoint
	}
	return nil
}

func (c *P2PClient) sendToServer(msg *P2PMessage) {
	c.mu.RLock()
	serverKey := c.serverPeerKey
	c.mu.RUnlock()
	if !serverKey.IsZero() {
		if serverPeer := c.device.LookupPeer(serverKey); serverPeer != nil {
			c.sendP2PMessage(serverPeer, msg)
			return
		}
	}

	c.device.peers.RLock()
	var serverPeer *Peer
	for _, peer := range c.device.peers.keyMap {
		peer.endpoint.Lock()
		hasEndpoint := peer.endpoint.val != nil
		peer.endpoint.Unlock()
		if hasEndpoint {
			serverPeer = peer
			break
		}
	}
	c.device.peers.RUnlock()

	if serverPeer == nil {
		return
	}

	c.mu.Lock()
	if c.serverPeerKey.IsZero() {
		c.serverPeerKey = serverPeer.handshake.remoteStatic
	}
	c.mu.Unlock()

	c.sendP2PMessage(serverPeer, msg)
}

func (c *P2PClient) isCoordinatorPeer(peer *Peer) bool {
	if peer == nil {
		return false
	}
	c.mu.RLock()
	serverKey := c.serverPeerKey
	c.mu.RUnlock()
	return !serverKey.IsZero() && serverKey.Equals(peer.handshake.remoteStatic)
}

func (c *P2PClient) sendP2PMessage(peer *Peer, msg *P2PMessage) {
	peer.SendP2PControl(msg.Encode())
}

func (c *P2PClient) HandlePunch(packet []byte, addr *net.UDPAddr) {
	if len(packet) != 41 || packet[0] != P2PSubtypePunchPacket || addr == nil {
		return
	}

	var nonce [8]byte
	copy(nonce[:], packet[1:9])

	c.mu.RLock()
	session := c.sessionByNonce[nonce]
	var peer *DiscoveredPeer
	var targetPubKey NoisePublicKey
	if session != nil && c.sessions[session.TargetID] == session && session.acceptsNonce(nonce) {
		peer = c.peers[session.TargetID]
		targetPubKey = session.TargetPubKey
	}
	c.mu.RUnlock()
	if session == nil || peer == nil {
		return
	}

	if !c.verifyPunchMAC(packet, targetPubKey) {
		return
	}

	endpoint, err := c.device.net.bind.ParseEndpoint(addr.String())
	if err != nil {
		return
	}

	now := time.Now()
	c.mu.Lock()
	peer = c.peers[session.TargetID]
	if peer == nil || c.sessions[session.TargetID] != session || peer.State == P2PStateEstablished {
		c.mu.Unlock()
		return
	}
	peer.LastUsed = now
	// Answer every authenticated punch, rate-limited: a single answer is
	// lost as easily as any punch, and the peer cannot authenticate this
	// side (and prepare its WireGuard peer) until one arrives.
	reply := now.Sub(session.lastReply) >= p2pPunchReplyInterval
	if reply {
		session.lastReply = now
	}
	startPromotion := !session.Promoting
	var job p2pPromotionJob
	if startPromotion {
		// The punch loop keeps running until validation ends.
		session.Established = true // authenticated punch path is bidirectional
		session.Promoting = true
		session.promotedAt = now
		job = p2pPromotionJob{
			peerID:     peer.ID,
			session:    session,
			publicKey:  peer.PublicKey,
			assignedIP: append(net.IP(nil), peer.AssignedIP...),
			endpoint:   endpoint,
			startedAt:  now,
		}
	}
	c.mu.Unlock()

	if reply {
		outer := make([]byte, 4+len(packet))
		binary.LittleEndian.PutUint32(outer[:4], MessageP2PType)
		copy(outer[4:], packet)
		_ = c.device.net.bind.Send([][]byte{outer}, endpoint)
	}
	if !startPromotion {
		return
	}
	job.relayPeer = c.relayPeerForIP(job.assignedIP)

	c.device.log.Verbosef("[P2P] Authenticated punch from %v (ID %d); validating WireGuard handshake", addr, job.peerID)
	if err := c.prepareDirectPeer(job.publicKey, job.assignedIP, endpoint.DstToString()); err != nil {
		c.failDirectPromotion(job, err)
		return
	}
	select {
	case <-c.ctx.Done():
		c.failDirectPromotion(job, c.ctx.Err())
	case c.promotionQueue <- job:
	default:
		c.failDirectPromotion(job, fmt.Errorf("promotion queue full"))
	}
}

// initiatesHandshake breaks the tie between two peers that authenticate each
// other at the same moment: only the side with the lower public key starts
// the WireGuard handshake, so the two initiations do not cross and replace
// each other's handshake state. The other side answers, and initiates only
// as a fallback after p2pResponderFallback.
func (c *P2PClient) initiatesHandshake(remote NoisePublicKey) bool {
	return bytes.Compare(c.myPublicKey[:], remote[:]) < 0
}

func (c *P2PClient) prepareDirectPeer(pubKey NoisePublicKey, assignedIP net.IP, endpointAddr string) error {
	if pubKey.IsZero() || assignedIP.To4() == nil || assignedIP.Equal(net.IPv4zero) {
		return fmt.Errorf("missing peer key or assigned IPv4 address")
	}
	c.mu.RLock()
	serverKey := c.serverPeerKey
	c.mu.RUnlock()
	if !serverKey.IsZero() && pubKey.Equals(serverKey) {
		return fmt.Errorf("direct peer key matches coordinator")
	}

	// Deliberately install no allowed_ip yet. Relay routing remains active
	// until promotionWorker observes a fresh authenticated WireGuard handshake.
	// Turning persistent keepalive on sends a keepalive at once, which starts
	// the handshake, so the waiting side leaves it off until later.
	initiate := c.initiatesHandshake(pubKey)
	conf := fmt.Sprintf("public_key=%x\nreplace_allowed_ips=true\nendpoint=%s\n", pubKey[:], endpointAddr)
	if initiate {
		conf += "persistent_keepalive_interval=25\n"
	}
	if err := c.device.IpcSet(conf); err != nil {
		return fmt.Errorf("configure direct candidate %s: %w", endpointAddr, err)
	}
	if wgPeer := c.device.LookupPeer(pubKey); wgPeer != nil {
		wgPeer.EnableRoaming()
		if initiate {
			wgPeer.SendKeepalive()
		}
	}
	return nil
}

// startDirectKeepalive turns persistent keepalive on for a direct candidate;
// if it was off this sends a keepalive, which initiates a handshake when no
// session exists yet.
func (c *P2PClient) startDirectKeepalive(pubKey NoisePublicKey) error {
	return c.device.IpcSet(fmt.Sprintf("public_key=%x\nupdate_only=true\npersistent_keepalive_interval=25\n", pubKey[:]))
}

func (c *P2PClient) promotionWorker() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case job := <-c.promotionQueue:
			c.validateAndPromote(job)
		}
	}
}

func (c *P2PClient) validateAndPromote(job p2pPromotionJob) {
	timer := time.NewTimer(p2pHandshakeTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(p2pHandshakePoll)
	defer ticker.Stop()
	initiate := c.initiatesHandshake(job.publicKey)
	fallbackAt := job.startedAt.Add(p2pResponderFallback)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
			c.failDirectPromotion(job, fmt.Errorf("direct handshake timeout"))
			return
		case <-ticker.C:
			wgPeer := c.device.LookupPeer(job.publicKey)
			if wgPeer == nil || wgPeer.lastHandshakeNano.Load() < job.startedAt.UnixNano() {
				if !initiate && wgPeer != nil && time.Now().After(fallbackAt) {
					// The peer's initiation never arrived (it may not have
					// authenticated us yet); initiate from this side.
					initiate = true
					c.device.log.Verbosef("[P2P] No handshake from peer %d yet; initiating", job.peerID)
					if err := c.startDirectKeepalive(job.publicKey); err != nil {
						c.device.log.Verbosef("[P2P] Direct keepalive for peer %d: %v", job.peerID, err)
					}
				}
				continue
			}

			// A newer relay may replace this session while the handshake is in
			// flight. Never let an obsolete promotion steal the /32 route.
			c.mu.RLock()
			peer := c.peers[job.peerID]
			current := peer != nil && peer.State == P2PStateTrying &&
				c.sessions[job.peerID] == job.session
			c.mu.RUnlock()
			if !current {
				return
			}
			if err := c.activateDirectPeer(job.publicKey, job.assignedIP); err != nil {
				c.failDirectPromotion(job, err)
				return
			}

			now := time.Now()
			removeObsoleteCandidate := false
			c.mu.Lock()
			peer = c.peers[job.peerID]
			if peer != nil && peer.State == P2PStateTrying && c.sessions[job.peerID] == job.session {
				peer.State = P2PStateEstablished
				peer.Endpoint = job.endpoint
				peer.RelayPeer = job.relayPeer
				peer.EstablishedAt = now
				peer.LastUsed = now
				peer.PunchAttempts = 0
				c.forgetSessionLocked(job.peerID, job.session)
				c.rebuildIndexesLocked()
			} else {
				removeObsoleteCandidate = true
			}
			c.mu.Unlock()
			job.session.signalDone()
			if removeObsoleteCandidate {
				c.device.RemovePeer(job.publicKey)
				c.restoreRelayRoute(job.assignedIP, job.relayPeer)
				return
			}
			c.device.log.Verbosef(
				"[P2P] Direct path established with peer %d at %s in %s",
				job.peerID,
				job.endpoint.DstToString(),
				time.Since(job.startedAt).Round(time.Millisecond),
			)
			return
		}
	}
}

func (c *P2PClient) relayPeerForIP(ip net.IP) *Peer {
	c.mu.RLock()
	serverKey := c.serverPeerKey
	c.mu.RUnlock()
	if !serverKey.IsZero() {
		if serverPeer := c.device.LookupPeer(serverKey); serverPeer != nil {
			return serverPeer
		}
	}
	if ip4 := ip.To4(); ip4 != nil {
		return c.device.allowedips.Lookup(ip4)
	}
	return nil
}

func (c *P2PClient) restoreRelayRoute(ip net.IP, relayPeer *Peer) {
	ip4 := ip.To4()
	if relayPeer == nil || ip4 == nil || ip.Equal(net.IPv4zero) {
		return
	}
	key := relayPeer.handshake.remoteStatic
	if c.device.LookupPeer(key) != relayPeer {
		return
	}
	conf := fmt.Sprintf("public_key=%x\nallowed_ip=%s/32\n", key[:], ip4.String())
	if err := c.device.IpcSet(conf); err != nil {
		c.device.log.Errorf("[P2P] Failed to restore relay route for %s: %v", ip4, err)
	}
}

func (c *P2PClient) activateDirectPeer(pubKey NoisePublicKey, assignedIP net.IP) error {
	ip4 := assignedIP.To4()
	if ip4 == nil || assignedIP.Equal(net.IPv4zero) {
		return fmt.Errorf("cannot activate direct peer without assigned IPv4 address")
	}
	// Keepalive is on for both sides once the path is live (the waiting side
	// left it off during validation).
	conf := fmt.Sprintf("public_key=%x\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n", pubKey[:], ip4.String())
	if err := c.device.IpcSet(conf); err != nil {
		return fmt.Errorf("activate direct route: %w", err)
	}

	if c.device.addPeerRouteHandler != nil {
		c.device.addPeerRouteHandler(ip4)
	}
	return nil
}

func (c *P2PClient) failDirectPromotion(job p2pPromotionJob, cause error) {
	removeCandidate := false
	c.mu.Lock()
	peer := c.peers[job.peerID]
	if peer != nil && c.sessions[job.peerID] == job.session && peer.State != P2PStateEstablished {
		peer.State = P2PStateFailed
		peer.LastUsed = time.Now()
		peer.PunchAttempts++
		c.setRetryGateLocked(peer)
		c.forgetSessionLocked(job.peerID, job.session)
		c.rebuildIndexesLocked()
		removeCandidate = true
	}
	c.mu.Unlock()
	job.session.signalDone()
	if removeCandidate && !job.publicKey.IsZero() {
		c.device.RemovePeer(job.publicKey)
		c.restoreRelayRoute(job.assignedIP, job.relayPeer)
	}
	c.device.log.Verbosef("[P2P] Direct path validation failed for peer %d; relay remains active: %v", job.peerID, cause)
}

func (c *P2PClient) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}

		c.mu.RLock()
		myID := c.myID
		c.mu.RUnlock()
		if c.registerDue(time.Now()) {
			c.register()
		}
		if myID == 0 {
			continue
		}

		c.requestPeerList()

		var removeDirect []p2pDirectTeardown
		c.mu.Lock()
		now := time.Now()
		indexesChanged := c.forgetUnlistedPeersLocked(now)
		for id, peer := range c.peers {
			switch peer.State {
			case P2PStateTrying:
				if now.Sub(peer.LastUsed) > p2pStalledAttemptTTL {
					peer.State = P2PStateFailed
					peer.LastUsed = now
					peer.PunchAttempts++
					c.setRetryGateLocked(peer)
					c.discardSessionLocked(id)
					indexesChanged = true
				}
			case P2PStateEstablished:
				wgPeer := c.device.LookupPeer(peer.PublicKey)
				lastHandshake := int64(0)
				if wgPeer != nil {
					lastHandshake = wgPeer.lastHandshakeNano.Load()
				}
				if lastHandshake == 0 || now.Sub(time.Unix(0, lastHandshake)) > p2pDirectStaleAfter {
					peer.State = P2PStateFailed
					peer.Endpoint = nil
					peer.LastUsed = now
					peer.PunchAttempts++
					c.setRetryGateLocked(peer)
					removeDirect = append(removeDirect, p2pDirectTeardown{
						publicKey:  peer.PublicKey,
						assignedIP: append(net.IP(nil), peer.AssignedIP...),
						relayPeer:  peer.RelayPeer,
					})
					indexesChanged = true
				}
			}
		}
		if indexesChanged {
			c.rebuildIndexesLocked()
		}
		c.mu.Unlock()

		for _, stale := range removeDirect {
			c.teardownDirect(stale)
		}
		if dropped := c.droppedControl.Swap(0); dropped > 0 {
			c.device.log.Verbosef("[P2P] Dropped %d control datagrams while the bounded queue was full", dropped)
		}
		if dropped := c.droppedAttempts.Swap(0); dropped > 0 {
			c.device.log.Verbosef("[P2P] Coalesced %d direct-path attempts while the queue was full", dropped)
		}
	}
}

func (c *P2PClient) discardSessionLocked(peerID uint32) {
	session := c.sessions[peerID]
	if session == nil {
		return
	}
	c.forgetSessionLocked(peerID, session)
	session.signalDone()
}

func (c *P2PClient) forgetSessionLocked(peerID uint32, session *P2PSession) {
	if c.sessions[peerID] == session {
		delete(c.sessions, peerID)
	}
	if c.sessionByNonce[session.Nonce] == session {
		delete(c.sessionByNonce, session.Nonce)
	}
	if session.hasAltNonce && c.sessionByNonce[session.altNonce] == session {
		delete(c.sessionByNonce, session.altNonce)
	}
}

func (c *P2PClient) GetEndpointForPeer(pk NoisePublicKey) conn.Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	peerID, ok := c.peerKeyIndex[pk]
	if !ok {
		return nil
	}
	peer := c.peers[peerID]
	if peer != nil && peer.State == P2PStateEstablished {
		return peer.Endpoint
	}
	return nil
}

func (c *P2PClient) IsExitNode() bool {
	return false
}

func (c *P2PClient) GetDiscoveredPeers() []*DiscoveredPeer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*DiscoveredPeer, 0, len(c.peers))
	for _, p := range c.peers {
		cp := *p
		cp.CandidateAddrs = append([]net.UDPAddr(nil), p.CandidateAddrs...)
		cp.AssignedIP = append(net.IP(nil), p.AssignedIP...)
		out = append(out, &cp)
	}
	return out
}
