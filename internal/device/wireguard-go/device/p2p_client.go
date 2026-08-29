package device

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
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
	p2pHandshakeTimeout    = 8 * time.Second
	p2pHandshakePoll       = 50 * time.Millisecond
	p2pDirectStaleAfter    = 4 * time.Minute
)

type P2PClient struct {
	device *Device

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

func (c *P2PClient) collectLocalCandidates(port int) []net.UDPAddr {
	candidates := make([]net.UDPAddr, 0, 4)
	if ip := c.getDefaultLocalIP(); ip != nil {
		appendPunchCandidate(&candidates, net.UDPAddr{IP: ip, Port: port}, nil)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return candidates
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !isUsefulLocalCandidateIP(ip) {
				continue
			}
			appendPunchCandidate(&candidates, net.UDPAddr{IP: ip, Port: port}, nil)
		}
	}
	return candidates
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
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

func (c *P2PClient) register() {
	c.device.net.RLock()
	port := int(c.device.net.port)
	c.device.net.RUnlock()

	candidates := c.collectLocalCandidates(port)
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
	c.sendToServer(msg)
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
	c.myID = msg.TargetID
	c.observedAddr = normalizeUDPAddr(msg.ObservedAddr())
	observedAddr := c.observedAddr
	c.mu.Unlock()

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

		peer, ok := c.peers[peerID]
		if !ok {
			peer = &DiscoveredPeer{
				ID:       peerID,
				State:    P2PStateDiscovered,
				LastUsed: now,
			}
			c.peers[peerID] = peer
		}
		// Do not let a recycled ID silently replace an active authenticated
		// session. A later maintenance refresh can rediscover it safely.
		if !peer.PublicKey.IsZero() && !publicKey.IsZero() && !peer.PublicKey.Equals(publicKey) &&
			(peer.State == P2PStateTrying || peer.State == P2PStateEstablished) {
			offset += 78
			continue
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
		offset += 78
	}

	c.rebuildIndexesLocked()
	c.mu.Unlock()

	c.device.log.Verbosef("[P2P] Discovered %d peers", count)
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
	peer, ok := c.peers[targetID]
	if !ok {
		peer = &DiscoveredPeer{ID: targetID, P2PCapable: true}
		c.peers[targetID] = peer
	}
	if peer.State == P2PStateEstablished {
		c.mu.Unlock()
		return
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
		done:           make(chan struct{}),
	}
	copy(session.Nonce[:], msg.Nonce[:])
	if previous := c.sessions[targetID]; previous != nil {
		delete(c.sessionByNonce, previous.Nonce)
		previous.signalDone()
	}
	c.sessions[targetID] = session
	c.sessionByNonce[session.Nonce] = session
	c.peerKeyIndex[peer.PublicKey] = targetID
	c.rebuildIndexesLocked()
	c.mu.Unlock()

	targets := buildPunchTargets(session)
	c.device.log.Verbosef("[P2P] Punch relay target=%d observed=%v local=%v candidates=%d targets=%d",
		targetID, peer.ObservedAddr, peer.LocalAddr, len(peer.CandidateAddrs), len(targets))

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
			c.device.log.Verbosef("[P2P] Punch relay for peer %d could not be scheduled", peer.ID)
		}
	}
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
	ctx, cancel := context.WithTimeout(c.ctx, p2pPunchTimeout)
	defer cancel()

	buffers := [][]byte{job.packet}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for round := 0; ; round++ {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			peer := c.peers[job.peerID]
			if c.failPunchSessionIfCurrentLocked(peer, job.session, time.Now()) {
				c.device.log.Verbosef("[P2P] Punch timeout for peer %d after %d targets — retry in ~%s",
					job.peerID, len(job.targets), p2pRetryDelay(peer.PunchAttempts))
			}
			c.mu.Unlock()
			return
		case <-job.session.done:
			return
		case <-timer.C:
			for _, target := range job.targets {
				_ = c.device.net.bind.Send(buffers, target)
			}
			timer.Reset(p2pPunchInterval(round))
		}
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
	delete(c.sessions, peer.ID)
	delete(c.sessionByNonce, session.Nonce)
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
	if nonce != session.Nonce {
		return false
	}

	c.device.staticIdentity.RLock()
	ss, err := c.device.staticIdentity.privateKey.sharedSecret(session.TargetPubKey)
	c.device.staticIdentity.RUnlock()
	if err != nil {
		return false
	}

	mac, _ := blake2s.New256(ss[:])
	mac.Write(nonce[:])
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

func (c *P2PClient) sendP2PMessage(peer *Peer, msg *P2PMessage) {
	encoded := msg.Encode()
	packet := make([]byte, 4+len(encoded))
	binary.LittleEndian.PutUint32(packet[:4], MessageP2PType)
	copy(packet[4:], encoded)
	peer.SendBuffers([][]byte{packet})
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
	if session != nil && c.sessions[session.TargetID] == session {
		peer = c.peers[session.TargetID]
	}
	c.mu.RUnlock()
	if session == nil || peer == nil {
		return
	}

	if !c.verifyPunchPacket(packet, session) {
		return
	}

	endpoint, err := c.device.net.bind.ParseEndpoint(addr.String())
	if err != nil {
		return
	}

	c.mu.Lock()
	peer = c.peers[session.TargetID]
	if peer == nil || c.sessions[session.TargetID] != session || peer.State == P2PStateEstablished || session.Promoting {
		c.mu.Unlock()
		return
	}
	session.Established = true // authenticated punch path is bidirectional
	session.Promoting = true
	session.signalDone()
	peer.LastUsed = time.Now()
	job := p2pPromotionJob{
		peerID:     peer.ID,
		session:    session,
		publicKey:  peer.PublicKey,
		assignedIP: append(net.IP(nil), peer.AssignedIP...),
		endpoint:   endpoint,
		startedAt:  time.Now(),
	}
	c.mu.Unlock()
	job.relayPeer = c.relayPeerForIP(job.assignedIP)

	c.device.log.Verbosef("[P2P] Authenticated punch from %v (ID %d); validating WireGuard handshake", addr, job.peerID)
	// One response proves the return path to a peer that only received our
	// packet. Promoting suppresses response loops on duplicate punches.
	outer := make([]byte, 4+len(packet))
	binary.LittleEndian.PutUint32(outer[:4], MessageP2PType)
	copy(outer[4:], packet)
	_ = c.device.net.bind.Send([][]byte{outer}, endpoint)

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
	conf := fmt.Sprintf("public_key=%x\nreplace_allowed_ips=true\nendpoint=%s\npersistent_keepalive_interval=25\n",
		pubKey[:], endpointAddr)
	if err := c.device.IpcSet(conf); err != nil {
		return fmt.Errorf("configure direct candidate %s: %w", endpointAddr, err)
	}
	if wgPeer := c.device.LookupPeer(pubKey); wgPeer != nil {
		wgPeer.SendKeepalive()
	}
	return nil
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
				delete(c.sessions, job.peerID)
				delete(c.sessionByNonce, job.session.Nonce)
				c.rebuildIndexesLocked()
			} else {
				removeObsoleteCandidate = true
			}
			c.mu.Unlock()
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
	conf := fmt.Sprintf("public_key=%x\nallowed_ip=%s/32\n", pubKey[:], ip4.String())
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
		delete(c.sessions, job.peerID)
		delete(c.sessionByNonce, job.session.Nonce)
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
		if myID == 0 {
			c.register()
			continue
		}

		c.requestPeerList()

		type staleDirectPeer struct {
			publicKey  NoisePublicKey
			assignedIP net.IP
			relayPeer  *Peer
		}
		var removeDirect []staleDirectPeer
		indexesChanged := false
		c.mu.Lock()
		now := time.Now()
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
					removeDirect = append(removeDirect, staleDirectPeer{
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
			c.device.RemovePeer(stale.publicKey)
			c.restoreRelayRoute(stale.assignedIP, stale.relayPeer)
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
	delete(c.sessions, peerID)
	delete(c.sessionByNonce, session.Nonce)
	session.signalDone()
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
