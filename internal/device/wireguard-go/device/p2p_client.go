package device

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
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
	LastUsed      time.Time
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

func NewP2PClient(device *Device) *P2PClient {
	return &P2PClient{
		device:      device,
		peers:       make(map[uint32]*DiscoveredPeer),
		sessions:    make(map[uint32]*P2PSession),
		myPublicKey: device.staticIdentity.publicKey,
	}
}

func (c *P2PClient) Start() {
	c.register()
	go c.maintenanceLoop()
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
	if len(candidates) > 0 {
		c.localAddr = candidates[0]
	} else {
		c.localAddr = net.UDPAddr{IP: net.IPv4zero, Port: port}
	}

	msg := &P2PMessage{
		Subtype: P2PSubtypeRegister,
		Payload: EncodeP2PCandidatePayload(candidates),
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	msg.SetLocalAddr(&c.localAddr)

	c.device.log.Verbosef("[P2P] Registering with server using local=%v candidates=%d", c.localAddr, len(candidates))
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
	c.myID = msg.TargetID
	c.observedAddr = normalizeUDPAddr(msg.ObservedAddr())

	c.device.log.Verbosef("[P2P] Registered with server. My ID: %d observed=%v", c.myID, c.observedAddr)
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
	if len(msg.Payload) < 4+int(count)*78 {
		return
	}

	c.mu.Lock()
	offset := 4
	for i := uint32(0); i < count; i++ {
		peer := &DiscoveredPeer{ID: binary.BigEndian.Uint32(msg.Payload[offset:])}
		copy(peer.PublicKey[:], msg.Payload[offset+4:])
		peer.LocalAddr.IP = append(net.IP(nil), msg.Payload[offset+36:offset+52]...)
		peer.LocalAddr.Port = int(binary.BigEndian.Uint16(msg.Payload[offset+52:]))
		peer.ObservedAddr.IP = append(net.IP(nil), msg.Payload[offset+54:offset+70]...)
		peer.ObservedAddr.Port = int(binary.BigEndian.Uint16(msg.Payload[offset+70:]))
		peer.LocalAddr = normalizeUDPAddr(peer.LocalAddr)
		peer.ObservedAddr = normalizeUDPAddr(peer.ObservedAddr)
		peer.NATType = NATType(msg.Payload[offset+72])
		peer.P2PCapable = msg.Payload[offset+73] == 1
		peer.AssignedIP = append(net.IP(nil), msg.Payload[offset+74:offset+78]...)
		peer.State = P2PStateDiscovered
		peer.LastUsed = time.Now()

		if existing, ok := c.peers[peer.ID]; ok {
			switch existing.State {
			case P2PStateEstablished, P2PStateTrying:
				offset += 78
				continue
			case P2PStateFailed:
				peer.State = P2PStateFailed
			}
			peer.LastUsed = existing.LastUsed
			peer.PunchAttempts = existing.PunchAttempts
			peer.Endpoint = existing.Endpoint
			peer.CandidateAddrs = existing.CandidateAddrs
		}
		c.peers[peer.ID] = peer
		offset += 78
	}

	var toPunch []*DiscoveredPeer
	for _, peer := range c.peers {
		if peer.P2PCapable && peer.State == P2PStateDiscovered {
			toPunch = append(toPunch, peer)
		}
	}
	c.mu.Unlock()

	c.device.log.Verbosef("[P2P] Discovered %d peers", count)
	for _, peer := range toPunch {
		go c.tryP2P(peer)
	}
}

func (c *P2PClient) TryP2P(peerID uint32) bool {
	c.mu.RLock()
	peer, ok := c.peers[peerID]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	return c.tryP2P(peer)
}

func (c *P2PClient) tryP2P(peer *DiscoveredPeer) bool {
	c.mu.Lock()
	now := time.Now()
	switch peer.State {
	case P2PStateEstablished, P2PStateTrying:
		c.mu.Unlock()
		return true
	case P2PStateFailed:
		if now.Sub(peer.LastUsed) < p2pRetryDelay(peer.PunchAttempts) {
			c.mu.Unlock()
			return false
		}
	}
	peer.State = P2PStateTrying
	peer.LastUsed = now
	c.mu.Unlock()

	msg := &P2PMessage{
		Subtype:  P2PSubtypePunchRequest,
		TargetID: peer.ID,
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
			c.mu.Unlock()
			c.device.log.Errorf("[P2P] Punch relay key mismatch for target %d", targetID)
			return
		}
	}
	if peer.PublicKey.IsZero() {
		peer.State = P2PStateFailed
		peer.LastUsed = now
		c.mu.Unlock()
		c.device.log.Verbosef("[P2P] Punch relay missing public key for target %d", targetID)
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
	}
	copy(session.Nonce[:], msg.Nonce[:])
	c.sessions[targetID] = session
	c.mu.Unlock()

	targets := buildPunchTargets(session)
	c.device.log.Verbosef("[P2P] Punch relay target=%d observed=%v local=%v candidates=%d targets=%d",
		targetID, peer.ObservedAddr, peer.LocalAddr, len(peer.CandidateAddrs), len(targets))

	go c.holePunch(session, peer, targets)
}

func (c *P2PClient) sendPunchPackets(session *P2PSession, targets []net.UDPAddr, ctx context.Context) {
	for round := 0; ; round++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		est := session.Established
		c.mu.RUnlock()
		if est {
			return
		}

		rawPacket := c.makePunchPacket(session)
		if len(rawPacket) != 0 {
			packet := make([]byte, 4+len(rawPacket))
			binary.LittleEndian.PutUint32(packet[:4], MessageP2PType)
			copy(packet[4:], rawPacket)

			for _, target := range targets {
				ep, err := c.device.net.bind.ParseEndpoint(target.String())
				if err == nil {
					_ = c.device.net.bind.Send([][]byte{packet}, ep)
				}
			}
		}

		timer := time.NewTimer(p2pPunchInterval(round))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (c *P2PClient) holePunch(session *P2PSession, peer *DiscoveredPeer, targets []net.UDPAddr) {
	if len(targets) == 0 {
		c.mu.Lock()
		failed := c.failPunchSessionIfCurrentLocked(peer, session, time.Now())
		c.mu.Unlock()
		if failed {
			c.device.log.Verbosef("[P2P] Punch relay for peer %d had no usable endpoint", peer.ID)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p2pPunchTimeout)
	defer cancel()

	go c.sendPunchPackets(session, targets, ctx)

	<-ctx.Done()
	c.mu.Lock()
	if c.failPunchSessionIfCurrentLocked(peer, session, time.Now()) {
		c.device.log.Verbosef("[P2P] Punch timeout for peer %d after %d targets — retry in ~%s",
			peer.ID, len(targets), p2pRetryDelay(peer.PunchAttempts))
	}
	c.mu.Unlock()
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
	if len(packet) != 41 || packet[0] != P2PSubtypePunchPacket {
		return
	}

	var nonce [8]byte
	copy(nonce[:], packet[1:9])

	c.mu.Lock()
	var session *P2PSession
	var peer *DiscoveredPeer
	for _, s := range c.sessions {
		if s.Nonce == nonce {
			session = s
			peer = c.peers[s.TargetID]
			break
		}
	}
	c.mu.Unlock()
	if session == nil || peer == nil {
		return
	}

	if c.verifyPunchPacket(packet, session) {
		c.mu.Lock()
		if peer.State == P2PStateEstablished {
			c.mu.Unlock()
			return
		}

		c.device.log.Verbosef("[P2P] Punch success from %v (ID %d)", addr, peer.ID)
		peer.State = P2PStateEstablished
		peer.LastUsed = time.Now()
		peer.PunchAttempts = 0
		session.Established = true

		ep, err := c.device.net.bind.ParseEndpoint(addr.String())
		if err == nil {
			peer.Endpoint = ep
		}

		pubKey := peer.PublicKey
		assignedIP := append(net.IP(nil), peer.AssignedIP...)
		addrStr := addr.String()
		c.mu.Unlock()

		go c.configureWireGuardPeer(pubKey, assignedIP, addrStr)
	}
}

func (c *P2PClient) configureWireGuardPeer(pubKey NoisePublicKey, assignedIP net.IP, endpointAddr string) {
	if pubKey.IsZero() || len(assignedIP) != net.IPv4len || assignedIP.Equal(net.IPv4zero) {
		c.device.log.Verbosef("[P2P] configureWireGuardPeer: skipping peer with missing key or IP")
		return
	}

	conf := fmt.Sprintf("public_key=%x\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n",
		pubKey[:], endpointAddr, assignedIP.String())
	if err := c.device.IpcSet(conf); err != nil {
		c.device.log.Errorf("[P2P] Failed to configure WireGuard peer %s via direct endpoint: %v", endpointAddr, err)
		return
	}
	c.device.log.Verbosef("[P2P] Configured WireGuard peer with direct endpoint %s (allowed %s/32)", endpointAddr, assignedIP)

	if c.device.addPeerRouteHandler != nil {
		c.device.addPeerRouteHandler(assignedIP)
	}

	wgPeer := c.device.LookupPeer(pubKey)
	if wgPeer != nil {
		wgPeer.SendKeepalive()
	}
}

func (c *P2PClient) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if c.myID == 0 {
			c.register()
			continue
		}

		c.requestPeerList()

		var toPunch []*DiscoveredPeer
		c.mu.Lock()
		now := time.Now()
		for id, peer := range c.peers {
			switch peer.State {
			case P2PStateFailed:
				if now.Sub(peer.LastUsed) > p2pRetryDelay(peer.PunchAttempts) {
					peer.State = P2PStateDiscovered
					delete(c.sessions, id)
					toPunch = append(toPunch, peer)
				}
			case P2PStateTrying:
				if now.Sub(peer.LastUsed) > p2pStalledAttemptTTL {
					peer.State = P2PStateDiscovered
					delete(c.sessions, id)
					toPunch = append(toPunch, peer)
				}
			}
		}
		c.mu.Unlock()

		for _, peer := range toPunch {
			go c.tryP2P(peer)
		}
	}
}

func (c *P2PClient) GetEndpointForPeer(pk NoisePublicKey) conn.Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, peer := range c.peers {
		if peer.PublicKey == pk && peer.State == P2PStateEstablished {
			return peer.Endpoint
		}
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
