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

type P2PClient struct {
	device *Device

	myID          uint32
	myPublicKey   NoisePublicKey
	serverPeerKey NoisePublicKey
	localAddr     net.UDPAddr
	observedAddr  net.UDPAddr

	// Discovered peers
	peers map[uint32]*DiscoveredPeer
	mu    sync.RWMutex

	// Active P2P sessions
	sessions map[uint32]*P2PSession // target ID -> session
}

type DiscoveredPeer struct {
	ID           uint32
	PublicKey    NoisePublicKey
	LocalAddr    net.UDPAddr
	ObservedAddr net.UDPAddr
	NATType      NATType
	P2PCapable   bool

	// State
	State      P2PState
	DirectConn *net.UDPConn  // nil until P2P established
	Endpoint   conn.Endpoint // The endpoint to use (P2P or relay)
	LastUsed   time.Time
	AssignedIP net.IP
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

type P2PSession struct {
	TargetID     uint32
	TargetPubKey NoisePublicKey
	LocalAddr    net.UDPAddr
	ObservedAddr net.UDPAddr
	Nonce        [8]byte
	Established  bool
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
	// Register with server
	c.register()

	// Start maintenance
	go c.maintenanceLoop()
}

func (c *P2PClient) getDefaultLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func (c *P2PClient) register() {
	msg := &P2PMessage{
		Subtype: P2PSubtypeRegister,
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])

	ip, _ := c.getDefaultLocalIP()
	if ip == nil {
		ip = net.IPv4zero
	}

	c.device.net.RLock()
	port := int(c.device.net.port)
	c.device.net.RUnlock()

	c.localAddr = net.UDPAddr{IP: ip, Port: port}
	msg.SetLocalAddr(&c.localAddr)

	c.device.log.Verbosef("[P2P] Registering with server using LocalAddr %v", c.localAddr)
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
	// P2PSubtypePunchPacket is handled by holePunch goroutine on specific socket
	case P2PSubtypeHeartbeat:
		// TODO: handle heartbeat on main socket if needed
	}
}

func (c *P2PClient) handleRegisterAck(msg *P2PMessage) {
	c.myID = msg.TargetID
	c.observedAddr = msg.ObservedAddr()

	c.device.log.Verbosef("[P2P] Registered with server. My ID: %d, Observed: %v", c.myID, c.observedAddr)

	// Request peer list
	c.requestPeerList()
}

func (c *P2PClient) requestPeerList() {
	msg := &P2PMessage{
		Subtype: P2PSubtypePeerList,
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	c.sendToServer(msg)
}

func (c *P2PClient) handlePeerList(msg *P2PMessage) {
	// Parse peer list
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
		peer := &DiscoveredPeer{
			ID: binary.BigEndian.Uint32(msg.Payload[offset:]),
		}
		copy(peer.PublicKey[:], msg.Payload[offset+4:])
		peer.LocalAddr.IP = net.IP(msg.Payload[offset+36 : offset+52])
		peer.LocalAddr.Port = int(binary.BigEndian.Uint16(msg.Payload[offset+52:]))
		peer.ObservedAddr.IP = net.IP(msg.Payload[offset+54 : offset+70])
		peer.ObservedAddr.Port = int(binary.BigEndian.Uint16(msg.Payload[offset+70:]))
		peer.NATType = NATType(msg.Payload[offset+72])
		peer.P2PCapable = msg.Payload[offset+73] == 1
		peer.AssignedIP = net.IP(msg.Payload[offset+74 : offset+78])
		peer.State = P2PStateDiscovered

		// Don't overwrite existing established or in-progress connections
		if existing, ok := c.peers[peer.ID]; ok {
			if existing.State == P2PStateEstablished || existing.State == P2PStateTrying {
				offset += 78
				continue
			}
			// Preserve LastUsed timing so retry backoff survives peer list refreshes
			peer.LastUsed = existing.LastUsed
		}
		c.peers[peer.ID] = peer
		// NOTE: WireGuard peer configuration is intentionally deferred until P2P
		// hole punch succeeds (in HandlePunch). Adding the peer without an endpoint
		// causes spurious handshake failures and breaks relay fallback because
		// WireGuard matches traffic to the endpoint-less peer instead of routing
		// it through the server (0.0.0.0/0).

		offset += 78
	}

	// Auto-try P2P for all newly discovered peers
	var toPunch []*DiscoveredPeer
	for _, peer := range c.peers {
		if peer.P2PCapable && peer.State == P2PStateDiscovered {
			toPunch = append(toPunch, peer)
		}
	}
	c.mu.Unlock()

	c.device.log.Verbosef("[P2P] Discovered %d peers", count)

	for _, peer := range toPunch {
		go c.tryP2PUnlocked(peer)
	}
}

// TryP2P attempts to establish direct connection to peer
func (c *P2PClient) TryP2P(peerID uint32) bool {
	c.mu.RLock()
	peer, ok := c.peers[peerID]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	c.tryP2PUnlocked(peer)
	return true
}

func (c *P2PClient) tryP2PUnlocked(peer *DiscoveredPeer) {
	// Transition to trying state under lock to prevent concurrent punch attempts
	c.mu.Lock()
	if peer.State != P2PStateDiscovered {
		c.mu.Unlock()
		return // Already trying, established, or failed — skip
	}
	peer.State = P2PStateTrying
	peer.LastUsed = time.Now()
	c.mu.Unlock()

	// Request server to coordinate hole punch
	msg := &P2PMessage{
		Subtype:  P2PSubtypePunchRequest,
		TargetID: peer.ID,
	}
	copy(msg.PublicKey[:], c.myPublicKey[:])
	c.sendToServer(msg)
}

func (c *P2PClient) handlePunchRelay(msg *P2PMessage) {
	// Server is telling us to punch to this peer
	targetID := msg.TargetID
	now := time.Now()

	var relayedPubKey NoisePublicKey
	copy(relayedPubKey[:], msg.PublicKey[:])

	c.mu.Lock()
	peer, ok := c.peers[targetID]
	if !ok {
		// Peer not in our list yet, create it
		peer = &DiscoveredPeer{
			ID: targetID,
		}
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
		if !assignedIP.Equal(net.IPv4zero) && (len(peer.AssignedIP) != net.IPv4len || peer.AssignedIP.Equal(net.IPv4zero)) {
			peer.AssignedIP = assignedIP
		}
	}

	// Update with latest addresses from server
	peer.LocalAddr = normalizeUDPAddr(msg.LocalAddr())
	peer.ObservedAddr = normalizeUDPAddr(msg.ObservedAddr())
	peer.LastUsed = now
	peer.State = P2PStateTrying

	// Create session
	session := &P2PSession{
		TargetID:     targetID,
		TargetPubKey: peer.PublicKey,
		LocalAddr:    peer.LocalAddr,
		ObservedAddr: peer.ObservedAddr,
	}
	copy(session.Nonce[:], msg.Nonce[:])
	c.sessions[targetID] = session
	c.mu.Unlock()

	c.device.log.Verbosef("[P2P] Punch relay received for target %d. Observed: %v, Local: %v",
		targetID, peer.ObservedAddr, peer.LocalAddr)

	// Start hole punching
	go c.holePunch(session, peer)
}

func (c *P2PClient) sendPunchPackets(session *P2PSession, targets []net.UDPAddr, ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			est := session.Established
			c.mu.RUnlock()
			if est {
				return
			}
			rawPacket := c.makePunchPacket(session)
			if len(rawPacket) == 0 {
				continue
			}
			// Wrap in WireGuard MessageP2PType (6)
			packet := make([]byte, 4+len(rawPacket))
			binary.LittleEndian.PutUint32(packet[:4], MessageP2PType)
			copy(packet[4:], rawPacket)

			for _, target := range targets {
				ep, err := c.device.net.bind.ParseEndpoint(target.String())
				if err == nil {
					c.device.net.bind.Send([][]byte{packet}, ep)
				}
			}
		}
	}
}

func (c *P2PClient) holePunch(session *P2PSession, peer *DiscoveredPeer) {
	// Try both addresses, but skip placeholders and duplicates.
	targets := make([]net.UDPAddr, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, candidate := range []net.UDPAddr{session.ObservedAddr, session.LocalAddr} {
		candidate = normalizeUDPAddr(candidate)
		if !isUsablePunchAddr(candidate) {
			continue
		}
		key := candidate.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, candidate)
	}
	if len(targets) == 0 {
		c.mu.Lock()
		peer.State = P2PStateFailed
		peer.LastUsed = time.Now()
		c.mu.Unlock()
		c.device.log.Verbosef("[P2P] Punch relay for peer %d had no usable endpoint", peer.ID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c.device.log.Verbosef("[P2P] Starting hole punch to %v and %v", session.ObservedAddr, session.LocalAddr)

	// Send punch packets
	go c.sendPunchPackets(session, targets, ctx)

	// Wait for response timeout
	<-ctx.Done()
	c.mu.Lock()
	if !session.Established {
		peer.State = P2PStateFailed
		peer.LastUsed = time.Now()
		c.device.log.Verbosef("[P2P] Punch timeout for peer %d — will retry in ~30s", peer.ID)
	}
	c.mu.Unlock()
}

func (c *P2PClient) makePunchPacket(session *P2PSession) []byte {
	if session.TargetPubKey.IsZero() {
		return nil
	}

	// Punch packet: [P2PSubtypePunchPacket:1][nonce:8][mac:32]
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
	// Prefer the peer we first registered through; that's the coordination server.
	c.mu.RLock()
	serverKey := c.serverPeerKey
	c.mu.RUnlock()
	if !serverKey.IsZero() {
		if serverPeer := c.device.LookupPeer(serverKey); serverPeer != nil {
			c.sendP2PMessage(serverPeer, msg)
			return
		}
	}

	// Before any direct peers exist, the only endpoint-bearing peer should be the server.
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
	// Use 4-byte LE uint32 header like all other WireGuard message types
	// receive.go reads: binary.LittleEndian.Uint32(packet[:4])
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

	// Find any session expecting this nonce
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

	// Verify
	if c.verifyPunchPacket(packet, session) {
		c.mu.Lock()

		if peer.State == P2PStateEstablished {
			c.mu.Unlock()
			return // Already established
		}

		c.device.log.Verbosef("[P2P] ⚡ Punch success from %v (ID %d)", addr, peer.ID)

		peer.State = P2PStateEstablished
		peer.LastUsed = time.Now()
		session.Established = true

		// Update Endpoint to the address we received from
		ep, err := c.device.net.bind.ParseEndpoint(addr.String())
		if err == nil {
			peer.Endpoint = ep
		}

		// Capture values for goroutine before releasing the lock
		pubKey := peer.PublicKey
		assignedIP := make(net.IP, len(peer.AssignedIP))
		copy(assignedIP, peer.AssignedIP)
		addrStr := addr.String()

		c.mu.Unlock()

		// Configure WireGuard peer with the established direct endpoint.
		// This is done after punch succeeds so WireGuard always has a reachable
		// endpoint, and traffic for this peer's /32 actually flows. If punch had
		// not succeeded the peer is never added to WireGuard routing, so traffic
		// falls back through the server's 0.0.0.0/0 route (relay).
		go c.configureWireGuardPeer(pubKey, assignedIP, addrStr)
	}
}

// configureWireGuardPeer adds the peer to WireGuard routing with its direct P2P
// endpoint. Called in a goroutine after hole punch succeeds so the receive path
// is not blocked. If the peer already exists in WireGuard (e.g. from a previous
// session) the endpoint and allowed-IPs are updated in place.
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

	// Add OS-level route for the peer's IP so the kernel knows to forward
	// packets destined for that address into the TUN interface.
	if c.device.addPeerRouteHandler != nil {
		c.device.addPeerRouteHandler(assignedIP)
	}

	// Trigger an immediate handshake now that WireGuard knows the endpoint.
	wgPeer := c.device.LookupPeer(pubKey)
	if wgPeer != nil {
		wgPeer.SendKeepalive()
	}
}

func (c *P2PClient) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Retry registration if not yet registered
		if c.myID == 0 {
			c.register()
			continue
		}

		// Refresh peer list periodically
		c.requestPeerList()

		// Reset failed/stale sessions so they can be retried
		c.mu.Lock()
		now := time.Now()
		for id, peer := range c.peers {
			switch peer.State {
			case P2PStateFailed:
				// After a backoff period, reset to Discovered so the next
				// handlePeerList call will kick off a fresh punch attempt.
				if now.Sub(peer.LastUsed) > 30*time.Second {
					peer.State = P2PStateDiscovered
					delete(c.sessions, id)
					c.device.log.Verbosef("[P2P] Resetting failed peer %d for retry", id)
				}
			case P2PStateTrying:
				// Guard against punch-request sent but no PunchRelay ever arrived
				// (server unreachable, dropped packet, etc.).
				if now.Sub(peer.LastUsed) > 30*time.Second {
					peer.State = P2PStateDiscovered
					delete(c.sessions, id)
					c.device.log.Verbosef("[P2P] Resetting stalled peer %d for retry", id)
				}
			}
		}
		c.mu.Unlock()
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

// IsExitNode returns true if this peer is currently acting as an exit node
func (c *P2PClient) IsExitNode() bool {
	// Not driven locally by P2P messages anymore; managed by system TUN routing mapping
	return false
}

// GetDiscoveredPeers returns a snapshot of all currently discovered peers.
// The returned slice is safe to read without holding any lock.
func (c *P2PClient) GetDiscoveredPeers() []*DiscoveredPeer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*DiscoveredPeer, 0, len(c.peers))
	for _, p := range c.peers {
		cp := *p // copy so callers don't race against mutations
		out = append(out, &cp)
	}
	return out
}
