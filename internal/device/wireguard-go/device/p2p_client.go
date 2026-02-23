package device

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"

	"golang.org/x/crypto/blake2s"
)

type P2PClient struct {
	device *Device

	myID         uint32
	myPublicKey  NoisePublicKey
	localAddr    net.UDPAddr
	observedAddr net.UDPAddr

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

	var toConfigure []string
	var toConfigureIDs []uint32

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

		// Don't overwrite existing established connections
		if existing, ok := c.peers[peer.ID]; !ok || existing.State != P2PStateEstablished {
			c.peers[peer.ID] = peer

			// Prepare to dynamically add this P2P peer to the WireGuard configuration
			if len(peer.AssignedIP) == 4 && !peer.AssignedIP.Equal(net.IPv4zero) {
				conf := fmt.Sprintf("public_key=%x\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n", peer.PublicKey[:], peer.AssignedIP.String())
				toConfigure = append(toConfigure, conf)
				toConfigureIDs = append(toConfigureIDs, peer.ID)
			}
		}

		offset += 78
	}

	c.mu.Unlock() // Unlock before configuring WireGuard to avoid deadlocks

	// Configure WireGuard peers sequentially
	for i, conf := range toConfigure {
		if err := c.device.IpcSet(conf); err != nil {
			c.device.log.Errorf("[P2P] Failed to dynamically configure peer %d: %v", toConfigureIDs[i], err)
		} else {
			c.device.log.Verbosef("[P2P] Dynamically configured WireGuard peer %d", toConfigureIDs[i])
		}
	}

	c.device.log.Verbosef("[P2P] Discovered %d peers", count)

	// Auto-try P2P for all discovered peers
	c.mu.RLock()
	var toPunch []*DiscoveredPeer
	for _, peer := range c.peers {
		if peer.P2PCapable && peer.State == P2PStateDiscovered {
			toPunch = append(toPunch, peer)
		}
	}
	c.mu.RUnlock()

	for _, peer := range toPunch {
		go c.tryP2PUnlocked(peer)
	}
}

// TryP2P attempts to establish direct connection to peer
func (c *P2PClient) TryP2P(peerID uint32) bool {
	c.mu.Lock()
	peer, ok := c.peers[peerID]
	if !ok || !peer.P2PCapable || peer.State == P2PStateEstablished {
		c.mu.Unlock()
		return ok && peer.State == P2PStateEstablished
	}
	peer.State = P2PStateTrying
	c.mu.Unlock()

	c.tryP2PUnlocked(peer)
	return true
}

func (c *P2PClient) tryP2PUnlocked(peer *DiscoveredPeer) {
	// Request server to coordinate
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

	c.mu.Lock()
	peer, ok := c.peers[targetID]
	if !ok {
		// Peer not in our list yet, create it
		peer = &DiscoveredPeer{
			ID: targetID,
		}
		c.peers[targetID] = peer
	}

	// Update with latest addresses from server
	peer.LocalAddr = msg.LocalAddr()
	peer.ObservedAddr = msg.ObservedAddr()

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

	// If we are in TUN mode and the peer has an IP assigned, add a route for it
	if c.device.addPeerRouteHandler != nil {
		wgPeer := c.device.LookupPeer(peer.PublicKey)
		if wgPeer != nil {
			c.device.allowedips.EntriesForPeer(wgPeer, func(prefix netip.Prefix) bool {
				c.device.addPeerRouteHandler(net.IP(prefix.Addr().AsSlice()))
				return false // stop after first route
			})
		}
	}

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
	// Try both addresses
	targets := []net.UDPAddr{session.ObservedAddr, session.LocalAddr}

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
		c.device.log.Verbosef("[P2P] Punch timeout for peer %d", peer.ID)
	}
	c.mu.Unlock()
}

func (c *P2PClient) makePunchPacket(session *P2PSession) []byte {
	// Punch packet: [P2PSubtypePunchPacket:1][nonce:8][mac:32]
	packet := make([]byte, 1+8+32)
	packet[0] = P2PSubtypePunchPacket
	copy(packet[1:9], session.Nonce[:])

	c.device.staticIdentity.RLock()
	ss, err := c.device.staticIdentity.privateKey.sharedSecret(session.TargetPubKey)
	c.device.staticIdentity.RUnlock()

	if err == nil {
		mac, _ := blake2s.New256(ss[:])
		mac.Write(session.Nonce[:])
		sum := mac.Sum(nil)
		copy(packet[9:], sum)
	}

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

	return string(sum) == string(packet[9:])
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
	// Find server peer (first peer with an endpoint)
	c.device.peers.RLock()
	var serverPeer *Peer
	for _, peer := range c.device.peers.keyMap {
		peer.endpoint.Lock()
		if peer.endpoint.val != nil {
			serverPeer = peer
		}
		peer.endpoint.Unlock()

		if serverPeer != nil {
			break
		}
	}
	c.device.peers.RUnlock()

	if serverPeer == nil {
		return
	}

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
		defer c.mu.Unlock()

		if peer.State == P2PStateEstablished {
			return // Already established
		}

		c.device.log.Verbosef("[P2P] ⚡ Punch success from %v (ID %d)", addr, peer.ID)

		peer.State = P2PStateEstablished
		session.Established = true

		// Update Endpoint to the address we received from
		ep, err := c.device.net.bind.ParseEndpoint(addr.String())
		if err == nil {
			peer.Endpoint = ep
		}

		// Trigger WireGuard to initiate handshake immediately now that P2P pinhole is open
		wgPeer := c.device.LookupPeer(peer.PublicKey)
		if wgPeer != nil {
			wgPeer.SendKeepalive()
		}
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

		// Clean up failed/stale sessions
		c.mu.Lock()
		for id, peer := range c.peers {
			if peer.State == P2PStateFailed && time.Since(peer.LastUsed) > 5*time.Minute {
				delete(c.peers, id)
				delete(c.sessions, id)
			}
			// Timeout trying state
			if peer.State == P2PStateTrying && time.Since(peer.LastUsed) > 15*time.Second {
				peer.State = P2PStateDiscovered // Reset to retry later
				delete(c.sessions, id)
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
