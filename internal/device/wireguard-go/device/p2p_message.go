package device

import (
	"encoding/binary"
	"net"
)

const (
	p2pCandidatePayloadMagic = "WPC1"
	p2pCandidateAddrLen      = 18 // 16-byte IP + 2-byte UDP port
)

// P2P message subtypes
const (
	P2PSubtypeRegister     = 1 // Client -> Server: Register my endpoints
	P2PSubtypeRegisterAck  = 2 // Server -> Client: Ack with assigned ID + observed endpoint
	P2PSubtypePeerList     = 3 // Client -> Server: Request peer list / Server -> Client: Peer list
	P2PSubtypePunchRequest = 4 // Client -> Server: Request punch to target
	P2PSubtypePunchRelay   = 5 // Server -> Both: Relay punch intent + endpoints
	P2PSubtypePunchPacket  = 6 // Client <-> Client: Direct punch packets (encrypted)
	P2PSubtypeHeartbeat    = 7 // Client <-> Client: Keepalive for P2P session
)

// MessageP2PType is the wire type for P2P coordination messages.
// This is an alias for MessagePunchType (both are type 6).
const MessageP2PType = MessagePunchType

// P2PMessage is sent as payload in MessageP2PType
// Total header: 4 + 32 + 16 + 2 + 16 + 2 + 8 + 4 = 84 bytes + variable payload
type P2PMessage struct {
	Subtype uint8   // One of P2PSubtype*
	_       [3]byte // Padding/reserved

	// Sender identification
	PublicKey [32]byte // WireGuard public key

	// Local endpoint (what client thinks it has)
	LocalIP   [16]byte // IPv6 or IPv4-mapped IPv6
	LocalPort uint16

	// Observed endpoint (filled by server)
	ObservedIP   [16]byte
	ObservedPort uint16

	// For punch coordination
	TargetID uint32  // Server-assigned peer ID
	Nonce    [8]byte // Punch coordination nonce

	// Variable payload: peer list, punch data, etc
	Payload []byte
}

func (m *P2PMessage) Encode() []byte {
	buf := make([]byte, 84+len(m.Payload))
	buf[0] = m.Subtype
	// buf[1:4] reserved
	copy(buf[4:36], m.PublicKey[:])
	copy(buf[36:52], m.LocalIP[:])
	binary.BigEndian.PutUint16(buf[52:54], m.LocalPort)
	copy(buf[54:70], m.ObservedIP[:])
	binary.BigEndian.PutUint16(buf[70:72], m.ObservedPort)
	binary.BigEndian.PutUint32(buf[72:76], m.TargetID)
	copy(buf[76:84], m.Nonce[:])
	copy(buf[84:], m.Payload)
	return buf
}

func DecodeP2PMessage(data []byte) *P2PMessage {
	if len(data) < 84 {
		return nil
	}
	m := &P2PMessage{
		Subtype: data[0],
		Payload: make([]byte, len(data)-84),
	}
	copy(m.PublicKey[:], data[4:36])
	copy(m.LocalIP[:], data[36:52])
	m.LocalPort = binary.BigEndian.Uint16(data[52:54])
	copy(m.ObservedIP[:], data[54:70])
	m.ObservedPort = binary.BigEndian.Uint16(data[70:72])
	m.TargetID = binary.BigEndian.Uint32(data[72:76])
	copy(m.Nonce[:], data[76:84])
	copy(m.Payload, data[84:])
	return m
}

func (m *P2PMessage) LocalAddr() net.UDPAddr {
	return net.UDPAddr{
		IP:   net.IP(m.LocalIP[:]),
		Port: int(m.LocalPort),
	}
}

func (m *P2PMessage) ObservedAddr() net.UDPAddr {
	return net.UDPAddr{
		IP:   net.IP(m.ObservedIP[:]),
		Port: int(m.ObservedPort),
	}
}

func (m *P2PMessage) SetLocalAddr(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	copy(m.LocalIP[:], addr.IP.To16())
	m.LocalPort = uint16(addr.Port)
}

func (m *P2PMessage) SetObservedAddr(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	copy(m.ObservedIP[:], addr.IP.To16())
	m.ObservedPort = uint16(addr.Port)
}

func AppendP2PCandidatePayload(prefix []byte, candidates []net.UDPAddr) []byte {
	encoded := EncodeP2PCandidatePayload(candidates)
	if len(encoded) == 0 {
		return prefix
	}
	out := make([]byte, 0, len(prefix)+len(encoded))
	out = append(out, prefix...)
	out = append(out, encoded...)
	return out
}

func EncodeP2PCandidatePayload(candidates []net.UDPAddr) []byte {
	if len(candidates) == 0 {
		return nil
	}
	buf := make([]byte, 4+1, 4+1+len(candidates)*p2pCandidateAddrLen)
	copy(buf[:4], p2pCandidatePayloadMagic)

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Port <= 0 {
			continue
		}
		ip := candidate.IP.To16()
		if ip == nil {
			continue
		}
		key := (&net.UDPAddr{IP: ip, Port: candidate.Port}).String()
		if _, ok := seen[key]; ok {
			continue
		}
		if int(buf[4]) == 255 {
			break
		}
		seen[key] = struct{}{}
		buf[4]++
		buf = append(buf, make([]byte, p2pCandidateAddrLen)...)
		offset := len(buf) - p2pCandidateAddrLen
		copy(buf[offset:offset+16], ip)
		binary.BigEndian.PutUint16(buf[offset+16:offset+18], uint16(candidate.Port))
	}
	if buf[4] == 0 {
		return nil
	}
	return buf
}

func DecodeP2PCandidatePayload(payload []byte, offset int) []net.UDPAddr {
	if offset < 0 || len(payload) < offset+5 || string(payload[offset:offset+4]) != p2pCandidatePayloadMagic {
		return nil
	}
	count := int(payload[offset+4])
	pos := offset + 5
	if len(payload) < pos+count*p2pCandidateAddrLen {
		return nil
	}

	candidates := make([]net.UDPAddr, 0, count)
	for i := 0; i < count; i++ {
		rawIP := append(net.IP(nil), payload[pos:pos+16]...)
		port := int(binary.BigEndian.Uint16(payload[pos+16 : pos+18]))
		if ip4 := rawIP.To4(); ip4 != nil {
			rawIP = append(net.IP(nil), ip4...)
		}
		if port > 0 && rawIP.To16() != nil {
			candidates = append(candidates, net.UDPAddr{IP: rawIP, Port: port})
		}
		pos += p2pCandidateAddrLen
	}
	return candidates
}
