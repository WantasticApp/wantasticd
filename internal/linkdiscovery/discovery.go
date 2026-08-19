package linkdiscovery

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bgptools/mndp"
	"github.com/mdlayher/lldp"
)

const (
	maxLLDPPayloadBytes      = 9216
	maxMNDPPayloadBytes      = 16 * 1024
	maxLLDPNeighbors         = 1024
	maxMNDPNeighbors         = 1024
	maxManagementAddresses   = 32
	maxOrganizationTLVs      = 64
	maxOrganizationDataBytes = 124
	maxMNDPAddresses         = 32
)

// OrganizationTLV preserves an LLDP organization-specific TLV. LLDP-MED is
// identified by OUI 00:12:bb and remains available without liblldpctl.
type OrganizationTLV struct {
	OUI     string
	Subtype uint8
	Data    []byte
	LLDPMED bool
}

// LLDPNeighbor is one received LLDPDU with the local ingress interface kept
// alongside the remote chassis and port identity.
type LLDPNeighbor struct {
	LocalInterface      string
	SourceMAC           net.HardwareAddr
	ChassisIDSubtype    uint8
	ChassisID           string
	PortIDSubtype       uint8
	PortID              string
	TTL                 time.Duration
	PortDescription     string
	SystemName          string
	SystemDescription   string
	ManagementAddresses []net.IP
	Organizations       []OrganizationTLV
	LastUpdate          time.Time
}

// MNDPNeighbor is identity/address data decoded from MikroTik Neighbor
// Discovery Protocol broadcasts.
type MNDPNeighbor struct {
	LocalInterface  string
	SourceAddress   net.IP
	MAC             net.HardwareAddr
	Identity        string
	Version         string
	Platform        string
	SoftwareID      string
	Board           string
	RemoteInterface string
	IPv4            []net.IP
	IPv6            []net.IP
	LastUpdate      time.Time
}

type Snapshot struct {
	LLDP      []LLDPNeighbor
	MNDP      []MNDPNeighbor
	LLDPReady bool
	MNDPReady bool
}

type Monitor struct {
	startOnce sync.Once
	mu        sync.Mutex
	lldp      map[string]LLDPNeighbor
	mndp      map[string]MNDPNeighbor
	lldpStart time.Time
	mndpStart time.Time
	lldpUp    bool
	mndpUp    bool
}

func NewMonitor() *Monitor {
	return &Monitor{
		lldp: make(map[string]LLDPNeighbor),
		mndp: make(map[string]MNDPNeighbor),
	}
}

var defaultMonitor = NewMonitor()

// StartDefault starts passive listeners once. It never executes lldpcli,
// mndp, tcpdump, or any other external command.
func StartDefault() { defaultMonitor.Start() }

func DefaultSnapshot() Snapshot { return defaultMonitor.Snapshot(time.Now()) }

func (m *Monitor) Start() {
	if m == nil {
		return
	}
	m.startOnce.Do(func() { startPlatformListeners(m) })
}

func (m *Monitor) Snapshot(now time.Time) Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	result := Snapshot{
		LLDPReady: m.lldpUp && (!m.lldpStart.IsZero() && now.Sub(m.lldpStart) >= 35*time.Second || len(m.lldp) > 0),
		MNDPReady: m.mndpUp && (!m.mndpStart.IsZero() && now.Sub(m.mndpStart) >= 75*time.Second || len(m.mndp) > 0),
	}
	for key, neighbor := range m.lldp {
		expires := neighbor.LastUpdate.Add(neighbor.TTL)
		if neighbor.TTL <= 0 || !now.Before(expires) {
			delete(m.lldp, key)
			continue
		}
		result.LLDP = append(result.LLDP, cloneLLDPNeighbor(neighbor))
	}
	for key, neighbor := range m.mndp {
		if now.Sub(neighbor.LastUpdate) > 3*time.Minute {
			delete(m.mndp, key)
			continue
		}
		result.MNDP = append(result.MNDP, cloneMNDPNeighbor(neighbor))
	}
	sort.Slice(result.LLDP, func(i, j int) bool {
		left := result.LLDP[i].LocalInterface + "\x00" + result.LLDP[i].ChassisID + "\x00" + result.LLDP[i].PortID
		right := result.LLDP[j].LocalInterface + "\x00" + result.LLDP[j].ChassisID + "\x00" + result.LLDP[j].PortID
		return left < right
	})
	sort.Slice(result.MNDP, func(i, j int) bool {
		return result.MNDP[i].MAC.String() < result.MNDP[j].MAC.String()
	})
	return result
}

func (m *Monitor) markLLDPStarted(started time.Time) {
	m.mu.Lock()
	m.lldpStart, m.lldpUp = started, true
	m.mu.Unlock()
}

func (m *Monitor) markMNDPStarted(started time.Time) {
	m.mu.Lock()
	m.mndpStart, m.mndpUp = started, true
	m.mu.Unlock()
}

func (m *Monitor) markLLDPStopped() {
	m.mu.Lock()
	m.lldpUp = false
	m.mu.Unlock()
}

func (m *Monitor) markMNDPStopped() {
	m.mu.Lock()
	m.mndpUp = false
	m.mu.Unlock()
}

func safelyRunListener(protocol string, markStopped func(), receive func()) {
	defer markStopped()
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("[USP] %s passive listener recovered from a panic and was disabled", protocol)
		}
	}()
	receive()
}

func (m *Monitor) observeLLDP(neighbor LLDPNeighbor) {
	key := strings.ToLower(neighbor.LocalInterface + "\x00" + neighbor.ChassisID + "\x00" + neighbor.PortID)
	if key == "\x00\x00" {
		return
	}
	m.mu.Lock()
	if m.lldp == nil {
		m.lldp = make(map[string]LLDPNeighbor)
	}
	if neighbor.TTL <= 0 {
		delete(m.lldp, key)
	} else {
		if _, exists := m.lldp[key]; !exists && len(m.lldp) >= maxLLDPNeighbors {
			m.mu.Unlock()
			return
		}
		m.lldp[key] = cloneLLDPNeighbor(neighbor)
	}
	m.mu.Unlock()
}

func (m *Monitor) observeMNDP(neighbor MNDPNeighbor) {
	key := strings.ToLower(neighbor.MAC.String())
	if key == "" {
		key = strings.ToLower(neighbor.Identity + "\x00" + neighbor.SourceAddress.String())
	}
	if strings.Trim(key, "\x00") == "" {
		return
	}
	m.mu.Lock()
	if m.mndp == nil {
		m.mndp = make(map[string]MNDPNeighbor)
	}
	if _, exists := m.mndp[key]; !exists && len(m.mndp) >= maxMNDPNeighbors {
		m.mu.Unlock()
		return
	}
	m.mndp[key] = cloneMNDPNeighbor(neighbor)
	m.mu.Unlock()
}

// ParseLLDPPayload decodes one LLDPDU using mdlayher/lldp and then maps the
// common and organization-specific TLVs needed by TR-181 and LLDP-MED.
func ParseLLDPPayload(localInterface string, sourceMAC net.HardwareAddr, payload []byte, receivedAt time.Time) (neighbor LLDPNeighbor, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			neighbor = LLDPNeighbor{}
			err = errors.New("decode LLDPDU panic")
		}
	}()
	if len(payload) > maxLLDPPayloadBytes {
		return LLDPNeighbor{}, fmt.Errorf("LLDPDU exceeds %d bytes", maxLLDPPayloadBytes)
	}
	payload, err = trimLLDPDU(payload)
	if err != nil {
		return LLDPNeighbor{}, err
	}
	var frame lldp.Frame
	if err := frame.UnmarshalBinary(payload); err != nil {
		return LLDPNeighbor{}, fmt.Errorf("decode LLDPDU: %w", err)
	}
	if frame.ChassisID == nil || frame.PortID == nil {
		return LLDPNeighbor{}, fmt.Errorf("LLDPDU missing chassis or port ID")
	}
	neighbor = LLDPNeighbor{
		LocalInterface:   truncateUTF8Bytes(strings.ToValidUTF8(strings.TrimSpace(localInterface), ""), 64),
		SourceMAC:        append(net.HardwareAddr(nil), sourceMAC...),
		ChassisIDSubtype: uint8(frame.ChassisID.Subtype),
		ChassisID:        discoveryID(uint8(frame.ChassisID.Subtype), frame.ChassisID.ID, true),
		PortIDSubtype:    uint8(frame.PortID.Subtype),
		PortID:           discoveryID(uint8(frame.PortID.Subtype), frame.PortID.ID, false),
		TTL:              frame.TTL,
		LastUpdate:       receivedAt.UTC(),
	}
	if neighbor.ChassisID == "" || neighbor.PortID == "" {
		return LLDPNeighbor{}, fmt.Errorf("LLDPDU has an empty chassis or port ID")
	}
	for _, tlv := range frame.Optional {
		if tlv == nil {
			continue
		}
		switch tlv.Type {
		case lldp.TLVTypePortDescription:
			neighbor.PortDescription = truncateUTF8Bytes(cleanDiscoveryText(tlv.Value), 255)
		case lldp.TLVTypeSystemName:
			neighbor.SystemName = truncateUTF8Bytes(cleanDiscoveryText(tlv.Value), 255)
		case lldp.TLVTypeSystemDescription:
			neighbor.SystemDescription = truncateUTF8Bytes(cleanDiscoveryText(tlv.Value), 1024)
		case lldp.TLVTypeManagementAddress:
			if len(neighbor.ManagementAddresses) < maxManagementAddresses {
				if ip := parseLLDPManagementAddress(tlv.Value); ip != nil {
					neighbor.ManagementAddresses = appendUniqueIP(neighbor.ManagementAddresses, ip)
				}
			}
		case lldp.TLVTypeOrganizationSpecific:
			if len(tlv.Value) < 4 || len(neighbor.Organizations) >= maxOrganizationTLVs {
				continue
			}
			oui := strings.ToLower(hex.EncodeToString(tlv.Value[:3]))
			data := tlv.Value[4:]
			if len(data) > maxOrganizationDataBytes {
				data = data[:maxOrganizationDataBytes]
			}
			neighbor.Organizations = append(neighbor.Organizations, OrganizationTLV{
				OUI: oui, Subtype: tlv.Value[3], Data: append([]byte(nil), data...), LLDPMED: oui == "0012bb",
			})
		}
	}
	return neighbor, nil
}

func trimLLDPDU(payload []byte) ([]byte, error) {
	for offset := 0; ; {
		if len(payload)-offset < 2 {
			return nil, fmt.Errorf("LLDPDU missing end TLV")
		}
		header := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvType := uint8(header >> 9)
		length := int(header & 0x1ff)
		if len(payload)-offset-2 < length {
			return nil, fmt.Errorf("short LLDP TLV type %d", tlvType)
		}
		offset += 2 + length
		if tlvType == 0 {
			if length != 0 {
				return nil, fmt.Errorf("invalid LLDP end TLV")
			}
			return append([]byte(nil), payload[:offset]...), nil
		}
	}
}

func discoveryID(subtype uint8, raw []byte, chassis bool) string {
	macSubtype := uint8(3)
	if chassis {
		macSubtype = 4
	}
	if subtype == macSubtype && len(raw) == 6 {
		return net.HardwareAddr(raw).String()
	}
	if subtype == 5 && chassis || subtype == 4 && !chassis {
		if len(raw) > 1 {
			switch raw[0] {
			case 1:
				if len(raw) >= 5 {
					return net.IP(raw[1:5]).String()
				}
			case 2:
				if len(raw) >= 17 {
					return net.IP(raw[1:17]).String()
				}
			}
		}
	}
	if text := cleanDiscoveryText(raw); text != "" {
		return truncateUTF8Bytes(text, 255)
	}
	return truncateUTF8Bytes(hex.EncodeToString(raw), 255)
}

func truncateUTF8Bytes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func cleanDiscoveryText(raw []byte) string {
	text := strings.TrimSpace(strings.TrimRight(string(raw), "\x00"))
	if text == "" {
		return ""
	}
	for _, r := range text {
		if r == unicode.ReplacementChar || unicode.IsControl(r) && r != '\t' {
			return ""
		}
	}
	return text
}

func parseLLDPManagementAddress(raw []byte) net.IP {
	if len(raw) < 2 {
		return nil
	}
	addressLength := int(raw[0])
	if addressLength < 2 || 1+addressLength > len(raw) {
		return nil
	}
	switch raw[1] {
	case 1:
		if addressLength == 5 {
			return append(net.IP(nil), raw[2:6]...)
		}
	case 2:
		if addressLength == 17 {
			return append(net.IP(nil), raw[2:18]...)
		}
	}
	return nil
}

func appendUniqueIP(values []net.IP, value net.IP) []net.IP {
	for _, existing := range values {
		if existing.Equal(value) {
			return values
		}
	}
	return append(values, append(net.IP(nil), value...))
}

func ParseMNDPPayload(localInterface string, sourceAddress net.IP, payload []byte, receivedAt time.Time) (neighbor MNDPNeighbor, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			neighbor = MNDPNeighbor{}
			err = errors.New("decode MNDP panic")
		}
	}()
	if len(payload) > maxMNDPPayloadBytes {
		return MNDPNeighbor{}, fmt.Errorf("MNDP packet exceeds %d bytes", maxMNDPPayloadBytes)
	}
	packet, err := mndp.DecodePacket(payload)
	if err != nil {
		return MNDPNeighbor{}, fmt.Errorf("decode MNDP: %w", err)
	}
	neighbor = MNDPNeighbor{LocalInterface: truncateUTF8Bytes(strings.ToValidUTF8(strings.TrimSpace(localInterface), ""), 64), SourceAddress: append(net.IP(nil), sourceAddress...), LastUpdate: receivedAt.UTC()}
	for _, part := range packet.Parts {
		switch part.Type {
		case mndp.MMDPTypeMACAddress:
			if value, ok := part.Value.(net.HardwareAddr); ok && len(value) == 6 {
				neighbor.MAC = append(net.HardwareAddr(nil), value...)
			}
		case mndp.MMDPTypeIdentity:
			neighbor.Identity, _ = part.Value.(string)
			neighbor.Identity = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.Identity, ""), 255)
		case mndp.MMDPTypeVersion:
			neighbor.Version, _ = part.Value.(string)
			neighbor.Version = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.Version, ""), 255)
		case mndp.MMDPTypePlatform:
			neighbor.Platform, _ = part.Value.(string)
			neighbor.Platform = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.Platform, ""), 255)
		case mndp.MMDPTypeSoftwareID:
			neighbor.SoftwareID, _ = part.Value.(string)
			neighbor.SoftwareID = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.SoftwareID, ""), 255)
		case mndp.MMDPTypeBoard:
			neighbor.Board, _ = part.Value.(string)
			neighbor.Board = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.Board, ""), 255)
		case mndp.MMDPTypeInterfaceName:
			neighbor.RemoteInterface, _ = part.Value.(string)
			neighbor.RemoteInterface = truncateUTF8Bytes(strings.ToValidUTF8(neighbor.RemoteInterface, ""), 64)
		case mndp.MMDPTypeIPv4Address:
			if value, ok := part.Value.(net.IP); ok && len(neighbor.IPv4) < maxMNDPAddresses {
				neighbor.IPv4 = appendUniqueIP(neighbor.IPv4, value)
			}
		case mndp.MMDPTypeIPv6Address:
			if value, ok := part.Value.(net.IP); ok && len(neighbor.IPv6) < maxMNDPAddresses {
				neighbor.IPv6 = appendUniqueIP(neighbor.IPv6, value)
			}
		}
	}
	return neighbor, nil
}

func cloneLLDPNeighbor(value LLDPNeighbor) LLDPNeighbor {
	value.SourceMAC = append(net.HardwareAddr(nil), value.SourceMAC...)
	value.ManagementAddresses = append([]net.IP(nil), value.ManagementAddresses...)
	value.Organizations = append([]OrganizationTLV(nil), value.Organizations...)
	for index := range value.ManagementAddresses {
		value.ManagementAddresses[index] = append(net.IP(nil), value.ManagementAddresses[index]...)
	}
	for index := range value.Organizations {
		value.Organizations[index].Data = append([]byte(nil), value.Organizations[index].Data...)
	}
	return value
}

func cloneMNDPNeighbor(value MNDPNeighbor) MNDPNeighbor {
	value.SourceAddress = append(net.IP(nil), value.SourceAddress...)
	value.MAC = append(net.HardwareAddr(nil), value.MAC...)
	value.IPv4 = append([]net.IP(nil), value.IPv4...)
	value.IPv6 = append([]net.IP(nil), value.IPv6...)
	for index := range value.IPv4 {
		value.IPv4[index] = append(net.IP(nil), value.IPv4[index]...)
	}
	for index := range value.IPv6 {
		value.IPv6[index] = append(net.IP(nil), value.IPv6[index]...)
	}
	return value
}
