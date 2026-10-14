package device

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

const (
	// A tenant can expose several directly attached networks, but the control
	// message stays deliberately small and bounded.
	maxLocalAccessRoutes       = 16
	maxTenantLocalAccessRoutes = 32

	localAccessRouteEntrySize = 1 + 4 // prefix bits + IPv4 network
)

type localNetworkCandidate struct {
	InterfaceName string
	Flags         net.Flags
	Prefix        netip.Prefix
}

// EncodeLocalAccessAdvertisement encodes an authenticated tenant-coordinator
// control message. An empty route set revokes this device's advertisement.
func EncodeLocalAccessAdvertisement(routes []string) ([]byte, error) {
	prefixes, err := parseLocalAccessRoutes(routes)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 2+len(prefixes)*localAccessRouteEntrySize)
	data[0] = byte(TUNControlActionSetLocalAccessRoutes)
	data[1] = byte(len(prefixes))
	for i, prefix := range prefixes {
		offset := 2 + i*localAccessRouteEntrySize
		data[offset] = byte(prefix.Bits())
		addr := prefix.Addr().As4()
		copy(data[offset+1:offset+5], addr[:])
	}
	return data, nil
}

func decodeLocalAccessRoutes(data []byte, headerSize int) ([]netip.Prefix, error) {
	if headerSize < 0 || len(data) < headerSize+1 {
		return nil, errors.New("local-access payload too short")
	}
	count := int(data[headerSize])
	if count > maxLocalAccessRoutes {
		return nil, fmt.Errorf("too many local-access routes: %d", count)
	}
	expected := headerSize + 1 + count*localAccessRouteEntrySize
	if len(data) != expected {
		return nil, fmt.Errorf("invalid local-access payload length: got %d want %d", len(data), expected)
	}

	prefixes := make([]netip.Prefix, 0, count)
	seen := make(map[netip.Prefix]struct{}, count)
	for i := 0; i < count; i++ {
		offset := headerSize + 1 + i*localAccessRouteEntrySize
		bits := int(data[offset])
		if bits < 8 || bits > 32 {
			return nil, fmt.Errorf("invalid local-access IPv4 prefix length: %d", bits)
		}
		addr := netip.AddrFrom4([4]byte(data[offset+1 : offset+5]))
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if !prefix.Addr().IsPrivate() {
			return nil, fmt.Errorf("local-access route must be private IPv4: %s", prefix)
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func encodeLocalAccessRouteUpdate(owner [32]byte, routes []netip.Prefix) ([]byte, error) {
	if len(routes) > maxLocalAccessRoutes {
		return nil, fmt.Errorf("too many local-access routes: %d", len(routes))
	}
	data := make([]byte, 34+len(routes)*localAccessRouteEntrySize)
	data[0] = byte(TUNControlActionApplyLocalAccessRoutes)
	copy(data[1:33], owner[:])
	data[33] = byte(len(routes))
	for i, prefix := range routes {
		if !validLocalAccessPrefix(prefix) {
			return nil, fmt.Errorf("invalid local-access route: %s", prefix)
		}
		offset := 34 + i*localAccessRouteEntrySize
		data[offset] = byte(prefix.Bits())
		addr := prefix.Masked().Addr().As4()
		copy(data[offset+1:offset+5], addr[:])
	}
	return data, nil
}

func decodeLocalAccessRouteUpdate(data []byte) ([32]byte, []netip.Prefix, error) {
	var owner [32]byte
	if len(data) < 34 {
		return owner, nil, errors.New("local-access update payload too short")
	}
	copy(owner[:], data[1:33])
	routes, err := decodeLocalAccessRoutes(data, 33)
	return owner, routes, err
}

func encodeLocalAccessRouteRemoval(owner [32]byte) []byte {
	data := make([]byte, 33)
	data[0] = byte(TUNControlActionRemoveLocalAccessRoutes)
	copy(data[1:], owner[:])
	return data
}

func decodeLocalAccessRouteRemoval(data []byte) ([32]byte, error) {
	var owner [32]byte
	if len(data) != 33 {
		return owner, fmt.Errorf("invalid local-access removal length: %d", len(data))
	}
	copy(owner[:], data[1:])
	return owner, nil
}

func decodeLocalAccessSnapshot(data []byte) (map[[32]byte][]string, error) {
	if len(data) < 2 || TUNControlAction(data[0]) != TUNControlActionSyncLocalAccessRoutes {
		return nil, errors.New("invalid local-access snapshot header")
	}
	ownerCount := int(data[1])
	if ownerCount > maxTenantLocalAccessRoutes {
		return nil, fmt.Errorf("too many local-access snapshot owners: %d", ownerCount)
	}

	result := make(map[[32]byte][]string, ownerCount)
	offset := 2
	totalRoutes := 0
	for range ownerCount {
		if len(data) < offset+33 {
			return nil, errors.New("truncated local-access snapshot owner")
		}
		var owner [32]byte
		copy(owner[:], data[offset:offset+32])
		offset += 32
		count := int(data[offset])
		offset++
		if count == 0 || count > maxLocalAccessRoutes {
			return nil, fmt.Errorf("invalid local-access snapshot route count: %d", count)
		}
		totalRoutes += count
		if totalRoutes > maxTenantLocalAccessRoutes || len(data) < offset+count*localAccessRouteEntrySize {
			return nil, errors.New("invalid local-access snapshot route payload")
		}
		routes := make([]string, 0, count)
		for range count {
			bits := int(data[offset])
			if bits < 8 || bits > 32 {
				return nil, fmt.Errorf("invalid local-access IPv4 prefix length: %d", bits)
			}
			addr := netip.AddrFrom4([4]byte(data[offset+1 : offset+5]))
			prefix := netip.PrefixFrom(addr, bits).Masked()
			if !prefix.Addr().IsPrivate() {
				return nil, fmt.Errorf("local-access route must be private IPv4: %s", prefix)
			}
			routes = append(routes, prefix.String())
			offset += localAccessRouteEntrySize
		}
		result[owner] = routes
	}
	if offset != len(data) {
		return nil, fmt.Errorf("trailing local-access snapshot data: %d bytes", len(data)-offset)
	}
	return result, nil
}

func validLocalAccessPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is4() && prefix.Addr().IsPrivate() &&
		prefix.Bits() >= 8 && prefix.Bits() <= 32
}

func parseLocalAccessRoutes(routes []string) ([]netip.Prefix, error) {
	if len(routes) > maxLocalAccessRoutes {
		return nil, fmt.Errorf("too many local-access routes: %d", len(routes))
	}
	prefixes := make([]netip.Prefix, 0, len(routes))
	seen := make(map[netip.Prefix]struct{}, len(routes))
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return nil, fmt.Errorf("invalid local-access route %q: %w", route, err)
		}
		prefix = prefix.Masked()
		if !validLocalAccessPrefix(prefix) {
			return nil, fmt.Errorf("local-access route must be private IPv4 between /8 and /32: %s", prefix)
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	return prefixes, nil
}

func discoverPrivateLANRoutes(tunName string) ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}

	candidates := make([]localNetworkCandidate, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, parseErr := netip.ParsePrefix(raw.String())
			if parseErr != nil {
				continue
			}
			candidates = append(candidates, localNetworkCandidate{
				InterfaceName: iface.Name,
				Flags:         iface.Flags,
				Prefix:        prefix,
			})
		}
	}
	return selectPrivateLANRoutes(candidates, tunName), nil
}

func selectPrivateLANRoutes(candidates []localNetworkCandidate, tunName string) []string {
	seen := make(map[netip.Prefix]struct{})
	for _, candidate := range candidates {
		prefix := candidate.Prefix.Masked()
		if candidate.InterfaceName == tunName || candidate.Flags&net.FlagUp == 0 ||
			candidate.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !validLocalAccessPrefix(prefix) {
			continue
		}
		seen[prefix] = struct{}{}
	}

	prefixes := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	if len(prefixes) > maxLocalAccessRoutes {
		prefixes = prefixes[:maxLocalAccessRoutes]
	}

	routes := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		routes[i] = prefix.String()
	}
	return routes
}

// EnableLocalAccess enables forwarding/SNAT from the Wantastic TUN to private
// IPv4 prefixes. If explicitRoutes is empty, directly attached LANs are
// discovered. Explicit routes may include /32 host routes.
func (d *Device) EnableLocalAccess(explicitRoutes []string) ([]string, error) {
	d.mu.RLock()
	if d.localAccessShared {
		routes := append([]string(nil), d.localAccessPublished...)
		d.mu.RUnlock()
		return routes, nil
	}
	tunName := d.tunName
	serverRoutes := append([]string(nil), d.config.Server.AllowedIPs...)
	d.mu.RUnlock()

	routes := append([]string(nil), explicitRoutes...)
	if len(routes) == 0 {
		var err error
		routes, err = discoverPrivateLANRoutes(tunName)
		if err != nil {
			return nil, err
		}
	} else {
		prefixes, err := parseLocalAccessRoutes(routes)
		if err != nil {
			return nil, err
		}
		routes = routes[:0]
		for _, prefix := range prefixes {
			routes = append(routes, prefix.String())
		}
	}
	if len(routes) == 0 {
		return nil, errors.New("no directly connected private IPv4 LAN subnet found")
	}
	sources := localAccessSourceRoutes(serverRoutes)
	if len(sources) == 0 {
		return nil, errors.New("no private IPv4 overlay source range is configured")
	}
	if err := enableLocalAccessSharingOS(tunName, routes, sources); err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.localAccessShared = true
	d.localAccessPublished = append([]string(nil), routes...)
	d.localAccessSources = append([]string(nil), sources...)
	d.mu.Unlock()
	return routes, nil
}

func (d *Device) DisableLocalAccess() error {
	d.mu.RLock()
	if !d.localAccessShared {
		d.mu.RUnlock()
		return nil
	}
	tunName := d.tunName
	routes := append([]string(nil), d.localAccessPublished...)
	sources := append([]string(nil), d.localAccessSources...)
	d.mu.RUnlock()

	if err := disableLocalAccessSharingOS(tunName, routes, sources); err != nil {
		return err
	}
	d.mu.Lock()
	d.localAccessShared = false
	d.localAccessPublished = nil
	d.localAccessSources = nil
	d.mu.Unlock()
	return nil
}

func localAccessSourceRoutes(routes []string) []string {
	seen := make(map[string]struct{})
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() == 0 {
			continue
		}
		seen[prefix.String()] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for route := range seen {
		result = append(result, route)
	}
	sort.Strings(result)
	return result
}

func (d *Device) isServerTUNControlPeer(peerPublicKeyHex string) bool {
	serverKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(d.config.Server.PublicKey))
	if err != nil || len(serverKey) != 32 {
		return false
	}
	return strings.EqualFold(peerPublicKeyHex, fmt.Sprintf("%x", serverKey))
}

func (d *Device) applyLocalAccessRouteUpdate(owner [32]byte, routes []netip.Prefix) error {
	d.mu.Lock()
	if len(d.localAccessByOwner) >= maxTenantLocalAccessRoutes {
		if _, exists := d.localAccessByOwner[owner]; !exists {
			d.mu.Unlock()
			return errors.New("too many tenant local-access advertisers")
		}
	}
	encoded := make([]string, len(routes))
	for i, route := range routes {
		encoded[i] = route.String()
	}
	d.localAccessByOwner[owner] = encoded
	d.mu.Unlock()
	return d.syncLocalAccessRoutes()
}

func (d *Device) removeLocalAccessRouteUpdate(owner [32]byte) error {
	d.mu.Lock()
	delete(d.localAccessByOwner, owner)
	d.mu.Unlock()
	return d.syncLocalAccessRoutes()
}

func (d *Device) applyLocalAccessSnapshot(routesByOwner map[[32]byte][]string) error {
	d.mu.Lock()
	if localAccessRouteMapsEqual(d.localAccessByOwner, routesByOwner) {
		d.mu.Unlock()
		return nil
	}
	d.localAccessByOwner = make(map[[32]byte][]string, len(routesByOwner))
	for owner, routes := range routesByOwner {
		d.localAccessByOwner[owner] = append([]string(nil), routes...)
	}
	d.mu.Unlock()
	return d.syncLocalAccessRoutes()
}

func localAccessRouteMapsEqual(a, b map[[32]byte][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for owner, aRoutes := range a {
		bRoutes, ok := b[owner]
		if !ok || len(aRoutes) != len(bRoutes) {
			return false
		}
		for i := range aRoutes {
			if aRoutes[i] != bRoutes[i] {
				return false
			}
		}
	}
	return true
}

func (d *Device) syncLocalAccessRoutes() error {
	d.localAccessSyncMu.Lock()
	defer d.localAccessSyncMu.Unlock()

	d.mu.RLock()
	byOwner := make(map[[32]byte][]string, len(d.localAccessByOwner))
	for owner, routes := range d.localAccessByOwner {
		byOwner[owner] = append([]string(nil), routes...)
	}
	current := append([]string(nil), d.localAccessRoutes...)
	serverKey := d.config.Server.PublicKey
	baseRoutes := append([]string(nil), d.config.Server.AllowedIPs...)
	tunName := d.tunName
	d.mu.RUnlock()

	desiredSet := make(map[string]struct{})
	for _, routes := range byOwner {
		for _, route := range routes {
			desiredSet[route] = struct{}{}
		}
	}
	desired := make([]string, 0, len(desiredSet))
	for route := range desiredSet {
		desired = append(desired, route)
	}
	sort.Strings(desired)

	// Prefer a directly connected LAN over an identical/overlapping tenant
	// advertisement. This avoids stealing access to the user's current LAN when
	// another site happens to use the same RFC1918 range.
	localRoutes, _ := discoverPrivateLANRoutes(tunName)
	desiredSystemRoutes := make([]string, 0, len(desired))
	for _, route := range desired {
		if !routeOverlapsAny(route, localRoutes) {
			desiredSystemRoutes = append(desiredSystemRoutes, route)
		}
	}

	serverKeyHex, err := base64ToHex(serverKey)
	if err != nil {
		return fmt.Errorf("decode server public key: %w", err)
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "public_key=%s\nreplace_allowed_ips=true\n", serverKeyHex)
	for _, route := range append(baseRoutes, desired...) {
		fmt.Fprintf(&cfg, "allowed_ip=%s\n", route)
	}
	if d.device == nil {
		return errors.New("device not started")
	}
	if err := d.device.IpcSet(cfg.String()); err != nil {
		return fmt.Errorf("apply tenant local-access routes to server peer: %w", err)
	}

	currentSet := make(map[string]struct{}, len(current))
	for _, route := range current {
		currentSet[route] = struct{}{}
	}
	desiredSystemSet := make(map[string]struct{}, len(desiredSystemRoutes))
	for _, route := range desiredSystemRoutes {
		desiredSystemSet[route] = struct{}{}
	}
	for _, route := range current {
		if _, keep := desiredSystemSet[route]; keep {
			continue
		}
		if err := removeRouteOS(tunName, route); err != nil {
			return fmt.Errorf("remove local-access route %s: %w", route, err)
		}
	}
	for _, route := range desiredSystemRoutes {
		if _, exists := currentSet[route]; exists {
			continue
		}
		if err := addRouteOS(tunName, route); err != nil {
			return fmt.Errorf("add local-access route %s: %w", route, err)
		}
	}

	d.mu.Lock()
	d.localAccessRoutes = desiredSystemRoutes
	d.mu.Unlock()
	return nil
}

func routeOverlapsAny(route string, candidates []string) bool {
	prefix, err := netip.ParsePrefix(route)
	if err != nil {
		return false
	}
	prefix = prefix.Masked()
	for _, candidate := range candidates {
		other, err := netip.ParsePrefix(candidate)
		if err != nil {
			continue
		}
		other = other.Masked()
		if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
