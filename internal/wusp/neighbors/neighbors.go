// Package neighbors builds Device.WUSP_Neighbors. from what the operating
// system already knows about its local networks.
//
// Everything in this file is OS-neutral: the platform backends hand it the
// rows they read out of the OS neighbor cache (Windows: the IP Helper
// neighbor table; macOS: the routing socket's RTM_GET sysctl) and this package
// merges them into the model's one-row-per-host shape and writes the fields.
//
// Collection is strictly passive. Nothing here sends a packet: Reachable is
// derived from the cache State the OS reported, never from a probe, and
// nothing runs on a timer — the tables are built when a collect asks for them.
package neighbors

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"
)

// Neighbor-cache states, the Device.WUSP_Neighbors.Neighbor.{i}.State enum.
const (
	StateReachable  = "reachable"
	StateStale      = "stale"
	StateDelay      = "delay"
	StateProbe      = "probe"
	StateIncomplete = "incomplete"
	StateFailed     = "failed"
	StatePermanent  = "permanent"
)

// Collection statuses, the Device.WUSP_Neighbors.Status enum.
const (
	StatusNotInstalled     = "not_installed"
	StatusDisabled         = "disabled"
	StatusOK               = "ok"
	StatusReadError        = "read_error"
	StatusPermissionDenied = "permission_denied"
)

// Platform families, the Device.WUSP_Neighbors.Platform enum.
const (
	PlatformWindows = "windows"
	PlatformMacOS   = "macos"
)

// Entry is one cached neighbor address exactly as the OS reported it. A
// dual-stack host produces several entries, which Build merges into one row.
type Entry struct {
	Interface string
	IP        net.IP
	MAC       net.HardwareAddr
	// State is one of the State* constants, already normalized from the
	// platform's own cache state. Empty when the OS does not say.
	State string
	// Static marks a manually configured (permanent) cache entry.
	Static bool
	// IsRouter is set when the neighbor announced itself as an IPv6 router.
	IsRouter bool
	// HostName / HostNameSource carry a name the OS already had cached. The
	// agent resolves nothing itself, so these stay empty on a platform whose
	// neighbor table carries no name.
	HostName       string
	HostNameSource string
	// LastSeen is when the OS last confirmed the entry, in Unix seconds; 0
	// when the cache keeps no timestamp.
	LastSeen int64
}

// Interface is one local network interface neighbors were seen on.
type Interface struct {
	Name           string
	Alias          string
	Type           string
	MACAddress     string
	IPv4Address    string
	IPv6Addresses  []string
	GatewayAddress string
	Up             bool
}

// Snapshot is one passive reading of the OS neighbor cache.
type Snapshot struct {
	Platform     string
	Status       string
	StatusDetail string
	Interfaces   []Interface
	Entries      []Entry
}

// Row is one merged neighbor: one host, on one interface, however many
// addresses the OS caches for it.
type Row struct {
	Interface      string
	IPv4Address    string
	IPv6Addresses  []string
	MACAddress     string
	Vendor         string
	OUI            string
	HostName       string
	HostNameSource string
	State          string
	Reachable      bool
	Static         bool
	IsGateway      bool
	IsRouter       bool
	FirstSeenTime  uint64
	LastSeenTime   uint64

	// key identifies the row: (Interface, MACAddress), or (Interface, IP)
	// for an incomplete entry the OS has no link-layer address for.
	key string
}

// Reachable reports the OS's own verdict on a neighbor being live. It is
// derived from the cache state and nothing else; the agent never probes.
func Reachable(state string) bool {
	return state == StateReachable || state == StatePermanent
}

// stateRank orders cache states from least to most informative about the host
// being there now. A host with a stale IPv4 entry and a reachable IPv6 entry
// reports reachable.
func stateRank(state string) int {
	switch state {
	case StateReachable:
		return 7
	case StatePermanent:
		return 6
	case StateDelay:
		return 5
	case StateProbe:
		return 4
	case StateStale:
		return 3
	case StateIncomplete:
		return 2
	case StateFailed:
		return 1
	default:
		return 0
	}
}

// NormalizeState maps a platform's own spelling of a neighbor-cache state onto
// the model enum. An unknown value becomes empty rather than failing schema
// validation.
func NormalizeState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case StateReachable:
		return StateReachable
	case StateStale:
		return StateStale
	case StateDelay:
		return StateDelay
	case StateProbe:
		return StateProbe
	case StateIncomplete:
		return StateIncomplete
	case StateFailed, "unreachable":
		return StateFailed
	case StatePermanent, "static":
		return StatePermanent
	default:
		return ""
	}
}

// NormalizeHostNameSource maps a name source onto the model enum.
func NormalizeHostNameSource(source string) string {
	switch s := strings.ToLower(strings.TrimSpace(source)); s {
	case "dns", "mdns", "netbios", "llmnr", "hosts", "dhcp", "other":
		return s
	case "":
		return ""
	default:
		return "other"
	}
}

// NormalizeInterfaceType maps an interface medium onto the model enum.
func NormalizeInterfaceType(kind string) string {
	switch k := strings.ToLower(strings.TrimSpace(kind)); k {
	case "ethernet", "wifi", "bridge", "vpn", "virtual", "cellular", "other":
		return k
	case "":
		return ""
	default:
		return "other"
	}
}

// OUIFromMAC returns the first three bytes of a MAC in upper-case hex, the
// form Device.WUSP_Neighbors.Neighbor.{i}.OUI wants (e.g. E05D54). It is empty
// when the MAC is unknown or shorter than three bytes.
func OUIFromMAC(mac string) string {
	var out strings.Builder
	bytes := 0
	for i := 0; i < len(mac) && bytes < 3; i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			out.WriteByte(c)
		case c >= 'a' && c <= 'f':
			out.WriteByte(c - 'a' + 'A')
		default:
			continue
		}
		if out.Len()%2 == 0 {
			bytes++
		}
	}
	if out.Len() != 6 {
		return ""
	}
	return out.String()
}

// LocallyAdministered reports whether a MAC is a locally administered
// (randomized) address, which belongs to no vendor.
func LocallyAdministered(mac string) bool {
	oui := OUIFromMAC(mac)
	if oui == "" {
		return false
	}
	first := hexNibble(oui[0])<<4 | hexNibble(oui[1])
	return first&0x02 != 0
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// VendorForOUI names the hardware vendor of an OUI. This agent bundles no OUI
// database, so it reports nothing rather than carrying a megabyte of vendor
// names onto every customer device: the console shows an empty vendor and the
// OUI itself. A randomized MAC reports no vendor either way.
func VendorForOUI(string) string { return "" }

// FirstSeen remembers when the agent first saw each neighbor, so a row can
// report FirstSeenTime on later collections. It is filled by collection only
// and holds nothing but a timestamp per (interface, MAC) key.
type FirstSeen struct {
	mu   sync.Mutex
	seen map[string]int64
}

// NewFirstSeen returns an empty first-seen memory.
func NewFirstSeen() *FirstSeen { return &FirstSeen{} }

// maxFirstSeenKeys bounds the memory: a few generations of a large LAN. Past
// it the oldest entries go, which only costs a FirstSeenTime of 0.
const maxFirstSeenKeys = 4 * wusp.WUSPNeighborsMaxNeighbors

// observe records that key was seen now and returns the first time it was
// seen, or 0 when this collection is the first one to carry it.
func (f *FirstSeen) observe(key string, now int64) uint64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = make(map[string]int64)
	}
	if first, ok := f.seen[key]; ok {
		if first <= 0 || first > now {
			return 0
		}
		return uint64(first)
	}
	if len(f.seen) >= maxFirstSeenKeys {
		f.prune(now)
	}
	f.seen[key] = now
	return 0
}

// prune drops the oldest half of the memory. Called with the lock held.
func (f *FirstSeen) prune(now int64) {
	times := make([]int64, 0, len(f.seen))
	for _, first := range f.seen {
		times = append(times, first)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	cutoff := times[len(times)/2]
	for key, first := range f.seen {
		if first <= cutoff {
			delete(f.seen, key)
		}
	}
}

// Build merges the snapshot's per-address entries into one row per host per
// interface and returns the rows in a stable order, newest-seen first.
func Build(snap Snapshot, now time.Time, tracker *FirstSeen) []Row {
	collected := now.Unix()
	gateways := gatewaySet(snap.Interfaces)

	byKey := make(map[string]*Row, len(snap.Entries))
	order := make([]*Row, 0, len(snap.Entries))
	for _, entry := range snap.Entries {
		ip := entry.IP
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		mac := normalizeMAC(entry.MAC)
		key := entry.Interface + "\x00" + mac
		if mac == "" {
			// An incomplete entry the OS has no answer for keys on its
			// address instead, so two of them stay two rows.
			key = entry.Interface + "\x00ip\x00" + ip.String()
		}
		row, ok := byKey[key]
		if !ok {
			row = &Row{Interface: entry.Interface, MACAddress: mac, key: key}
			byKey[key] = row
			order = append(order, row)
		}
		mergeEntry(row, entry, ip)
		if gateways[entry.Interface+"\x00"+ip.String()] {
			row.IsGateway = true
		}
	}

	rows := make([]Row, 0, len(order))
	for _, row := range order {
		row.OUI = OUIFromMAC(row.MACAddress)
		if !LocallyAdministered(row.MACAddress) {
			row.Vendor = VendorForOUI(row.OUI)
		}
		row.Reachable = Reachable(row.State)
		row.Static = row.Static || row.State == StatePermanent
		if row.LastSeenTime == 0 {
			row.LastSeenTime = uint64(max64(collected, 0))
		}
		sort.Strings(row.IPv6Addresses)
		row.FirstSeenTime = tracker.observe(row.key, collected)
		rows = append(rows, *row)
	}

	// Newest-seen first, so truncating at the table cap keeps the most
	// recently seen neighbors; ties fall back to a stable address order.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].LastSeenTime != rows[j].LastSeenTime {
			return rows[i].LastSeenTime > rows[j].LastSeenTime
		}
		if rows[i].Interface != rows[j].Interface {
			return rows[i].Interface < rows[j].Interface
		}
		return rows[i].key < rows[j].key
	})
	return rows
}

func mergeEntry(row *Row, entry Entry, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		if row.IPv4Address == "" || v4.String() < row.IPv4Address {
			row.IPv4Address = v4.String()
		}
	} else {
		text := ip.String()
		if !containsString(row.IPv6Addresses, text) {
			row.IPv6Addresses = append(row.IPv6Addresses, text)
		}
	}
	state := NormalizeState(entry.State)
	if stateRank(state) > stateRank(row.State) {
		row.State = state
	}
	row.Static = row.Static || entry.Static
	row.IsRouter = row.IsRouter || entry.IsRouter
	if row.HostName == "" && strings.TrimSpace(entry.HostName) != "" {
		row.HostName = truncate(strings.TrimSpace(entry.HostName), 128)
		row.HostNameSource = NormalizeHostNameSource(entry.HostNameSource)
	}
	if entry.LastSeen > 0 && uint64(entry.LastSeen) > row.LastSeenTime {
		row.LastSeenTime = uint64(entry.LastSeen)
	}
}

// gatewaySet indexes the default gateway of every interface, so a neighbor
// that is one can say so.
func gatewaySet(interfaces []Interface) map[string]bool {
	out := make(map[string]bool, len(interfaces))
	for _, iface := range interfaces {
		gateway := strings.TrimSpace(iface.GatewayAddress)
		if gateway == "" {
			continue
		}
		for _, one := range strings.Split(gateway, ",") {
			if parsed := net.ParseIP(strings.TrimSpace(one)); parsed != nil {
				out[iface.Name+"\x00"+parsed.String()] = true
			}
		}
	}
	return out
}

// Append writes Device.WUSP_Neighbors. onto msg. installed says whether the
// platform exposes a neighbor cache at all and enabled whether the console
// asked for the collection; a disabled or unsupported backend reports empty
// tables rather than stale ones.
func Append(msg *wusp.Message, snap Snapshot, installed, enabled bool, now time.Time, tracker *FirstSeen) {
	if msg == nil {
		return
	}
	prefix := wusp.WUSPNeighborsPrefix
	msg.Set(prefix+"Installed", wusp.Bool(installed))
	msg.Set(prefix+"Enable", wusp.Bool(enabled))
	if snap.Platform != "" {
		msg.Set(prefix+"Platform", wusp.String(snap.Platform))
	}

	switch {
	case !installed:
		setEmpty(msg, prefix, StatusNotInstalled, snap.StatusDetail)
		return
	case !enabled:
		setEmpty(msg, prefix, StatusDisabled, "")
		return
	}

	status := snap.Status
	if status == "" {
		status = StatusOK
	}
	msg.Set(prefix+"Status", wusp.String(status))
	msg.Set(prefix+"StatusDetail", wusp.String(truncate(snap.StatusDetail, 256)))
	if status == StatusOK {
		msg.Set(prefix+"LastCollectTime", wusp.Uint(uint64(max64(now.Unix(), 0))))
	}

	rows := Build(snap, now, tracker)
	perInterface := make(map[string]uint64, len(snap.Interfaces))
	var reachable, named uint64
	for _, row := range rows {
		perInterface[row.Interface]++
		if row.Reachable {
			reachable++
		}
		if row.HostName != "" {
			named++
		}
	}
	msg.Set(prefix+"TotalNeighbors", wusp.Uint(uint64(len(rows))))
	msg.Set(prefix+"ReachableNeighbors", wusp.Uint(reachable))
	msg.Set(prefix+"NamedNeighbors", wusp.Uint(named))

	interfaces := snap.Interfaces
	if len(interfaces) > wusp.WUSPNeighborsMaxInterfaces {
		interfaces = interfaces[:wusp.WUSPNeighborsMaxInterfaces]
	}
	msg.Set(prefix+"InterfaceNumberOfEntries", wusp.Uint(uint64(len(interfaces))))
	for i, iface := range interfaces {
		base := prefix + "Interface." + itoa(i+1) + "."
		msg.Set(base+"Name", wusp.String(truncate(iface.Name, 64)))
		msg.Set(base+"Alias", wusp.String(truncate(iface.Alias, 64)))
		msg.Set(base+"Type", wusp.String(NormalizeInterfaceType(iface.Type)))
		msg.Set(base+"MACAddress", wusp.String(truncate(iface.MACAddress, 32)))
		msg.Set(base+"IPv4Address", wusp.String(truncate(iface.IPv4Address, 64)))
		msg.Set(base+"IPv6Addresses", wusp.String(joinWithin(iface.IPv6Addresses, 512)))
		msg.Set(base+"GatewayAddress", wusp.String(truncate(iface.GatewayAddress, 64)))
		msg.Set(base+"Up", wusp.Bool(iface.Up))
		msg.Set(base+"NeighborCount", wusp.Uint(perInterface[iface.Name]))
	}

	if len(rows) > wusp.WUSPNeighborsMaxNeighbors {
		rows = rows[:wusp.WUSPNeighborsMaxNeighbors]
	}
	msg.Set(prefix+"NeighborNumberOfEntries", wusp.Uint(uint64(len(rows))))
	for i, row := range rows {
		base := prefix + "Neighbor." + itoa(i+1) + "."
		msg.Set(base+"Interface", wusp.String(truncate(row.Interface, 64)))
		msg.Set(base+"IPv4Address", wusp.String(truncate(row.IPv4Address, 64)))
		msg.Set(base+"IPv6Addresses", wusp.String(joinWithin(row.IPv6Addresses, 512)))
		msg.Set(base+"MACAddress", wusp.String(truncate(row.MACAddress, 32)))
		msg.Set(base+"Vendor", wusp.String(truncate(row.Vendor, 64)))
		msg.Set(base+"OUI", wusp.String(truncate(row.OUI, 16)))
		msg.Set(base+"HostName", wusp.String(truncate(row.HostName, 128)))
		msg.Set(base+"HostNameSource", wusp.String(row.HostNameSource))
		msg.Set(base+"State", wusp.String(row.State))
		msg.Set(base+"Reachable", wusp.Bool(row.Reachable))
		msg.Set(base+"Static", wusp.Bool(row.Static))
		msg.Set(base+"IsGateway", wusp.Bool(row.IsGateway))
		msg.Set(base+"IsRouter", wusp.Bool(row.IsRouter))
		msg.Set(base+"FirstSeenTime", wusp.Uint(row.FirstSeenTime))
		msg.Set(base+"LastSeenTime", wusp.Uint(row.LastSeenTime))
	}
}

// setEmpty reports a backend that collected nothing: the tables are cleared
// rather than left holding what an earlier collection found.
func setEmpty(msg *wusp.Message, prefix, status, detail string) {
	msg.Set(prefix+"Status", wusp.String(status))
	msg.Set(prefix+"StatusDetail", wusp.String(truncate(detail, 256)))
	msg.Set(prefix+"InterfaceNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"NeighborNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"TotalNeighbors", wusp.Uint(0))
	msg.Set(prefix+"ReachableNeighbors", wusp.Uint(0))
	msg.Set(prefix+"NamedNeighbors", wusp.Uint(0))
}

func normalizeMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return ""
	}
	text := strings.ToUpper(mac.String())
	// An all-zero link-layer address is the OS saying it has no answer.
	if strings.Trim(text, "0:") == "" {
		return ""
	}
	return truncate(text, 32)
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// joinWithin joins items with commas, dropping whole items rather than
// cutting one in half when the model's MaxLength would be exceeded.
func joinWithin(items []string, limit int) string {
	var out strings.Builder
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		extra := len(item)
		if out.Len() > 0 {
			extra++
		}
		if out.Len()+extra > limit {
			break
		}
		if out.Len() > 0 {
			out.WriteByte(',')
		}
		out.WriteString(item)
	}
	return out.String()
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
