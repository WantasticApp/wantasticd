// Package netctl provides low-level network control using native platform APIs.
//
// On Linux:  netlink (AF_NETLINK) for routes/links/addresses, nl80211 via
//
//	libnl-genl-3 for WiFi control, nfnetlink for iptables.
//	Build with -tags netctl for CGo-accelerated WiFi (libnl-genl).
//
// On macOS:  BSD route sockets, CoreWLAN.framework for WiFi.
// On Windows: WinAPI (wlanapi, iphlpapi) for WiFi and route management.
//
// All pure-Go fallbacks use raw syscall or sysfs when CGo tags are absent.
package netctl

import "net/netip"

// WiFiCapabilities describes a radio's hardware capabilities.
type WiFiCapabilities struct {
	PHYName          string   // e.g. "phy0"
	SupportedHTModes []string // e.g. ["HT20","HT40","VHT20","VHT40","VHT80","VHT160"]
	Bands            []string // e.g. ["2.4GHz","5GHz"]
	MaxTxStreams     int
	MaxRxStreams     int
	HT               bool // 802.11n
	VHT              bool // 802.11ac
	HE               bool // 802.11ax (WiFi 6)
	EHT              bool // 802.11be (WiFi 7)
}

// WiFiStationInfo describes a connected WiFi client.
type WiFiStationInfo struct {
	MAC           string
	Signal        int    // dBm
	Noise         int    // dBm
	RxRate        uint32 // kbit/s
	TxRate        uint32 // kbit/s
	RxBytes       uint64
	TxBytes       uint64
	ConnectedSecs uint32
	Inactive      uint32 // ms since last activity
}

// FirewallRule represents a NAT/filter rule.
type FirewallRule struct {
	Table string // "nat", "filter", "mangle"
	Chain string // "POSTROUTING", "FORWARD", etc.
	Args  []string
}

// Controller is the unified network control interface.
// Each platform provides a concrete implementation.
type Controller interface {
	// ── Link management ─────────────────────────────────────────────────
	LinkSetUp(ifname string) error
	LinkSetDown(ifname string) error
	LinkSetMTU(ifname string, mtu int) error

	// ── Address management ──────────────────────────────────────────────
	AddrAdd(ifname string, addr netip.Prefix) error
	AddrDel(ifname string, addr netip.Prefix) error

	// ── Route management ────────────────────────────────────────────────
	RouteReplace(ifname string, dst netip.Prefix) error
	RouteDel(ifname string, dst netip.Prefix) error
	RouteGetDefault() (ifname string, gateway netip.Addr, err error)

	// ── WiFi capabilities ───────────────────────────────────────────────
	WiFiGetCapabilities(ifname string) (*WiFiCapabilities, error)
	WiFiGetStations(ifname string) ([]WiFiStationInfo, error)

	// ── Firewall / NAT ──────────────────────────────────────────────────
	FirewallEnsureRule(rule FirewallRule) error
	FirewallDeleteRule(rule FirewallRule) error
	IPForwardingSet(enabled bool) error

	// ── Cleanup ─────────────────────────────────────────────────────────
	Close() error
}

// New returns the platform-native Controller.
// CGo implementations are selected via build tags; pure-Go fallbacks are used otherwise.
func New() Controller {
	return newController()
}
