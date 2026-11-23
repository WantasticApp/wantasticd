package wusp

// WUSPNeighbors: the Wantastic network-neighbor data model on Windows and
// macOS devices.
//
// The agent reads what the operating system already knows about its local
// networks and reports it: the IPv4 ARP cache and the IPv6 neighbor cache
// (Windows: the IP Helper neighbor table, Get-NetNeighbor's source; macOS:
// the routing socket's RTM_GET sysctl, the source of arp -an and ndp -an),
// plus the interface each entry was seen on and whatever name resolution the
// OS has already cached (NetBIOS/LLMNR/mDNS, the hosts file, reverse DNS).
//
// The model is OS-neutral: every leaf is what the platform can supply, empty
// where it cannot. One row per neighbor so a technician can answer "what is
// on this customer's LAN" without a site visit.
//
// Collection is strictly passive. The agent never probes, pings, ARP-sweeps
// or port-scans a neighbor to fill this table: Reachable is the OS's own
// verdict, taken from State, not a packet the agent sent. There are no
// Operate commands on this object and nothing here runs on a timer; the table
// is read when the console asks for the path.

const WUSPNeighborsPrefix = "Device.WUSP_Neighbors."

// Bounds for the tables. A busy office LAN, a /24 with every address live and
// both address families cached, still fits; beyond the cap the agent reports
// the most recently seen neighbors and the true count in TotalNeighbors.
const (
	WUSPNeighborsMaxInterfaces = 32
	WUSPNeighborsMaxNeighbors  = 256
)

var WUSPNeighborsObjects = []Object{
	{Path: WUSPNeighborsPrefix, SinceVersion: "1.0", Description: "Network neighbors this device can see on its local networks, read from the operating system's own ARP and neighbor caches. Read-only: no Operate commands, no probing."},
	{Path: WUSPNeighborsPrefix + "Interface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per local network interface neighbors were seen on."},
	// Row identity is (Interface, MACAddress): one row per host per
	// interface, not one per cached address. A dual-stack host reports its
	// IPv4 address in IPv4Address and every cached IPv6 address in
	// IPv6Addresses, so it stays one row. A neighbor the OS caches without a
	// link-layer address (an incomplete entry) keys on (Interface,
	// IPv4Address) with MACAddress empty.
	{Path: WUSPNeighborsPrefix + "Neighbor.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per neighbor host, keyed by the interface it was seen on and its MAC address."},
}

func neighborsParam(leaf string, typ ParamType, access Access, description string, limits Limits) Param {
	return Param{Path: WUSPNeighborsPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPNeighborsParams = []Param{
	neighborsParam("Installed", TypeBoolean, ReadOnly, "True when this device's platform exposes a neighbor cache the agent can read.", Limits{}),
	neighborsParam("Enable", TypeBoolean, ReadWrite, "Collect network neighbors on this device. Off clears the tables and stops reading the OS caches.", Limits{}),
	neighborsParam("Platform", TypeString, ReadOnly, "Platform family this backend speaks: windows or macos.", Limits{Enums: []string{"", "windows", "macos"}}),
	neighborsParam("Status", TypeString, ReadOnly, "Collection status of the neighbor backend.", Limits{Enums: []string{"not_installed", "disabled", "ok", "read_error", "permission_denied"}}),
	neighborsParam("StatusDetail", TypeString, ReadOnly, "Detail for the current status, empty when ok.", Limits{MaxLength: 256}),
	neighborsParam("LastCollectTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the last successful collection.", Limits{Min: iptr(0)}),

	neighborsParam("InterfaceNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_Neighbors.Interface.{i}.", Limits{Min: iptr(0), Max: iptr(WUSPNeighborsMaxInterfaces)}),
	neighborsParam("NeighborNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_Neighbors.Neighbor.{i}. Rows are capped at 256; TotalNeighbors keeps the true count.", Limits{Min: iptr(0), Max: iptr(WUSPNeighborsMaxNeighbors)}),

	neighborsParam("TotalNeighbors", TypeUnsignedInt, ReadOnly, "Neighbors the OS caches across every collected interface, even when more than the table cap.", Limits{Min: iptr(0)}),
	neighborsParam("ReachableNeighbors", TypeUnsignedInt, ReadOnly, "Neighbors the OS currently considers reachable or permanent.", Limits{Min: iptr(0)}),
	neighborsParam("NamedNeighbors", TypeUnsignedInt, ReadOnly, "Neighbors for which the OS already had a host name, no lookup performed.", Limits{Min: iptr(0)}),

	neighborsParam("Interface.{i}.Name", TypeString, ReadOnly, "OS interface name: an adapter GUID-backed name on Windows (the connection name, e.g. Ethernet or Wi-Fi), a BSD name on macOS (en0, bridge0).", Limits{MaxLength: 64}),
	neighborsParam("Interface.{i}.Alias", TypeString, ReadOnly, "Friendly name the OS shows for the interface, empty when it has none.", Limits{MaxLength: 64}),
	neighborsParam("Interface.{i}.Type", TypeString, ReadOnly, "Interface medium as the OS classifies it.", Limits{Enums: []string{"", "ethernet", "wifi", "bridge", "vpn", "virtual", "cellular", "other"}}),
	neighborsParam("Interface.{i}.MACAddress", TypeString, ReadOnly, "Link-layer address of this interface.", Limits{MaxLength: 32}),
	neighborsParam("Interface.{i}.IPv4Address", TypeString, ReadOnly, "This interface's IPv4 address in CIDR form, e.g. 192.168.1.24/24; empty when it has none.", Limits{MaxLength: 64}),
	neighborsParam("Interface.{i}.IPv6Addresses", TypeString, ReadOnly, "Comma-separated IPv6 addresses of this interface in CIDR form, link-local included.", Limits{MaxLength: 512}),
	neighborsParam("Interface.{i}.GatewayAddress", TypeString, ReadOnly, "Default gateway reached through this interface, empty when it is not a default route.", Limits{MaxLength: 64}),
	neighborsParam("Interface.{i}.Up", TypeBoolean, ReadOnly, "True when the interface is up and has a usable link.", Limits{}),
	neighborsParam("Interface.{i}.NeighborCount", TypeUnsignedInt, ReadOnly, "Neighbors cached on this interface.", Limits{Min: iptr(0)}),

	neighborsParam("Neighbor.{i}.Interface", TypeString, ReadOnly, "Interface this neighbor was seen on; matches an Interface.{i}.Name.", Limits{MaxLength: 64}),
	neighborsParam("Neighbor.{i}.IPv4Address", TypeString, ReadOnly, "The neighbor's IPv4 address, empty for an IPv6-only neighbor.", Limits{MaxLength: 64}),
	neighborsParam("Neighbor.{i}.IPv6Addresses", TypeString, ReadOnly, "Comma-separated IPv6 addresses the OS caches for this neighbor, link-local included; empty for an IPv4-only neighbor.", Limits{MaxLength: 512}),
	neighborsParam("Neighbor.{i}.MACAddress", TypeString, ReadOnly, "The neighbor's link-layer address; empty when the OS has an incomplete entry with no answer yet.", Limits{MaxLength: 32}),
	neighborsParam("Neighbor.{i}.Vendor", TypeString, ReadOnly, "Hardware vendor for the MAC's OUI from the agent's bundled OUI table, empty when unknown. A randomized (locally administered) MAC reports no vendor.", Limits{MaxLength: 64}),
	neighborsParam("Neighbor.{i}.OUI", TypeString, ReadOnly, "First three bytes of the MAC in hex, e.g. E05D54; empty when the MAC is unknown.", Limits{MaxLength: 16}),
	neighborsParam("Neighbor.{i}.HostName", TypeString, ReadOnly, "Host name the OS already had for this neighbor, empty when it had none. The agent resolves nothing itself.", Limits{MaxLength: 128}),
	neighborsParam("Neighbor.{i}.HostNameSource", TypeString, ReadOnly, "Where the cached name came from.", Limits{Enums: []string{"", "dns", "mdns", "netbios", "llmnr", "hosts", "dhcp", "other"}}),
	neighborsParam("Neighbor.{i}.State", TypeString, ReadOnly, "The OS's own neighbor-cache state: reachable (answered recently), stale (not confirmed lately, still usable), delay/probe (the OS is confirming it), incomplete (no answer yet), failed (resolution gave up), permanent (a static entry). Taken from the cache; the agent sends no probe of its own.", Limits{Enums: []string{"", "reachable", "stale", "delay", "probe", "incomplete", "failed", "permanent"}}),
	neighborsParam("Neighbor.{i}.Reachable", TypeBoolean, ReadOnly, "True when the OS considers the neighbor live: State is reachable or permanent. Derived from State, never from a probe the agent sent.", Limits{}),
	neighborsParam("Neighbor.{i}.Static", TypeBoolean, ReadOnly, "True for a manually configured (permanent) cache entry.", Limits{}),
	neighborsParam("Neighbor.{i}.IsGateway", TypeBoolean, ReadOnly, "True when this neighbor is a default gateway of the interface it was seen on.", Limits{}),
	neighborsParam("Neighbor.{i}.IsRouter", TypeBoolean, ReadOnly, "True when the neighbor announced itself as a router (IPv6 router advertisement).", Limits{}),
	neighborsParam("Neighbor.{i}.FirstSeenTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the agent first saw this neighbor, 0 when it only has the current collection.", Limits{Min: iptr(0)}),
	neighborsParam("Neighbor.{i}.LastSeenTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the entry was last confirmed by the OS, falling back to the collection time for a cached entry with no timestamp.", Limits{Min: iptr(0)}),
}
