// Package wusp (WireGuard USP) defines the TR-181 Issue 2 (Amendment 20)
// data model for wantasticd. It enumerates every Device. object path with
// its value type, access level, and limits so that a future USP Agent or
// CWMP client can drive Get/Set/Add/Delete operations without hand-coding
// path strings or type coercions.
//
// Source: BBF TR-181 Issue 2, Amendment 20 (November 2025)
// https://usp-data-models.broadband-forum.org/tr-181-2-20-1-usp-full.xml
package wusp

// ---------------------------------------------------------------------------
// Core type system
// ---------------------------------------------------------------------------

// ParamType mirrors the BBF CWMP/USP primitive types.
type ParamType string

const (
	TypeString       ParamType = "string"
	TypeInt          ParamType = "int"
	TypeUnsignedInt  ParamType = "unsignedInt"
	TypeLong         ParamType = "long"
	TypeUnsignedLong ParamType = "unsignedLong"
	TypeBoolean      ParamType = "boolean"
	TypeDateTime     ParamType = "dateTime"
	TypeBase64       ParamType = "base64"
	TypeHexBinary    ParamType = "hexBinary"
	TypeDecimal      ParamType = "decimal"

	// Composite / referenced types defined in TR-106 / TR-181 data-type library.
	TypeIPv4Address  ParamType = "IPv4Address"  // dotted-decimal, e.g. "192.168.1.1"
	TypeIPv6Address  ParamType = "IPv6Address"  // colon-hex, e.g. "fe80::1"
	TypeIPv4Prefix   ParamType = "IPv4Prefix"   // CIDR, e.g. "192.168.1.0/24"
	TypeIPv6Prefix   ParamType = "IPv6Prefix"   // CIDR, e.g. "fe80::/10"
	TypeMACAddress   ParamType = "MACAddress"   // colon-hex, e.g. "aa:bb:cc:dd:ee:ff"
	TypeAlias        ParamType = "Alias"        // USP/CWMP instance alias, max 64 chars
	TypeStatsCounter ParamType = "StatsCounter" // wrapping 32-bit or 64-bit counter
	TypePathRef      ParamType = "PathRef"      // reference to another object path
	TypeList         ParamType = "list"         // comma-separated list of values
)

// Access describes who can change a parameter.
type Access string

const (
	ReadOnly  Access = "readOnly"
	ReadWrite Access = "readWrite"
	WriteOnly Access = "writeOnly" // used for passwords / keys
)

// Limits constrains the legal value range for a parameter.
// Only the fields relevant to the type need to be filled in.
type Limits struct {
	// Numeric bounds (int / unsignedInt / long / unsignedLong / decimal).
	Min    *int64
	Max    *int64
	MinF   *float64 // decimal lower bound
	MaxF   *float64 // decimal upper bound

	// String / base64 / hexBinary length.
	MinLength int
	MaxLength int // 0 = no limit specified

	// Enumeration — nil means no restriction.
	Enums []string

	// Pattern — POSIX ERE pattern; empty = no restriction.
	Pattern string

	// List element count (for TypeList parameters).
	MinItems int
	MaxItems int // 0 = no limit
}

// Param is a fully-described TR-181 parameter.
type Param struct {
	// Path is the fully qualified TR-181 path, e.g.
	// "Device.DeviceInfo.Manufacturer".
	Path string

	// Type is the BBF primitive type.
	Type ParamType

	// Access is the read/write capability of the parameter.
	Access Access

	// SinceVersion is the TR-181 version that introduced this parameter,
	// e.g. "2.0", "2.20".
	SinceVersion string

	// Description is the normative description from the BBF specification.
	Description string

	// Limits holds value constraints. Zero-valued fields are ignored.
	Limits Limits
}

// Object represents a TR-181 object node (singleton or multi-instance).
type Object struct {
	// Path is the fully qualified TR-181 object path including the trailing
	// dot, e.g. "Device.WireGuard." or "Device.WiFi.Radio.{i}.".
	Path string

	// MultiInstance is true for {i} table objects.
	MultiInstance bool

	// SinceVersion is the TR-181 version that introduced the object.
	SinceVersion string

	// Description is the normative description from the BBF specification.
	Description string
}

// ---------------------------------------------------------------------------
// Convenience helpers for limit construction.
// ---------------------------------------------------------------------------

func intPtr(v int64) *int64   { return &v }
func f64Ptr(v float64) *float64 { return &v }

func maxLen(n int) Limits     { return Limits{MaxLength: n} }
func bounded(lo, hi int64) Limits {
	return Limits{Min: intPtr(lo), Max: intPtr(hi)}
}
func minBound(lo int64) Limits { return Limits{Min: intPtr(lo)} }
func enumL(vals ...string) Limits { return Limits{Enums: vals} }
func maxLenEnum(n int, vals ...string) Limits {
	return Limits{MaxLength: n, Enums: vals}
}

// ---------------------------------------------------------------------------
// Device. — root object parameters
// ---------------------------------------------------------------------------

// DeviceRootParams are the parameters that live directly on Device. (the
// root object). They are not nested under any sub-object.
var DeviceRootParams = []Param{
	{
		Path:         "Device.RootDataModelVersion",
		Type:         TypeString,
		Access:       ReadOnly,
		SinceVersion: "2.4",
		Description:  "Indicates the highest version of the BBF standard data model the agent supports. Format: \"<major>.<minor>\", e.g. \"2.20\".",
		Limits:       maxLen(32),
	},
	{
		Path:         "Device.InterfaceStackNumberOfEntries",
		Type:         TypeUnsignedInt,
		Access:       ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.InterfaceStack.{i}.",
	},
	{
		Path:         "Device.ProxiedDeviceNumberOfEntries",
		Type:         TypeUnsignedInt,
		Access:       ReadOnly,
		SinceVersion: "2.6",
		Description:  "Number of entries in Device.ProxiedDevice.{i}.",
	},
	{
		Path:         "Device.CollectionDeviceNumberOfEntries",
		Type:         TypeUnsignedInt,
		Access:       ReadOnly,
		SinceVersion: "v2.13",
		Description:  "Number of entries in Device.CollectionDevice.{i}.",
	},
	{
		Path:         "Device.IoTCapabilityNumberOfEntries",
		Type:         TypeUnsignedInt,
		Access:       ReadOnly,
		SinceVersion: "2.13",
		Description:  "Number of entries in Device.IoTCapability.{i}.",
	},
	{
		Path:         "Device.NodeNumberOfEntries",
		Type:         TypeUnsignedInt,
		Access:       ReadOnly,
		SinceVersion: "2.13",
		Description:  "Number of entries in Device.Node.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device. — complete top-level object catalogue (TR-181 v2.20.1)
// ---------------------------------------------------------------------------

// DeviceObjects enumerates every standardised top-level object under
// Device. sorted alphabetically. Use this list to build USP supported-paths
// tables, schema validators, or documentation generators.
var DeviceObjects = []Object{
	{Path: "Device.", SinceVersion: "2.0", Description: "Root TR-181 device object."},

	{Path: "Device.ATM.", SinceVersion: "2.0",
		Description: "Asynchronous Transfer Mode (ATM) link interfaces and F5 loopback diagnostics."},
	{Path: "Device.ATM.Link.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "ATM link layer table. Each entry represents one AAL5 PVC."},

	{Path: "Device.BASAPM.", SinceVersion: "2.12",
		Description: "Broadband Access Service Attributes and Performance Metrics (BASAPM); IETF IPPM-based active tests."},

	{Path: "Device.Bridging.", SinceVersion: "2.0",
		Description: "Layer 2 bridging — bridges, filters, and spanning tree."},
	{Path: "Device.Bridging.Bridge.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "IEEE 802.1D/Q bridge table."},

	{Path: "Device.BulkData.", SinceVersion: "2.5",
		Description: "Bulk data collection profiles (HTTP, MQTT, USPEventNotif, IPDR Streaming)."},
	{Path: "Device.BulkData.Profile.{i}.", MultiInstance: true, SinceVersion: "2.5",
		Description: "A single bulk-data collection profile."},

	{Path: "Device.CWMPManagementServer.", SinceVersion: "2.0",
		Description: "TR-069 CWMP management server configuration (URL, credentials, inform interval)."},

	{Path: "Device.CaptivePortal.", SinceVersion: "2.0",
		Description: "Captive portal URL and enable flag for subscriber redirection."},

	{Path: "Device.Cellular.", SinceVersion: "2.8",
		Description: "Cellular (LTE / 5G NR) interfaces and APN configuration."},
	{Path: "Device.Cellular.Interface.{i}.", MultiInstance: true, SinceVersion: "2.8",
		Description: "Cellular radio interface (IMEI, IMSI, signal, operator, tech)."},
	{Path: "Device.Cellular.AccessPoint.{i}.", MultiInstance: true, SinceVersion: "2.8",
		Description: "APN / PDN configuration for a cellular interface."},

	{Path: "Device.ConnectionMonitoring.", SinceVersion: "2.20",
		Description: "ARP/ND-based connectivity probing per interface (new in v2.20)."},
	{Path: "Device.ConnectionMonitoring.Connection.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Per-target probe configuration (target IP, thresholds, probe interval)."},

	{Path: "Device.DHCPv4.", SinceVersion: "2.0",
		Description: "DHCP for IPv4 (RFC 2131) — client, server, and relay agent."},
	{Path: "Device.DHCPv4.Client.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "DHCPv4 client instance per interface."},
	{Path: "Device.DHCPv4.Server.", SinceVersion: "2.0",
		Description: "DHCPv4 server configuration."},
	{Path: "Device.DHCPv4.Server.Pool.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "DHCPv4 address pool."},
	{Path: "Device.DHCPv4.Relay.", SinceVersion: "2.0",
		Description: "DHCPv4 relay agent configuration."},

	{Path: "Device.DHCPv6.", SinceVersion: "2.2",
		Description: "DHCP for IPv6 (RFC 8415) — client and server."},
	{Path: "Device.DHCPv6.Client.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "DHCPv6 client instance per interface (IA_NA, IA_PD, options)."},
	{Path: "Device.DHCPv6.Server.", SinceVersion: "2.2",
		Description: "DHCPv6 server configuration."},

	{Path: "Device.DLNA.", SinceVersion: "2.0",
		Description: "DLNA (Digital Living Network Alliance) server parameters."},

	{Path: "Device.DNS.", SinceVersion: "2.0",
		Description: "DNS client, relay, and service discovery (RFC 6763)."},
	{Path: "Device.DNS.Client.", SinceVersion: "2.0",
		Description: "DNS stub resolver configuration (server list, search domains)."},
	{Path: "Device.DNS.Relay.", SinceVersion: "2.0",
		Description: "DNS proxy / forwarding relay."},
	{Path: "Device.DNS.SD.", SinceVersion: "2.6",
		Description: "DNS Service Discovery (RFC 6763) service advertisement."},
	{Path: "Device.DNS.Diagnostics.", SinceVersion: "2.0",
		Description: "NSLookup diagnostic command."},
	{Path: "Device.DNS.Zone.{i}.", MultiInstance: true, SinceVersion: "2.6",
		Description: "Authoritative DNS zone table."},

	{Path: "Device.DOCSIS.", SinceVersion: "2.13",
		Description: "DOCSIS 3.x cable interface objects (CM, CMTS)."},

	{Path: "Device.DSL.", SinceVersion: "2.0",
		Description: "DSL lines, channels, bonding, and diagnostics (ITU G.99x)."},
	{Path: "Device.DSL.Line.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Physical DSL line."},
	{Path: "Device.DSL.Channel.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "DSL bearer channel."},

	{Path: "Device.DSLite.", SinceVersion: "2.2",
		Description: "IPv6 Dual-Stack Lite (RFC 6333) tunnel configuration."},
	{Path: "Device.DSLite.InterfaceSetting.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "DS-Lite AFTR tunnel configuration per interface."},

	{Path: "Device.DeviceInfo.", SinceVersion: "2.0",
		Description: "General device information: manufacturer, model, firmware, hardware, uptime."},
	{Path: "Device.DeviceInfo.MemoryStatus.", SinceVersion: "2.0",
		Description: "Physical memory usage (Total, Free bytes)."},
	{Path: "Device.DeviceInfo.ProcessStatus.", SinceVersion: "2.0",
		Description: "Running processes table (PID, name, CPU, memory, state)."},
	{Path: "Device.DeviceInfo.TemperatureStatus.", SinceVersion: "2.0",
		Description: "Temperature sensors table."},
	{Path: "Device.DeviceInfo.NetworkProperties.", SinceVersion: "2.2",
		Description: "Low-level network stack properties (MaxTCPWindowSize, TCPImplementation, etc.)."},
	{Path: "Device.DeviceInfo.KernelFaults.", SinceVersion: "2.16",
		Description: "Kernel panic / oops tracking."},
	{Path: "Device.DeviceInfo.ProcessFaults.", SinceVersion: "2.16",
		Description: "Per-process crash dump configuration."},
	{Path: "Device.DeviceInfo.FirmwareImage.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Firmware bank / image table."},
	{Path: "Device.DeviceInfo.VendorConfigFile.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Vendor-specific configuration file table."},
	{Path: "Device.DeviceInfo.VendorLogFile.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Vendor-specific log file table."},
	{Path: "Device.DeviceInfo.Location.{i}.", MultiInstance: true, SinceVersion: "2.4",
		Description: "Device location entries (GPS, MANUAL, etc.)."},
	{Path: "Device.DeviceInfo.LogRotate.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "Log rotation configuration entries."},

	{Path: "Device.DynamicDNS.", SinceVersion: "2.10",
		Description: "Dynamic DNS client (e.g. DynDNS, No-IP) configuration."},
	{Path: "Device.DynamicDNS.Client.{i}.", MultiInstance: true, SinceVersion: "2.10",
		Description: "DDNS client instance."},

	{Path: "Device.Ethernet.", SinceVersion: "2.0",
		Description: "Ethernet physical interfaces, layer-2 links, VLANs, LAG, and RMON."},
	{Path: "Device.Ethernet.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Physical Ethernet port (speed, duplex, MACAddress, stats)."},
	{Path: "Device.Ethernet.Link.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Ethernet link layer (VLAN tag, X-bit EtherType)."},
	{Path: "Device.Ethernet.VLANTermination.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "IEEE 802.1Q VLAN termination."},
	{Path: "Device.Ethernet.LAG.{i}.", MultiInstance: true, SinceVersion: "2.7",
		Description: "Link Aggregation Group (LACP / IEEE 802.3ad)."},
	{Path: "Device.Ethernet.RMONStats.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "RMON statistics collection entry."},
	{Path: "Device.Ethernet.WoL.", SinceVersion: "2.15",
		Description: "Wake-on-LAN configuration."},

	{Path: "Device.FAP.", SinceVersion: "2.4",
		Description: "Femto Access Point (FAP) 3GPP container object."},

	{Path: "Device.FAST.", SinceVersion: "2.10",
		Description: "FAST lines per ITU G.9701 (G.fast)."},
	{Path: "Device.FAST.Line.{i}.", MultiInstance: true, SinceVersion: "2.10",
		Description: "G.fast physical line."},

	{Path: "Device.FWE.", SinceVersion: "2.14",
		Description: "5G Wireline Wireless Encapsulation (RFC 8822) — FWE tunnel table."},

	{Path: "Device.FaultMgmt.", SinceVersion: "2.4",
		Description: "Fault and alarm management (ITU-T X.733)."},
	{Path: "Device.FaultMgmt.CurrentAlarm.{i}.", MultiInstance: true, SinceVersion: "2.4",
		Description: "Table of currently active alarms."},
	{Path: "Device.FaultMgmt.HistoryEvent.{i}.", MultiInstance: true, SinceVersion: "2.4",
		Description: "Historical alarm event log."},

	{Path: "Device.Firewall.", SinceVersion: "2.2",
		Description: "Packet filtering and stateful firewall — chains, rules, DMZ, pinholes, policies."},
	{Path: "Device.Firewall.Level.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "Predefined firewall security level (High, Low, etc.)."},
	{Path: "Device.Firewall.Chain.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "Firewall rule chain."},
	{Path: "Device.Firewall.DMZ.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "DMZ host mapping entry."},
	{Path: "Device.Firewall.Pinhole.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "IPv6 pinhole (RFC 6092) entry."},
	{Path: "Device.Firewall.Set.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "Named IP/MAC address set for use in firewall rule matching."},
	{Path: "Device.Firewall.ConnectionTracking.", SinceVersion: "2.14",
		Description: "IP connection tracking and ALG (SIP, H.323, FTP, PPTP, …) configuration."},

	{Path: "Device.GRE.", SinceVersion: "2.5",
		Description: "Generic Routing Encapsulation tunnels (RFC 2784 / RFC 2890)."},
	{Path: "Device.GRE.Tunnel.{i}.", MultiInstance: true, SinceVersion: "2.5",
		Description: "GRE tunnel instance."},

	{Path: "Device.GatewayInfo.", SinceVersion: "2.0",
		Description: "Information about the upstream gateway (manufacturer, model, IP)."},

	{Path: "Device.Ghn.", SinceVersion: "2.4",
		Description: "G.hn (ITU-T G.9960/G.9961) home networking over power line, coax, or phone."},
	{Path: "Device.Ghn.Interface.{i}.", MultiInstance: true, SinceVersion: "2.4",
		Description: "G.hn network interface table."},

	{Path: "Device.HPNA.", SinceVersion: "2.0",
		Description: "HomePNA (HPNA) interface and diagnostic table."},

	{Path: "Device.Hardware.", SinceVersion: "2.20",
		Description: "Hardware inventory: CPUs, memory banks, power management (new in v2.20)."},

	{Path: "Device.HomePlug.", SinceVersion: "2.0",
		Description: "HomePlug AV (HPAV 1.1) powerline networking interfaces."},
	{Path: "Device.HomePlug.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "HomePlug interface table."},

	{Path: "Device.Hosts.", SinceVersion: "2.0",
		Description: "LAN hosts table (DHCP-learned and static) plus MAC-based access control."},
	{Path: "Device.Hosts.Host.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Per-host entry: IP, MAC, hostname, DHCP lease, active/inactive, L1/L3 interface."},
	{Path: "Device.Hosts.AccessControl.{i}.", MultiInstance: true, SinceVersion: "2.13",
		Description: "MAC-based access control entry (allow/block schedule)."},

	{Path: "Device.IEEE1905.", SinceVersion: "2.12",
		Description: "IEEE 1905.1a multi-technology LAN management."},

	{Path: "Device.IEEE8021x.", SinceVersion: "2.5",
		Description: "IEEE 802.1x authentication supplicant table."},
	{Path: "Device.IEEE8021x.Supplicant.{i}.", MultiInstance: true, SinceVersion: "2.5",
		Description: "802.1x supplicant instance."},

	{Path: "Device.IP.", SinceVersion: "2.0",
		Description: "IPv4/IPv6 stack: interfaces, active ports, and diagnostics."},
	{Path: "Device.IP.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "IP interface table — addresses, gateways, and per-interface stats."},
	{Path: "Device.IP.ActivePort.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Currently open TCP/UDP ports on the device."},
	{Path: "Device.IP.Diagnostics.", SinceVersion: "2.0",
		Description: "IP diagnostic commands: Ping, TraceRoute, Download/UploadDiagnostics, IPLayerCapacity, etc."},

	{Path: "Device.IPsec.", SinceVersion: "2.5",
		Description: "IPsec (RFC 4301) ESP/AH tunnels with IKEv2 keying."},
	{Path: "Device.IPsec.Tunnel.{i}.", MultiInstance: true, SinceVersion: "2.5",
		Description: "IPsec tunnel instance."},

	{Path: "Device.IPv6rd.", SinceVersion: "2.2",
		Description: "IPv6 Rapid Deployment — 6rd prefix delegation (RFC 5969)."},
	{Path: "Device.IPv6rd.InterfaceSetting.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "6rd tunnel configuration per interface."},

	{Path: "Device.L2TPv3.", SinceVersion: "2.12",
		Description: "L2TPv3 stateless tunnels (RFC 3931)."},
	{Path: "Device.L2TPv3.Tunnel.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "L2TPv3 tunnel instance."},

	{Path: "Device.LANConfigSecurity.", SinceVersion: "2.0",
		Description: "Generic LAN configuration security — admin password hash algorithm."},

	{Path: "Device.LEDs.", SinceVersion: "2.12",
		Description: "LED status indicator configuration table."},
	{Path: "Device.LEDs.LED.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Individual LED configuration (colour, behaviour, location)."},

	{Path: "Device.LLDP.", SinceVersion: "2.8",
		Description: "Link Layer Discovery Protocol (IEEE 802.1AB-2009)."},

	{Path: "Device.LMAP.", SinceVersion: "2.12",
		Description: "Large-Scale Measurement of Broadband Performance (IETF LMAP)."},

	{Path: "Device.LocalAgent.", SinceVersion: "2.12",
		Description: "USP Agent info: EndpointID, MTPs, controllers, subscriptions, request tracking."},
	{Path: "Device.LocalAgent.MTP.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Message Transfer Protocol instance (STOMP, MQTT, WebSocket, CoAP, UDS)."},
	{Path: "Device.LocalAgent.Controller.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Trusted USP controller entry (EndpointID, certificate, allowed operations)."},
	{Path: "Device.LocalAgent.Subscription.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "USP event / ValueChange / ObjectCreation subscription."},
	{Path: "Device.LocalAgent.Request.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Pending USP request tracking table."},
	{Path: "Device.LocalAgent.Monitor.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "Parameter monitor entry (threshold-based change notifications)."},
	{Path: "Device.LocalAgent.Certificate.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Trusted controller certificates accepted by the agent."},
	{Path: "Device.LocalAgent.ControllerTrust.", SinceVersion: "2.12",
		Description: "Global controller trust policy (TOFU, allow/deny lists)."},
	{Path: "Device.LocalAgent.Threshold.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "Threshold configuration entries for parameter monitoring."},
	{Path: "Device.LocalAgent.Watchdog.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "USP Agent watchdog timers."},

	{Path: "Device.Logical.", SinceVersion: "2.14",
		Description: "Layer-agnostic logical interface objects for stacking."},
	{Path: "Device.Logical.Interface.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "Logical interface instance."},

	{Path: "Device.MAP.", SinceVersion: "2.8",
		Description: "Mapping of Address and Port (RFC 7597 / 7598 / 7599)."},
	{Path: "Device.MAP.Domain.{i}.", MultiInstance: true, SinceVersion: "2.8",
		Description: "MAP domain configuration."},

	{Path: "Device.MQTT.", SinceVersion: "2.15",
		Description: "MQTT broker/client parameters (v3.1.1 / v5.0)."},
	{Path: "Device.MQTT.Client.{i}.", MultiInstance: true, SinceVersion: "2.15",
		Description: "MQTT client instance."},

	{Path: "Device.MoCA.", SinceVersion: "2.0",
		Description: "MoCA (Multimedia over Coax Alliance) network interfaces."},
	{Path: "Device.MoCA.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "MoCA interface table."},

	{Path: "Device.NAT.", SinceVersion: "2.0",
		Description: "Network Address Translation — per-interface settings, port mappings, and triggers."},
	{Path: "Device.NAT.InterfaceSetting.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "NAT enable/mode per IP interface."},
	{Path: "Device.NAT.PortMapping.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Static or UPnP-created port forwarding entry."},
	{Path: "Device.NAT.PortTrigger.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Port trigger entry (outbound trigger → inbound forward)."},

	{Path: "Device.NeighborDiscovery.", SinceVersion: "2.2",
		Description: "IPv6 Neighbor Discovery Protocol (RFC 4861) configuration."},
	{Path: "Device.NeighborDiscovery.InterfaceSetting.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "ND configuration per IPv6 interface."},

	{Path: "Device.Optical.", SinceVersion: "2.4",
		Description: "Generic optical layer-1 interface table."},
	{Path: "Device.Optical.Interface.{i}.", MultiInstance: true, SinceVersion: "2.4",
		Description: "Optical interface instance."},

	{Path: "Device.PCP.", SinceVersion: "2.8",
		Description: "Port Control Protocol client (RFC 6887)."},
	{Path: "Device.PCP.Client.{i}.", MultiInstance: true, SinceVersion: "2.8",
		Description: "PCP client instance."},

	{Path: "Device.PDU.", SinceVersion: "2.14",
		Description: "5G Protocol Data Unit sessions (5G-RG to data network)."},
	{Path: "Device.PDU.Session.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "PDU session instance."},

	{Path: "Device.PPP.", SinceVersion: "2.0",
		Description: "Point-to-Point Protocol (RFC 1661) interface table."},
	{Path: "Device.PPP.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "PPP interface instance (PPPoE, PPPoA, L2TP, etc.)."},

	{Path: "Device.PTM.", SinceVersion: "2.0",
		Description: "Packet Transfer Mode (G.993.1 Annex H) link interfaces."},
	{Path: "Device.PTM.Link.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "PTM link layer table."},

	{Path: "Device.PeriodicFileTransfer.", SinceVersion: "2.20",
		Description: "Periodic log / crash-dump uploads to a remote server (new in v2.20)."},
	{Path: "Device.PeriodicFileTransfer.Profile.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Upload profile (type, URL, schedule, compression)."},
	{Path: "Device.PeriodicFileTransfer.Transfer.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Historical transfer record."},

	{Path: "Device.PeriodicStatistics.", SinceVersion: "2.2",
		Description: "Periodic statistics collection and parameter sampling profiles."},
	{Path: "Device.PeriodicStatistics.SampleSet.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "Sampled data-set collection profile."},

	{Path: "Device.QoS.", SinceVersion: "2.0",
		Description: "QoS — traffic classification, policing, queuing, shaping, and scheduling."},
	{Path: "Device.QoS.Classification.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Traffic classification rule."},
	{Path: "Device.QoS.App.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Application-layer classification entry."},
	{Path: "Device.QoS.Flow.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Flow identifier for application-layer classification."},
	{Path: "Device.QoS.Policer.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Token-bucket policer entry."},
	{Path: "Device.QoS.Queue.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Egress queue entry (FIFO, WFQ, etc.)."},
	{Path: "Device.QoS.QueueStats.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Per-queue statistics."},
	{Path: "Device.QoS.Shaper.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Token-bucket shaper entry."},
	{Path: "Device.QoS.Scheduler.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Packet scheduler entry."},

	{Path: "Device.RadSecProxy.", SinceVersion: "2.20",
		Description: "RadSec proxy (RFC 6614) — RADIUS over TLS/TCP (new in v2.20)."},

	{Path: "Device.RouterAdvertisement.", SinceVersion: "2.2",
		Description: "IPv6 Router Advertisement (RFC 4861) — sending RAs per interface."},
	{Path: "Device.RouterAdvertisement.InterfaceSetting.{i}.", MultiInstance: true, SinceVersion: "2.2",
		Description: "RA configuration per IPv6 interface."},

	{Path: "Device.Routing.", SinceVersion: "2.0",
		Description: "Routing — virtual router table, static routes, RIP, and Babel (RFC 8966)."},
	{Path: "Device.Routing.Router.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Virtual router instance (IPv4/IPv6 forwarding tables)."},
	{Path: "Device.Routing.RouteInformation.", SinceVersion: "2.2",
		Description: "IPv6 route information received from Router Advertisement (RFC 4191)."},
	{Path: "Device.Routing.RIP.", SinceVersion: "2.0",
		Description: "RIP routing protocol configuration."},
	{Path: "Device.Routing.Babel.", SinceVersion: "2.13",
		Description: "Babel routing protocol (RFC 8966)."},

	{Path: "Device.SFPs.", SinceVersion: "2.20",
		Description: "Small Form-Factor Pluggable cages and transceiver info (SFF-8024/8472) (new in v2.20)."},
	{Path: "Device.SFPs.SFP.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "SFP cage / transceiver instance."},

	{Path: "Device.SSH.", SinceVersion: "2.16",
		Description: "SSH client/server management."},
	{Path: "Device.SSH.Client.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "SSH client instance."},
	{Path: "Device.SSH.Server.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "SSH server instance."},
	{Path: "Device.SSH.AuthorizedKey.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "Authorised public key for SSH login."},

	{Path: "Device.STOMP.", SinceVersion: "2.13",
		Description: "STOMP message broker connection (USP MTP per TR-369)."},
	{Path: "Device.STOMP.Connection.{i}.", MultiInstance: true, SinceVersion: "2.13",
		Description: "STOMP connection instance."},

	{Path: "Device.Schedules.", SinceVersion: "2.15",
		Description: "Schedule management embedded in the device."},
	{Path: "Device.Schedules.Schedule.{i}.", MultiInstance: true, SinceVersion: "2.15",
		Description: "Named schedule entry (cron-style or absolute)."},

	{Path: "Device.Security.", SinceVersion: "2.7",
		Description: "X.509 certificate store."},
	{Path: "Device.Security.Certificate.{i}.", MultiInstance: true, SinceVersion: "2.7",
		Description: "Certificate entry (Subject, Issuer, NotBefore, NotAfter, Fingerprint, etc.)."},

	{Path: "Device.Services.", SinceVersion: "2.0",
		Description: "General services information container (vendor extensions live here)."},

	{Path: "Device.SessionManagement.", SinceVersion: "2.20",
		Description: "3GPP data sessions for FN-RG/5G-RG (PDP, PDN, PDU session tracking) (new in v2.20)."},

	{Path: "Device.SmartCardReaders.", SinceVersion: "2.0",
		Description: "Smart card reader table."},
	{Path: "Device.SmartCardReaders.SmartCardReader.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Smart card reader instance."},

	{Path: "Device.SoftwareModules.", SinceVersion: "2.6",
		Description: "Dynamically managed software (execution environments, deployment units, execution units)."},
	{Path: "Device.SoftwareModules.ExecEnv.{i}.", MultiInstance: true, SinceVersion: "2.6",
		Description: "Software execution environment (Linux container, OSGi, etc.)."},
	{Path: "Device.SoftwareModules.DeploymentUnit.{i}.", MultiInstance: true, SinceVersion: "2.6",
		Description: "Deployed software package."},
	{Path: "Device.SoftwareModules.ExecutionUnit.{i}.", MultiInstance: true, SinceVersion: "2.6",
		Description: "Running application / service unit within an execution environment."},

	{Path: "Device.Standby.", SinceVersion: "2.16",
		Description: "Standby / sleep state capabilities (deprecated in v2.20; succeeded by Device.Hardware.)."},

	{Path: "Device.Syslog.", SinceVersion: "2.16",
		Description: "Syslog client/server configuration (RFC 5424/5425)."},
	{Path: "Device.Syslog.Client.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "Syslog client instance (remote server, transport, severity filter)."},
	{Path: "Device.Syslog.Server.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "Syslog server instance."},

	{Path: "Device.Thread.", SinceVersion: "2.20",
		Description: "Thread mesh networking (Thread 1.3.0 spec) (new in v2.20)."},
	{Path: "Device.Thread.BorderRouter.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Thread border router instance."},
	{Path: "Device.Thread.Radio.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Thread radio interface."},

	{Path: "Device.Time.", SinceVersion: "2.0",
		Description: "NTP/SNTP time clients and servers, current local time, and timezone."},
	{Path: "Device.Time.Client.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "NTP client instance (server URL, version, burst, poll interval)."},
	{Path: "Device.Time.Server.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "NTP server instance."},

	{Path: "Device.TrustedElements.", SinceVersion: "2.20",
		Description: "SIM/eSIM and Trusted Execution Environments for IoT/5G (new in v2.20)."},
	{Path: "Device.TrustedElements.SIM.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "SIM / eSIM module instance."},

	{Path: "Device.UPA.", SinceVersion: "2.0",
		Description: "Universal Powerline Association (UPA-PLC) interfaces."},

	{Path: "Device.UPnP.", SinceVersion: "2.0",
		Description: "UPnP Device and Service Discovery parameters."},

	{Path: "Device.USB.", SinceVersion: "2.0",
		Description: "Universal Serial Bus interfaces (USB 1.0 / 2.0 / 3.0)."},
	{Path: "Device.USB.Interface.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "USB host controller interface."},
	{Path: "Device.USB.Port.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "USB port / device table."},

	{Path: "Device.USPServices.", SinceVersion: "2.16",
		Description: "USP microservices installed on the device (TR-369 Annex A)."},
	{Path: "Device.USPServices.USPService.{i}.", MultiInstance: true, SinceVersion: "2.16",
		Description: "USP micro-agent service instance."},

	{Path: "Device.UnixDomainSockets.", SinceVersion: "2.15",
		Description: "Unix Domain Socket (UDS) MTP configuration for local USP agents."},
	{Path: "Device.UnixDomainSockets.UnixDomainSocket.{i}.", MultiInstance: true, SinceVersion: "2.15",
		Description: "UDS socket instance."},

	{Path: "Device.UserInterface.", SinceVersion: "2.0",
		Description: "Web UI and local console user interface parameters."},

	{Path: "Device.Users.", SinceVersion: "2.0",
		Description: "User accounts, groups, roles, and supported shells."},
	{Path: "Device.Users.User.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "User account entry (Username, Password, Enable, roles)."},
	{Path: "Device.Users.Group.{i}.", MultiInstance: true, SinceVersion: "2.11",
		Description: "User group entry."},
	{Path: "Device.Users.Role.{i}.", MultiInstance: true, SinceVersion: "2.11",
		Description: "RBAC role entry (allowed commands / objects)."},
	{Path: "Device.Users.SupportedShell.{i}.", MultiInstance: true, SinceVersion: "2.11",
		Description: "Allowed login shell path."},

	{Path: "Device.VXLAN.", SinceVersion: "2.12",
		Description: "VXLAN stateless tunnels (RFC 7348)."},
	{Path: "Device.VXLAN.Tunnel.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "VXLAN tunnel instance."},

	{Path: "Device.WWC.", SinceVersion: "2.14",
		Description: "Wireline Wireless Convergence — 5G feature capabilities for residential gateway."},

	{Path: "Device.WiFi.", SinceVersion: "2.0",
		Description: "Wi-Fi (IEEE 802.11-2020) radios, SSIDs, access points, stations, and EasyMesh."},
	{Path: "Device.WiFi.Radio.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Physical Wi-Fi radio (band, channel, capabilities, regulatory domain)."},
	{Path: "Device.WiFi.SSID.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Virtual Wi-Fi SSID / BSS interface."},
	{Path: "Device.WiFi.AccessPoint.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Access point configuration (WPA2/WPA3 security, MAC filtering, WPS)."},
	{Path: "Device.WiFi.EndPoint.{i}.", MultiInstance: true, SinceVersion: "2.0",
		Description: "Wi-Fi station / client mode configuration."},
	{Path: "Device.WiFi.DataElements.", SinceVersion: "2.12",
		Description: "Wi-Fi Alliance Data Elements (EasyMesh telemetry and topology)."},
	{Path: "Device.WiFi.MultiAP.", SinceVersion: "2.13",
		Description: "Multi-AP (Wi-Fi EasyMesh) network-wide configuration."},

	// -------------------------------------------------------------------------
	// Device.WireGuard. — added in TR-181 Amendment 20 (v2.20, November 2025)
	// -------------------------------------------------------------------------
	{Path: "Device.WireGuard.", SinceVersion: "2.20",
		Description: "WireGuard VPN subsystem — tunnel interfaces and global peer table."},
	{Path: "Device.WireGuard.Tunnel.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "WireGuard tunnel interface (private key, listen port, peer references, stats)."},
	{Path: "Device.WireGuard.Tunnel.{i}.Stats.", MultiInstance: false, SinceVersion: "2.20",
		Description: "Traffic statistics for a WireGuard Tunnel interface."},
	{Path: "Device.WireGuard.Tunnel.{i}.Interface.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "Stackable Layer3Interface created by the WireGuard tunnel (inherits standard interface params)."},
	{Path: "Device.WireGuard.Peer.{i}.", MultiInstance: true, SinceVersion: "2.20",
		Description: "WireGuard peer entry (public key, endpoint, AllowedIPs list, keepalive). Referenced by Tunnel.{i}.PeerReferences."},

	{Path: "Device.XMPP.", SinceVersion: "2.7",
		Description: "XMPP client capabilities for USP (TR-369) messaging."},
	{Path: "Device.XMPP.Connection.{i}.", MultiInstance: true, SinceVersion: "2.7",
		Description: "XMPP connection instance."},

	{Path: "Device.XPON.", SinceVersion: "2.14",
		Description: "xPON ONU interfaces (ITU G-PON / XGS-PON / NG-PON2)."},
	{Path: "Device.XPON.ONU.{i}.", MultiInstance: true, SinceVersion: "2.14",
		Description: "xPON ONU instance."},

	{Path: "Device.ZigBee.", SinceVersion: "2.7",
		Description: "ZigBee 2007 specification network interfaces."},
	{Path: "Device.ZigBee.Interface.{i}.", MultiInstance: true, SinceVersion: "2.7",
		Description: "ZigBee network interface table."},
}

// ---------------------------------------------------------------------------
// Device.DeviceInfo. parameters (representative set)
// ---------------------------------------------------------------------------

// DeviceInfoParams holds the Param definitions for Device.DeviceInfo.*.
// These are the most commonly read/written parameters for device identification.
var DeviceInfoParams = []Param{
	{
		Path: "Device.DeviceInfo.Manufacturer", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Company that manufactured the device.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.ManufacturerOUI", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Organisationally Unique Identifier (OUI) — 6 uppercase hex digits, e.g. \"00E04C\".",
		Limits:       Limits{MinLength: 6, MaxLength: 6, Pattern: `^[0-9A-F]{6}$`},
	},
	{
		Path: "Device.DeviceInfo.ModelName", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Model name as marketed to end-users.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.ModelNumber", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Model number (may differ from ModelName for OEM devices).",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.Description", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Human-readable device description.",
		Limits:       maxLen(256),
	},
	{
		Path: "Device.DeviceInfo.ProductClass", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Identifier of the class of product — used in conjunction with SerialNumber and OUI for unique identification.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.SerialNumber", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Unique serial number of the device. MUST remain fixed for the lifetime of the device.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.HardwareVersion", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Hardware revision string.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.SoftwareVersion", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Overall firmware / software version string.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.ProvisioningCode", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Service-provider provisioning / configuration tag.",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.DeviceInfo.UpTime", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of seconds elapsed since the last device restart.",
	},
	{
		Path: "Device.DeviceInfo.FirstUseDate", Type: TypeDateTime, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "UTC date-time of the first IP connection combined with a successful NTP sync.",
	},
	{
		Path: "Device.DeviceInfo.HostName", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Device hostname (FQDN or first label). Used in DHCP option 12 and mDNS.",
		Limits:       Limits{MaxLength: 255, Pattern: `^[a-zA-Z0-9\-\.]*$`},
	},
	{
		Path: "Device.DeviceInfo.FriendlyName", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Human-friendly name used in USP EndpointID advertisement and mDNS.",
		Limits:       maxLen(32),
	},
	{
		Path: "Device.DeviceInfo.FirmwareImageNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.DeviceInfo.FirmwareImage.{i}.",
	},
	{
		Path: "Device.DeviceInfo.VendorConfigFileNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.DeviceInfo.VendorConfigFile.{i}.",
	},
	{
		Path: "Device.DeviceInfo.VendorLogFileNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.DeviceInfo.VendorLogFile.{i}.",
	},
	{
		Path: "Device.DeviceInfo.LocationNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.4",
		Description:  "Number of entries in Device.DeviceInfo.Location.{i}.",
	},
	{
		Path: "Device.DeviceInfo.MaxNumberOfActivateTimeWindows", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Maximum number of time-windows allowed in a FirmwareImage.{i}.Activate() command call.",
		Limits:       bounded(1, 5),
	},
	// MemoryStatus sub-object (flattened representative params)
	{
		Path: "Device.DeviceInfo.MemoryStatus.Total", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Total physical RAM in kilobytes.",
	},
	{
		Path: "Device.DeviceInfo.MemoryStatus.Free", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Free (available) physical RAM in kilobytes.",
	},
	// NetworkProperties sub-object
	{
		Path: "Device.DeviceInfo.NetworkProperties.MaxTCPWindowSize", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Maximum TCP receive window size in bytes advertised by the device.",
	},
	{
		Path: "Device.DeviceInfo.NetworkProperties.TCPImplementation", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "TCP congestion-control algorithm in use (e.g. \"CUBIC\", \"BBR\", \"Reno\").",
		Limits:       enumL("CUBIC", "Reno", "BIC", "Hybla", "Westwood", "Vegas", "Scalable", "LP", "Veno", "BBR", "Other"),
	},
}

// ---------------------------------------------------------------------------
// Device.Time. parameters
// ---------------------------------------------------------------------------

var DeviceTimeParams = []Param{
	{
		Path: "Device.Time.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable or disable all NTP time clients and servers on this device.",
	},
	{
		Path: "Device.Time.Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Current NTP synchronisation status.",
		Limits: enumL(
			"Disabled",
			"Unsynchronized",
			"Synchronized",
			"Error_FailedToSynchronize",
			"Error",
		),
	},
	{
		Path: "Device.Time.CurrentLocalTime", Type: TypeDateTime, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Current device date and time expressed in local time (including DST if applicable).",
	},
	{
		Path: "Device.Time.LocalTimeZone", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "POSIX TZ string defining the local time zone and DST rules, e.g. \"EST+5 EDT,M4.1.0/2,M10.5.0/2\".",
		Limits:       maxLen(256),
	},
	{
		Path: "Device.Time.ClientNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.16",
		Description:  "Number of entries in Device.Time.Client.{i}.",
	},
	{
		Path: "Device.Time.ServerNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.16",
		Description:  "Number of entries in Device.Time.Server.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.IP. parameters
// ---------------------------------------------------------------------------

var DeviceIPParams = []Param{
	{
		Path: "Device.IP.IPv4Capable", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "True if the device is capable of operating in IPv4.",
	},
	{
		Path: "Device.IP.IPv4Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable or disable the IPv4 stack (layer 3 and above). A false value does not affect the IPv6 stack.",
	},
	{
		Path: "Device.IP.IPv4Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "IPv4 stack operational status.",
		Limits:       enumL("Disabled", "Enabled", "Error"),
	},
	{
		Path: "Device.IP.IPv6Capable", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "True if the device is capable of operating in IPv6.",
	},
	{
		Path: "Device.IP.IPv6Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable or disable the IPv6 stack.",
	},
	{
		Path: "Device.IP.IPv6Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "IPv6 stack operational status.",
		Limits:       enumL("Disabled", "Enabled", "Error"),
	},
	{
		Path: "Device.IP.ULAPrefix", Type: TypeIPv6Prefix, Access: ReadWrite,
		SinceVersion: "2.2",
		Description:  "IPv6 Unique-Local Address (ULA) /48 prefix for the device per RFC 4193 §3.",
	},
	{
		Path: "Device.IP.InterfaceNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.IP.Interface.{i}.",
	},
	{
		Path: "Device.IP.ActivePortNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.IP.ActivePort.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.Firewall. parameters
// ---------------------------------------------------------------------------

var DeviceFirewallParams = []Param{
	{
		Path: "Device.Firewall.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.2",
		Description:  "Enable or disable the firewall subsystem.",
	},
	{
		Path: "Device.Firewall.Config", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.2",
		Description:  "Current firewall configuration mode.",
		Limits:       enumL("High", "Low", "Off", "Advanced", "Policy"),
	},
	{
		Path: "Device.Firewall.Type", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Firewall tracking capability.",
		Limits:       enumL("Stateless", "Stateful"),
	},
	{
		Path: "Device.Firewall.Version", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Internal firewall settings version string.",
		Limits:       maxLen(16),
	},
	{
		Path: "Device.Firewall.LastChange", Type: TypeDateTime, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Timestamp of the most recent firewall configuration change.",
	},
	{
		Path: "Device.Firewall.ChainNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Number of entries in Device.Firewall.Chain.{i}.",
	},
	{
		Path: "Device.Firewall.DMZNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Number of entries in Device.Firewall.DMZ.{i}.",
	},
	{
		Path: "Device.Firewall.PinholeNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.2",
		Description:  "Number of entries in Device.Firewall.Pinhole.{i}.",
	},
	{
		Path: "Device.Firewall.SetNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.14",
		Description:  "Number of entries in Device.Firewall.Set.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.NAT. parameters
// ---------------------------------------------------------------------------

var DeviceNATParams = []Param{
	{
		Path: "Device.NAT.InterfaceSettingNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.NAT.InterfaceSetting.{i}.",
	},
	{
		Path: "Device.NAT.PortMappingNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.NAT.PortMapping.{i}.",
	},
	{
		Path: "Device.NAT.MaxNumberOfPortMappings", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Maximum number of port-mapping entries supported (0 = unlimited).",
	},
	{
		Path: "Device.NAT.PortTriggerNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in Device.NAT.PortTrigger.{i}.",
	},
	{
		Path: "Device.NAT.MaxNumberOfPortTriggers", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Maximum number of port-trigger entries supported (0 = unlimited).",
	},
}

// ---------------------------------------------------------------------------
// Device.BulkData. parameters
// ---------------------------------------------------------------------------

var DeviceBulkDataParams = []Param{
	{
		Path: "Device.BulkData.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.5",
		Description:  "Enable or disable all bulk data collection profiles.",
	},
	{
		Path: "Device.BulkData.Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Operational status of the bulk data collection mechanism.",
		Limits:       enumL("Enabled", "Disabled", "Error"),
	},
	{
		Path: "Device.BulkData.MinReportingInterval", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Minimum allowed reporting interval in seconds (0 = no minimum).",
	},
	{
		Path: "Device.BulkData.Protocols", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Comma-separated list of supported bulk data transport protocols.",
		Limits:       enumL("Streaming", "File", "HTTP", "MQTT", "USPEventNotif"),
	},
	{
		Path: "Device.BulkData.EncodingTypes", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Comma-separated list of supported data encoding formats.",
		Limits:       enumL("XML", "XDR", "CSV", "JSON"),
	},
	{
		Path: "Device.BulkData.ParameterWildCardSupported", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "True if wildcard parameter references are supported in collection profiles.",
	},
	{
		Path: "Device.BulkData.MaxNumberOfProfiles", Type: TypeInt, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Maximum number of Profile.{i}. instances (-1 = unlimited).",
		Limits:       minBound(-1),
	},
	{
		Path: "Device.BulkData.MaxNumberOfParameterReferences", Type: TypeInt, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Maximum number of parameter references per profile (-1 = unlimited).",
		Limits:       minBound(-1),
	},
	{
		Path: "Device.BulkData.ProfileNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.5",
		Description:  "Number of entries in Device.BulkData.Profile.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent. parameters
// ---------------------------------------------------------------------------

var DeviceLocalAgentParams = []Param{
	{
		Path: "Device.LocalAgent.EndpointID", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Globally unique USP EndpointID for this agent, e.g. \"proto::serial:ABCDEF123\".",
		Limits:       maxLen(256),
	},
	{
		Path: "Device.LocalAgent.SoftwareVersion", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "USP Agent software version (may differ from Device.DeviceInfo.SoftwareVersion).",
		Limits:       maxLen(64),
	},
	{
		Path: "Device.LocalAgent.UpTime", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Seconds since the USP Agent process last started.",
	},
	{
		Path: "Device.LocalAgent.SupportedProtocols", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Comma-separated list of USP MTP protocols this agent supports.",
		Limits:       enumL("CoAP", "WebSocket", "STOMP", "MQTT", "UDS"),
	},
	{
		Path: "Device.LocalAgent.SupportedFingerprintAlgorithms", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Certificate fingerprint algorithms supported for controller authentication.",
		Limits:       enumL("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"),
	},
	{
		Path: "Device.LocalAgent.MaxSubscriptionChangeAdoptionTime", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.14",
		Description:  "Maximum seconds between a subscription parameter change and when the agent adopts the new subscription configuration.",
		Limits:       minBound(5),
	},
	{
		Path: "Device.LocalAgent.MTPNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Device.LocalAgent.MTP.{i}.",
	},
	{
		Path: "Device.LocalAgent.ControllerNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Device.LocalAgent.Controller.{i}.",
	},
	{
		Path: "Device.LocalAgent.SubscriptionNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Device.LocalAgent.Subscription.{i}.",
	},
	{
		Path: "Device.LocalAgent.RequestNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Device.LocalAgent.Request.{i}.",
	},
	{
		Path: "Device.LocalAgent.CertificateNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Device.LocalAgent.Certificate.{i}.",
	},
	{
		Path: "Device.LocalAgent.SupportedNumberOfSubscriptions", Type: TypeInt, Access: ReadOnly,
		SinceVersion: "2.14",
		Description:  "Maximum number of concurrent subscriptions supported (-1 = no limit).",
		Limits:       minBound(-1),
	},
}

// ---------------------------------------------------------------------------
// AllDeviceParams aggregates every Param slice for easy iteration.
// ---------------------------------------------------------------------------

// AllDeviceParams is the union of all Device.* parameter slices defined in
// this file. Consumers can range over it to build USP Get parameter lists,
// schema validators, or human-readable documentation.
// AllDeviceParams is populated by init() so that wireguard.go (and future
// sub-tree files) can append their params after their own vars are ready.
var AllDeviceParams []Param

func init() {
	AllDeviceParams = concat(
		DeviceRootParams,
		DeviceInfoParams,
		DeviceTimeParams,
		DeviceIPParams,
		DeviceFirewallParams,
		DeviceNATParams,
		DeviceBulkDataParams,
		DeviceLocalAgentParams,
		AllWireGuardParams,       // wireguard.go — Device.WireGuard.*
		AllManagementServerParams, // tr069.go    — Device.ManagementServer.* (CWMP/TR-069)
		AllLocalAgentSubParams,    // tr369.go    — Device.LocalAgent.* sub-tables (USP/TR-369)
	)
}
