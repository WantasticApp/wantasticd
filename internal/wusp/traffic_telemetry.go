package wusp

const WUSPTrafficTelemetryPrefix = "Device.WUSP_TrafficTelemetry."

// Traffic telemetry bounds: rows per device, so one snapshot stays small.
const (
	TrafficTelemetryMaxInterfaces    = 64
	TrafficTelemetryMaxFirewallRules = 64
	TrafficTelemetryMaxWiredHosts    = 256
)

// History metric identifiers for traffic telemetry, sharing the WiFi history
// block v1 encoding (EncodeWiFiHistoryBlock). IDs never collide with the
// WiFiMetric* set.
const (
	TrafficMetricRxRate       uint8 = 16 // kbit/s received
	TrafficMetricTxRate       uint8 = 17 // kbit/s sent
	TrafficMetricRxPacketRate uint8 = 18 // packets/s received
	TrafficMetricTxPacketRate uint8 = 19 // packets/s sent
	TrafficMetricErrors       uint8 = 20 // rx+tx errors during the interval
	TrafficMetricDrops        uint8 = 21 // rx+tx drops during the interval
	TrafficMetricRulePackets  uint8 = 22 // packets/s matched by a firewall rule
	TrafficMetricRuleRate     uint8 = 23 // kbit/s matched by a firewall rule
)

var WUSPTrafficTelemetryObjects = []Object{
	{Path: WUSPTrafficTelemetryPrefix, SinceVersion: "1.0", Description: "Agent-owned interface throughput and firewall rule hit-rate telemetry with a rolling 30-sample history."},
	{Path: WUSPTrafficTelemetryPrefix + "Interface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Throughput, packet rate, errors and drops for one network interface."},
	{Path: WUSPTrafficTelemetryPrefix + "FirewallRule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Packet and byte counters and hit rate for one firewall rule."},
	{Path: WUSPTrafficTelemetryPrefix + "WiredHost.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "A host learned on a bridge port, with the port's negotiated link speed."},
}

func trafficParam(path string, typ ParamType, description string, limits Limits) Param {
	return Param{Path: WUSPTrafficTelemetryPrefix + path, Type: typ, Access: ReadOnly, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPTrafficTelemetryParams = []Param{
	trafficParam("Status", TypeString, "Sampler state.", Limits{Enums: []string{"Collecting", "Ready", "Error"}}),
	trafficParam("SampleIntervalSeconds", TypeUnsignedInt, "Interval between samples.", Limits{Min: iptr(0)}),
	trafficParam("HistoryDepth", TypeUnsignedInt, "Maximum number of samples carried in each History block.", Limits{Min: iptr(0)}),
	trafficParam("LastSampleTime", TypeDateTime, "Time the most recent sample completed.", Limits{}),
	trafficParam("FirewallSource", TypeString, "Where firewall counters were read from.", Limits{Enums: []string{"iptables", "nftables", "none"}}),
	trafficParam("InterfaceNumberOfEntries", TypeUnsignedInt, "Number of entries in Interface.{i}.", Limits{Min: iptr(0)}),
	trafficParam("FirewallRuleNumberOfEntries", TypeUnsignedInt, "Number of entries in FirewallRule.{i}.", Limits{Min: iptr(0)}),
	trafficParam("WiredHostNumberOfEntries", TypeUnsignedInt, "Number of entries in WiredHost.{i}.", Limits{Min: iptr(0)}),

	trafficParam("Interface.{i}.Alias", TypeAlias, "Stable alias derived from the interface name.", Limits{MaxLength: 64}),
	trafficParam("Interface.{i}.Name", TypeString, "Kernel interface name.", Limits{MaxLength: 16}),
	trafficParam("Interface.{i}.Status", TypeString, "Kernel operational state.", Limits{Enums: []string{"Up", "Down", "Dormant", "LowerLayerDown", "NotPresent", "Unknown"}}),
	trafficParam("Interface.{i}.RxRate", TypeUnsignedInt, "Receive throughput over the last interval in kbit/s.", Limits{Min: iptr(0)}),
	trafficParam("Interface.{i}.TxRate", TypeUnsignedInt, "Transmit throughput over the last interval in kbit/s.", Limits{Min: iptr(0)}),
	trafficParam("Interface.{i}.RxPacketRate", TypeUnsignedInt, "Receive packets per second over the last interval.", Limits{Min: iptr(0)}),
	trafficParam("Interface.{i}.TxPacketRate", TypeUnsignedInt, "Transmit packets per second over the last interval.", Limits{Min: iptr(0)}),
	trafficParam("Interface.{i}.BytesReceived", TypeUnsignedLong, "Total bytes received.", Limits{}),
	trafficParam("Interface.{i}.BytesSent", TypeUnsignedLong, "Total bytes sent.", Limits{}),
	trafficParam("Interface.{i}.Errors", TypeUnsignedLong, "Total receive plus transmit errors.", Limits{}),
	trafficParam("Interface.{i}.Drops", TypeUnsignedLong, "Total receive plus transmit drops.", Limits{}),
	trafficParam("Interface.{i}.LinkSpeed", TypeUnsignedInt, "Negotiated physical link speed in Mbit/s, 0 when the driver does not report one.", Limits{Min: iptr(0)}),
	trafficParam("Interface.{i}.Duplex", TypeString, "Negotiated duplex mode.", Limits{Enums: []string{"Full", "Half", "Unknown"}}),
	trafficParam("Interface.{i}.History", TypeHexBinary, "Rolling history in the WUSP WiFi history block v1 encoding with TrafficMetric* series.", Limits{MaxLength: wifiHistoryMaxBlockLen}),

	trafficParam("FirewallRule.{i}.Alias", TypeAlias, "Stable alias derived from table, chain and rule identity.", Limits{MaxLength: 64}),
	trafficParam("FirewallRule.{i}.Table", TypeString, "Firewall table (filter, nat, mangle, inet fw4, ...).", Limits{MaxLength: 32}),
	trafficParam("FirewallRule.{i}.Chain", TypeString, "Chain the rule belongs to.", Limits{MaxLength: 64}),
	trafficParam("FirewallRule.{i}.Name", TypeString, "Rule comment or name (OpenWrt firewall rule name when present).", Limits{MaxLength: 128}),
	trafficParam("FirewallRule.{i}.Target", TypeString, "Rule verdict or jump target.", Limits{MaxLength: 32}),
	trafficParam("FirewallRule.{i}.Packets", TypeUnsignedLong, "Packets matched since the counters were last reset.", Limits{}),
	trafficParam("FirewallRule.{i}.Bytes", TypeUnsignedLong, "Bytes matched since the counters were last reset.", Limits{}),
	trafficParam("FirewallRule.{i}.PacketRate", TypeUnsignedInt, "Packets per second matched over the last interval.", Limits{Min: iptr(0)}),
	trafficParam("FirewallRule.{i}.ByteRate", TypeUnsignedInt, "Matched throughput over the last interval in kbit/s.", Limits{Min: iptr(0)}),
	trafficParam("FirewallRule.{i}.History", TypeHexBinary, "Rolling history in the WUSP WiFi history block v1 encoding with TrafficMetricRule* series.", Limits{MaxLength: wifiHistoryMaxBlockLen}),

	trafficParam("WiredHost.{i}.MACAddress", TypeMACAddress, "Host MAC address from the bridge forwarding database.", Limits{}),
	trafficParam("WiredHost.{i}.Bridge", TypeString, "Bridge the host was learned on.", Limits{MaxLength: 16}),
	trafficParam("WiredHost.{i}.Port", TypeString, "Bridge port (physical or virtual interface) the host is behind.", Limits{MaxLength: 16}),
	trafficParam("WiredHost.{i}.LinkSpeed", TypeUnsignedInt, "Negotiated link speed of that port in Mbit/s, 0 when unknown (for example a switch CPU port).", Limits{Min: iptr(0)}),
	trafficParam("WiredHost.{i}.Duplex", TypeString, "Duplex of that port.", Limits{Enums: []string{"Full", "Half", "Unknown"}}),
	trafficParam("WiredHost.{i}.IdleSeconds", TypeUnsignedInt, "Seconds since the bridge last saw a frame from the host.", Limits{Min: iptr(0)}),
}
