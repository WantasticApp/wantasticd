package wusp

// WUSPONU: the Wantastic ONU data model on EcoNet EN7528-based XPON ONUs
// (ECNT/Photon PTF2164Q family, CMCC firmware).
//
// The agent runs on the ONU itself and reads the vendor kernel surfaces
// directly: /proc/pon_phy (SFF-8472 DDMI), /proc/xpon (GPON/EPON MAC state,
// activation state machine, GEM counters) and the boa cgi-bin API on
// 127.0.0.1 (getSysteminfo.cgi and friends, no authentication needed from
// localhost). Setters map onto the same cgi calls; Operate commands run
// only when the console asks, never on a timer.

const WUSPONUPrefix = "Device.WUSP_ONU."

// Operate commands on Device.WUSP_ONU.
const (
	WUSPONURebootCommand         = WUSPONUPrefix + "Reboot()"
	WUSPONUFactoryRestoreCommand = WUSPONUPrefix + "FactoryRestore()"
	// Upgrade applies a firmware image staged through the WUSP upload
	// channel (input: FileName). BackupConfig returns the running
	// configuration text in the result message (field Config).
	// RestoreConfig applies a configuration text (input: Config).
	WUSPONUUpgradeCommand       = WUSPONUPrefix + "Upgrade()"
	WUSPONUBackupConfigCommand  = WUSPONUPrefix + "BackupConfig()"
	WUSPONURestoreConfigCommand = WUSPONUPrefix + "RestoreConfig()"
)

// Network Operate commands on Device.WUSP_ONU.Network.
const (
	WUSPONUNetworkFirewallFlushCommand = WUSPONUPrefix + "Network.Firewall.FlushChain()"
	WUSPONUNetworkFirewallAddCommand   = WUSPONUPrefix + "Network.Firewall.AddRule()"
	WUSPONUNetworkFirewallDelCommand   = WUSPONUPrefix + "Network.Firewall.DeleteRule()"
	WUSPONUNetworkRouteAddCommand      = WUSPONUPrefix + "Network.Route.Add()"
	WUSPONUNetworkRouteDelCommand      = WUSPONUPrefix + "Network.Route.Delete()"
	WUSPONUNetworkDHCPRestartCommand   = WUSPONUPrefix + "Network.DHCP.Restart()"
	WUSPONUNetworkDNSRestartCommand    = WUSPONUPrefix + "Network.DNS.Restart()"
	WUSPONUNetworkWLANRestartCommand   = WUSPONUPrefix + "Network.WLAN.Restart()"
	WUSPONUNetworkWLANKickCommand      = WUSPONUPrefix + "Network.WLAN.KickStation()"
	WUSPONUNetworkBackupCommand        = WUSPONUPrefix + "Network.BackupNetworkConfig()"
)

var WUSPONUObjects = []Object{
	{Path: WUSPONUPrefix, SinceVersion: "1.0", Description: "XPON/GPON/EPON ONU platform state: PON link, activation, optical DDMI and GEM counters."},
	{Path: WUSPONUPrefix + "Network.", SinceVersion: "1.0", Description: "ONU Linux network state: interfaces, routes, iptables, DHCP, DNS, WLAN radios, stations."},
	{Path: WUSPONUPrefix + "Network.Interface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Network interface table from /proc/net/dev."},
	{Path: WUSPONUPrefix + "Network.Route.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "IPv4 routing table from /proc/net/route."},
	{Path: WUSPONUPrefix + "Network.Firewall.", SinceVersion: "1.0", Description: "iptables firewall state (filter, nat, mangle)."},
	{Path: WUSPONUPrefix + "Network.Firewall.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per iptables policy or rule across all tables."},
	{Path: WUSPONUPrefix + "Network.DHCP.", SinceVersion: "1.0", Description: "DHCP server/client lease state."},
	{Path: WUSPONUPrefix + "Network.DHCP.Lease.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DHCP lease table."},
	{Path: WUSPONUPrefix + "Network.DNS.", SinceVersion: "1.0", Description: "DNS resolver configuration from resolv.conf."},
	{Path: WUSPONUPrefix + "Network.DNS.Server.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DNS nameserver table."},
	{Path: WUSPONUPrefix + "Network.Radio.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "WLAN radio (ieee80211 phy) table."},
	{Path: WUSPONUPrefix + "Network.WirelessInterface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Wireless interface table from /proc/net/wireless."},
	{Path: WUSPONUPrefix + "Network.Station.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Associated WLAN station (client) table."},
	{Path: WUSPONUPrefix + "Network.WAN.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "WAN interface table: uplink connections with VLAN tagging and service bindings."},
}

func onuParam(leaf string, typ ParamType, access Access, description string, limits Limits) Param {
	return Param{Path: WUSPONUPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPONUParams = []Param{
	onuParam("Installed", TypeBoolean, ReadOnly, "True when the ONU fiber platform is detected on this device.", Limits{}),
	onuParam("Enable", TypeBoolean, ReadWrite, "Collect ONU telemetry and accept ONU control on this device.", Limits{}),
	onuParam("Platform", TypeString, ReadOnly, "Platform family this backend speaks: onu.", Limits{MaxLength: 16}),
	onuParam("Status", TypeString, ReadOnly, "Collection status of the ONU backend.", Limits{Enums: []string{"not_installed", "disabled", "ok", "read_error", "cgi_error"}}),
	onuParam("StatusDetail", TypeString, ReadOnly, "Detail for the current status, empty when ok.", Limits{MaxLength: 256}),
	onuParam("LastCollectTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the last successful collection.", Limits{Min: iptr(0)}),

	onuParam("Mode", TypeString, ReadOnly, "PON mode the device is operating in: xpon, gpon or epon.", Limits{Enums: []string{"", "xpon", "gpon", "epon"}}),
	onuParam("LinkStatus", TypeString, ReadOnly, "PON link state.", Limits{Enums: []string{"", "up", "down"}}),
	onuParam("ActivationState", TypeString, ReadOnly, "GPON/XPON activation state: O1..O5, or inactive.", Limits{Enums: []string{"", "inactive", "O1", "O2", "O3", "O4", "O5"}}),
	onuParam("RogueState", TypeBoolean, ReadOnly, "True when the ONU is in rogue mode.", Limits{}),
	onuParam("OnuType", TypeUnsignedInt, ReadOnly, "Vendor ONU type code.", Limits{Min: iptr(0)}),
	onuParam("OltType", TypeString, ReadOnly, "OLT type code the ONU synchronized with, in hex.", Limits{MaxLength: 16}),

	onuParam("SerialNumber", TypeString, ReadOnly, "ONU serial number (GPON_SN).", Limits{MaxLength: 64}),
	onuParam("MacAddress", TypeString, ReadOnly, "Base MAC address of the device.", Limits{MaxLength: 32}),
	onuParam("OUI", TypeString, ReadOnly, "Organizationally unique identifier of the MAC.", Limits{MaxLength: 16}),
	onuParam("Manufacturer", TypeString, ReadOnly, "Device manufacturer code.", Limits{MaxLength: 32}),
	onuParam("ModelName", TypeString, ReadOnly, "Device model name reported by the vendor.", Limits{MaxLength: 64}),
	onuParam("FirmwareVersion", TypeString, ReadOnly, "Firmware version reported by the vendor.", Limits{MaxLength: 64}),
	onuParam("HardwareVersion", TypeString, ReadOnly, "Hardware version reported by the vendor.", Limits{MaxLength: 64}),

	onuParam("Temperature", TypeDecimal, ReadOnly, "Optical module temperature in degrees Celsius.", Limits{}),
	onuParam("Voltage", TypeDecimal, ReadOnly, "Optical module supply voltage in volts.", Limits{}),
	onuParam("BiasCurrent", TypeDecimal, ReadOnly, "Laser bias current in milliamps.", Limits{}),
	onuParam("TxPower", TypeDecimal, ReadOnly, "Transmit optical power in dBm.", Limits{}),
	onuParam("RxPower", TypeDecimal, ReadOnly, "Receive optical power in dBm.", Limits{}),
	onuParam("RSSI", TypeDecimal, ReadOnly, "Receive signal strength current (vendor RSSI) when available.", Limits{}),
	onuParam("BER", TypeDecimal, ReadOnly, "Bit error rate from the optical module.", Limits{}),
	onuParam("Los", TypeBoolean, ReadOnly, "True when the optical module reports loss of signal.", Limits{}),
	onuParam("PhyStatus", TypeString, ReadOnly, "Optical PHY status text, e.g. unplug or active.", Limits{MaxLength: 32}),

	onuParam("EqualizationDelay", TypeUnsignedInt, ReadOnly, "GPON equalization delay in nanoseconds (G_EQD).", Limits{Min: iptr(0)}),
	onuParam("GemRxCount", TypeUnsignedInt, ReadOnly, "GEM frames received on the PON since boot.", Limits{Min: iptr(0)}),
	onuParam("GemTxCount", TypeUnsignedInt, ReadOnly, "GEM frames transmitted on the PON since boot.", Limits{Min: iptr(0)}),
	onuParam("RxCrcErrorCount", TypeUnsignedInt, ReadOnly, "PON receive CRC errors since boot.", Limits{Min: iptr(0)}),
	onuParam("GemHecErrorCount", TypeUnsignedInt, ReadOnly, "GEM header error correction errors since boot.", Limits{Min: iptr(0)}),

	onuParam("SupportedOperations", TypeString, ReadOnly, "Comma-separated Operate commands. They run only when requested, never on a timer.", Limits{MaxLength: 512}),
	onuParam("LastOperationStatus", TypeString, ReadOnly, "Result of the latest ONU Operate command.", Limits{Enums: []string{"", "Success", "Error"}}),
	onuParam("LastOperationCode", TypeString, ReadOnly, "Stable machine-readable code of the latest ONU Operate command.", Limits{MaxLength: 64}),
	onuParam("LastOperationMessage", TypeString, ReadOnly, "Short result detail of the latest ONU Operate command.", Limits{MaxLength: 256}),

	onuParam("Config", TypeString, ReadOnly, "Result field of BackupConfig(): the running configuration text.", Limits{MaxLength: 1 << 20}),

	// Network subsystem: interfaces, routes, firewall, DHCP, DNS, WLAN.
	onuParam("Network.InterfaceNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of network interfaces.", Limits{Min: iptr(0)}),
	onuParam("Network.RouteNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of IPv4 routes.", Limits{Min: iptr(0)}),
	onuParam("Network.DHCP.LeaseNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of DHCP leases.", Limits{Min: iptr(0)}),
	onuParam("Network.DHCP.Enable", TypeBoolean, ReadWrite, "Enable or disable the DHCP server.", Limits{}),
	onuParam("Network.DNS.ServerNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of DNS nameservers.", Limits{Min: iptr(0)}),
	onuParam("Network.DNS.SearchDomain", TypeString, ReadOnly, "DNS search domain.", Limits{MaxLength: 256}),
	onuParam("Network.DNS.Server.{i}.Address", TypeString, ReadWrite, "DNS nameserver address (writable: updates resolv.conf).", Limits{MaxLength: 64}),
	onuParam("Network.Radio.{i}.Phy", TypeString, ReadOnly, "ieee80211 phy name (phy0, phy1, ...).", Limits{MaxLength: 32}),
	onuParam("Network.Radio.{i}.Interfaces", TypeString, ReadOnly, "Comma-separated interface names on this radio.", Limits{MaxLength: 128}),
	onuParam("Network.Radio.{i}.Band", TypeString, ReadOnly, "Frequency band (2.4G, 5G, 6G) when available.", Limits{MaxLength: 16}),
	onuParam("Network.Radio.{i}.Enable", TypeBoolean, ReadWrite, "Bring this radio's interface up or down.", Limits{}),
	onuParam("Network.RadioNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of WLAN radios (ieee80211 phys).", Limits{Min: iptr(0)}),
	onuParam("Network.WirelessInterface.{i}.Name", TypeString, ReadOnly, "Wireless interface name.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.LinkQuality", TypeString, ReadOnly, "Link quality metric.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.SignalLevel", TypeString, ReadOnly, "Signal level.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.NoiseLevel", TypeString, ReadOnly, "Noise level.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterfaceNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of wireless interfaces.", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.Interface", TypeString, ReadOnly, "Interface the station is on.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.MACAddress", TypeString, ReadOnly, "Client MAC address.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.Signal", TypeString, ReadOnly, "Signal strength.", Limits{MaxLength: 16}),
	onuParam("Network.Station.{i}.RxBitrate", TypeString, ReadOnly, "Receive bitrate.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.TxBitrate", TypeString, ReadOnly, "Transmit bitrate.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.RxBytes", TypeUnsignedInt, ReadOnly, "Bytes received from station.", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.TxBytes", TypeUnsignedInt, ReadOnly, "Bytes transmitted to station.", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.ConnectedTime", TypeString, ReadOnly, "Time connected.", Limits{MaxLength: 32}),
	onuParam("Network.StationNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of associated WLAN stations.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.Name", TypeString, ReadOnly, "Interface name.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.MACAddress", TypeString, ReadOnly, "Interface MAC address.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.IPv4Address", TypeString, ReadOnly, "IPv4 address.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.OperState", TypeString, ReadOnly, "Operational state.", Limits{MaxLength: 16}),
	onuParam("Network.Interface.{i}.MTU", TypeUnsignedInt, ReadOnly, "Interface MTU.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.RxBytes", TypeUnsignedInt, ReadOnly, "Bytes received.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.RxPackets", TypeUnsignedInt, ReadOnly, "Packets received.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.RxErrors", TypeUnsignedInt, ReadOnly, "Receive errors.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.TxBytes", TypeUnsignedInt, ReadOnly, "Bytes transmitted.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.TxPackets", TypeUnsignedInt, ReadOnly, "Packets transmitted.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.TxErrors", TypeUnsignedInt, ReadOnly, "Transmit errors.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.Enable", TypeBoolean, ReadWrite, "Bring interface up or down.", Limits{}),
	onuParam("Network.Route.{i}.Interface", TypeString, ReadOnly, "Route interface.", Limits{MaxLength: 32}),
	onuParam("Network.Route.{i}.Destination", TypeString, ReadOnly, "Route destination.", Limits{MaxLength: 32}),
	onuParam("Network.Route.{i}.Gateway", TypeString, ReadOnly, "Route gateway.", Limits{MaxLength: 32}),
	onuParam("Network.Route.{i}.Mask", TypeString, ReadOnly, "Route mask.", Limits{MaxLength: 32}),
	onuParam("Network.Route.{i}.Flags", TypeUnsignedInt, ReadOnly, "Route flags.", Limits{Min: iptr(0)}),
	onuParam("Network.Route.{i}.Metric", TypeUnsignedInt, ReadOnly, "Route metric.", Limits{Min: iptr(0)}),
	onuParam("Network.DHCP.Lease.{i}.Expires", TypeString, ReadOnly, "Lease expiry.", Limits{MaxLength: 32}),
	onuParam("Network.DHCP.Lease.{i}.MACAddress", TypeString, ReadOnly, "Client MAC.", Limits{MaxLength: 32}),
	onuParam("Network.DHCP.Lease.{i}.IPAddress", TypeString, ReadOnly, "Leased IP.", Limits{MaxLength: 32}),
	onuParam("Network.DHCP.Lease.{i}.Hostname", TypeString, ReadOnly, "Client hostname.", Limits{MaxLength: 128}),
	onuParam("Network.Firewall.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Total iptables rules and policies across all tables.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.Rule.{i}.Table", TypeString, ReadOnly, "iptables table: filter, nat, mangle.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.Rule.{i}.Chain", TypeString, ReadOnly, "Chain name (INPUT, OUTPUT, FORWARD, etc.).", Limits{MaxLength: 32}),
	onuParam("Network.Firewall.Rule.{i}.Type", TypeString, ReadOnly, "Entry type: policy or rule.", Limits{Enums: []string{"policy", "rule"}}),
	onuParam("Network.Firewall.Rule.{i}.Policy", TypeString, ReadOnly, "Chain default policy (ACCEPT, DROP) for policy-type entries.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.Rule.{i}.Raw", TypeString, ReadOnly, "Raw iptables-save rule text for rule-type entries.", Limits{MaxLength: 512}),
	onuParam("Network.Config", TypeString, ReadOnly, "Result field of BackupNetworkConfig(): full network config dump.", Limits{MaxLength: 1 << 20}),

	// WAN interfaces: uplink connections with VLAN tagging (OLT assigns VLAN4000 as service VLAN).
	onuParam("Network.WANNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of WAN interfaces.", Limits{Min: iptr(0)}),
	onuParam("Network.WAN.{i}.Name", TypeString, ReadOnly, "WAN interface name.", Limits{MaxLength: 32}),
	onuParam("Network.WAN.{i}.Active", TypeBoolean, ReadOnly, "WAN interface is active.", Limits{}),
	onuParam("Network.WAN.{i}.VLANMode", TypeString, ReadWrite, "VLAN mode: TAG, UNTAG, TRANSPARENT.", Limits{MaxLength: 16}),
	onuParam("Network.WAN.{i}.VLANID", TypeString, ReadWrite, "802.1Q VLAN ID (e.g. 4000).", Limits{MaxLength: 8}),
	onuParam("Network.WAN.{i}.Priority", TypeString, ReadWrite, "802.1p priority (0-7).", Limits{MaxLength: 4}),
	onuParam("Network.WAN.{i}.Mode", TypeString, ReadWrite, "WAN mode: Route or Bridge.", Limits{MaxLength: 16}),
	onuParam("Network.WAN.{i}.LinkMode", TypeString, ReadOnly, "Link mode: linkPPP, linkIP.", Limits{MaxLength: 16}),
	onuParam("Network.WAN.{i}.ServiceList", TypeString, ReadOnly, "Service binding: INTERNET, IPTV, VOIP, TR069.", Limits{MaxLength: 64}),
	onuParam("Network.WAN.{i}.IPAddress", TypeString, ReadOnly, "WAN IPv4 address.", Limits{MaxLength: 32}),
	onuParam("Network.WAN.{i}.Status", TypeString, ReadOnly, "WAN connection status.", Limits{MaxLength: 32}),
	onuParam("Network.WAN.{i}.Encapsulation", TypeString, ReadOnly, "Encapsulation type.", Limits{MaxLength: 32}),
}
