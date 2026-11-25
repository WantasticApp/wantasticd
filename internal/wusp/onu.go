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

const (
	// WLAN.Apply() writes a set of Wi-Fi changes in one commit. Its input
	// fields are the changed parameters by their own paths
	// (Network.Radio.{i}.Enable/Channel/Bandwidth/Mode/TxPower,
	// Network.SSID.{i}.Name/Enable/Hidden/AuthMode/Encryption/Passphrase/
	// MaxStations, and optionally Network.SSID.{i}.Interface as a guard
	// that the row is still the SSID the console showed), or the TR-181
	// names of the same settings (Device.WiFi.Radio.{i}.*,
	// Device.WiFi.SSID.{i}.*, Device.WiFi.AccessPoint.{i}.* incl.
	// Security.ModeEnabled/KeyPassphrase). Disruptive: committing restarts
	// the radio and drops its clients.
	WUSPONUNetworkWLANApplyCommand = WUSPONUPrefix + "Network.WLAN.Apply()"
)

// Firewall configuration commands. They write the ONU's own firewall
// settings the way its web pages do (tcapi), never raw iptables.
const (
	// Firewall.Apply() writes a set of firewall settings: its input fields
	// are the changed parameters by their own paths (Network.Firewall.Enable,
	// Level, DoSProtection, PortScanProtection, IPv6SessionProtection,
	// MACFilter.Enable/Mode, PortFilter.InboundEnable/InboundMode/
	// OutboundEnable/OutboundMode, URLFilter.Enable/Mode). Each page's group
	// is committed once and the configuration saved once.
	WUSPONUNetworkFirewallApplyCommand = WUSPONUPrefix + "Network.Firewall.Apply()"
	// MACFilter.AddRule() input: Name, MACAddress. DeleteRule() input:
	// EntryIndex, and optionally MACAddress as a guard that the entry is
	// still the rule the console showed.
	WUSPONUNetworkMACFilterAddCommand = WUSPONUPrefix + "Network.Firewall.MACFilter.AddRule()"
	WUSPONUNetworkMACFilterDelCommand = WUSPONUPrefix + "Network.Firewall.MACFilter.DeleteRule()"
	// PortFilter.AddRule() input: Direction (inbound/outbound), Name, and
	// any of Protocol, SourceIP, SourceIPEnd or SourceMask, SourcePort,
	// SourcePortEnd, DestIP, DestIPEnd or DestMask, DestPort, DestPortEnd;
	// Interface for an inbound rule. DeleteRule() input: Direction,
	// EntryIndex, optionally Name as a guard.
	WUSPONUNetworkPortFilterAddCommand = WUSPONUPrefix + "Network.Firewall.PortFilter.AddRule()"
	WUSPONUNetworkPortFilterDelCommand = WUSPONUPrefix + "Network.Firewall.PortFilter.DeleteRule()"
	// URLFilter.AddRule() input: URL. DeleteRule() input: EntryIndex,
	// optionally URL as a guard.
	WUSPONUNetworkURLFilterAddCommand = WUSPONUPrefix + "Network.Firewall.URLFilter.AddRule()"
	WUSPONUNetworkURLFilterDelCommand = WUSPONUPrefix + "Network.Firewall.URLFilter.DeleteRule()"
)

var WUSPONUObjects = []Object{
	{Path: WUSPONUPrefix, SinceVersion: "1.0", Description: "XPON/GPON/EPON ONU platform state: PON link, activation, optical DDMI and GEM counters."},
	{Path: WUSPONUPrefix + "Network.", SinceVersion: "1.0", Description: "ONU network state: interfaces, routes, firewall configuration, DHCP, DNS, Wi-Fi radios, SSIDs and stations."},
	{Path: WUSPONUPrefix + "Network.Interface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Network interfaces in /proc/net/dev order (Interface.{i}.Enable resolves the same order), with role, IPv4 (netlink) and state."},
	{Path: WUSPONUPrefix + "Network.Route.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "IPv4 routing table from /proc/net/route."},
	{Path: WUSPONUPrefix + "Network.Firewall.", SinceVersion: "1.0", Description: "The ONU's own firewall configuration (web pages sec-firewall/macfilter/portfilter/urlfilter/protocolfilter, read with tcapi), plus the raw iptables listing."},
	{Path: WUSPONUPrefix + "Network.Firewall.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Raw iptables listing (iptables -S): one row per chain policy or rule across filter, nat and mangle."},
	{Path: WUSPONUPrefix + "Network.Firewall.MACFilter.", SinceVersion: "1.0", Description: "MAC address filter (IpMacFilter_Common ActiveMac, ListTypeMac)."},
	{Path: WUSPONUPrefix + "Network.Firewall.MACFilter.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "MAC filter rules, as sec_macfilterlist.cgi lists them."},
	{Path: WUSPONUPrefix + "Network.Firewall.PortFilter.", SinceVersion: "1.0", Description: "IP/port filter, inbound (ActivePortIn, ListTypeIpDown) and outbound (ActivePortOut, ListTypeIpUp)."},
	{Path: WUSPONUPrefix + "Network.Firewall.PortFilter.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "IP/port filter rules of both directions, as sec_portfilterinlist.cgi and sec_portfilteroutlist.cgi list them."},
	{Path: WUSPONUPrefix + "Network.Firewall.URLFilter.", SinceVersion: "1.0", Description: "URL filter (UrlFilter_Common Activate, Filter_Policy)."},
	{Path: WUSPONUPrefix + "Network.Firewall.URLFilter.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "URL filter entries, as sec_urlfilterlist.cgi lists them."},
	{Path: WUSPONUPrefix + "Network.Firewall.ProtocolFilter.", SinceVersion: "1.0", Description: "Per-port protocol (ethertype) filter, IpMacFilter_EtherTypeFilter P0..P11."},
	{Path: WUSPONUPrefix + "Network.Firewall.ProtocolFilter.Rule.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per LAN port or SSID that blocks at least one protocol."},
	{Path: WUSPONUPrefix + "Network.DHCP.", SinceVersion: "1.0", Description: "DHCP server/client lease state."},
	{Path: WUSPONUPrefix + "Network.DHCP.Lease.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DHCP lease table."},
	{Path: WUSPONUPrefix + "Network.DNS.", SinceVersion: "1.0", Description: "DNS resolver configuration from resolv.conf."},
	{Path: WUSPONUPrefix + "Network.DNS.Server.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DNS nameserver table."},
	{Path: WUSPONUPrefix + "Network.Radio.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Wi-Fi radios: one per band whose driver interface exists (ra0 2.4 GHz, rai0 5 GHz), configuration from tcapi WLan_Common / WLan11ac_Common. mac80211 phys on other builds."},
	{Path: WUSPONUPrefix + "Network.SSID.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Wi-Fi SSIDs from tcapi WLan_Entry<n> / WLan11ac_Entry<n> (interface ra<n> / rai<n>). Keys and passphrases are never read."},
	{Path: WUSPONUPrefix + "Network.WirelessInterface.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Legacy: wireless interface table from /proc/net/wireless. No longer collected."},
	{Path: WUSPONUPrefix + "Network.Station.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Associated Wi-Fi clients: iwpriv <radio> get_mac_table on the MediaTek driver, iw station dump on mac80211."},
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
	onuParam("Network.RadioNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of Wi-Fi radios.", Limits{Min: iptr(0)}),
	onuParam("Network.Radio.{i}.Band", TypeString, ReadOnly, "Frequency band: 2.4GHz or 5GHz (mac80211 builds: the phy's band text).", Limits{MaxLength: 16}),
	onuParam("Network.Radio.{i}.Interfaces", TypeString, ReadOnly, "Comma-separated SSID interfaces of this radio (ra0,ra1,... or rai0,...).", Limits{MaxLength: 128}),
	onuParam("Network.Radio.{i}.Enable", TypeBoolean, ReadWrite, "Radio switched on (APOn). Disruptive: writing it commits the radio configuration and drops its clients. On builds without the MediaTek driver it brings the radio's first interface up or down.", Limits{}),
	onuParam("Network.Radio.{i}.Up", TypeBoolean, ReadOnly, "The radio's first interface is administratively up (IFF_UP).", Limits{}),
	onuParam("Network.Radio.{i}.Channel", TypeUnsignedInt, ReadWrite, "Configured channel; 0 means automatic channel selection. Writable on both radios, to 0 or a channel in ChannelsAvailable (the firmware page's list for CountryRegion / CountryRegionABand); on 2.4 GHz HT_EXTCHA is set with it as the firmware page does. Disruptive.", Limits{Min: iptr(0), Max: iptr(196)}),
	onuParam("Network.Radio.{i}.AutoChannel", TypeBoolean, ReadOnly, "True when the channel is chosen automatically (Channel 0).", Limits{}),
	onuParam("Network.Radio.{i}.Bandwidth", TypeString, ReadWrite, "Channel width: 20 MHz, 20/40 MHz, 40 MHz, 80 MHz, 160 MHz or 80+80 MHz. Writable to a value in BandwidthsAvailable: 2.4 GHz HT_BW with HT_EXTCHA and HT_BSSCoexistence; 5 GHz HT_BW and VHT_BW (20/40 MHz in 802.11a/n, 80 MHz from 802.11ac, 160 MHz on a 7615 chip only). Disruptive.", Limits{Enums: []string{"20 MHz", "20/40 MHz", "40 MHz", "80 MHz", "160 MHz", "80+80 MHz"}}),
	onuParam("Network.Radio.{i}.Mode", TypeString, ReadWrite, "802.11 mode, e.g. 802.11b/g/n. Writable on the 2.4 GHz radio only, to a value in ModesAvailable (WirelessMode). Disruptive.", Limits{MaxLength: 32}),
	onuParam("Network.Radio.{i}.TxPower", TypeUnsignedInt, ReadWrite, "Transmit power in percent of full power. Writable to a value in TxPowersAvailable: 100, 80, 60, 40 or 20 on 2.4 GHz (TxPowerLevel 1-5), 100, 80, 50, 25 or 10 on 5 GHz (TxPower, the values the firmware page posts). Disruptive.", Limits{Min: iptr(1), Max: iptr(100)}),
	onuParam("Network.Radio.{i}.TxPowersAvailable", TypeString, ReadOnly, "Comma-separated transmit power percentages TxPower accepts on this radio.", Limits{MaxLength: 32}),
	onuParam("Network.Radio.{i}.ChannelsAvailable", TypeString, ReadOnly, "Comma-separated channels the firmware page offers for the radio's region (CountryRegion / CountryRegionABand); automatic (0) is always offered.", Limits{MaxLength: 128}),
	onuParam("Network.Radio.{i}.BandwidthsAvailable", TypeString, ReadOnly, "Comma-separated widths Bandwidth accepts now; absent when the width is not writable (a mode without 802.11n).", Limits{MaxLength: 64}),
	onuParam("Network.Radio.{i}.ModesAvailable", TypeString, ReadOnly, "Comma-separated modes Mode accepts; absent when the mode is not writable.", Limits{MaxLength: 128}),
	onuParam("Network.Radio.{i}.SecurityModesAvailable", TypeString, ReadOnly, "Comma-separated AuthMode values this radio's SSIDs accept: OPEN, WPAPSK, WPA2PSK, WPAPSKWPA2PSK, and WPA3PSK, WPA2PSKWPA3PSK when the firmware supports WPA3.", Limits{MaxLength: 128}),
	onuParam("Network.Radio.{i}.ExtensionChannel", TypeString, ReadOnly, "Side of the 40 MHz extension channel (HT_EXTCHA), 2.4 GHz only.", Limits{Enums: []string{"above", "below"}}),
	onuParam("Network.Radio.{i}.Writable", TypeString, ReadOnly, "Comma-separated leaves of this radio the agent can write: Enable, Channel, Mode (2.4 GHz), Bandwidth, TxPower. Absent on agents without Wi-Fi configuration.", Limits{MaxLength: 64}),
	onuParam("Network.Radio.{i}.SSIDWritable", TypeString, ReadOnly, "Comma-separated leaves of this radio's SSIDs the agent can write: Name, Enable, Hidden, AuthMode, Encryption, Passphrase, MaxStations.", Limits{MaxLength: 96}),
	onuParam("Network.Radio.{i}.ModeCode", TypeString, ReadOnly, "Vendor WirelessMode code behind Mode.", Limits{MaxLength: 8}),
	onuParam("Network.Radio.{i}.Country", TypeString, ReadOnly, "Regulatory country code.", Limits{MaxLength: 16}),
	onuParam("Network.Radio.{i}.CountryRegion", TypeString, ReadOnly, "Vendor channel-plan region code.", Limits{MaxLength: 8}),
	onuParam("Network.Radio.{i}.Chip", TypeString, ReadOnly, "Wi-Fi chip id reported by the firmware (rt_device), e.g. 7603.", Limits{MaxLength: 16}),
	onuParam("Network.Radio.{i}.SSIDCount", TypeUnsignedInt, ReadOnly, "Number of SSIDs configured on the radio (BssidNum).", Limits{Min: iptr(0), Max: iptr(16)}),
	onuParam("Network.Radio.{i}.Phy", TypeString, ReadOnly, "mac80211 phy name; only on builds without the MediaTek driver.", Limits{MaxLength: 32}),

	onuParam("Network.SSIDNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of configured SSIDs.", Limits{Min: iptr(0)}),
	onuParam("Network.SSID.{i}.Name", TypeString, ReadWrite, "Network name (SSID): 1 to 32 printable ASCII characters, not ending in a space, unique on its radio. Disruptive.", Limits{MinLength: 1, MaxLength: 32, Pattern: "^[\\x20-\\x7e]{0,31}[\\x21-\\x7e]$"}),
	onuParam("Network.SSID.{i}.Radio", TypeUnsignedInt, ReadOnly, "Radio instance this SSID belongs to.", Limits{Min: iptr(1)}),
	onuParam("Network.SSID.{i}.Band", TypeString, ReadOnly, "Band of the SSID's radio: 2.4GHz or 5GHz.", Limits{MaxLength: 16}),
	onuParam("Network.SSID.{i}.Index", TypeUnsignedInt, ReadOnly, "SSID number on its radio, 1-based (SSID1 is interface ra0 / rai0).", Limits{Min: iptr(1)}),
	onuParam("Network.SSID.{i}.Interface", TypeString, ReadOnly, "Driver interface of the SSID (ra<n> or rai<n>).", Limits{MaxLength: 32}),
	onuParam("Network.SSID.{i}.Enable", TypeBoolean, ReadWrite, "SSID switched on (EnableSSID). Disruptive.", Limits{}),
	onuParam("Network.SSID.{i}.Up", TypeBoolean, ReadOnly, "The SSID's interface is administratively up (IFF_UP).", Limits{}),
	onuParam("Network.SSID.{i}.Hidden", TypeBoolean, ReadWrite, "SSID broadcast suppressed (HideSSID). Disruptive.", Limits{}),
	onuParam("Network.SSID.{i}.AuthMode", TypeString, ReadWrite, "Vendor authentication mode: OPEN, WEP-64Bits, WEP-128Bits, WPAPSK, WPA2PSK, WPAPSKWPA2PSK, WPA3PSK, WPA2PSKWPA3PSK, WPA3, ... Writable to a value in the radio's SecurityModesAvailable; moving from a network without a pre-shared key to a WPA mode needs Passphrase in the same WLAN.Apply(). Disruptive.", Limits{MaxLength: 32}),
	onuParam("Network.SSID.{i}.Encryption", TypeString, ReadWrite, "Vendor cipher (EncrypType): NONE, WEP, TKIP, AES or TKIPAES. Writable: NONE with OPEN; TKIP, AES or TKIPAES with WPAPSK, WPA2PSK and WPAPSKWPA2PSK; AES only with the WPA3 modes and when the radio mode is 802.11n. Disruptive.", Limits{MaxLength: 16}),
	onuParam("Network.SSID.{i}.Passphrase", TypeString, WriteOnly, "Write-only pre-shared key (WPAPSK): 8 to 63 printable ASCII characters or 64 hexadecimal digits. Never read from the device, never reported in a snapshot. Disruptive.", Limits{MinLength: 8, MaxLength: 64}),
	onuParam("Network.SSID.{i}.MaxStations", TypeUnsignedInt, ReadWrite, "Client limit of the SSID (MaxStaNum): 1 to 40 on 2.4 GHz, 0 to 40 on 5 GHz. Disruptive.", Limits{Min: iptr(0), Max: iptr(40)}),
	onuParam("Network.SSID.{i}.StationCount", TypeUnsignedInt, ReadOnly, "Clients associated to the SSID now.", Limits{Min: iptr(0)}),

	onuParam("Network.WirelessInterface.{i}.Name", TypeString, ReadOnly, "Legacy: wireless interface name.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.LinkQuality", TypeString, ReadOnly, "Legacy: link quality metric.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.SignalLevel", TypeString, ReadOnly, "Legacy: signal level.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterface.{i}.NoiseLevel", TypeString, ReadOnly, "Legacy: noise level.", Limits{MaxLength: 32}),
	onuParam("Network.WirelessInterfaceNumberOfEntries", TypeUnsignedInt, ReadOnly, "Legacy: number of wireless interfaces.", Limits{Min: iptr(0)}),

	onuParam("Network.StationNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of associated Wi-Fi clients.", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.Interface", TypeString, ReadOnly, "SSID interface the client is on.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.Band", TypeString, ReadOnly, "Band of the client's radio: 2.4GHz or 5GHz.", Limits{MaxLength: 16}),
	onuParam("Network.Station.{i}.MACAddress", TypeString, ReadOnly, "Client MAC address.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.Signal", TypeString, ReadOnly, "Signal strength, e.g. -52 dBm (MediaTek: the strongest receive chain).", Limits{MaxLength: 16}),
	onuParam("Network.Station.{i}.RxBitrate", TypeString, ReadOnly, "Receive bitrate (mac80211 only).", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.TxBitrate", TypeString, ReadOnly, "Transmit bitrate, e.g. 72 Mbit/s.", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.PhyMode", TypeString, ReadOnly, "PHY mode of the link: CCK, OFDM, HTMIX, GREENFIELD or VHT (MediaTek).", Limits{MaxLength: 16}),
	onuParam("Network.Station.{i}.Bandwidth", TypeString, ReadOnly, "Link channel width, e.g. 20M or 40M (MediaTek).", Limits{MaxLength: 16}),
	onuParam("Network.Station.{i}.MCS", TypeString, ReadOnly, "Current MCS index (MediaTek).", Limits{MaxLength: 8}),
	onuParam("Network.Station.{i}.PowerSave", TypeBoolean, ReadOnly, "Client is in power-save mode (MediaTek).", Limits{}),
	onuParam("Network.Station.{i}.RxBytes", TypeUnsignedInt, ReadOnly, "Bytes received from station (mac80211 only).", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.TxBytes", TypeUnsignedInt, ReadOnly, "Bytes transmitted to station (mac80211 only).", Limits{Min: iptr(0)}),
	onuParam("Network.Station.{i}.ConnectedTime", TypeString, ReadOnly, "Time connected (mac80211 only).", Limits{MaxLength: 32}),
	onuParam("Network.Station.{i}.InactiveTime", TypeString, ReadOnly, "Time since the last frame (mac80211 only).", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.Name", TypeString, ReadOnly, "Interface name.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.MACAddress", TypeString, ReadOnly, "Interface MAC address.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.IPv4Address", TypeString, ReadOnly, "First IPv4 address (from netlink), without prefix.", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.IPv4PrefixLength", TypeUnsignedInt, ReadOnly, "Prefix length of IPv4Address.", Limits{Min: iptr(0), Max: iptr(32)}),
	onuParam("Network.Interface.{i}.IPv4Addresses", TypeString, ReadOnly, "All IPv4 addresses in CIDR form, comma-separated (aliases such as br0:15 included).", Limits{MaxLength: 256}),
	onuParam("Network.Interface.{i}.OperState", TypeString, ReadOnly, "Kernel operstate. The MediaTek Wi-Fi driver reports unknown even while up; see Up.", Limits{MaxLength: 16}),
	onuParam("Network.Interface.{i}.Up", TypeBoolean, ReadOnly, "Administratively up (IFF_UP).", Limits{}),
	onuParam("Network.Interface.{i}.Role", TypeString, ReadOnly, "What the interface is: uplink (nas*/ppp*/default route), lan_bridge (br*), lan_port (eth0.N), wifi (ra*/rai*) or internal (lo, omci, sit0, wds*, wan_int*, ...).", Limits{Enums: []string{"uplink", "lan_bridge", "lan_port", "wifi", "internal"}}),
	onuParam("Network.Interface.{i}.LANPort", TypeUnsignedInt, ReadOnly, "LAN port number N of an eth0.N interface.", Limits{Min: iptr(0)}),
	onuParam("Network.Interface.{i}.Bridge", TypeString, ReadOnly, "Bridge this interface is a port of (e.g. br0).", Limits{MaxLength: 32}),
	onuParam("Network.Interface.{i}.DefaultRoute", TypeBoolean, ReadOnly, "The interface carries the IPv4 default route.", Limits{}),
	onuParam("Network.Interface.{i}.Controllable", TypeBoolean, ReadOnly, "The console may offer Enable on this interface: LAN ports and Wi-Fi only, never the default-route interface.", Limits{}),
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
	onuParam("Network.DHCP.Lease.{i}.ClientID", TypeString, ReadOnly, "DHCP client identifier.", Limits{MaxLength: 128}),
	onuParam("Network.Firewall.Enable", TypeBoolean, ReadWrite, "ONU firewall (attack protection) switched on (Firewall_Entry firewall_status). Writable when Writable lists Enable.", Limits{}),
	onuParam("Network.Firewall.Level", TypeString, ReadWrite, "ONU firewall level (firewall_level). low: tear drop, LAND, ping of death and source-address spoofing; medium adds Smurf; high also drops pings and unsolicited or invalid packets from the WAN. Absent when the ONU stores none (the firmware then uses medium).", Limits{Enums: []string{"low", "medium", "high"}}),
	onuParam("Network.Firewall.SPIEnable", TypeBoolean, ReadOnly, "Stored spi_status. Read-only: this firmware no longer acts on it.", Limits{}),
	onuParam("Network.Firewall.DoSProtection", TypeBoolean, ReadWrite, "DoS / SYN-flood protection (Firewall_DoSEntry Enable).", Limits{}),
	onuParam("Network.Firewall.PortScanProtection", TypeBoolean, ReadWrite, "Port-scan protection (Firewall_PortScanEntry Enable). While on, new connections from outside the LAN to the ONU and to LAN devices are dropped, so port forwards stop answering.", Limits{}),
	onuParam("Network.Firewall.IPv6SessionProtection", TypeBoolean, ReadWrite, "IPv6 session protection (Firewall_IPv6SessionEntry Enable).", Limits{}),
	onuParam("Network.Firewall.Writable", TypeString, ReadOnly, "Comma-separated firewall settings this agent can write: Enable, Level, DoSProtection, PortScanProtection, IPv6SessionProtection, MACFilter.Enable, MACFilter.Mode, MACFilter.Rule, PortFilter.InboundEnable, PortFilter.InboundMode, PortFilter.OutboundEnable, PortFilter.OutboundMode, PortFilter.Rule, URLFilter.Enable, URLFilter.Mode, URLFilter.Rule (Rule: the AddRule() and DeleteRule() commands). Absent on agents without firewall configuration.", Limits{MaxLength: 512}),
	onuParam("Network.Firewall.LevelsAvailable", TypeString, ReadOnly, "Comma-separated levels Level accepts.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.Guarded", TypeString, ReadOnly, "Comma-separated settings the agent refuses to turn on because the ONU has a system tunnel interface their rules would filter: Enable, Level, PortScanProtection. Absent when nothing is refused.", Limits{MaxLength: 128}),

	onuParam("Network.Firewall.MACFilter.Enable", TypeBoolean, ReadWrite, "MAC filter on (ActiveMac).", Limits{}),
	onuParam("Network.Firewall.MACFilter.Mode", TypeString, ReadWrite, "black: listed MACs are blocked; white: only listed MACs pass (ListTypeMac).", Limits{Enums: []string{"black", "white"}}),
	onuParam("Network.Firewall.MACFilter.MaxRules", TypeUnsignedInt, ReadOnly, "Most MAC filter rules the firmware stores (40, or 32 on NPU builds).", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.MACFilter.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of MAC filter rules.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.MACFilter.Rule.{i}.EntryIndex", TypeString, ReadOnly, "Firmware entry index (IpMacFilter_Entry<n>).", Limits{MaxLength: 8}),
	onuParam("Network.Firewall.MACFilter.Rule.{i}.Name", TypeString, ReadOnly, "Rule name. AddRule() takes 1 to 31 characters: letters, digits and . - _ ( ) @ ! * / ; ? without spaces.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.MACFilter.Rule.{i}.MACAddress", TypeString, ReadOnly, "Filtered MAC address.", Limits{MaxLength: 32}),
	onuParam("Network.Firewall.MACFilter.Rule.{i}.Enable", TypeBoolean, ReadOnly, "Rule active.", Limits{}),
	onuParam("Network.Firewall.MACFilter.Rule.{i}.Interface", TypeString, ReadOnly, "Interface the rule applies to, when set.", Limits{MaxLength: 64}),

	onuParam("Network.Firewall.PortFilter.InboundEnable", TypeBoolean, ReadWrite, "Inbound (downlink) IP/port filter on (ActivePortIn). Filters traffic forwarded from the WAN to the LAN, not the ONU's own.", Limits{}),
	onuParam("Network.Firewall.PortFilter.InboundMode", TypeString, ReadWrite, "Inbound list mode (ListTypeIpDown): black blocks what the rules match, white drops everything else arriving from the WAN.", Limits{Enums: []string{"black", "white"}}),
	onuParam("Network.Firewall.PortFilter.OutboundEnable", TypeBoolean, ReadWrite, "Outbound (uplink) IP/port filter on (ActivePortOut). Filters traffic forwarded from the LAN to the WAN, not the ONU's own.", Limits{}),
	onuParam("Network.Firewall.PortFilter.OutboundMode", TypeString, ReadWrite, "Outbound list mode (ListTypeIpUp): black blocks what the rules match, white drops everything else leaving the LAN.", Limits{Enums: []string{"black", "white"}}),
	onuParam("Network.Firewall.PortFilter.MaxRules", TypeUnsignedInt, ReadOnly, "Most IP/port filter rules per direction (40).", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.PortFilter.ProtocolsAvailable", TypeString, ReadOnly, "Comma-separated Protocol values AddRule() accepts (it may also be empty): TCP/UDP, TCP, UDP, ICMP, All.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.AddressForm", TypeString, ReadOnly, "range: AddRule() takes address and port ranges (SourceIPEnd, DestIPEnd, SourcePortEnd, DestPortEnd) and no masks; mask: single addresses with SourceMask / DestMask and single ports.", Limits{Enums: []string{"range", "mask"}}),
	onuParam("Network.Firewall.PortFilter.InterfacesAvailable", TypeString, ReadOnly, "Comma-separated WAN connections an inbound rule's Interface accepts (nas<p>_<e>, ppp<n>).", Limits{MaxLength: 256}),
	onuParam("Network.Firewall.PortFilter.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of IP/port filter rules, both directions.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.EntryIndex", TypeString, ReadOnly, "Firmware entry index (IpMacFilter_Entry<n>).", Limits{MaxLength: 8}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.Direction", TypeString, ReadOnly, "inbound or outbound.", Limits{Enums: []string{"inbound", "outbound"}}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.Name", TypeString, ReadOnly, "Rule name (IPName).", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.Enable", TypeBoolean, ReadOnly, "Rule active.", Limits{}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.Interface", TypeString, ReadOnly, "WAN connection the rule applies to.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.Protocol", TypeString, ReadOnly, "Protocol: TCP, UDP, TCP/UDP, ICMP or ALL.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.SourceIP", TypeString, ReadOnly, "Source address (range start).", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.SourceIPEnd", TypeString, ReadOnly, "Source address range end.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.SourceMask", TypeString, ReadOnly, "Source netmask.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.SourcePort", TypeString, ReadOnly, "Source port (range start).", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.SourcePortEnd", TypeString, ReadOnly, "Source port range end.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.DestIP", TypeString, ReadOnly, "Destination address (range start).", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.DestIPEnd", TypeString, ReadOnly, "Destination address range end.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.DestMask", TypeString, ReadOnly, "Destination netmask.", Limits{MaxLength: 64}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.DestPort", TypeString, ReadOnly, "Destination port (range start).", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.PortFilter.Rule.{i}.DestPortEnd", TypeString, ReadOnly, "Destination port range end.", Limits{MaxLength: 16}),

	onuParam("Network.Firewall.URLFilter.Enable", TypeBoolean, ReadWrite, "URL filter on (UrlFilter_Common Activate). Filters forwarded HTTP (port 80) requests.", Limits{}),
	onuParam("Network.Firewall.URLFilter.Mode", TypeString, ReadWrite, "black: listed URLs are blocked; white: only listed URLs are reachable (Filter_Policy 0/1).", Limits{Enums: []string{"black", "white"}}),
	onuParam("Network.Firewall.URLFilter.MaxRules", TypeUnsignedInt, ReadOnly, "Most URL filter entries (100).", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.URLFilter.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of URL filter entries.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.URLFilter.Rule.{i}.EntryIndex", TypeString, ReadOnly, "Firmware entry index (UrlFilter_Entry<n>).", Limits{MaxLength: 8}),
	onuParam("Network.Firewall.URLFilter.Rule.{i}.URL", TypeString, ReadOnly, "Filtered URL or domain. AddRule() takes 3 to 31 printable ASCII characters without http:// or https://, and only while the filter is on.", Limits{MaxLength: 256}),

	onuParam("Network.Firewall.ProtocolFilter.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of ports with a protocol filter.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.ProtocolFilter.Rule.{i}.Port", TypeString, ReadOnly, "LAN1..LAN4 or SSID1..SSID8.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.ProtocolFilter.Rule.{i}.Blocked", TypeString, ReadOnly, "Blocked protocols, comma-separated: IPv4oE, PPPoE, ARP, IPv6oE.", Limits{MaxLength: 64}),

	onuParam("Network.Firewall.RuleNumberOfEntries", TypeUnsignedInt, ReadOnly, "Raw iptables listing: rules and chain policies across all tables.", Limits{Min: iptr(0)}),
	onuParam("Network.Firewall.Rule.{i}.Table", TypeString, ReadOnly, "iptables table: filter, nat, mangle.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.Rule.{i}.Chain", TypeString, ReadOnly, "Chain name (INPUT, OUTPUT, FORWARD, etc.).", Limits{MaxLength: 32}),
	onuParam("Network.Firewall.Rule.{i}.Type", TypeString, ReadOnly, "Entry type: policy or rule.", Limits{Enums: []string{"policy", "rule"}}),
	onuParam("Network.Firewall.Rule.{i}.Policy", TypeString, ReadOnly, "Chain default policy (ACCEPT, DROP) for policy-type entries.", Limits{MaxLength: 16}),
	onuParam("Network.Firewall.Rule.{i}.Raw", TypeString, ReadOnly, "Raw iptables rule text (iptables -S form) for rule-type entries.", Limits{MaxLength: 512}),
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
