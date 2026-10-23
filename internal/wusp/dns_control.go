package wusp

const WUSPDNSPrefix = "Device.WUSP_DNS."

// WUSPDNSMaxServers bounds the manual resolver list.
const WUSPDNSMaxServers = 4

var WUSPDNSObjects = []Object{
	{Path: WUSPDNSPrefix, SinceVersion: "1.0", Description: "Device DNS resolver control, applied through the platform's own DNS manager (dnsmasq on OpenWrt, systemd-resolved, NetworkManager, resolv.conf, macOS network services, Windows adapters)."},
}

var AllWUSPDNSParams = []Param{
	{Path: WUSPDNSPrefix + "Supported", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "True when the agent can change DNS servers on this device."},
	{Path: WUSPDNSPrefix + "Method", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "DNS manager the agent writes through.", Limits: Limits{Enums: []string{"openwrt-dnsmasq", "systemd-resolved", "networkmanager", "resolvconf", "resolv.conf", "macos-networksetup", "windows-dnsclient", "unsupported"}}},
	{Path: WUSPDNSPrefix + "Mode", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Automatic uses resolvers from DHCP/the ISP; Manual uses Servers.", Limits: Limits{Enums: []string{"Automatic", "Manual"}}},
	{Path: WUSPDNSPrefix + "Servers", Type: TypeList, Access: ReadWrite, SinceVersion: "1.0", Description: "Manual resolver IP addresses in order (at most 4). Setting an empty list returns to Automatic.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPDNSPrefix + "EffectiveServers", Type: TypeList, Access: ReadOnly, SinceVersion: "1.0", Description: "Resolvers the device is using now (manual or learned).", Limits: Limits{MaxLength: 512}},
	{Path: WUSPDNSPrefix + "LastError", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Why DNS control is unavailable, empty when supported.", Limits: Limits{MaxLength: 256}},
}
