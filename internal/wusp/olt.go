package wusp

// WUSPOLT: the Wantastic OLT data model on Broadcom-based GPON OLTs
// (Photon PTF3708 / GP8X2G6 family, FOS firmware).
//
// The agent runs on the OLT itself and talks to the vendor web API
// (goform/* on 127.0.0.1) plus /tmp/sysinfo.txt. Because the OLT manages
// the ONUs behind it, the per-ONU table covers the whole PON from one
// device: no ONU-side agent is required for basic ONU visibility and
// control. Setters map onto goform calls; Operate commands run only when
// the console asks, never on a timer.

const WUSPOLTPrefix = "Device.WUSP_OLT."

// Bounds for the tables, matching the FOS platform limits with headroom.
const (
	WUSPOLTMaxPONPorts = 32
	WUSPOLTMaxONUs     = 256
	WUSPOLTMaxAlarms   = 64
)

// Operate commands on Device.WUSP_OLT.
const (
	WUSPOLTRebootCommand         = WUSPOLTPrefix + "Reboot()"
	WUSPOLTFactoryRestoreCommand = WUSPOLTPrefix + "FactoryRestore()"
	WUSPOLTONURebootCommand      = WUSPOLTPrefix + "ONU.Reboot()"
	WUSPOLTONUResetCommand       = WUSPOLTPrefix + "ONU.Reset()"
	WUSPOLTONUEnableCommand      = WUSPOLTPrefix + "ONU.Enable()"
	WUSPOLTONUDisableCommand     = WUSPOLTPrefix + "ONU.Disable()"
	// Upgrade applies a firmware image staged through the WUSP upload
	// channel (input: FileName). BackupConfig returns the running
	// configuration text in the result message (field Config).
	// RestoreConfig applies a configuration text (input: Config).
	WUSPOLTUpgradeCommand       = WUSPOLTPrefix + "Upgrade()"
	WUSPOLTBackupConfigCommand  = WUSPOLTPrefix + "BackupConfig()"
	WUSPOLTRestoreConfigCommand = WUSPOLTPrefix + "RestoreConfig()"

	WUSPOLTNetworkACLAddCommand           = WUSPOLTPrefix + "Network.ACL.Add()"
	WUSPOLTNetworkACLDeleteCommand        = WUSPOLTPrefix + "Network.ACL.Delete()"
	WUSPOLTNetworkRouteAddCommand         = WUSPOLTPrefix + "Network.Route.Add()"
	WUSPOLTNetworkRouteDeleteCommand      = WUSPOLTPrefix + "Network.Route.Delete()"
	WUSPOLTNetworkBackupConfigCommand     = WUSPOLTPrefix + "Network.BackupNetworkConfig()"
	WUSPOLTNetworkServicePortAddCommand   = WUSPOLTPrefix + "Network.ServicePort.Add()"
	WUSPOLTNetworkServicePortDeleteCommand = WUSPOLTPrefix + "Network.ServicePort.Delete()"
	WUSPOLTNetworkQVLANAddCommand         = WUSPOLTPrefix + "Network.QVLAN.Add()"
	WUSPOLTNetworkQVLANDeleteCommand      = WUSPOLTPrefix + "Network.QVLAN.Delete()"
)

var WUSPOLTObjects = []Object{
	{Path: WUSPOLTPrefix, SinceVersion: "1.0", Description: "GPON OLT platform state, PON ports, and the ONUs this OLT manages."},
	{Path: WUSPOLTPrefix + "PONPort.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per PON/uplink port of the OLT."},
	{Path: WUSPOLTPrefix + "ONU.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per ONU known to this OLT."},
	{Path: WUSPOLTPrefix + "Alarms.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Recent device alarms."},
	{Path: WUSPOLTPrefix + "Syslog.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Recent device log entries from the OLT log buffer."},
	{Path: WUSPOLTPrefix + "LineProfile.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "GPON line profiles configured on the OLT."},
	{Path: WUSPOLTPrefix + "ProvisionedONU.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "The ONU authentication table: provisioned ONUs the OLT accepts on its PON ports."},
	{Path: WUSPOLTPrefix + "Network.", SinceVersion: "1.0", Description: "OLT network state: management interface, DNS, NTP, ACL, routes."},
	{Path: WUSPOLTPrefix + "Network.Mgmt.", SinceVersion: "1.0", Description: "Management interface configuration."},
	{Path: WUSPOLTPrefix + "Network.DNS.", SinceVersion: "1.0", Description: "DNS resolver configuration."},
	{Path: WUSPOLTPrefix + "Network.DNS.Server.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DNS nameserver table."},
	{Path: WUSPOLTPrefix + "Network.NTP.", SinceVersion: "1.0", Description: "NTP time sync configuration."},
	{Path: WUSPOLTPrefix + "Network.ACL.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "ACL (firewall) rule table."},
	{Path: WUSPOLTPrefix + "Network.Route.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Static route table."},
	{Path: WUSPOLTPrefix + "Network.ServicePort.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Service port table: maps ONUs to VLANs (SVLAN/CVLAN/GEM port bindings for GPON traffic)."},
	{Path: WUSPOLTPrefix + "Network.QVLAN.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "QVLAN table: 802.1Q VLANs configured on the OLT."},
}

func oltParam(leaf string, typ ParamType, access Access, description string, limits Limits) Param {
	return Param{Path: WUSPOLTPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPOLTParams = []Param{
	oltParam("Installed", TypeBoolean, ReadOnly, "True when the OLT fiber platform is detected on this device.", Limits{}),
	oltParam("Enable", TypeBoolean, ReadWrite, "Collect OLT telemetry and accept OLT control on this device.", Limits{}),
	oltParam("Platform", TypeString, ReadOnly, "Platform family this backend speaks: olt.", Limits{MaxLength: 16}),
	oltParam("Status", TypeString, ReadOnly, "Collection status of the OLT backend.", Limits{Enums: []string{"not_installed", "disabled", "ok", "api_error", "login_error"}}),
	oltParam("StatusDetail", TypeString, ReadOnly, "Detail for the current status, empty when ok.", Limits{MaxLength: 256}),
	oltParam("LastCollectTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the last successful collection.", Limits{Min: iptr(0)}),

	oltParam("PONPortNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.PONPort.{i}.", Limits{Min: iptr(0)}),
	oltParam("ONUNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.ONU.{i}.", Limits{Min: iptr(0)}),
	oltParam("AlarmNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.Alarms.{i}.", Limits{Min: iptr(0)}),

	oltParam("TotalONUs", TypeUnsignedInt, ReadOnly, "ONUs known to the OLT.", Limits{Min: iptr(0)}),
	oltParam("OnlineONUs", TypeUnsignedInt, ReadOnly, "ONUs currently online.", Limits{Min: iptr(0)}),

	oltParam("Temperature", TypeDecimal, ReadOnly, "Switch ASIC temperature in degrees Celsius.", Limits{}),
	oltParam("PonTemperature", TypeDecimal, ReadOnly, "PON MAC temperature in degrees Celsius.", Limits{}),
	oltParam("FanSpeed", TypeUnsignedInt, ReadOnly, "Fan speed in RPM, 0 when unknown or stopped.", Limits{Min: iptr(0)}),
	oltParam("CpuPercent", TypeUnsignedInt, ReadOnly, "CPU load in percent.", Limits{Min: iptr(0), Max: iptr(100)}),
	oltParam("MemoryPercent", TypeUnsignedInt, ReadOnly, "Memory load in percent.", Limits{Min: iptr(0), Max: iptr(100)}),
	oltParam("Uptime", TypeUnsignedInt, ReadOnly, "Seconds since the OLT booted.", Limits{Min: iptr(0)}),

	oltParam("SupportedOperations", TypeString, ReadOnly, "Comma-separated Operate commands available: Reboot, FactoryRestore, ONU.Reboot, ONU.Reset, ONU.Enable, ONU.Disable. They run only when requested, never on a timer.", Limits{MaxLength: 128}),
	oltParam("LastOperationStatus", TypeString, ReadOnly, "Result of the latest OLT Operate command.", Limits{Enums: []string{"", "Success", "Error"}}),
	oltParam("LastOperationCode", TypeString, ReadOnly, "Stable machine-readable code of the latest OLT Operate command.", Limits{MaxLength: 64}),
	oltParam("LastOperationMessage", TypeString, ReadOnly, "Short result detail of the latest OLT Operate command.", Limits{MaxLength: 256}),

	oltParam("PONPort.{i}.Name", TypeString, ReadOnly, "Port name, e.g. pon1 or ge3.", Limits{MaxLength: 16}),
	oltParam("PONPort.{i}.Type", TypeString, ReadOnly, "Port type: pon, ge or xge.", Limits{Enums: []string{"pon", "ge", "xge", "other"}}),
	oltParam("PONPort.{i}.Enable", TypeBoolean, ReadWrite, "Administrative enable of the port.", Limits{}),
	oltParam("PONPort.{i}.Status", TypeString, ReadOnly, "Link state of the port.", Limits{Enums: []string{"up", "down"}}),
	oltParam("PONPort.{i}.Speed", TypeUnsignedInt, ReadOnly, "Port speed in Mbps.", Limits{Min: iptr(0)}),
	oltParam("PONPort.{i}.OnlineONUs", TypeUnsignedInt, ReadOnly, "ONUs online on this PON port.", Limits{Min: iptr(0)}),
	oltParam("PONPort.{i}.TotalONUs", TypeUnsignedInt, ReadOnly, "ONUs known on this PON port.", Limits{Min: iptr(0)}),

	oltParam("ONU.{i}.Index", TypeString, ReadOnly, "ONT ID on the PON, e.g. 0/1/1.", Limits{MaxLength: 16}),
	oltParam("ONU.{i}.PONPort", TypeString, ReadOnly, "PON port the ONU hangs off, e.g. pon1.", Limits{MaxLength: 16}),
	oltParam("ONU.{i}.SerialNumber", TypeString, ReadOnly, "ONU vendor serial number.", Limits{MaxLength: 64}),
	oltParam("ONU.{i}.Model", TypeString, ReadOnly, "ONU model reported by the vendor, empty when unknown.", Limits{MaxLength: 64}),
	oltParam("ONU.{i}.Status", TypeString, ReadOnly, "Registration state of the ONU.", Limits{Enums: []string{"", "online", "offline", "unconfigured", "initial"}}),
	oltParam("ONU.{i}.RunState", TypeString, ReadOnly, "Run state of the ONU, e.g. working.", Limits{MaxLength: 32}),
	oltParam("ONU.{i}.Enable", TypeBoolean, ReadWrite, "Allow the ONU to stay active on the PON.", Limits{}),
	oltParam("ONU.{i}.RxPower", TypeDecimal, ReadOnly, "ONU receive optical power in dBm as seen by the OLT.", Limits{}),
	oltParam("ONU.{i}.TxPower", TypeDecimal, ReadOnly, "ONU transmit optical power in dBm as seen by the OLT.", Limits{}),
	oltParam("ONU.{i}.Distance", TypeUnsignedInt, ReadOnly, "Fiber distance to the ONU in meters.", Limits{Min: iptr(0)}),
	oltParam("ONU.{i}.UpTime", TypeUnsignedInt, ReadOnly, "Seconds the ONU has been online.", Limits{Min: iptr(0)}),

	oltParam("Alarms.{i}.Time", TypeUnsignedInt, ReadOnly, "Unix seconds when the alarm was raised.", Limits{Min: iptr(0)}),
	oltParam("Alarms.{i}.Severity", TypeString, ReadOnly, "Alarm severity.", Limits{MaxLength: 16}),
	oltParam("Alarms.{i}.Message", TypeString, ReadOnly, "Alarm text.", Limits{MaxLength: 256}),

	oltParam("TemperatureAlarmHigh", TypeDecimal, ReadOnly, "High temperature alarm threshold in degrees Celsius.", Limits{}),
	oltParam("Config", TypeString, ReadOnly, "Result field of BackupConfig(): the running configuration text.", Limits{MaxLength: 1 << 20}),
	oltParam("TemperatureAlarmLow", TypeDecimal, ReadOnly, "Low temperature alarm threshold in degrees Celsius.", Limits{}),

	oltParam("SyslogNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.Syslog.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfileNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.{i}.", Limits{Min: iptr(0)}),
	oltParam("ProvisionedONUNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.ProvisionedONU.{i}.", Limits{Min: iptr(0)}),

	oltParam("Syslog.{i}.Time", TypeString, ReadOnly, "Log entry timestamp as reported by the device.", Limits{MaxLength: 32}),
	oltParam("Syslog.{i}.Type", TypeString, ReadOnly, "Log severity: Info, Warning, Error, ...", Limits{MaxLength: 16}),
	oltParam("Syslog.{i}.Message", TypeString, ReadOnly, "Log message text.", Limits{MaxLength: 256}),

	oltParam("LineProfile.{i}.ID", TypeString, ReadOnly, "Profile index.", Limits{MaxLength: 8}),
	oltParam("LineProfile.{i}.Name", TypeString, ReadOnly, "Profile name.", Limits{MaxLength: 64}),
	oltParam("LineProfile.{i}.ONTType", TypeString, ReadOnly, "ONT type the profile accepts.", Limits{MaxLength: 32}),
	oltParam("LineProfile.{i}.MappingMode", TypeString, ReadOnly, "Service mapping mode (vlan, port, ...).", Limits{MaxLength: 32}),
	oltParam("LineProfile.{i}.TrafficMode", TypeString, ReadOnly, "Traffic mode (car, ...).", Limits{MaxLength: 32}),

	oltParam("ProvisionedONU.{i}.OnuID", TypeString, ReadOnly, "ONT ID on the PON, e.g. 0/1/1.", Limits{MaxLength: 16}),
	oltParam("ProvisionedONU.{i}.Mode", TypeString, ReadWrite, "Authentication mode: sn, password, mac.", Limits{MaxLength: 16}),
	oltParam("ProvisionedONU.{i}.Info", TypeString, ReadWrite, "Authentication value: serial number, password or MAC.", Limits{MaxLength: 64}),
	oltParam("ProvisionedONU.{i}.LineID", TypeString, ReadWrite, "Line profile index applied to the ONU.", Limits{MaxLength: 8}),
	oltParam("ProvisionedONU.{i}.Desc", TypeString, ReadWrite, "Free-form description.", Limits{MaxLength: 32}),

	oltParam("ONU.{i}.Voltage", TypeDecimal, ReadOnly, "ONU power feed voltage in volts as seen by the OLT.", Limits{}),
	oltParam("ONU.{i}.BiasCurrent", TypeDecimal, ReadOnly, "ONU laser bias current in milliamps as seen by the OLT.", Limits{}),
	oltParam("ONU.{i}.Temperature", TypeDecimal, ReadOnly, "ONU temperature in degrees Celsius as seen by the OLT.", Limits{}),
	oltParam("ONU.{i}.ConfigState", TypeString, ReadOnly, "ONU configuration state, e.g. Normal.", Limits{MaxLength: 32}),
	oltParam("ONU.{i}.EthPortUp", TypeBoolean, ReadOnly, "True when the ONU's Ethernet port reports link up.", Limits{}),

	// Network subsystem: management interface, DNS, NTP, ACL, routes.
	oltParam("Network.Mgmt.IPAddress", TypeString, ReadWrite, "Management interface IP address.", Limits{MaxLength: 32}),
	oltParam("Network.Mgmt.SubnetMask", TypeString, ReadWrite, "Management interface subnet mask.", Limits{MaxLength: 32}),
	oltParam("Network.Mgmt.Gateway", TypeString, ReadWrite, "Management interface default gateway.", Limits{MaxLength: 32}),
	oltParam("Network.Mgmt.MACAddress", TypeString, ReadOnly, "Management interface MAC address.", Limits{MaxLength: 32}),
	oltParam("Network.Mgmt.VLAN", TypeString, ReadWrite, "Management VLAN ID.", Limits{MaxLength: 8}),
	oltParam("Network.Mgmt.Status", TypeString, ReadOnly, "Management interface status.", Limits{MaxLength: 16}),
	oltParam("Network.DNS.ServerNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of DNS nameservers.", Limits{Min: iptr(0)}),
	oltParam("Network.DNS.Server.{i}.Address", TypeString, ReadWrite, "DNS nameserver address.", Limits{MaxLength: 64}),
	oltParam("Network.NTP.Server", TypeString, ReadWrite, "NTP server hostname.", Limits{MaxLength: 128}),
	oltParam("Network.NTP.Enabled", TypeBoolean, ReadWrite, "NTP time synchronization enabled.", Limits{}),
	oltParam("Network.ACLNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of ACL rules.", Limits{Min: iptr(0)}),
	oltParam("Network.ACL.{i}.ID", TypeString, ReadOnly, "ACL rule ID.", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.Name", TypeString, ReadOnly, "ACL rule name.", Limits{MaxLength: 64}),
	oltParam("Network.ACL.{i}.Type", TypeString, ReadOnly, "ACL type (standard, extended).", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.Action", TypeString, ReadOnly, "ACL action (permit, deny).", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.Protocol", TypeString, ReadOnly, "Protocol (tcp, udp, icmp, any).", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.SrcIP", TypeString, ReadOnly, "Source IP/mask.", Limits{MaxLength: 32}),
	oltParam("Network.ACL.{i}.DstIP", TypeString, ReadOnly, "Destination IP/mask.", Limits{MaxLength: 32}),
	oltParam("Network.ACL.{i}.SrcPort", TypeString, ReadOnly, "Source port or range.", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.DstPort", TypeString, ReadOnly, "Destination port or range.", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.Status", TypeString, ReadOnly, "Rule status (enabled, disabled).", Limits{MaxLength: 16}),
	oltParam("Network.RouteNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of static routes.", Limits{Min: iptr(0)}),
	oltParam("Network.Route.{i}.Destination", TypeString, ReadOnly, "Route destination.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Mask", TypeString, ReadOnly, "Route mask.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Gateway", TypeString, ReadOnly, "Route gateway.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Interface", TypeString, ReadOnly, "Route interface.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Metric", TypeUnsignedInt, ReadOnly, "Route metric.", Limits{Min: iptr(0)}),
	oltParam("Network.Config", TypeString, ReadOnly, "Result field of BackupNetworkConfig(): full network config.", Limits{MaxLength: 1 << 20}),

	// Service ports: ONU-to-VLAN mappings. VLAN4000 is the typical service VLAN for ONU connectivity.
	oltParam("Network.ServicePortNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of service port entries.", Limits{Min: iptr(0)}),
	oltParam("Network.ServicePort.{i}.PONPort", TypeString, ReadOnly, "PON port name, e.g. pon1.", Limits{MaxLength: 16}),
	oltParam("Network.ServicePort.{i}.OnuID", TypeString, ReadOnly, "ONU ID on the PON port.", Limits{MaxLength: 16}),
	oltParam("Network.ServicePort.{i}.GEMPort", TypeString, ReadOnly, "GEM port number.", Limits{MaxLength: 16}),
	oltParam("Network.ServicePort.{i}.SVLAN", TypeString, ReadWrite, "Service VLAN ID (e.g. 4000).", Limits{MaxLength: 8}),
	oltParam("Network.ServicePort.{i}.CVLAN", TypeString, ReadWrite, "Customer VLAN ID.", Limits{MaxLength: 8}),
	oltParam("Network.ServicePort.{i}.VLANMode", TypeString, ReadWrite, "VLAN mode (tag, translate, transparent, qinq).", Limits{MaxLength: 16}),

	// Q-VLANs: 802.1Q VLAN database on the OLT.
	oltParam("Network.QVLANNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of Q-VLAN entries.", Limits{Min: iptr(0)}),
	oltParam("Network.QVLAN.{i}.ID", TypeString, ReadOnly, "VLAN ID.", Limits{MaxLength: 8}),
	oltParam("Network.QVLAN.{i}.Name", TypeString, ReadOnly, "VLAN name.", Limits{MaxLength: 64}),
	oltParam("Network.QVLAN.{i}.StartVLAN", TypeString, ReadOnly, "Start of VLAN range.", Limits{MaxLength: 8}),
	oltParam("Network.QVLAN.{i}.EndVLAN", TypeString, ReadOnly, "End of VLAN range.", Limits{MaxLength: 8}),
	oltParam("Network.QVLAN.{i}.Enabled", TypeBoolean, ReadOnly, "VLAN is active.", Limits{}),
}
