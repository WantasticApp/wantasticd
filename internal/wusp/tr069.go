// tr069.go — TR-181 Issue 2 Amendment 20 Device.ManagementServer.* data model.
//
// Device.ManagementServer.* is the TR-069 CWMP ACS connection configuration
// object tree defined in tr-181-2-cwmp.xml. It is only present in CWMP
// (TR-069) data models — USP (TR-369) uses Device.LocalAgent.* instead.
//
// Source: BroadbandForum/cwmp-data-models tr-181-2-cwmp.xml
// https://cwmp-data-models.broadband-forum.org/
package wusp

// ---------------------------------------------------------------------------
// Device.ManagementServer. objects (added to DeviceObjects in device.go)
// ---------------------------------------------------------------------------

var ManagementServerObjects = []Object{
	{
		Path:          "Device.ManagementServer.",
		SinceVersion:  "2.0",
		Description:   "TR-069 CWMP ACS connection — URL, credentials, inform schedule, STUN/XMPP connection request.",
		MultiInstance: false,
	},
	{
		Path:          "Device.ManagementServer.ManageableDevice.{i}.",
		SinceVersion:  "2.0",
		Description:   "Embedded device manageable via the ACS (OUI + serial + product class).",
		MultiInstance: true,
	},
	{
		Path:          "Device.ManagementServer.AutonomousTransferCompletePolicy.",
		SinceVersion:  "2.0",
		Description:   "Policy for autonomous transfer-complete event notifications.",
		MultiInstance: false,
	},
	{
		Path:          "Device.ManagementServer.DUStateChangeComplPolicy.",
		SinceVersion:  "2.1",
		Description:   "Policy for Deployment-Unit state-change-complete event notifications.",
		MultiInstance: false,
	},
	{
		Path:          "Device.ManagementServer.InformParameter.{i}.",
		SinceVersion:  "2.8",
		Description:   "Extra parameters to include in every CWMP Inform message.",
		MultiInstance: true,
	},
	{
		Path:          "Device.ManagementServer.StandbyPolicy.",
		SinceVersion:  "2.8",
		Description:   "Standby-mode policy negotiated with the ACS.",
		MultiInstance: false,
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer. parameters
// ---------------------------------------------------------------------------

var ManagementServerParams = []Param{
	// ACS connection
	{
		Path: "Device.ManagementServer.URL", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "HTTP or HTTPS URL of the ACS. Empty = no ACS configured.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.Username", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "CPE credential username for ACS authentication.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.Password", Type: TypeString, Access: WriteOnly,
		SinceVersion: "2.0",
		Description:  "CPE credential password for ACS authentication (write-only / secured).",
		Limits:       Limits{MaxLength: 256},
	},
	// Periodic Inform
	{
		Path: "Device.ManagementServer.PeriodicInformEnable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable periodic Inform messages to the ACS.",
	},
	{
		Path: "Device.ManagementServer.PeriodicInformInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Interval in seconds between periodic Inform messages.",
		Limits:       Limits{Min: iptr(1)},
	},
	{
		Path: "Device.ManagementServer.PeriodicInformTime", Type: TypeDateTime, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "UTC reference time for computing the periodic-inform schedule.",
	},
	{
		Path: "Device.ManagementServer.ParameterKey", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Most recent ParameterKey value set by the ACS. Included in every Inform (forcedInform).",
		Limits:       Limits{MaxLength: 32},
	},
	// Connection-request (HTTP)
	{
		Path: "Device.ManagementServer.ConnectionRequestURL", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "HTTP URL the ACS uses to send connection-request notifications to the CPE (forcedInform).",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.ConnectionRequestUsername", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Username the ACS uses when sending a connection request to the CPE.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.ConnectionRequestPassword", Type: TypeString, Access: WriteOnly,
		SinceVersion: "2.0",
		Description:  "Password the ACS uses when sending a connection request (write-only / secured).",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.HTTPConnectionRequestEnable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.6",
		Description:  "Enable HTTP-based connection requests. Default: true.",
	},
	{
		Path: "Device.ManagementServer.SupportedConnReqMethods", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.6",
		Description:  "Connection-request methods supported by this CPE.",
		Limits:       Limits{Enums: []string{"HTTP", "STUN", "XMPP"}},
	},
	// Firmware upgrade policy
	{
		Path: "Device.ManagementServer.UpgradesManaged", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "ACS manages firmware upgrades for this device.",
	},
	{
		Path: "Device.ManagementServer.KickURL", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "LAN-accessible URL the CPE presents to redirect users via the ACS kick mechanism.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.DownloadProgressURL", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "URL of a page showing download progress.",
		Limits:       Limits{MaxLength: 256},
	},
	// Session & retry
	{
		Path: "Device.ManagementServer.SessionStatus", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.6",
		Description:  "Current CWMP session status.",
		Limits:       Limits{Enums: []string{"Idle", "InProgress"}},
	},
	{
		Path: "Device.ManagementServer.DefaultActiveNotificationThrottle", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Minimum seconds between consecutive active-notification sessions.",
	},
	{
		Path: "Device.ManagementServer.CWMPRetryMinimumWaitInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Base retry wait-interval in seconds (range 1–65535).",
		Limits:       Limits{Min: iptr(1), Max: iptr(65535)},
	},
	{
		Path: "Device.ManagementServer.CWMPRetryIntervalMultiplier", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Retry back-off multiplier in units of 0.001 (range 1000–65535; 2000 = ×2).",
		Limits:       Limits{Min: iptr(1000), Max: iptr(65535)},
	},
	// STUN (UDP connection request)
	{
		Path: "Device.ManagementServer.UDPConnectionRequestAddress", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "UDP connection-request authority (IP:port) when STUN is active.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.NATDetected", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "True if a NAT was detected between the CPE and the STUN server.",
	},
	{
		Path: "Device.ManagementServer.STUNEnable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable STUN for UDP connection-request support.",
	},
	{
		Path: "Device.ManagementServer.STUNServerAddress", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "STUN server hostname or IP address.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.STUNServerPort", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "STUN server port. 0 = default (3478).",
		Limits:       Limits{Min: iptr(0), Max: iptr(65535)},
	},
	{
		Path: "Device.ManagementServer.STUNUsername", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Username for STUN authentication.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.STUNPassword", Type: TypeString, Access: WriteOnly,
		SinceVersion: "2.0",
		Description:  "Password for STUN authentication (write-only / secured).",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.STUNMaximumKeepAlivePeriod", Type: TypeInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Maximum STUN keepalive interval in seconds. -1 = unlimited.",
		Limits:       Limits{Min: iptr(-1)},
	},
	{
		Path: "Device.ManagementServer.STUNMinimumKeepAlivePeriod", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Minimum STUN keepalive interval in seconds.",
	},
	// Instance addressing
	{
		Path: "Device.ManagementServer.AliasBasedAddressing", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.3",
		Description:  "True if the CPE supports alias-based addressing (forcedInform).",
	},
	{
		Path: "Device.ManagementServer.InstanceMode", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.3",
		Description:  "Whether instance addressing uses InstanceNumber or InstanceAlias.",
		Limits:       Limits{Enums: []string{"InstanceNumber", "InstanceAlias"}},
	},
	{
		Path: "Device.ManagementServer.AutoCreateInstances", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.3",
		Description:  "If true, SetParameterValues on a non-existent multi-instance child auto-creates the instance.",
	},
	// XMPP connection request
	{
		Path: "Device.ManagementServer.ConnReqXMPPConnection", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.6",
		Description:  "Strong pathRef to the Device.XMPP.Connection.{i}. entry used for XMPP connection requests.",
	},
	{
		Path: "Device.ManagementServer.ConnReqAllowedJabberIDs", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.6",
		Description:  "List of allowed ACS Jabber IDs for XMPP connection requests (max 32 entries, 256 chars each).",
		Limits:       Limits{MaxItems: 32, MaxLength: 256},
	},
	{
		Path: "Device.ManagementServer.ConnReqJabberID", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.6",
		Description:  "CPE Jabber ID used for XMPP connection requests (activeNotify).",
		Limits:       Limits{MaxLength: 256},
	},
	// Manageable device counts
	{
		Path: "Device.ManagementServer.ManageableDeviceNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Number of entries in ManageableDevice.{i}.",
	},
	{
		Path: "Device.ManagementServer.ManageableDeviceNotificationLimit", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Minimum seconds between manageable-device discovered/deleted notifications.",
	},
	{
		Path: "Device.ManagementServer.InformParameterNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.8",
		Description:  "Number of entries in InformParameter.{i}.",
	},
	// Reboot scheduling
	{
		Path: "Device.ManagementServer.ScheduleReboot", Type: TypeDateTime, Access: ReadWrite,
		SinceVersion: "2.6",
		Description:  "UTC time at which the CPE should reboot (ACS-scheduled reboot).",
	},
	{
		Path: "Device.ManagementServer.DelayReboot", Type: TypeInt, Access: ReadWrite,
		SinceVersion: "2.6",
		Description:  "Seconds to delay before rebooting. -1 = cancel scheduled reboot.",
		Limits:       Limits{Min: iptr(-1)},
	},
	// Allowed source prefixes (TR-069 Amendment 6)
	{
		Path: "Device.ManagementServer.AllowAllIPv4", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.9",
		Description:  "Allow connection requests from any IPv4 address. Default: true.",
	},
	{
		Path: "Device.ManagementServer.AllowAllIPv6", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.9",
		Description:  "Allow connection requests from any IPv6 address. Default: true.",
	},
	{
		Path: "Device.ManagementServer.IPv4AllowedSourcePrefix", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.9",
		Description:  "Comma-separated IPv4 CIDR prefixes from which connection requests are accepted (max 1024 chars total).",
		Limits:       Limits{MaxLength: 1024},
	},
	{
		Path: "Device.ManagementServer.IPv6AllowedSourcePrefix", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.9",
		Description:  "Comma-separated IPv6 CIDR prefixes from which connection requests are accepted (max 1024 chars total).",
		Limits:       Limits{MaxLength: 1024},
	},
	{
		Path: "Device.ManagementServer.InstanceWildcardsSupported", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.9",
		Description:  "True if the CPE supports instance wildcards in parameter paths.",
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer.ManageableDevice.{i}. parameters
// ---------------------------------------------------------------------------

var ManagementServerManageableDeviceParams = []Param{
	{
		Path: "Device.ManagementServer.ManageableDevice.{i}.ManufacturerOUI", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "OUI of the embedded device (6 uppercase hex digits, e.g. \"00256D\").",
		Limits:       Limits{MinLength: 6, MaxLength: 6, Pattern: `[0-9A-F]{6}`},
	},
	{
		Path: "Device.ManagementServer.ManageableDevice.{i}.SerialNumber", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Serial number of the embedded device.",
		Limits:       Limits{MaxLength: 64},
	},
	{
		Path: "Device.ManagementServer.ManageableDevice.{i}.ProductClass", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Product class of the embedded device.",
		Limits:       Limits{MaxLength: 64},
	},
	{
		Path: "Device.ManagementServer.ManageableDevice.{i}.Host", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.0",
		Description:  "Strong pathRefs to Device.Hosts.Host.{i}. entries for this embedded device.",
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer.AutonomousTransferCompletePolicy. parameters
// ---------------------------------------------------------------------------

var ManagementServerXferPolicyParams = []Param{
	{
		Path: "Device.ManagementServer.AutonomousTransferCompletePolicy.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Enable autonomous-transfer-complete notifications.",
	},
	{
		Path: "Device.ManagementServer.AutonomousTransferCompletePolicy.TransferTypeFilter", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Which transfer types trigger the notification.",
		Limits:       Limits{Enums: []string{"Upload", "Download", "Both"}},
	},
	{
		Path: "Device.ManagementServer.AutonomousTransferCompletePolicy.ResultTypeFilter", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "Which result types (success/failure) trigger the notification.",
		Limits:       Limits{Enums: []string{"Success", "Failure", "Both"}},
	},
	{
		Path: "Device.ManagementServer.AutonomousTransferCompletePolicy.FileTypeFilter", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.0",
		Description:  "List of file types that trigger the notification (max 1024 chars total).",
		Limits:       Limits{MaxLength: 1024},
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer.DUStateChangeComplPolicy. parameters
// ---------------------------------------------------------------------------

var ManagementServerDUPolicyParams = []Param{
	{
		Path: "Device.ManagementServer.DUStateChangeComplPolicy.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.1",
		Description:  "Enable DU-state-change-complete autonomous notifications.",
	},
	{
		Path: "Device.ManagementServer.DUStateChangeComplPolicy.OperationTypeFilter", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.1",
		Description:  "Which DU operations trigger the notification.",
		Limits:       Limits{Enums: []string{"Install", "Update", "Uninstall"}},
	},
	{
		Path: "Device.ManagementServer.DUStateChangeComplPolicy.ResultTypeFilter", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.1",
		Description:  "Which result types trigger the notification.",
		Limits:       Limits{Enums: []string{"Success", "Failure", "Both"}},
	},
	{
		Path: "Device.ManagementServer.DUStateChangeComplPolicy.FaultCodeFilter", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.1",
		Description:  "CWMP fault codes (9001–9032) that trigger the notification.",
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer.InformParameter.{i}. parameters
// ---------------------------------------------------------------------------

var ManagementServerInformParamParams = []Param{
	{
		Path: "Device.ManagementServer.InformParameter.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Enable inclusion of this parameter in Inform messages.",
	},
	{
		Path: "Device.ManagementServer.InformParameter.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Non-functional unique key for this InformParameter instance.",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.ManagementServer.InformParameter.{i}.ParameterName", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Parameter path (or wildcard pattern) to include in every Inform.",
	},
}

// ---------------------------------------------------------------------------
// Device.ManagementServer.StandbyPolicy. parameters
// ---------------------------------------------------------------------------

var ManagementServerStandbyParams = []Param{
	{
		Path: "Device.ManagementServer.StandbyPolicy.NetworkAwarenessCapable", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.8",
		Description:  "True if the CPE supports CR-Aware Standby.",
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.SelfTimerCapable", Type: TypeBoolean, Access: ReadOnly,
		SinceVersion: "2.8",
		Description:  "True if the CPE supports Timer-Aware Standby.",
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.CRAwarenessRequested", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Request CR-Aware Standby from the ACS.",
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.PeriodicAwarenessRequested", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Request Periodic-Aware Standby from the ACS.",
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.CRUnawarenessMaxDuration", Type: TypeInt, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Maximum CR-unaware standby duration in seconds. -1 = unlimited.",
		Limits:       Limits{Min: iptr(-1)},
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.MaxMissedPeriodic", Type: TypeInt, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Maximum consecutive missed periodic Informs before reconnecting. -1 = unlimited.",
		Limits:       Limits{Min: iptr(-1)},
	},
	{
		Path: "Device.ManagementServer.StandbyPolicy.NotifyMissedScheduled", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.8",
		Description:  "Notify ACS of missed scheduled Informs on next session.",
	},
}

// ---------------------------------------------------------------------------
// Aggregated slice
// ---------------------------------------------------------------------------

// AllManagementServerParams is the union of all Device.ManagementServer.*
// parameter definitions. Merged into AllDeviceParams at package init time.
var AllManagementServerParams = concat(
	ManagementServerParams,
	ManagementServerManageableDeviceParams,
	ManagementServerXferPolicyParams,
	ManagementServerDUPolicyParams,
	ManagementServerInformParamParams,
	ManagementServerStandbyParams,
)
