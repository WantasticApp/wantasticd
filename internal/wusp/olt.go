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

	WUSPOLTNetworkACLAddCommand       = WUSPOLTPrefix + "Network.ACL.Add()"
	WUSPOLTNetworkACLDeleteCommand    = WUSPOLTPrefix + "Network.ACL.Delete()"
	WUSPOLTNetworkRouteAddCommand     = WUSPOLTPrefix + "Network.Route.Add()"
	WUSPOLTNetworkRouteDeleteCommand  = WUSPOLTPrefix + "Network.Route.Delete()"
	WUSPOLTNetworkBackupConfigCommand = WUSPOLTPrefix + "Network.BackupNetworkConfig()"
	WUSPOLTNetworkQVLANAddCommand     = WUSPOLTPrefix + "Network.QVLAN.Add()"
	WUSPOLTNetworkQVLANDeleteCommand  = WUSPOLTPrefix + "Network.QVLAN.Delete()"

	// ONT authorization (ONT List > Auth Config): setOntListConfig action
	// add / delOntListConfig {list:[row]}.
	WUSPOLTProvisionedONUAddCommand    = WUSPOLTPrefix + "ProvisionedONU.Add()"
	WUSPOLTProvisionedONUDeleteCommand = WUSPOLTPrefix + "ProvisionedONU.Delete()"

	// DescribeControls returns the console control schema (JSON) in the
	// result field ControlSchema; ControlSchemaVersion is collected every
	// cycle so the console knows when to fetch it again.
	WUSPOLTDescribeControlsCommand = WUSPOLTPrefix + "DescribeControls()"

	// SaveConfig persists the running configuration (the web UI's Save:
	// setGlobalConfig {action:"all"}). Every write changes only the running
	// configuration until it is saved (or AutoSave is on).
	WUSPOLTSaveConfigCommand = WUSPOLTPrefix + "SaveConfig()"
)

// OLTEffect classifies what writing a parameter or running a command does
// to the OLT. The console uses it to decide how much confirmation to ask
// for; the agent uses it to keep destructive actions out of plain Set.
type OLTEffect string

const (
	// OLTEffectNone: read-only or informational (reads, backups).
	OLTEffectNone OLTEffect = "none"
	// OLTEffectConfig: changes configuration; reversible, no service hit.
	OLTEffectConfig OLTEffect = "config"
	// OLTEffectDisruptive: interrupts service while it applies (ONU or
	// port down, management IP change, reboot). Console must confirm.
	OLTEffectDisruptive OLTEffect = "disruptive"
	// OLTEffectDestructive: erases or replaces state (factory restore,
	// config restore, firmware, deleting provisioning). Operate-only: a
	// destructive action is never exposed as a writable parameter.
	OLTEffectDestructive OLTEffect = "destructive"
)

// OLTUI is console rendering metadata for one control. Group/Section place
// the control on a console page (Group defaults to the first path segment,
// "System" for root leaves; Section to the second segment). Page names the
// OLT web UI page the control mirrors, for traceability.
type OLTUI struct {
	Label   string `json:"label,omitempty"`
	Group   string `json:"group,omitempty"`
	Section string `json:"section,omitempty"`
	Page    string `json:"page,omitempty"`
	Units   string `json:"units,omitempty"`
	Help    string `json:"help,omitempty"`
	// EnumLabels are display titles matching Limits.Enums (without the
	// leading "" the schema adds).
	EnumLabels []string `json:"enumLabels,omitempty"`
}

// OLTParamDef is one declared Device.WUSP_OLT parameter.
type OLTParamDef struct {
	Param
	UI     OLTUI
	Effect OLTEffect
}

// OLTArgDef is one Operate input or output argument. Outputs name the
// result parameter (Path) the command fills in its reply message.
type OLTArgDef struct {
	Name        string
	Type        ParamType
	Required    bool
	Description string
	Limits      Limits
	Path        string
}

// OLTCommandDef is one declared Device.WUSP_OLT Operate command.
type OLTCommandDef struct {
	Path        string
	Description string
	Effect      OLTEffect
	Inputs      []OLTArgDef
	Outputs     []OLTArgDef
	UI          OLTUI
}

// OLTTableDef adds console/table metadata to a multi-instance object of
// WUSPOLTObjects: the stable vendor key column, the count parameter, and
// whether rows can be created/removed with USP Add/Delete (AddArgs lists
// the initial fields Add accepts). Tables whose rows are created through
// Operate commands name them in AddCommand/DeleteCommand.
type OLTTableDef struct {
	Path          string
	Key           string
	CountParam    string
	Addable       bool
	Deletable     bool
	AddArgs       []OLTArgDef
	AddCommand    string
	DeleteCommand string
	UI            OLTUI
}

type oltOpt func(*OLTParamDef)

func oltUnits(units string) oltOpt { return func(d *OLTParamDef) { d.UI.Units = units } }
func oltGroup(group, section string) oltOpt {
	return func(d *OLTParamDef) { d.UI.Group, d.UI.Section = group, section }
}
func oltEffect(effect OLTEffect) oltOpt { return func(d *OLTParamDef) { d.Effect = effect } }
func oltLabel(label string) oltOpt      { return func(d *OLTParamDef) { d.UI.Label = label } }

// oltParam declares one parameter under Device.WUSP_OLT. Effect defaults
// to none for read-only and config for writable parameters.
func oltParam(leaf string, typ ParamType, access Access, description string, limits Limits, opts ...oltOpt) OLTParamDef {
	d := OLTParamDef{Param: Param{Path: WUSPOLTPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}}
	if access == ReadOnly {
		d.Effect = OLTEffectNone
	} else {
		d.Effect = OLTEffectConfig
	}
	for _, opt := range opts {
		opt(&d)
	}
	return d
}

func oltParamsFromDefs(defs []OLTParamDef) []Param {
	out := make([]Param, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.Param)
	}
	return out
}

func oltArg(name string, typ ParamType, required bool, description string) OLTArgDef {
	return OLTArgDef{Name: name, Type: typ, Required: required, Description: description}
}

func oltStr(name string, required bool, description string) OLTArgDef {
	return oltArg(name, TypeString, required, description)
}

// WUSPOLTCommands declares every Device.WUSP_OLT Operate command.
var WUSPOLTCommands = append(wuspOLTBaseCommands, oltPageCommands()...)

var wuspOLTBaseCommands = []OLTCommandDef{
	{Path: WUSPOLTRebootCommand, Effect: OLTEffectDisruptive, Description: "Reboot the OLT. Every ONU loses service until the OLT is back.", UI: OLTUI{Label: "Reboot OLT", Group: "Maintenance", Section: "System"}},
	{Path: WUSPOLTFactoryRestoreCommand, Effect: OLTEffectDestructive, Description: "Restore the OLT factory configuration. All provisioning is erased.", UI: OLTUI{Label: "Factory restore", Group: "Maintenance", Section: "System"}},
	{Path: WUSPOLTUpgradeCommand, Effect: OLTEffectDestructive, Description: "Apply a firmware image staged through the WUSP upload channel.", Inputs: []OLTArgDef{oltStr("FileName", true, "Staged image file name.")}, UI: OLTUI{Label: "Upgrade firmware", Group: "Maintenance", Section: "Firmware"}},
	{Path: WUSPOLTBackupConfigCommand, Effect: OLTEffectNone, Description: "Return the running configuration text.", Outputs: []OLTArgDef{{Name: "Config", Type: TypeString, Path: WUSPOLTPrefix + "Config", Description: "Running configuration text."}}, UI: OLTUI{Label: "Back up configuration", Group: "Maintenance", Section: "Configuration"}},
	{Path: WUSPOLTRestoreConfigCommand, Effect: OLTEffectDestructive, Description: "Replace the configuration with the given text.", Inputs: []OLTArgDef{oltStr("Config", true, "Configuration text (olt_config.txt).")}, UI: OLTUI{Label: "Restore from file", Group: "Maintenance", Section: "Configuration"}},
	{Path: WUSPOLTONURebootCommand, Effect: OLTEffectDisruptive, Description: "Reboot one ONU.", Inputs: []OLTArgDef{oltStr("Index", true, "ONU ID, e.g. 0/1/1.")}, UI: OLTUI{Label: "Reboot ONU", Group: "ONU", Section: "Actions"}},
	{Path: WUSPOLTONUResetCommand, Effect: OLTEffectDestructive, Description: "Reset one ONU to its defaults.", Inputs: []OLTArgDef{oltStr("Index", true, "ONU ID, e.g. 0/1/1.")}, UI: OLTUI{Label: "Reset ONU", Group: "ONU", Section: "Actions"}},
	{Path: WUSPOLTONUEnableCommand, Effect: OLTEffectConfig, Description: "Activate one ONU on its PON.", Inputs: []OLTArgDef{oltStr("Index", true, "ONU ID, e.g. 0/1/1.")}, UI: OLTUI{Label: "Activate ONU", Group: "ONU", Section: "Actions"}},
	{Path: WUSPOLTONUDisableCommand, Effect: OLTEffectDisruptive, Description: "Deactivate one ONU; its subscriber loses service.", Inputs: []OLTArgDef{oltStr("Index", true, "ONU ID, e.g. 0/1/1.")}, UI: OLTUI{Label: "Deactivate ONU", Group: "ONU", Section: "Actions"}},
	{Path: WUSPOLTProvisionedONUAddCommand, Effect: OLTEffectConfig, Description: "Authorize one ONT (setOntListConfig action add: {onuid, mode, sn|loid, lineid, desc}). The vendor dialog has no password field, so none is sent.", Inputs: []OLTArgDef{
		oltStr("OnuID", false, "ONT ID, e.g. 0/1/1 (or give Port and Index)."), oltStr("Port", false, "PON port (pon1..pon8 or 1..8) when OnuID is not given."), oltStr("Index", false, "ONT index on the port (1-128) when OnuID is not given."),
		oltStr("Mode", false, "Authentication mode: sn (default) or loid."), oltStr("Info", true, "Serial number (sn) or logical ID (loid)."),
		oltStr("LineID", false, "Line profile ID (default 0)."), oltStr("Desc", false, "Description (max 32)."),
	}, UI: OLTUI{Label: "Authorize ONT", Group: "ONU", Section: "Authentication"}},
	{Path: WUSPOLTProvisionedONUDeleteCommand, Effect: OLTEffectDestructive, Description: "De-authorize one ONT (delOntListConfig {list:[row]}); its subscriber loses service.", Inputs: []OLTArgDef{oltStr("OnuID", true, "ONT ID, e.g. 0/1/1.")}, UI: OLTUI{Label: "De-authorize ONT", Group: "ONU", Section: "Authentication"}},
	{Path: WUSPOLTNetworkACLAddCommand, Effect: OLTEffectConfig, Description: "Create an ACL (setAclListInfo action add). Rules are added under Security.ACL.IPRule.", Inputs: []OLTArgDef{
		oltStr("ID", true, "ACL ID: 100-199 (ipv4)."), oltStr("Name", false, "Remark."), oltStr("Type", false, "ipv4 (default)."),
	}, UI: OLTUI{Label: "Add ACL", Group: "Network", Section: "ACL"}},
	{Path: WUSPOLTNetworkACLDeleteCommand, Effect: OLTEffectDestructive, Description: "Delete an ACL and its rules.", Inputs: []OLTArgDef{oltStr("ID", true, "ACL ID.")}, UI: OLTUI{Label: "Delete ACL rule", Group: "Network", Section: "ACL"}},
	{Path: WUSPOLTNetworkRouteAddCommand, Effect: OLTEffectConfig, Description: "Add a static route.", Inputs: []OLTArgDef{
		oltStr("Destination", true, "Destination network."), oltStr("Mask", true, "Destination mask."),
		oltStr("Gateway", true, "Next hop."),
	}, UI: OLTUI{Label: "Add static route", Group: "Network", Section: "Route"}},
	{Path: WUSPOLTNetworkRouteDeleteCommand, Effect: OLTEffectDisruptive, Description: "Delete a static route.", Inputs: []OLTArgDef{oltStr("Destination", true, "Destination network of the route."), oltStr("Mask", false, "Mask, when several routes share the destination.")}, UI: OLTUI{Label: "Delete static route", Group: "Network", Section: "Route"}},
	{Path: WUSPOLTNetworkQVLANAddCommand, Effect: OLTEffectConfig, Description: "Create a VLAN or VLAN range (setQvlanInfo action add).", Inputs: []OLTArgDef{oltStr("StartVLAN", true, "First VLAN ID (2-4094)."), oltStr("EndVLAN", false, "Last VLAN ID; defaults to StartVLAN."), oltStr("Name", false, "VLAN description.")}, UI: OLTUI{Label: "Add VLAN", Group: "Network", Section: "QVLAN"}},
	{Path: WUSPOLTNetworkQVLANDeleteCommand, Effect: OLTEffectDisruptive, Description: "Delete a VLAN (refused for VLAN 1 and the VLAN the agent reaches the OLT through).", Inputs: []OLTArgDef{oltStr("ID", true, "VLAN ID.")}, UI: OLTUI{Label: "Delete VLAN", Group: "Network", Section: "QVLAN"}},
	{Path: WUSPOLTNetworkBackupConfigCommand, Effect: OLTEffectNone, Description: "Return the running configuration text.", Outputs: []OLTArgDef{{Name: "Config", Type: TypeString, Path: WUSPOLTPrefix + "Network.Config", Description: "Running configuration text."}}, UI: OLTUI{Label: "Back up network configuration", Group: "Network", Section: "Configuration"}},
	{Path: WUSPOLTSaveConfigCommand, Effect: OLTEffectConfig, Description: "Save the running configuration to flash (web UI Save button).", UI: OLTUI{Label: "Save configuration", Group: "Maintenance", Section: "Configuration"}},
	{Path: WUSPOLTDescribeControlsCommand, Effect: OLTEffectNone, Description: "Return the OLT control schema (JSON) the console renders controls from.", Outputs: []OLTArgDef{{Name: "ControlSchema", Type: TypeString, Path: WUSPOLTPrefix + "ControlSchema", Description: "Control schema JSON."}}, UI: OLTUI{Label: "Describe controls", Group: "System", Section: "Agent"}},
}

// WUSPOLTTableDefs annotates every multi-instance object of WUSPOLTObjects.
var WUSPOLTTableDefs = append(wuspOLTBaseTableDefs, oltPageTableDefs...)

var wuspOLTBaseTableDefs = []OLTTableDef{
	{Path: WUSPOLTPrefix + "PONPort.{i}.", Key: "Name", CountParam: WUSPOLTPrefix + "PONPortNumberOfEntries", UI: OLTUI{Label: "Ports", Group: "PON", Section: "Ports"}},
	{Path: WUSPOLTPrefix + "ONU.{i}.", Key: "Index", CountParam: WUSPOLTPrefix + "ONUNumberOfEntries", UI: OLTUI{Label: "ONUs", Group: "ONU", Section: "Status"}},
	{Path: WUSPOLTPrefix + "Alarms.{i}.", CountParam: WUSPOLTPrefix + "AlarmNumberOfEntries", UI: OLTUI{Label: "Alarms", Group: "System", Section: "Alarms"}},
	{Path: WUSPOLTPrefix + "Syslog.{i}.", CountParam: WUSPOLTPrefix + "SyslogNumberOfEntries", UI: OLTUI{Label: "System log", Group: "System", Section: "Log"}},
	{Path: WUSPOLTPrefix + "PageCache.{i}.", Key: "Name", CountParam: WUSPOLTPrefix + "PageCacheNumberOfEntries", UI: OLTUI{Label: "Page freshness", Group: "System", Section: "Agent"}},
	{Path: WUSPOLTPrefix + "LineProfile.{i}.", Key: "ID", CountParam: WUSPOLTPrefix + "LineProfileNumberOfEntries", UI: OLTUI{Label: "Line profiles", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "ProvisionedONU.{i}.", Key: "OnuID", CountParam: WUSPOLTPrefix + "ProvisionedONUNumberOfEntries", Addable: true, Deletable: true, AddArgs: []OLTArgDef{
		oltStr("OnuID", true, "ONU ID on the PON, e.g. 0/1/1."), oltStr("Mode", false, "Authentication mode: sn, password, mac."),
		oltStr("Info", false, "Serial number, password or MAC."), oltStr("LineID", false, "Line profile index."), oltStr("Desc", false, "Description."),
	}, AddCommand: WUSPOLTProvisionedONUAddCommand, DeleteCommand: WUSPOLTProvisionedONUDeleteCommand, UI: OLTUI{Label: "ONU authentication", Group: "ONU", Section: "Authentication"}},
	{Path: WUSPOLTPrefix + "LineProfile.Tcont.{i}.", Key: "TcontID", CountParam: WUSPOLTPrefix + "LineProfile.TcontNumberOfEntries", UI: OLTUI{Label: "Line profile T-CONTs", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "LineProfile.Gemport.{i}.", Key: "Gemport", CountParam: WUSPOLTPrefix + "LineProfile.GemportNumberOfEntries", UI: OLTUI{Label: "Line profile GEM ports", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "LineProfile.Mapping.{i}.", Key: "MappingIndex", CountParam: WUSPOLTPrefix + "LineProfile.MappingNumberOfEntries", UI: OLTUI{Label: "Line profile GEM mappings", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "LineProfile.Flow.{i}.", Key: "FlowIndex", CountParam: WUSPOLTPrefix + "LineProfile.FlowNumberOfEntries", UI: OLTUI{Label: "Line profile service flows", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "LineProfile.Multicast.{i}.", Key: "ONTPort", CountParam: WUSPOLTPrefix + "LineProfile.MulticastNumberOfEntries", UI: OLTUI{Label: "Line profile multicast", Group: "Profiles", Section: "Line"}},
	{Path: WUSPOLTPrefix + "Network.DNS.Server.{i}.", CountParam: WUSPOLTPrefix + "Network.DNS.ServerNumberOfEntries", UI: OLTUI{Label: "DNS servers", Group: "Network", Section: "DNS"}},
	{Path: WUSPOLTPrefix + "Network.ACL.{i}.", Key: "ID", CountParam: WUSPOLTPrefix + "Network.ACLNumberOfEntries", AddCommand: WUSPOLTNetworkACLAddCommand, DeleteCommand: WUSPOLTNetworkACLDeleteCommand, UI: OLTUI{Label: "ACL rules", Group: "Network", Section: "ACL"}},
	{Path: WUSPOLTPrefix + "Network.Route.{i}.", Key: "Destination", CountParam: WUSPOLTPrefix + "Network.RouteNumberOfEntries", AddCommand: WUSPOLTNetworkRouteAddCommand, DeleteCommand: WUSPOLTNetworkRouteDeleteCommand, UI: OLTUI{Label: "Static routes", Group: "Network", Section: "Route"}},
	{Path: WUSPOLTPrefix + "Network.QVLAN.{i}.", Key: "ID", CountParam: WUSPOLTPrefix + "Network.QVLANNumberOfEntries", AddCommand: WUSPOLTNetworkQVLANAddCommand, DeleteCommand: WUSPOLTNetworkQVLANDeleteCommand, UI: OLTUI{Label: "VLANs", Group: "Network", Section: "QVLAN"}},
}

var WUSPOLTObjects = append(wuspOLTBaseObjects, oltPageObjs...)

var wuspOLTBaseObjects = []Object{
	{Path: WUSPOLTPrefix, SinceVersion: "1.0", Description: "GPON OLT platform state, PON ports, and the ONUs this OLT manages."},
	{Path: WUSPOLTPrefix + "PONPort.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per PON/uplink port of the OLT."},
	{Path: WUSPOLTPrefix + "ONU.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per ONU known to this OLT."},
	{Path: WUSPOLTPrefix + "Alarms.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Recent device alarms."},
	{Path: WUSPOLTPrefix + "LineProfile.Tcont.{i}.", MultiInstance: true, SinceVersion: "1.1", Description: "T-CONTs of every line profile (getLineprofileTcontInfo per profile)."},
	{Path: WUSPOLTPrefix + "LineProfile.Gemport.{i}.", MultiInstance: true, SinceVersion: "1.1", Description: "GEM ports of every line profile (getLineprofileGemInfo per profile)."},
	{Path: WUSPOLTPrefix + "LineProfile.Mapping.{i}.", MultiInstance: true, SinceVersion: "1.1", Description: "GEM mappings of every line profile (getLineprofileMappingInfo per profile)."},
	{Path: WUSPOLTPrefix + "LineProfile.Flow.{i}.", MultiInstance: true, SinceVersion: "1.1", Description: "Service flows of every line profile (getLineprofileFlowInfo optype line per profile)."},
	{Path: WUSPOLTPrefix + "LineProfile.Multicast.{i}.", MultiInstance: true, SinceVersion: "1.1", Description: "Multicast settings of every line profile (getLineprofileMultInfo per profile)."},
	{Path: WUSPOLTPrefix + "Syslog.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Recent device log entries from the OLT log buffer."},
	{Path: WUSPOLTPrefix + "PageCache.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Per goform page: where the current values came from (helper, web, cached) and when they were last read."},
	{Path: WUSPOLTPrefix + "WebBudget.", SinceVersion: "1.0", Description: "Web UI traffic budget: background refresher interval and backoff."},
	{Path: WUSPOLTPrefix + "LineProfile.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "GPON line profiles configured on the OLT."},
	{Path: WUSPOLTPrefix + "ProvisionedONU.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "The ONU authentication table: provisioned ONUs the OLT accepts on its PON ports."},
	{Path: WUSPOLTPrefix + "Network.", SinceVersion: "1.0", Description: "OLT network state: management interface, DNS, NTP, ACL, routes."},
	{Path: WUSPOLTPrefix + "Network.Mgmt.", SinceVersion: "1.0", Description: "Management interface configuration."},
	{Path: WUSPOLTPrefix + "Network.DNS.", SinceVersion: "1.0", Description: "DNS resolver configuration."},
	{Path: WUSPOLTPrefix + "Network.DNS.Server.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "DNS nameserver table."},
	{Path: WUSPOLTPrefix + "Network.NTP.", SinceVersion: "1.0", Description: "NTP time sync configuration."},
	{Path: WUSPOLTPrefix + "Network.ACL.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "ACL (firewall) rule table."},
	{Path: WUSPOLTPrefix + "Network.Route.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Static route table."},
	{Path: WUSPOLTPrefix + "Network.QVLAN.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "QVLAN table: 802.1Q VLANs configured on the OLT."},
}

// AllWUSPOLTParams is the schema view of WUSPOLTParamDefs (what the
// registry, path codes, validation and GetSupportedDM consume).
var AllWUSPOLTParams = oltParamsFromDefs(WUSPOLTAllParamDefs)

// WUSPOLTAllParamDefs is the hand-written WUSPOLTParamDefs plus every
// parameter derived from the web-UI page specs (olt_spec.go).
var WUSPOLTAllParamDefs = append(append([]OLTParamDef{}, WUSPOLTParamDefs...), oltPageParamDefs()...)

var oltPageObjs, oltPageTableDefs = oltPageObjects()

// WUSPOLTParamDefs declares every Device.WUSP_OLT parameter together with
// its console metadata (units, grouping, side-effect class). Behavior
// (getter/setter against the OLT web API) is bound by path in
// internal/wusp/fiberolt; a cross-check test keeps both sides in sync.
var WUSPOLTParamDefs = []OLTParamDef{
	oltParam("Installed", TypeBoolean, ReadOnly, "True when the OLT fiber platform is detected on this device.", Limits{}),
	oltParam("Enable", TypeBoolean, ReadWrite, "Collect OLT telemetry and accept OLT control on this device.", Limits{}, oltLabel("Manage this OLT"), oltGroup("System", "Agent")),
	oltParam("Platform", TypeString, ReadOnly, "Platform family this backend speaks: olt.", Limits{MaxLength: 16}),
	oltParam("Status", TypeString, ReadOnly, "Collection status of the OLT backend.", Limits{Enums: []string{"not_installed", "disabled", "ok", "api_error", "login_error"}}),
	oltParam("StatusDetail", TypeString, ReadOnly, "Detail for the current status, empty when ok.", Limits{MaxLength: 256}),
	oltParam("LastCollectTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the last successful collection.", Limits{Min: iptr(0)}, oltUnits("unix-s"), oltGroup("System", "Agent")),
	// Web-traffic budget (fiberolt/webbudget.go): how each goform page was
	// obtained this cycle and the state of the slow web refresher.
	oltParam("PageCacheNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.PageCache.{i}.", Limits{Min: iptr(0)}, oltGroup("System", "Agent")),
	oltParam("PageCache.{i}.Name", TypeString, ReadOnly, "Source name (page:<goform path> for page specs).", Limits{MaxLength: 256}, oltGroup("System", "Agent")),
	oltParam("PageCache.{i}.Endpoint", TypeString, ReadOnly, "goform getter of the page (empty for derived sources).", Limits{MaxLength: 256}, oltGroup("System", "Agent")),
	oltParam("PageCache.{i}.Source", TypeString, ReadOnly, "Where this cycle's values came from: helper, web, cli, cached (last-known, stale) or none (never read yet).", Limits{Enums: []string{"helper", "web", "cli", "cached", "none"}}, oltGroup("System", "Agent")),
	oltParam("PageCache.{i}.LastRefreshed", TypeUnsignedInt, ReadOnly, "Unix seconds the values were last read from the device (0 = never).", Limits{Min: iptr(0)}, oltUnits("unix-s"), oltGroup("System", "Agent")),
	oltParam("PageCache.{i}.Objects", TypeString, ReadOnly, "Comma-separated Device.WUSP_OLT objects this page feeds.", Limits{MaxLength: 1024}, oltGroup("System", "Agent")),
	oltParam("WebBudget.Interval", TypeUnsignedInt, ReadOnly, "Seconds between background web page reads (one goform request each; 0 = never).", Limits{Min: iptr(0)}, oltUnits("s"), oltGroup("System", "Agent")),
	oltParam("WebBudget.BackoffUntil", TypeUnsignedInt, ReadOnly, "Unix seconds until which background web reads are paused after a web UI timeout (0 = not paused).", Limits{Min: iptr(0)}, oltUnits("unix-s"), oltGroup("System", "Agent")),
	oltParam("WebBudget.PendingPages", TypeUnsignedInt, ReadOnly, "Pages not served by the helper, waiting for a background web read.", Limits{Min: iptr(0)}, oltGroup("System", "Agent")),

	oltParam("PONPortNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.PONPort.{i}.", Limits{Min: iptr(0)}),
	oltParam("ONUNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.ONU.{i}.", Limits{Min: iptr(0)}),
	oltParam("AlarmNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.Alarms.{i}.", Limits{Min: iptr(0)}),

	oltParam("TotalONUs", TypeUnsignedInt, ReadOnly, "ONUs known to the OLT.", Limits{Min: iptr(0)}),
	oltParam("OnlineONUs", TypeUnsignedInt, ReadOnly, "ONUs currently online.", Limits{Min: iptr(0)}),

	oltParam("Temperature", TypeDecimal, ReadOnly, "Switch ASIC temperature in degrees Celsius.", Limits{}, oltUnits("°C"), oltGroup("System", "Health")),
	oltParam("PonTemperature", TypeDecimal, ReadOnly, "PON MAC temperature in degrees Celsius.", Limits{}, oltUnits("°C"), oltGroup("System", "Health")),
	oltParam("FanSpeed", TypeUnsignedInt, ReadOnly, "Fan speed in RPM, 0 when unknown or stopped.", Limits{Min: iptr(0)}, oltUnits("RPM"), oltGroup("System", "Health")),
	oltParam("CpuPercent", TypeUnsignedInt, ReadOnly, "CPU load in percent.", Limits{Min: iptr(0), Max: iptr(100)}, oltUnits("%"), oltGroup("System", "Health")),
	oltParam("MemoryPercent", TypeUnsignedInt, ReadOnly, "Memory load in percent.", Limits{Min: iptr(0), Max: iptr(100)}, oltUnits("%"), oltGroup("System", "Health")),
	oltParam("Uptime", TypeUnsignedInt, ReadOnly, "Seconds since the OLT booted.", Limits{Min: iptr(0)}, oltUnits("s"), oltGroup("System", "Health")),

	oltParam("SupportedOperations", TypeString, ReadOnly, "Comma-separated Operate commands available: Reboot, FactoryRestore, ONU.Reboot, ONU.Reset, ONU.Enable, ONU.Disable. They run only when requested, never on a timer.", Limits{MaxLength: 128}),
	oltParam("LastOperationStatus", TypeString, ReadOnly, "Result of the latest OLT Operate command.", Limits{Enums: []string{"", "Success", "Error"}}),
	oltParam("LastOperationCode", TypeString, ReadOnly, "Stable machine-readable code of the latest OLT Operate command.", Limits{MaxLength: 64}),
	oltParam("LastOperationMessage", TypeString, ReadOnly, "Short result detail of the latest OLT Operate command.", Limits{MaxLength: 256}),

	oltParam("PONPort.{i}.Name", TypeString, ReadOnly, "Port name, e.g. pon1 or ge3.", Limits{MaxLength: 16}),
	oltParam("PONPort.{i}.Type", TypeString, ReadOnly, "Port type: pon, ge or xge.", Limits{Enums: []string{"pon", "ge", "xge", "other"}}),
	oltParam("PONPort.{i}.Enable", TypeBoolean, ReadWrite, "Administrative enable of the port.", Limits{}),
	oltParam("PONPort.{i}.Status", TypeString, ReadOnly, "Link state of the port.", Limits{Enums: []string{"up", "down"}}),
	oltParam("PONPort.{i}.Speed", TypeUnsignedInt, ReadOnly, "Port speed in Mbps.", Limits{Min: iptr(0)}, oltUnits("Mbps")),
	oltParam("PONPort.{i}.OnlineONUs", TypeUnsignedInt, ReadOnly, "ONUs online on this PON port.", Limits{Min: iptr(0)}),
	oltParam("PONPort.{i}.TotalONUs", TypeUnsignedInt, ReadOnly, "ONUs known on this PON port.", Limits{Min: iptr(0)}),

	oltParam("ONU.{i}.Index", TypeString, ReadOnly, "ONT ID on the PON, e.g. 0/1/1.", Limits{MaxLength: 16}),
	oltParam("ONU.{i}.PONPort", TypeString, ReadOnly, "PON port the ONU hangs off, e.g. pon1.", Limits{MaxLength: 16}),
	oltParam("ONU.{i}.SerialNumber", TypeString, ReadOnly, "ONU vendor serial number.", Limits{MaxLength: 64}),
	oltParam("ONU.{i}.Model", TypeString, ReadOnly, "ONU model reported by the vendor, empty when unknown.", Limits{MaxLength: 64}),
	oltParam("ONU.{i}.Status", TypeString, ReadOnly, "Registration state of the ONU.", Limits{Enums: []string{"", "online", "offline", "unconfigured", "initial"}}),
	oltParam("ONU.{i}.RunState", TypeString, ReadOnly, "Run state of the ONU, e.g. working.", Limits{MaxLength: 32}),
	oltParam("ONU.{i}.Enable", TypeBoolean, ReadWrite, "Allow the ONU to stay active on the PON.", Limits{}, oltEffect(OLTEffectDisruptive)),
	oltParam("ONU.{i}.RxPower", TypeDecimal, ReadOnly, "ONU receive optical power in dBm as seen by the OLT.", Limits{}, oltUnits("dBm")),
	oltParam("ONU.{i}.TxPower", TypeDecimal, ReadOnly, "ONU transmit optical power in dBm as seen by the OLT.", Limits{}, oltUnits("dBm")),
	oltParam("ONU.{i}.Distance", TypeUnsignedInt, ReadOnly, "Fiber distance to the ONU in meters.", Limits{Min: iptr(0)}, oltUnits("m")),
	oltParam("ONU.{i}.UpTime", TypeUnsignedInt, ReadOnly, "Seconds the ONU has been online.", Limits{Min: iptr(0)}, oltUnits("s")),

	oltParam("Alarms.{i}.Time", TypeUnsignedInt, ReadOnly, "Unix seconds when the alarm was raised.", Limits{Min: iptr(0)}),
	oltParam("Alarms.{i}.Severity", TypeString, ReadOnly, "Alarm severity.", Limits{MaxLength: 16}),
	oltParam("Alarms.{i}.Message", TypeString, ReadOnly, "Alarm text.", Limits{MaxLength: 256}),

	oltParam("TemperatureAlarmHigh", TypeDecimal, ReadWrite, "High temperature alarm threshold in degrees Celsius (30..80).", Limits{MinF: fptr(30), MaxF: fptr(80)}, oltUnits("°C"), oltGroup("System", "Health")),
	oltParam("Config", TypeString, ReadOnly, "Result field of BackupConfig(): the running configuration text.", Limits{MaxLength: 1 << 20}),
	oltParam("ControlSchema", TypeString, ReadOnly, "Result field of DescribeControls(): the console control schema (JSON).", Limits{MaxLength: 1 << 22}, oltGroup("System", "Agent")),
	oltParam("AutoSave", TypeBoolean, ReadWrite, "Agent-local: save the running configuration (SaveConfig) shortly after every successful write. Default false.", Limits{}, oltLabel("Auto save"), oltGroup("System", "Agent")),
	oltParam("ControlSchemaVersion", TypeString, ReadOnly, "Version hash of the control schema; refetch with DescribeControls() when it changes.", Limits{MaxLength: 32}, oltGroup("System", "Agent")),
	oltParam("TemperatureAlarmLow", TypeDecimal, ReadWrite, "Low temperature alarm threshold in degrees Celsius (-30..0).", Limits{MinF: fptr(-30), MaxF: fptr(0)}, oltUnits("°C"), oltGroup("System", "Health")),

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

	oltParam("ONU.{i}.Voltage", TypeDecimal, ReadOnly, "ONU power feed voltage in volts as seen by the OLT.", Limits{}, oltUnits("V")),
	oltParam("ONU.{i}.BiasCurrent", TypeDecimal, ReadOnly, "ONU laser bias current in milliamps as seen by the OLT.", Limits{}, oltUnits("mA")),
	oltParam("ONU.{i}.Temperature", TypeDecimal, ReadOnly, "ONU temperature in degrees Celsius as seen by the OLT.", Limits{}, oltUnits("°C")),
	oltParam("ONU.{i}.ConfigState", TypeString, ReadOnly, "ONU configuration state, e.g. Normal.", Limits{MaxLength: 32}),
	oltParam("ONU.{i}.EthPortUp", TypeBoolean, ReadOnly, "True when the ONU's Ethernet port reports link up.", Limits{}),
	oltParam("ONU.{i}.LastDownCause", TypeString, ReadOnly, "Vendor reason of the last ONU down event (getOntListBrife downcause); absent while \"-\".", Limits{MaxLength: 64}),
	// Line profile detail tables (one row per profile item; ProfileID names the profile).
	oltParam("LineProfile.TcontNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.Tcont.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfile.Tcont.{i}.ProfileID", TypeString, ReadOnly, "Line profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Tcont.{i}.TcontID", TypeString, ReadOnly, "T-CONT ID (1-8).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Tcont.{i}.DBAProfile", TypeString, ReadOnly, "DBA profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.GemportNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.Gemport.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfile.Gemport.{i}.ProfileID", TypeString, ReadOnly, "Line profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Gemport.{i}.Gemport", TypeString, ReadOnly, "GEM port ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Gemport.{i}.TcontID", TypeString, ReadOnly, "T-CONT ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Gemport.{i}.QueueID", TypeString, ReadOnly, "Queue ID (-1 = not required).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Gemport.{i}.USProfile", TypeString, ReadOnly, "US profile ID (-1 = not required).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Gemport.{i}.DSProfile", TypeString, ReadOnly, "DS profile ID (-1 = not required).", Limits{MaxLength: 8}),
	oltParam("LineProfile.MappingNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.Mapping.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfile.Mapping.{i}.ProfileID", TypeString, ReadOnly, "Line profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Mapping.{i}.MappingIndex", TypeString, ReadOnly, "Mapping index.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Mapping.{i}.VLAN", TypeString, ReadOnly, "VLAN (1-4094 or transparent).", Limits{MaxLength: 16}),
	oltParam("LineProfile.Mapping.{i}.Gemport", TypeString, ReadOnly, "GEM port ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Mapping.{i}.MappingPort", TypeString, ReadOnly, "Mapped port type (0 none, 1 ETH, 2 VEIP, 3 IP-Host).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Mapping.{i}.MappingPortNum", TypeString, ReadOnly, "ETH port number.", Limits{MaxLength: 8}),
	oltParam("LineProfile.FlowNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.Flow.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfile.Flow.{i}.ProfileID", TypeString, ReadOnly, "Line profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Flow.{i}.FlowIndex", TypeString, ReadOnly, "Flow index.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Flow.{i}.Port", TypeString, ReadOnly, "ONT port (veip or 1-24).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Flow.{i}.FlowMode", TypeString, ReadOnly, "Flow mode (0 default vlan, 1 transparent, 2 translation, 3 keep).", Limits{MaxLength: 8}),
	oltParam("LineProfile.Flow.{i}.CVID", TypeString, ReadOnly, "Customer VLAN.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Flow.{i}.SVID", TypeString, ReadOnly, "Service VLAN.", Limits{MaxLength: 8}),
	oltParam("LineProfile.MulticastNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OLT.LineProfile.Multicast.{i}.", Limits{Min: iptr(0)}),
	oltParam("LineProfile.Multicast.{i}.ProfileID", TypeString, ReadOnly, "Line profile ID.", Limits{MaxLength: 8}),
	oltParam("LineProfile.Multicast.{i}.ONTPort", TypeString, ReadOnly, "ONT port.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.Mode", TypeString, ReadOnly, "Multicast mode.", Limits{MaxLength: 32}),
	oltParam("LineProfile.Multicast.{i}.VLAN", TypeString, ReadOnly, "Multicast VLAN.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.FastLeave", TypeString, ReadOnly, "Fast leave.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.MaxGroups", TypeString, ReadOnly, "Max groups.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.MaxBandwidth", TypeString, ReadOnly, "Max bandwidth.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.DsTagAction", TypeString, ReadOnly, "Downstream tag action.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.DsTagVLAN", TypeString, ReadOnly, "Downstream tag VLAN.", Limits{MaxLength: 16}),
	oltParam("LineProfile.Multicast.{i}.DsTagPriority", TypeString, ReadOnly, "Downstream tag priority.", Limits{MaxLength: 16}),

	// Network subsystem: management interface, DNS, NTP, ACL, routes.
	oltParam("Network.Mgmt.IPAddress", TypeString, ReadWrite, "Management interface IP address.", Limits{MaxLength: 32}, oltEffect(OLTEffectDisruptive)),
	oltParam("Network.Mgmt.SubnetMask", TypeString, ReadWrite, "Management interface subnet mask.", Limits{MaxLength: 32}, oltEffect(OLTEffectDisruptive)),
	oltParam("Network.Mgmt.Gateway", TypeString, ReadWrite, "Management interface default gateway.", Limits{MaxLength: 32}, oltEffect(OLTEffectDisruptive)),
	oltParam("Network.Mgmt.MACAddress", TypeString, ReadOnly, "Management interface MAC address.", Limits{MaxLength: 32}),
	oltParam("Network.Mgmt.VLAN", TypeString, ReadWrite, "Management VLAN ID.", Limits{MaxLength: 8}, oltEffect(OLTEffectDisruptive)),
	oltParam("Network.DNS.ServerNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of DNS nameservers.", Limits{Min: iptr(0)}),
	oltParam("Network.DNS.Server.{i}.Address", TypeString, ReadWrite, "DNS nameserver address.", Limits{MaxLength: 64}),
	oltParam("Network.NTP.Server", TypeString, ReadWrite, "NTP server hostname.", Limits{MaxLength: 128}),
	oltParam("Network.NTP.Enabled", TypeBoolean, ReadWrite, "NTP time synchronization enabled.", Limits{}),
	oltParam("Network.ACLNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of ACL rules.", Limits{Min: iptr(0)}),
	oltParam("Network.ACL.{i}.ID", TypeString, ReadOnly, "ACL ID (100-199 IPv4).", Limits{MaxLength: 16}),
	oltParam("Network.ACL.{i}.Name", TypeString, ReadOnly, "ACL remark.", Limits{MaxLength: 64}),
	oltParam("Network.ACL.{i}.Type", TypeString, ReadOnly, "ACL type (standard, extended).", Limits{MaxLength: 16}),
	oltParam("Network.RouteNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of static routes.", Limits{Min: iptr(0)}),
	oltParam("Network.Route.{i}.Destination", TypeString, ReadOnly, "Route destination.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Mask", TypeString, ReadOnly, "Route mask.", Limits{MaxLength: 32}),
	oltParam("Network.Route.{i}.Gateway", TypeString, ReadOnly, "Route next hop.", Limits{MaxLength: 32}),
	oltParam("Network.Config", TypeString, ReadOnly, "Result field of BackupNetworkConfig(): full network config.", Limits{MaxLength: 1 << 20}),

	// Q-VLANs: 802.1Q VLAN database on the OLT.
	oltParam("Network.QVLANNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of Q-VLAN entries.", Limits{Min: iptr(0)}),
	oltParam("Network.QVLAN.{i}.ID", TypeString, ReadOnly, "VLAN ID.", Limits{MaxLength: 8}),
	oltParam("Network.QVLAN.{i}.Name", TypeString, ReadOnly, "VLAN name.", Limits{MaxLength: 64}),
	oltParam("Network.QVLAN.{i}.StartVLAN", TypeString, ReadOnly, "Start of VLAN range.", Limits{MaxLength: 8}),
	oltParam("Network.QVLAN.{i}.EndVLAN", TypeString, ReadOnly, "End of VLAN range.", Limits{MaxLength: 8}),
}
