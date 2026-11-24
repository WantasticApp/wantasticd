package wusp

// Web-UI pages of the PON menu (see olt_spec.go).
//
// Already covered elsewhere and not repeated here: ONT List > List / Optical
// (ONU.{i}), ONT List > Auth Config (ProvisionedONU.{i}), the ONT bulk
// actions Active/Deactive/Reboot/FactoryReset (ONU.* commands).

var oltPONPorts = []string{"pon1", "pon2", "pon3", "pon4", "pon5", "pon6", "pon7", "pon8"}

// oltAutoAddRuleWrite is the setOntAutoAddConfig body of the Add dialog;
// the rule table and the AddRule()/DeleteRule() commands share it.
var oltAutoAddRuleBody = []string{"index", "name", "type", "param", "portbinding", "lineprofile", "autounique"}

var oltAutoAddRuleTable = OLTTable{
	Object: "PON.AutoAdd.Rule",
	Get:    OLTCall{Path: "/goform/getOntAutoAddConfig"},
	Key:    []string{"index"},
	Label:  "ONT auto-add rules",
	Help:   "Param must be \"Null\" unless Type is EQUIPMENT-ID (the web UI forces it).",
	Edit: &OLTWrite{
		Path:   "/goform/setOntAutoAddConfig",
		Body:   oltAutoAddRuleBody,
		Extra:  map[string]any{"action": "edit"},
		Origin: "empty",
	},
	Add: &OLTWrite{
		Path:  "/goform/setOntAutoAddConfig",
		Body:  oltAutoAddRuleBody,
		Extra: map[string]any{"action": "add", "originData": map[string]any{}},
	},
	Delete: &OLTWrite{Path: "/goform/delOntAutoAddConfig"},
	Columns: []OLTField{
		{Leaf: "Index", Vendor: "index", Required: true, Min: i64(0), Max: i64(1023), Label: "Rule index", Help: "0-1023; fixed once created."},
		{Leaf: "Name", Vendor: "name", Write: true, Required: true, MaxLength: 32, Label: "Rule name"},
		// The device stores and reports the type in upper case ("ALL-ONT");
		// the web UI's own Add default posts "ALL-ONT" too.
		{Leaf: "Type", Vendor: "type", Write: true, Required: true, Label: "Match type",
			Enum: []string{"ALL-ONT", "ALL-HGU", "ALL-SFU", "EQUIPMENT-ID"}, EnumLabels: []string{"All ONTs", "All HGUs", "All SFUs", "Equipment ID"}},
		{Leaf: "Param", Vendor: "param", Write: true, MaxLength: 32, Label: "Equipment ID", Help: "Equipment ID to match (Type EQUIPMENT-ID); \"Null\" otherwise."},
		{Leaf: "PortBinding", Vendor: "portbinding", Write: true, Required: true, Label: "Port binding",
			Enum: append(append([]string{}, oltPONPorts...), "all"), EnumLabels: append(append([]string{}, oltPONPorts...), "all")},
		{Leaf: "LineProfile", Vendor: "lineprofile", Write: true, Required: true, MaxLength: 8, Label: "Line profile", Help: "Line profile ID (LineProfile.{i}.ID)."},
		{Leaf: "AutoUnique", Vendor: "autounique", Codec: "bool01", Write: true, Required: true, Label: "Auto unique"},
	},
}

// oltPONPortTable is the PON port settings page (getPonPortBasicList /
// setPonPortBasicInfo). The vendor dialog posts every field, "-1" meaning
// "no change", and port:[portName]; each writable column posts exactly
// that: its own value plus "-1" for the others.
var oltPONPortTable = OLTTable{
	Object: "PON.Port",
	Get:    OLTCall{Path: "/goform/getPonPortBasicList"},
	Key:    []string{"portName"},
	Label:  "PON port settings",
	Help:   "Per-PON-port admin state, auto-find, P2P, auto-auth and auth mode (setPonPortBasicInfo). The vendor's single-row Edit dialog opens every select at -1 (no change) and posts port:[portName]; a write here posts the changed field and -1 for the others, exactly that body.",
	Columns: []OLTField{
		{Leaf: "Name", Vendor: "portName", MaxLength: 16, Label: "Port"},
		{Leaf: "PortNum", Vendor: "portNum", Codec: "uint", Label: "Port number"},
		{Leaf: "Enable", Vendor: "portstate", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "Port state",
			Help: "Administrative enable of the PON port; disabling drops every ONT on it.", Set: ponPortSet("portstate")},
		{Leaf: "Status", Vendor: "portStatus", MaxLength: 16, Label: "Link status"},
		{Leaf: "AutoFind", Vendor: "autofind", Codec: "bool01", Write: true, Label: "Auto find", Set: ponPortSet("autofind")},
		{Leaf: "P2P", Vendor: "p2p", Codec: "bool01", Write: true, Label: "P2P", Set: ponPortSet("p2p")},
		{Leaf: "AutoAuth", Vendor: "autoauth", Codec: "bool01", Write: true, Label: "Auto auth", Set: ponPortSet("autoauth")},
		{Leaf: "AuthMode", Vendor: "authmode", Write: true, Effect: OLTEffectDisruptive, Label: "Auth mode",
			Help:       "ONT authentication mode of the port; changing it can de-authorize ONTs.",
			Enum:       []string{"0", "1", "2", "3", "4", "5", "6"},
			EnumLabels: []string{"adaptive", "loid-password", "mac-or-loid-password", "loid", "mac-or-loid", "mac", "auto"},
			Set:        ponPortSet("authmode")},
		{Leaf: "LoopDetect", Vendor: "loopdetect", MaxLength: 16, Label: "Loop detect"},
		{Leaf: "LoopbackShutdown", Vendor: "loopbackshutdown", MaxLength: 16, Label: "Loopback shutdown"},
		{Leaf: "PowerLimit", Vendor: "powerlimit", MaxLength: 16, Label: "Power limit"},
	},
}

var ponPortFields = []string{"portstate", "autofind", "p2p", "autoauth", "authmode", "powerlimit", "loopbackdetect", "loopbackshutdown"}

// ponPortSet posts one setPonPortBasicInfo field; every other field is "-1".
func ponPortSet(field string) *OLTWrite {
	extra := map[string]any{}
	for _, f := range ponPortFields {
		if f != field {
			extra[f] = "-1"
		}
	}
	return &OLTWrite{Path: "/goform/setPonPortBasicInfo", Body: []string{field}, Extra: extra, Port: "name"}
}

var oltPagesPON = []OLTPage{
	{
		Route: "/gpon/ponport/basic", Title: "PON Port > Basic", Group: "PON", Section: "Port",
		Tables: []OLTTable{oltPONPortTable},
	},
	{
		Route: "/gpon/ontlist/version", Title: "ONT List > Version", Group: "PON", Section: "ONTVersion",
		Tables: []OLTTable{{
			Object: "PON.ONTVersion",
			Get:    OLTCall{Path: "/goform/getOntListVersion", Params: map[string]string{"PonPortName": "all"}},
			Key:    []string{"onuid"},
			Label:  "ONT versions",
			Columns: []OLTField{
				{Leaf: "OnuID", Vendor: "onuid", MaxLength: 16, Label: "ONT"},
				{Leaf: "SerialNumber", Vendor: "sn", MaxLength: 32, Label: "SN"},
				{Leaf: "Status", Vendor: "status", MaxLength: 16, Label: "Status"},
				{Leaf: "EquipmentID", Vendor: "equipid", MaxLength: 64, Label: "Equipment ID"},
				{Leaf: "Vendor", Vendor: "vendor", MaxLength: 16, Label: "Vendor ID"},
				{Leaf: "Firmware", Vendor: "firmware", MaxLength: 64, Label: "Firmware version"},
				{Leaf: "ActiveSoftware", Vendor: "software1", MaxLength: 64, Label: "Active software"},
				{Leaf: "InactiveSoftware", Vendor: "software2", MaxLength: 64, Label: "Inactive software"},
			},
		}},
	},
	{
		Route: "/gpon/ontlist/mac", Title: "ONT List > MAC", Group: "PON", Section: "ONTMAC",
		Tables: []OLTTable{{
			Object: "PON.ONTMAC",
			Get:    OLTCall{Path: "/goform/getOntListMac", Params: map[string]string{"PonPortName": "all"}},
			Key:    []string{"mac", "vlan", "onuid"},
			Label:  "MAC addresses learned behind ONTs",
			Columns: []OLTField{
				{Leaf: "MACAddress", Vendor: "mac", MaxLength: 32, Label: "MAC address"},
				{Leaf: "VLAN", Vendor: "vlan", MaxLength: 8, Label: "VLAN"},
				{Leaf: "OnuID", Vendor: "onuid", MaxLength: 16, Label: "ONT"},
				{Leaf: "SerialNumber", Vendor: "sn", MaxLength: 32, Label: "SN"},
				{Leaf: "GEMIndex", Vendor: "gemidx", MaxLength: 8, Label: "GEM index"},
				{Leaf: "GEMID", Vendor: "gemid", MaxLength: 8, Label: "GEM ID"},
			},
		}},
	},
	{
		Route: "/gpon/ontautofind/brief", Title: "ONT Auto-find > List", Group: "PON", Section: "AutoFind",
		Tables: []OLTTable{{
			Object: "PON.AutoFind.List",
			Get:    OLTCall{Path: "/goform/getOntAutoFindBrife", Params: map[string]string{"PonPortName": "all"}},
			Key:    []string{"port", "index"},
			Label:  "Discovered (unauthorized) ONTs",
			Help:   "ONTs seen on the PONs but not authorized. Authorize them with ProvisionedONU Add or an auto-add rule.",
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "port", MaxLength: 16, Label: "Port"},
				{Leaf: "Index", Vendor: "index", MaxLength: 8, Label: "Index"},
				{Leaf: "SerialNumber", Vendor: "sn", MaxLength: 32, Label: "SN"},
				{Leaf: "EquipmentID", Vendor: "eid", MaxLength: 64, Label: "Equipment ID"},
				{Leaf: "LastFind", Vendor: "lastfind", MaxLength: 32, Label: "Last find"},
				{Leaf: "FindCount", Vendor: "findcnt", Codec: "uint", Label: "Find count"},
				{Leaf: "Reason", Vendor: "reason", MaxLength: 64, Label: "Reason"},
			},
		}},
	},
	{
		Route: "/gpon/ontautofind/config", Title: "ONT Auto-find > Config", Group: "PON", Section: "AutoFind",
		Tables: []OLTTable{{
			Object: "PON.AutoFind.Config",
			Get:    OLTCall{Path: "/goform/getOntAutoFindConfig"},
			Key:    []string{"portNum"},
			Label:  "Auto-find per PON port",
			// {find, age, interval, agetime, mindistance, maxdistance,
			//  portNum, port:[portNum], action:"edit", originData:<row>}
			Edit: &OLTWrite{
				Path:   "/goform/setOntAutoFindConfig",
				Body:   []string{"portNum", "find", "age", "interval", "agetime", "mindistance", "maxdistance"},
				Extra:  map[string]any{"action": "edit"},
				Origin: "row",
				Port:   "num",
			},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portNum", MaxLength: 16, Label: "Port"},
				{Leaf: "FindEnable", Vendor: "find", Codec: "bool01", Write: true, Label: "Find"},
				{Leaf: "Interval", Vendor: "interval", Codec: "uint", Write: true, Min: i64(20), Max: i64(30), Units: "s", Label: "Interval"},
				{Leaf: "AgeEnable", Vendor: "age", Codec: "bool01", Write: true, Label: "Age"},
				{Leaf: "AgeTime", Vendor: "agetime", Codec: "uint", Write: true, Min: i64(1), Max: i64(86400), Units: "s", Label: "Age time"},
				{Leaf: "MinDistance", Vendor: "mindistance", Codec: "uint", Write: true, Min: i64(0), Max: i64(40), Units: "km", Label: "Distance min"},
				{Leaf: "MaxDistance", Vendor: "maxdistance", Codec: "uint", Write: true, Min: i64(0), Max: i64(60), Effect: OLTEffectDisruptive, Units: "km", Label: "Distance max",
					Help: "ONTs beyond this distance are not discovered/registered."},
			},
		}},
	},
	{
		Route: "/gpon/ontautoadd/config", Title: "ONT Auto-Add > List", Group: "PON", Section: "AutoAdd",
		Tables: []OLTTable{
			{
				// getOntAutoAddEnable answers {list:[{globalswitch}]}: one
				// row. Written through PON.AutoAdd.SetEnable().
				Object: "PON.AutoAdd.Global",
				Get:    OLTCall{Path: "/goform/getOntAutoAddEnable"},
				Label:  "ONT auto-add global switch",
				Columns: []OLTField{
					{Leaf: "Enable", Vendor: "globalswitch", Codec: "bool01", Label: "Enable ONT auto-add"},
				},
			},
			oltAutoAddRuleTable,
		},
		Actions: []OLTAction{
			{
				Command: "PON.AutoAdd.SetEnable()",
				Label:   "Enable/disable ONT auto-add",
				Help:    "setOntAutoAddEnable {globalswitch}: turn automatic authorization of discovered ONTs on or off.",
				Write:   OLTWrite{Path: "/goform/setOntAutoAddEnable", Body: []string{"globalswitch"}},
				Inputs: []OLTField{
					{Leaf: "Enable", Vendor: "globalswitch", Codec: "bool01", Required: true, Label: "Enable"},
				},
			},
			{
				Command: "PON.AutoAdd.AddRule()",
				Label:   "Add ONT auto-add rule", Effect: OLTEffectConfig,
				Help:  "setOntAutoAddConfig {index, name, type, param, portbinding, lineprofile, autounique, action:add, originData:{}} - the Add dialog.",
				Write: *oltAutoAddRuleTable.Add,
				Inputs: []OLTField{
					{Leaf: "Index", Vendor: "index", Required: true, Min: i64(0), Max: i64(1023), Label: "Rule index (0-1023)"},
					{Leaf: "Name", Vendor: "name", Required: true, MaxLength: 32, Label: "Rule name"},
					{Leaf: "Type", Vendor: "type", Required: true, Label: "Match type", Enum: []string{"ALL-ONT", "ALL-HGU", "ALL-SFU", "EQUIPMENT-ID"}},
					{Leaf: "Param", Vendor: "param", Required: true, MaxLength: 32, Label: "Equipment ID, or Null"},
					{Leaf: "PortBinding", Vendor: "portbinding", Required: true, Label: "PON port (pon1..pon8) or all"},
					{Leaf: "LineProfile", Vendor: "lineprofile", Required: true, MaxLength: 8, Label: "Line profile ID"},
					{Leaf: "AutoUnique", Vendor: "autounique", Codec: "bool01", Required: true, Label: "Auto unique"},
				},
			},
			{
				Command: "PON.AutoAdd.DeleteRule()",
				Label:   "Delete ONT auto-add rule", Effect: OLTEffectDestructive,
				Help:  "delOntAutoAddConfig {list:[rule row]} for the rule named by Index.",
				Write: OLTWrite{Path: "/goform/delOntAutoAddConfig"},
				Rows:  &oltAutoAddRuleTable,
			},
		},
	},
	{
		Route: "/gpon/ontautodel/config", Title: "ONT Auto-Del > List", Group: "PON", Section: "AutoDelete",
		Tables: []OLTTable{{
			// Enable is destructive (offline ONTs get deleted): read-only
			// here, changed only through the SetPort/EnableAll commands.
			Object: "PON.AutoDelete.Config",
			Get:    OLTCall{Path: "/goform/getOntAutoDelConfig"},
			Key:    []string{"portnum"},
			Label:  "ONT auto-delete per PON port",
			Edit: &OLTWrite{
				Path:   "/goform/setOntAutoDelConfig",
				Body:   []string{"portnum", "enable", "timeout", "trigger"},
				Extra:  map[string]any{"action": "edit"},
				Origin: "empty",
			},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portnum", MaxLength: 16, Label: "Port"},
				{Leaf: "Enable", Vendor: "enable", Codec: "bool01", Label: "Auto delete"},
				{Leaf: "Timeout", Vendor: "timeout", Codec: "uint", Write: true, Min: i64(5), Max: i64(525600), Units: "min", Label: "Timeout", Help: "Offline minutes before an ONT is deleted (5-525600)."},
				{Leaf: "Trigger", Vendor: "trigger", Codec: "uint", Write: true, Min: i64(1), Max: i64(128), Label: "Trigger number", Help: "Number of offline ONTs that triggers deletion (1-128)."},
				{Leaf: "CurrentSum", Vendor: "sum", Codec: "uint", Label: "Current sum"},
			},
		}},
		Actions: []OLTAction{
			{
				Command: "PON.AutoDelete.SetPort()",
				Label:   "Configure auto-delete on one port", Effect: OLTEffectDestructive,
				Help:  "setOntAutoDelConfig for one PON port (row edit). Enabling deletes ONTs offline longer than Timeout.",
				Write: OLTWrite{Path: "/goform/setOntAutoDelConfig", Body: []string{"portnum", "enable", "timeout", "trigger"}, Extra: map[string]any{"action": "edit", "originData": map[string]any{}}},
				Inputs: []OLTField{
					{Leaf: "Port", Vendor: "portnum", Required: true, MaxLength: 16, Label: "Port"},
					{Leaf: "Enable", Vendor: "enable", Codec: "bool01", Required: true, Label: "Auto delete"},
					{Leaf: "Timeout", Vendor: "timeout", Codec: "uint", Required: true, Min: i64(5), Max: i64(525600), Units: "min", Label: "Timeout (5-525600 min)"},
					{Leaf: "Trigger", Vendor: "trigger", Codec: "uint", Required: true, Min: i64(1), Max: i64(128), Label: "Trigger number (1-128)"},
				},
			},
			{
				Command: "PON.AutoDelete.EnableAll()",
				Label:   "Enable auto-delete on all ports", Effect: OLTEffectDestructive,
				Help:  "Enable All: {portnum:all, enable:1, timeout:1440, trigger:128}; resets every port's timeout/trigger to the defaults.",
				Write: OLTWrite{Path: "/goform/setOntAutoDelConfig", Extra: map[string]any{"portnum": "all", "enable": "1", "timeout": "1440", "trigger": "128"}},
			},
			{
				Command: "PON.AutoDelete.DisableAll()",
				Label:   "Disable auto-delete on all ports",
				Help:    "Disable All: {portnum:all, enable:0, timeout:1440, trigger:128}; resets every port's timeout/trigger to the defaults.",
				Write:   OLTWrite{Path: "/goform/setOntAutoDelConfig", Extra: map[string]any{"portnum": "all", "enable": "0", "timeout": "1440", "trigger": "128"}},
			},
		},
	},
	{
		// The image itself is uploaded with a multipart form to
		// /cgi-bin/uploadImage (not expressible as a spec; not exposed).
		Route: "/gpon/ontupgrade/image", Title: "ONT Upgrade > Load Image", Group: "PON", Section: "Upgrade",
		Tables: []OLTTable{{
			Object: "PON.Upgrade.Image",
			Get:    OLTCall{Path: "/goform/getOntUpgradeImage"},
			Key:    []string{"fname"},
			Label:  "ONT firmware images on the OLT",
			Delete: &OLTWrite{Path: "/goform/delOntUpgradeImage"},
			Columns: []OLTField{
				{Leaf: "FileName", Vendor: "fname", MaxLength: 128, Label: "File name"},
				{Leaf: "Size", Vendor: "size", Codec: "uint", Units: "kB", Label: "Size"},
				{Leaf: "CreationTime", Vendor: "ctime", MaxLength: 32, Label: "Creation time"},
			},
		}},
	},
	{
		// The ONU picker is the PON.ONTVersion table (same getter).
		Route: "/gpon/ontupgrade/op", Title: "ONT Upgrade > Upgrade Operation", Group: "PON", Section: "Upgrade",
		Actions: []OLTAction{{
			Command: "PON.Upgrade.Start()",
			Label:   "Upgrade ONTs", Effect: OLTEffectDestructive,
			Help:  "setOntUpgradeOp {fname, ontlist, action:add}: flash the image on the listed ONTs (they reboot). Progress in PON.Upgrade.Status.",
			Write: OLTWrite{Path: "/goform/setOntUpgradeOp", Body: []string{"fname", "ontlist"}, Extra: map[string]any{"action": "add"}},
			Inputs: []OLTField{
				{Leaf: "ONTList", Vendor: "ontlist", Required: true, MaxLength: 4096, Label: "ONT IDs", Help: "Comma-separated ONT IDs, e.g. 0/1/1,0/1/2."},
				{Leaf: "FileName", Vendor: "fname", Required: true, MaxLength: 128, Label: "Image file name", Help: "A PON.Upgrade.Image FileName."},
			},
		}},
	},
	{
		Route: "/gpon/ontupgrade/status", Title: "ONT Upgrade > Upgrade Status", Group: "PON", Section: "Upgrade",
		Tables: []OLTTable{{
			Object: "PON.Upgrade.Status",
			Get:    OLTCall{Path: "/goform/getOntUpgradeOp", Params: map[string]string{"PonPortName": "all"}},
			Key:    []string{"onuid"},
			Label:  "ONT upgrade status",
			Delete: &OLTWrite{Path: "/goform/delOntUpgradeState"},
			Columns: []OLTField{
				{Leaf: "OnuID", Vendor: "onuid", MaxLength: 16, Label: "ONT"},
				{Leaf: "ActiveVersion", Vendor: "ver1", MaxLength: 64, Label: "Active version"},
				{Leaf: "InactiveVersion", Vendor: "ver2", MaxLength: 64, Label: "Inactive version"},
				{Leaf: "Progress", Vendor: "progress", MaxLength: 16, Label: "Progress"},
				{Leaf: "Result", Vendor: "result", MaxLength: 64, Label: "Result"},
			},
		}},
	},
	{
		Route: "/gpon/ontrogue/brief", Title: "ONT Rogue-Detect", Group: "PON", Section: "Rogue",
		Tables: []OLTTable{{
			Object: "PON.Rogue.Config",
			Get:    OLTCall{Path: "/goform/getOntRogueConfig"},
			Key:    []string{"port"},
			Label:  "Rogue ONT detection per PON port",
			// {port, enable, interval, action} - no add/edit wrapper;
			// "action" is the rogue action value.
			Edit: &OLTWrite{Path: "/goform/setOntRogueConfig", Body: []string{"port", "enable", "interval", "action"}},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "port", MaxLength: 16, Label: "Port"},
				{Leaf: "Enable", Vendor: "enable", Write: true, Label: "Enable", Enum: []string{"enable", "disable"}, EnumLabels: []string{"Enable", "Disable"}},
				{Leaf: "Type", Vendor: "type", MaxLength: 32, Label: "Type"},
				// Reads 0 while detection is disabled; the UI accepts 1-3600.
				{Leaf: "Interval", Vendor: "interval", Codec: "uint", Write: true, Min: i64(0), Max: i64(3600), Units: "s", Label: "Interval",
					Help: "Detection interval 1-3600 s (0 is reported while detection is disabled)."},
				{Leaf: "Action", Vendor: "action", Write: true, Effect: OLTEffectDisruptive, Label: "Action",
					Help: "What to do with a detected rogue ONT: none, reboot or disable it.",
					Enum: []string{"none", "reboot", "disable"}, EnumLabels: []string{"None", "Reboot", "Disable"}},
				{Leaf: "DetectCount", Vendor: "d_cnt", Codec: "uint", Label: "Detect counter"},
				{Leaf: "SuspectCount", Vendor: "s_cnt", Codec: "uint", Label: "Suspect counter"},
			},
		}},
		Actions: []OLTAction{
			{
				Command: "PON.Rogue.EnableAll()",
				Label:   "Enable rogue detection on all ports",
				Help:    "Enable All: {port:all, enable:enable, interval:60, action:none}; resets interval and action on every port.",
				Write:   OLTWrite{Path: "/goform/setOntRogueConfig", Extra: map[string]any{"port": "all", "enable": "enable", "interval": "60", "action": "none"}},
			},
			{
				Command: "PON.Rogue.DisableAll()",
				Label:   "Disable rogue detection on all ports",
				Help:    "Disable All: {port:all, enable:disable, interval:60, action:none}; resets interval and action on every port.",
				Write:   OLTWrite{Path: "/goform/setOntRogueConfig", Extra: map[string]any{"port": "all", "enable": "disable", "interval": "60", "action": "none"}},
			},
		},
	},
	{
		Route: "(none - orphan chunk 116, module 669)", Title: "ServiceProfile multicast VLAN (legacy EPON, hidden)",
		Unsupported: "orphan legacy EPON chunk, not routed; its getters goform/getSrvprofileList and goform/getSrvprofileOne have no backend handler on firmware 1.1.3.18 (errCode 106)",
	},
}
