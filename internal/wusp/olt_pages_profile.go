package wusp

import "strings"

// Web-UI pages of the Profile menu (see olt_spec.go).
//
// Notes:
//   - Line and Unique profile rows cannot be edited per column: the getter
//     reports traffic_mode / refMultProfileId "-20" / refWifiProfileId "-20"
//     while the setter wants trafficmode / "None", so a row re-post would
//     corrupt the untouched fields. Edits are Operate commands that post the
//     whole dialog (all inputs required), like the UI does.
//   - Line profile detail (T-CONT, GEM port, mapping, flow, multicast,
//     MAC limit) getters need a profileid, so the per-profile tables are
//     not read; the Add buttons are Operate commands with a ProfileID input.
//     Their deletes post {list:[row+profileid(+optype)]}, which an Operate
//     command cannot build yet, so they are not exposed.

var dbaTypeEnum = []string{"1", "2", "3", "4", "5"}
var dbaTypeLabels = []string{"type1 (fixed)", "type2 (assured)", "type3 (assured+max)", "type4 (max)", "type5 (fixed+assured+max)"}

// profileCommands derives the Create()/Delete() Operate commands of a
// profile table from its Add/Delete writes: Create posts the Add dialog
// body (inputs = the Add columns), Delete posts {list:[row]} for the row
// named by Index. Tables with a bind column refuse to delete a profile
// that ONTs still reference (guard profileBind).
func profileCommands(t *OLTTable, bound bool) []OLTAction {
	var inputs []OLTField
	for _, c := range t.Columns {
		key := c.Vendor
		if c.SetKey != "" {
			key = c.SetKey
		}
		for _, b := range t.Add.Body {
			if set, _ := OLTBodyKey(b); set == key || set == c.Vendor {
				in := c
				in.Vendor = key
				in.Write, in.Set = false, nil
				inputs = append(inputs, in)
			}
		}
	}
	del := *t.Delete
	if bound {
		del.Guard = "profileBind"
	}
	return []OLTAction{
		{
			Command: t.Object + ".Create()", Label: "Create " + strings.ToLower(t.Label), Effect: OLTEffectConfig,
			Help:   "Same request as the table Add: " + t.Add.Path + " action add.",
			Write:  *t.Add,
			Inputs: inputs,
		},
		{
			Command: t.Object + ".Delete()", Label: "Delete " + strings.ToLower(t.Label), Effect: OLTEffectDestructive,
			Help:  "Same request as the table Delete: " + t.Delete.Path + " {list:[row]} for the profile named by Index" + map[bool]string{true: "; refused while the profile's Bind count is above 0.", false: "."}[bound],
			Write: del,
			Rows:  t,
		},
	}
}

// profilePage wraps one profile table with its Create()/Delete() commands.
func profilePage(route, title string, t OLTTable, bound bool) OLTPage {
	tbl := t
	if bound {
		d := *tbl.Delete
		d.Guard = "profileBind"
		tbl.Delete = &d
	}
	return OLTPage{Route: route, Title: title, Tables: []OLTTable{tbl}, Actions: profileCommands(&tbl, bound)}
}

// rateProfilePage is the US/DS traffic profile page (same shape).
func rateProfilePage(route, title, object, getPath, setPath, delPath string, rateMax, burstMax int64) OLTPage {
	body := []string{"profileid", "profilename", "cir", "cbs", "pir", "pbs"}
	return profilePage(route, title, OLTTable{
		Object: object,
		Get:    OLTCall{Path: getPath},
		Key:    []string{"profileid"},
		Label:  title,
		Add:    &OLTWrite{Path: setPath, Body: body, Extra: map[string]any{"action": "add", "originData": map[string]any{}}},
		Edit:   &OLTWrite{Path: setPath, Body: body, Extra: map[string]any{"action": "edit"}, Origin: "empty"},
		Delete: &OLTWrite{Path: delPath},
		Columns: []OLTField{
			{Leaf: "ID", Vendor: "profileid", Required: true, Min: i64(0), Max: i64(127), Label: "Profile ID"},
			{Leaf: "Name", Vendor: "profilename", Write: true, Required: true, MaxLength: 32, Label: "Profile name"},
			{Leaf: "CIR", Vendor: "cir", Write: true, Required: true, Min: i64(64), Max: i64(rateMax), Units: "kbps", Label: "CIR"},
			{Leaf: "CBS", Vendor: "cbs", Write: true, Required: true, Min: i64(2), Max: i64(burstMax), Units: "kB", Label: "CBS"},
			{Leaf: "PIR", Vendor: "pir", Write: true, Required: true, Min: i64(64), Max: i64(rateMax), Units: "kbps", Label: "PIR"},
			{Leaf: "PBS", Vendor: "pbs", Write: true, Required: true, Min: i64(2), Max: i64(burstMax), Units: "kB", Label: "PBS"},
			{Leaf: "Bind", Vendor: "bind", Label: "Bound ONTs"},
		},
	}, true)
}

// idNameProfilePage is the Multicast/WiFi profile list (id + name). The
// getter has no bind count, so Delete cannot check for references.
func idNameProfilePage(route, title, object, getPath, setPath, delPath string) OLTPage {
	body := []string{"profileId", "profilename"}
	return profilePage(route, title, OLTTable{
		Object: object,
		Get:    OLTCall{Path: getPath},
		Key:    []string{"profileId"},
		Label:  title,
		Help:   "Name must be unique and must not start with INDEX_.",
		Add:    &OLTWrite{Path: setPath, Body: body, Extra: map[string]any{"action": "add", "originData": map[string]any{}}},
		Edit:   &OLTWrite{Path: setPath, Body: body, Extra: map[string]any{"action": "edit"}, Origin: "empty"},
		Delete: &OLTWrite{Path: delPath},
		Columns: []OLTField{
			{Leaf: "ID", Vendor: "profileId", Required: true, Min: i64(0), Max: i64(127), Label: "Profile ID"},
			{Leaf: "Name", Vendor: "profilename", Write: true, Required: true, MaxLength: 32, Label: "Profile name"},
		},
	}, false)
}

func lineDetailAdd(cmd, label, item string, body []string, inputs []OLTField) OLTAction {
	return OLTAction{
		Command: cmd, Label: label,
		Help:   "setLineprofile item \"" + item + "\", action add, originData {} (line profile detail tab).",
		Write:  OLTWrite{Path: "/goform/setLineprofile", Body: append(body, "profileid"), Extra: map[string]any{"item": item, "action": "add", "originData": map[string]any{}}},
		Inputs: append([]OLTField{{Leaf: "ProfileID", Vendor: "profileid", Required: true, Label: "Line profile ID"}}, inputs...),
	}
}

var oltLineProfileTable = OLTTable{
	Object: "Profile.Line",
	Get:    OLTCall{Path: "/goform/getLineprofileList"},
	Key:    []string{"profileid"},
	Label:  "Line profiles",
	Help:   "Edit with Profile.Line.Edit(); profile 0 (default) cannot be deleted.",
	Add: &OLTWrite{Path: "/goform/setLineprofile", Body: []string{"profileid", "profilename", "onttype", "trafficmode", "refMultProfileId"},
		Extra: map[string]any{"item": "refmult", "action": "add", "originData": map[string]any{}}},
	Delete: &OLTWrite{Path: "/goform/delLineprofile", Guard: "profileBind"},
	Columns: []OLTField{
		{Leaf: "ID", Vendor: "profileid", Required: true, Min: i64(0), Max: i64(2047), Label: "Profile ID"},
		{Leaf: "Name", Vendor: "profilename", Required: true, MaxLength: 32, Label: "Profile name"},
		{Leaf: "ONTType", Vendor: "onttype", Required: true, Enum: []string{"adaptive", "hgu", "sfu"}, Label: "ONT type"},
		{Leaf: "MappingMode", Vendor: "mapping_mode", Label: "Mapping mode"},
		{Leaf: "TrafficMode", Vendor: "traffic_mode", SetKey: "trafficmode", Required: true, Enum: []string{"car", "queue"}, Label: "Traffic mode"},
		{Leaf: "RefMulticastProfile", Vendor: "refMultProfileId", Required: true, Label: "Referenced multicast profile",
			Help: "Multicast profile ID, or None. Reads -20 when none."},
		{Leaf: "Bind", Vendor: "bind", Label: "Bound ONTs"},
	},
}

var oltDBAProfileTable = OLTTable{
	Object: "Profile.DBA",
	Get:    OLTCall{Path: "/goform/getDbaprofileList"},
	Key:    []string{"profileid"},
	Label:  "DBA profiles",
	Help:   "Editing a profile bound to ONTs changes their upstream bandwidth. Fixed/Assured/Max are posted for every type.",
	Add: &OLTWrite{Path: "/goform/setDbaprofile", Body: []string{"profileid", "profilename", "type", "fix", "assure", "max"},
		Extra: map[string]any{"action": "add", "originData": map[string]any{}}},
	Edit: &OLTWrite{Path: "/goform/setDbaprofile", Body: []string{"profileid", "profilename", "type", "fix", "assure", "max"},
		Extra: map[string]any{"action": "edit"}, Origin: "empty"},
	Delete: &OLTWrite{Path: "/goform/delDbaprofile", Guard: "profileBind"},
	Columns: []OLTField{
		{Leaf: "ID", Vendor: "profileid", Required: true, Min: i64(0), Max: i64(127), Label: "Profile ID"},
		{Leaf: "Name", Vendor: "profilename", Write: true, Required: true, MaxLength: 32, Label: "Profile name"},
		{Leaf: "Type", Vendor: "type", Write: true, Required: true, Enum: dbaTypeEnum, EnumLabels: dbaTypeLabels, Label: "DBA type"},
		{Leaf: "Fixed", Vendor: "fix", Write: true, Min: i64(256), Max: i64(800000), Units: "kbps", Label: "Fixed bandwidth"},
		{Leaf: "Assured", Vendor: "assure", Write: true, Min: i64(0), Max: i64(800000), Units: "kbps", Label: "Assured bandwidth"},
		{Leaf: "Max", Vendor: "max", Write: true, Min: i64(256), Max: i64(1200000), Units: "kbps", Label: "Max bandwidth"},
		{Leaf: "Bind", Vendor: "bind", Label: "Bound ONTs"},
	},
}

var oltUniqueProfileTable = OLTTable{
	Object: "Profile.Unique",
	Get:    OLTCall{Path: "/goform/getOntUniqueProfileList"},
	Key:    []string{"profileId"},
	Label:  "Unique (per-ONT) profiles",
	Help:   "Keyed by ONT id (e.g. 0/1/1). Edit with Profile.Unique.Edit(); flows via Profile.Line.AddFlow(OptType=unique).",
	Add:    &OLTWrite{Path: "/goform/setOntUniqueProfile", Body: []string{"profileId", "profilename", "refWifiProfileId"}, Extra: map[string]any{"action": "add"}},
	Delete: &OLTWrite{Path: "/goform/delOntUniqueProfile"},
	Columns: []OLTField{
		{Leaf: "ONTID", Vendor: "profileId", Required: true, MaxLength: 16, Label: "ONT id"},
		{Leaf: "Name", Vendor: "profilename", Required: true, MaxLength: 32, Label: "Profile name"},
		{Leaf: "RefWiFiProfile", Vendor: "refWifiProfileId", Required: true, Label: "Referenced WiFi profile",
			Help: "WiFi profile ID, or None. Reads -20 when none."},
	},
}

var oltPagesProfile = []OLTPage{
	{
		Route: "/gponprofile/linebrief", Title: "Line Profile",
		Tables: []OLTTable{oltLineProfileTable},
		Actions: append(profileCommands(&oltLineProfileTable, true), OLTAction{
			Command: "Profile.Line.Edit()",
			Label:   "Edit line profile",
			Help:    "setLineprofile {profileid, profilename, onttype, trafficmode, refMultProfileId, item:\"refmult\", action:\"edit\", originData:{}} - posts the whole dialog, every input required.",
			Write: OLTWrite{Path: "/goform/setLineprofile", Body: []string{"profileid", "profilename", "onttype", "trafficmode", "refMultProfileId"},
				Extra: map[string]any{"item": "refmult", "action": "edit", "originData": map[string]any{}}},
			Inputs: []OLTField{
				{Leaf: "ID", Vendor: "profileid", Required: true, Label: "Profile ID"},
				{Leaf: "Name", Vendor: "profilename", Required: true, MaxLength: 32, Label: "Profile name"},
				{Leaf: "ONTType", Vendor: "onttype", Required: true, Enum: []string{"adaptive", "hgu", "sfu"}, Label: "ONT type"},
				{Leaf: "TrafficMode", Vendor: "trafficmode", Required: true, Enum: []string{"car", "queue"}, Label: "Traffic mode"},
				{Leaf: "RefMulticastProfile", Vendor: "refMultProfileId", Required: true, Label: "Multicast profile ID or None"},
			},
		}),
	},
	{
		// Hidden sub-page (View on a line profile). Per-profile getters are
		// not read (they need profileid); Add buttons only.
		Route: "/gponprofile/linedetail", Title: "Line Profile Detail", Group: "Profile", Section: "Line",
		Actions: []OLTAction{
			lineDetailAdd("Profile.Line.AddTcont()", "Add T-CONT", "tcont", []string{"tcontid", "dbaprofile"}, []OLTField{
				{Leaf: "TcontID", Vendor: "tcontid", Required: true, Min: i64(1), Max: i64(8), Label: "T-CONT ID"},
				{Leaf: "DBAProfile", Vendor: "dbaprofile", Required: true, Label: "DBA profile ID"},
			}),
			lineDetailAdd("Profile.Line.AddGemport()", "Add GEM port", "gemport", []string{"gemport", "tcontid", "qid", "usid", "dsid"}, []OLTField{
				{Leaf: "Gemport", Vendor: "gemport", Required: true, Min: i64(1), Max: i64(1024), Label: "GEM port ID"},
				{Leaf: "TcontID", Vendor: "tcontid", Required: true, Min: i64(1), Max: i64(8), Label: "T-CONT ID"},
				{Leaf: "QueueID", Vendor: "qid", Required: true, Min: i64(-1), Max: i64(7), Label: "Queue ID (-1 = not required)"},
				{Leaf: "USProfile", Vendor: "usid", Required: true, Min: i64(-1), Max: i64(127), Label: "US profile ID (-1 = not required)"},
				{Leaf: "DSProfile", Vendor: "dsid", Required: true, Min: i64(-1), Max: i64(127), Label: "DS profile ID (-1 = not required)"},
			}),
			lineDetailAdd("Profile.Line.AddMapping()", "Add GEM mapping", "mapping", []string{"mappingindex", "vlan", "mappingPort", "gemport"}, []OLTField{
				{Leaf: "MappingIndex", Vendor: "mappingindex", Required: true, Min: i64(0), Max: i64(47), Label: "Mapping index"},
				{Leaf: "VLAN", Vendor: "vlan", Required: true, Label: "VLAN (1-4094 or transparent)"},
				{Leaf: "MappingPort", Vendor: "mappingPort", Required: true, Enum: []string{"iphost"}, EnumLabels: []string{"IP-Host"}, Label: "Port"},
				// Posted only when given (the UI drops it unless the port is eth).
				{Leaf: "MappingPortNum", Vendor: "mappingPortNum", Min: i64(1), Max: i64(24), Label: "ETH port number"},
				{Leaf: "Gemport", Vendor: "gemport", Required: true, Label: "GEM port ID"},
			}),
			{
				// GPON VLAN service: flows of a line profile (optype line) or
				// of an ONT unique profile (optype unique, ProfileID = ONT id).
				Command: "Profile.Line.AddFlow()", Label: "Add service flow",
				Help: "setLineprofile {flowindex, port, flowmode, cvid, svid, profileid, optype, item:\"flow\", action:\"add\", originData:{}}. " +
					"OptType line: ProfileID = line profile ID; unique: ProfileID = ONT id (e.g. 0/1/1).",
				Write: OLTWrite{Path: "/goform/setLineprofile", Body: []string{"flowindex", "port", "flowmode", "cvid", "svid", "profileid", "optype"},
					Extra: map[string]any{"item": "flow", "action": "add", "originData": map[string]any{}}},
				Inputs: []OLTField{
					{Leaf: "ProfileID", Vendor: "profileid", Required: true, Label: "Line profile ID or ONT id"},
					{Leaf: "OptType", Vendor: "optype", Required: true, Enum: []string{"line", "unique"}, EnumLabels: []string{"Line profile", "Unique profile"}, Label: "Profile kind"},
					{Leaf: "FlowIndex", Vendor: "flowindex", Required: true, Min: i64(1), Max: i64(1024), Label: "Flow index"},
					{Leaf: "Port", Vendor: "port", Required: true, Label: "ONT port (veip or 1-24)"},
					{Leaf: "FlowMode", Vendor: "flowmode", Required: true, Enum: []string{"0", "1", "2", "3"},
						EnumLabels: []string{"default vlan", "transparent", "translation", "keep"}, Label: "Flow mode"},
					{Leaf: "CVID", Vendor: "cvid", Min: i64(1), Max: i64(4095), Label: "Customer VLAN"},
					{Leaf: "SVID", Vendor: "svid", Min: i64(1), Max: i64(4095), Label: "Service VLAN (translation)"},
				},
			},
			lineDetailAdd("Profile.Line.AddMulticast()", "Configure multicast", "mult",
				[]string{"ont_port", "mult_mode", "mult_vlan", "fast_leave", "max_groups", "max_bw", "dstag_action", "dstag_vlan", "dstag_pri"}, []OLTField{
					{Leaf: "ONTPort", Vendor: "ont_port", Required: true, Label: "ONT port (1-24 or Not_Required)"},
					{Leaf: "Mode", Vendor: "mult_mode", Required: true, Enum: []string{"igmp-snooping", "olt-control", "Not_Required"}, Label: "Multicast mode"},
					{Leaf: "VLAN", Vendor: "mult_vlan", Required: true, Label: "Multicast VLAN or Not_Required"},
					{Leaf: "FastLeave", Vendor: "fast_leave", Required: true, Enum: []string{"disable", "enable"}, Label: "Fast leave"},
					{Leaf: "MaxGroups", Vendor: "max_groups", Required: true, Label: "Max groups or Not_Required"},
					{Leaf: "MaxBandwidth", Vendor: "max_bw", Required: true, Label: "Max bandwidth or Not_Required"},
					{Leaf: "DsTagAction", Vendor: "dstag_action", Required: true, Enum: []string{"Not_Required", "remove", "add", "translate"}, Label: "Downstream tag action"},
					{Leaf: "DsTagVLAN", Vendor: "dstag_vlan", Required: true, Label: "Downstream tag VLAN or Not_Required"},
					{Leaf: "DsTagPriority", Vendor: "dstag_pri", Required: true, Label: "Downstream tag priority (0-7) or Not_Required"},
				}),
			{
				Command: "Profile.Line.SetMacLimit()", Label: "Set ONT port MAC limit",
				Help:  "setLineprofileMacAddrMax {port, macCount, profileid, action:\"add\", originData:{}}.",
				Write: OLTWrite{Path: "/goform/setLineprofileMacAddrMax", Body: []string{"port", "macCount", "profileid"}, Extra: map[string]any{"action": "add", "originData": map[string]any{}}},
				Inputs: []OLTField{
					{Leaf: "ProfileID", Vendor: "profileid", Required: true, Label: "Line profile ID"},
					{Leaf: "Port", Vendor: "port", Required: true, Min: i64(1), Max: i64(24), Label: "ONT port"},
					{Leaf: "MaxMAC", Vendor: "macCount", Required: true, Min: i64(1), Max: i64(255), Label: "Max MAC count"},
				},
			},
		},
	},
	{
		Route: "/gponprofile/dbabrief", Title: "DBA Profile",
		Tables:  []OLTTable{oltDBAProfileTable},
		Actions: profileCommands(&oltDBAProfileTable, true),
	},
	rateProfilePage("/gponprofile/usbrief", "US Profile", "Profile.Upstream", "/goform/getUsprofileList", "/goform/setUsprofile", "/goform/delUsprofile", 1200000, 37500),
	rateProfilePage("/gponprofile/dsbrief", "DS Profile", "Profile.Downstream", "/goform/getDsprofileList", "/goform/setDsprofile", "/goform/delDsprofile", 2608832, 75000),
	{
		Route: "/gponprofile/uniquebrief", Title: "Unique Profile",
		Tables: []OLTTable{oltUniqueProfileTable},
		Actions: append(profileCommands(&oltUniqueProfileTable, false), OLTAction{
			Command: "Profile.Unique.Edit()",
			Label:   "Edit unique profile",
			Help:    "setOntUniqueProfile {profileId, profilename, refWifiProfileId, action:\"edit\"} (no originData) - every input required.",
			Write:   OLTWrite{Path: "/goform/setOntUniqueProfile", Body: []string{"profileId", "profilename", "refWifiProfileId"}, Extra: map[string]any{"action": "edit"}},
			Inputs: []OLTField{
				{Leaf: "ONTID", Vendor: "profileId", Required: true, Label: "ONT id"},
				{Leaf: "Name", Vendor: "profilename", Required: true, MaxLength: 32, Label: "Profile name"},
				{Leaf: "RefWiFiProfile", Vendor: "refWifiProfileId", Required: true, Label: "WiFi profile ID or None"},
			},
		}),
	},
	idNameProfilePage("/gponprofile/multicastbrief", "Multicast Profile", "Profile.Multicast", "/goform/getOntMulticastProfileList", "/goform/setOntMulticastProfile", "/goform/delOntMulticastProfile"),
	idNameProfilePage("/gponprofile/wifibrief", "Wifi Profile", "Profile.WiFi", "/goform/getWifiProfileList", "/goform/setWifiProfile", "/goform/delWifiProfile"),
	// Hidden detail pages whose getters need a per-profile id and whose
	// deletes post {list:[{id, index}]}: not expressible yet.
	{Route: "/gponprofile/uniquedetail", Title: "Unique Profile Detail",
		Unsupported: "hidden sub-page: every getter needs ?ontid= (WAN/WLAN/LAN/CATV/SIP/TR-069 tabs); flows are written via Profile.Line.AddFlow(OptType=unique)"},
	{Route: "/gponprofile/multicastdetail", Title: "Multicast Profile Detail",
		Unsupported: "hidden sub-page: getOntMulticastList needs ?multicastId=; delete posts {list:[{multicastId,index}]}"},
	{Route: "/gponprofile/wifidetail", Title: "Wifi Profile Detail",
		Unsupported: "hidden sub-page: getOntWifiProfileInfo needs ?wifiProfileId=; delete posts {list:[{wifiProfileId,index}]}"},
}
