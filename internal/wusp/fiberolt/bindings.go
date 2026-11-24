package fiberolt

// Binding tables for the hand-written (legacy-path) Device.WUSP_OLT
// controls. The web-UI page specs (internal/wusp/olt_pages_*.go) are
// interpreted into further entries by pages.go. See OLT-WUSP-DESIGN.md.
//
// Request bodies follow OLT-WEBUI-CONTROLS.md (what the web UI sends on
// firmware 1.1.3.18): setters post JSON, errCode "0" is success, add/edit
// share one setter with action/originData, deletes post {list:[rows]}.

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// CollectBudget bounds one collection (all sources together).
var CollectBudget = 15 * time.Second

// GateSource must answer for the collection to report Status=ok; when it
// fails the collection stops with Status=api_error.
const GateSource = "sysStatus"

// SupportedOperations is the legacy summary string the console shows; the
// full command list is in the control schema (DescribeControls()).
const SupportedOperations = "Reboot, FactoryRestore, ONU.Reboot, ONU.Reset, ONU.Enable, ONU.Disable"

var nowUnix = func() int64 { return time.Now().Unix() }

// Sources lists every hand-written batched read. Getters reference them by
// Name; page specs add "page:<path>?<query>" sources (pages.go).
var Sources = []Source{
	{Name: "sysStatus", Endpoint: "/goform/getSysStatus"},
	{Name: "onus", Fetch: fetchONUs},
	{Name: "ontBrief", Endpoint: "/goform/getOntListBrife", Query: map[string]string{"PonPortName": "all"}},
	{Name: "syslog", Endpoint: "/goform/getSystemLogList"},
	{Name: "lineProfiles", Endpoint: "/goform/getLineprofileList"},
	{Name: "ontAuth", Endpoint: "/goform/getOntListConfig", Query: map[string]string{"PonPortName": "all"}},
	{Name: "sysTime", Endpoint: "/goform/getSystemTimeInfo"},
	{Name: "acl", Endpoint: "/goform/getAclList"},
	{Name: "staticRoutes", Endpoint: "/goform/getStaticRouteList"},
	{Name: "qvlans", Endpoint: "/goform/getQvlanList"},
}

// lineProfileDetail registers its own page sources, so it joins Sources in
// init (a literal entry would be an initialization cycle).
func init() {
	Sources = append(Sources, Source{Name: "lineProfileDetail", Fetch: fetchLineProfileDetail, Composite: true})
}

// lineProfileDetailGetters are the per-profile detail tabs of a line
// profile (every getter needs ?profileid=; the flow tab also optype=line).
var lineProfileDetailGetters = []struct {
	key, path string
	query     map[string]string
}{
	{"tcont", "/goform/getLineprofileTcontInfo", nil},
	{"gem", "/goform/getLineprofileGemInfo", nil},
	{"mapping", "/goform/getLineprofileMappingInfo", nil},
	{"flow", "/goform/getLineprofileFlowInfo", map[string]string{"optype": "line"}},
	{"mult", "/goform/getLineprofileMultInfo", nil},
}

// fetchLineProfileDetail reads the detail getters of every line profile.
// Each (profile, getter) pair is its own page source, registered when the
// profile is first seen, so the web budget refreshes them one page per
// tick and serves them from the page cache meanwhile; a full cycle reads
// them live. Rows carry the profileid they belong to; a failing getter
// leaves that profile's rows out and is logged, like the web UI's tabs.
func fetchLineProfileDetail(c *Cycle) (any, error) {
	profiles, err := c.Source("lineProfiles")
	if err != nil {
		return nil, err
	}
	out := Doc{}
	for _, g := range lineProfileDetailGetters {
		out[g.key] = []any{}
	}
	for _, p := range ListRows(profiles, "list") {
		id := strings.TrimSpace(Str(p["profileid"]))
		if id == "" {
			continue
		}
		for _, g := range lineProfileDetailGetters {
			q := map[string]string{"profileid": id}
			for k, v := range g.query {
				q[k] = v
			}
			name := pageSourceName(g.path, q)
			registerSource(Source{Name: name, Endpoint: g.path, Query: q})
			raw, err := c.Source(name)
			if err != nil {
				continue // logged by Source
			}
			for _, row := range ListRows(raw, "list") {
				r := copyRow(row)
				r["profileid"] = id
				out[g.key] = append(out[g.key].([]any), r)
			}
		}
	}
	return out, nil
}

// lineDetailRows selects one detail list of the lineProfileDetail source.
func lineDetailRows(key string) func(*Cycle, any) []Doc {
	return func(_ *Cycle, raw any) []Doc { return ListRows(raw, key) }
}

// ponPortEnable writes PONPort.{i}.Enable through setPonPortBasicInfo the
// way the PON port dialog does for a single row: {port:[portName],
// portstate, every other field "-1" (no change)}. Only PON ports have it;
// uplink ports are switched through Switching.Port.Config.{i}.Status.
func ponPortEnable(sc *SetCall) error {
	name := strings.TrimSpace(Str(sc.Row["portName"]))
	if !strings.HasPrefix(name, "pon") {
		return fmt.Errorf("%w: %s: only PON ports take setPonPortBasicInfo; use Switching.Port.Config Status for %s", wusp.ErrUSPPathUnsupported, sc.Path, name)
	}
	state := "0"
	if sc.Value.AsBool() {
		state = "1"
	}
	body := map[string]any{"port": []any{name}, "portstate": state}
	for _, f := range []string{"autofind", "p2p", "autoauth", "authmode", "powerlimit", "loopbackdetect", "loopbackshutdown"} {
		body[f] = "-1"
	}
	return postChecked(sc.Ctx, sc.Env.API, "/goform/setPonPortBasicInfo", body, true)
}

// onuIDInput resolves the ONT id of an Operate: OnuID, or Port + Index
// ("0/<pon>/<index>", the vendor's slot/pon/onu form).
func onuIDInput(in func(string) string) (string, error) {
	if id := strings.TrimSpace(in("OnuID")); id != "" {
		return id, nil
	}
	port, idx := strings.TrimSpace(in("Port")), strings.TrimSpace(in("Index"))
	if port == "" || idx == "" {
		return "", fmt.Errorf("olt: ProvisionedONU.Add() requires OnuID (e.g. 0/1/1) or Port and Index")
	}
	port = strings.TrimPrefix(port, "pon")
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("olt: ProvisionedONU.Add(): Port must be pon1..pon8 or 1..8")
	}
	if _, err := strconv.Atoi(idx); err != nil {
		return "", fmt.Errorf("olt: ProvisionedONU.Add(): Index must be a number")
	}
	return "0/" + port + "/" + idx, nil
}

// AsFloat emits native float64 values (including 0).
var AsFloat Conv = func(raw any) (wusp.Value, bool) {
	f, ok := raw.(float64)
	return wusp.Float(f), ok
}

// boolForm encodes a boolean as the vendor's "1"/"0".
func boolForm(v wusp.Value) (any, error) {
	if v.AsBool() {
		return "1", nil
	}
	return "0", nil
}

// deviceInfoForm builds the setDeviceInfo body the summary page's "Edit
// Device Info" dialog posts, from the current getSysStatus document:
// {deviceName, deviceLocation (already Base64 in the getter), ip, dnsType,
// editdevice:1, originData:<getSysStatus>, preferredDNS, alternateDNS,
// ipType, mask, inbandip, inbandmask, mngvlan, gateway, mnghost}.
func deviceInfoForm(cur Doc) map[string]any {
	body := map[string]any{"editdevice": "1", "originData": copyRow(cur)}
	for _, k := range []string{"deviceName", "deviceLocation", "ip", "dnsType", "preferredDNS", "alternateDNS",
		"ipType", "mask", "inbandip", "inbandmask", "mngvlan", "gateway", "mnghost"} {
		body[k] = Str(cur[k])
	}
	for _, k := range []string{"preferredDNS", "alternateDNS"} {
		if body[k] == "0.0.0.0" {
			body[k] = ""
		}
	}
	return body
}

// deviceInfoSetter writes one setDeviceInfo field through the whole form.
func deviceInfoSetter(field string, guard string) *Setter {
	return &Setter{ReadModifyWrite: true, Read: "sysStatus", Endpoint: "/goform/setDeviceInfo", Field: field,
		Form: deviceInfoForm, Guard: guard}
}

// timeForm is the setSystemTimeInfo body: {timeType, systemTime, timeZone,
// sntppserver, sntpsserver}.
func timeForm(cur Doc) map[string]any {
	body := map[string]any{}
	for _, k := range []string{"timeType", "systemTime", "timeZone", "sntppserver", "sntpsserver"} {
		body[k] = Str(cur[k])
	}
	return body
}

// Bindings lists every hand-written scalar Device.WUSP_OLT parameter.
// Prologue fields (Installed, Status, ...) are set by collect().
var Bindings = []Binding{
	{Leaf: "Enable", Set: &Setter{Local: true, Func: func(sc *SetCall) error {
		if sc.Env.EnableWrite == nil {
			return wusp.ErrUSPPathUnsupported
		}
		return sc.Env.EnableWrite(sc.Value.AsBool())
	}}},
	{Leaf: "AutoSave", Get: &Getter{Func: func(c *Cycle, _ Doc) (wusp.Value, bool) {
		return wusp.Bool(c.Env.autoSave()), true
	}}, Set: &Setter{Local: true, Func: func(sc *SetCall) error {
		if sc.Env.SetAutoSave == nil {
			return wusp.ErrUSPPathUnsupported
		}
		return sc.Env.SetAutoSave(sc.Value.AsBool())
	}}},

	// System health (goform/getSysStatus).
	{Leaf: "CpuPercent", Get: From("sysStatus", AsPercent, "cpuPercent")},
	{Leaf: "MemoryPercent", Get: From("sysStatus", AsPercent, "memoryPercent")},
	{Leaf: "Temperature", Get: From("sysStatus", AsDecimal, "temp1value")},
	{Leaf: "PonTemperature", Get: From("sysStatus", AsDecimal, "temp2value")},
	{Leaf: "FanSpeed", Get: From("sysStatus", AsFanRPM, "fan1")},
	{Leaf: "Uptime", Get: From("sysStatus", AsUint, "runTime")},
	// Temperature alarm thresholds: summary page, setAlarmInfo
	// {temphi, templo, isAlarm:1}.
	{Leaf: "TemperatureAlarmHigh", Get: From("sysStatus", AsDecimal, "temphi"), Set: alarmSetter("temphi")},
	{Leaf: "TemperatureAlarmLow", Get: From("sysStatus", AsDecimal, "templo"), Set: alarmSetter("templo")},

	// ONU totals (ONU table).
	{Leaf: "TotalONUs", Get: &Getter{Func: func(c *Cycle, _ Doc) (wusp.Value, bool) {
		rows, err := c.Source("onus")
		if err != nil {
			return wusp.Value{}, false
		}
		return wusp.Uint(uint64(len(rows.([]Doc)))), true
	}}},
	{Leaf: "OnlineONUs", Get: &Getter{Func: onlineONUs}},

	// Management interface: getSysStatus, written through setDeviceInfo
	// (the whole "Edit Device Info" form). Guarded: the agent refuses to
	// move the address it reaches the OLT through.
	{Leaf: "Network.Mgmt.IPAddress", Get: From("sysStatus", AsString, "ip"), Set: deviceInfoSetter("ip", "mgmtAddress")},
	{Leaf: "Network.Mgmt.SubnetMask", Get: From("sysStatus", AsString, "mask"), Set: deviceInfoSetter("mask", "mgmtAddress")},
	{Leaf: "Network.Mgmt.Gateway", Get: From("sysStatus", AsNonEmpty, "gateway"), Set: deviceInfoSetter("gateway", "mgmtAddress")},
	{Leaf: "Network.Mgmt.MACAddress", Get: From("sysStatus", AsNonEmpty, "mac")},
	// Management VLAN: part of the device info form; guarded like the address.
	{Leaf: "Network.Mgmt.VLAN", Get: From("sysStatus", AsNonEmpty, "mngvlan"), Set: deviceInfoSetter("mngvlan", "mgmtAddress")},

	// NTP: getSystemTimeInfo / setSystemTimeInfo (whole form). Enabled is
	// timeType "network" (Internet Time) vs "local".
	{Leaf: "Network.NTP.Server", Get: From("sysTime", AsNonEmpty, "sntppserver"),
		Set: &Setter{ReadModifyWrite: true, Read: "sysTime", Endpoint: "/goform/setSystemTimeInfo", Field: "sntppserver", Form: timeForm}},
	{Leaf: "Network.NTP.Enabled", Get: &Getter{Func: func(c *Cycle, _ Doc) (wusp.Value, bool) {
		doc, err := c.Doc("sysTime")
		if err != nil {
			return wusp.Value{}, false
		}
		return wusp.Bool(Str(doc["timeType"]) == "network"), true
	}}, Set: &Setter{ReadModifyWrite: true, Read: "sysTime", Endpoint: "/goform/setSystemTimeInfo", Field: "timeType", Form: timeForm,
		Encode: func(v wusp.Value) (any, error) {
			if v.AsBool() {
				return "network", nil
			}
			return "local", nil
		}}},
}

func alarmSetter(field string) *Setter {
	return &Setter{ReadModifyWrite: true, Read: "sysStatus", Endpoint: "/goform/setAlarmInfo", Field: field,
		Encode: func(v wusp.Value) (any, error) { return strconv.FormatFloat(v.AsFloat(), 'f', -1, 64), nil },
		Form: func(cur Doc) map[string]any {
			return map[string]any{"temphi": Str(cur["temphi"]), "templo": Str(cur["templo"]), "isAlarm": 1}
		}}
}

// ontAuthBody is the setOntListConfig body of the Auth Config dialog:
// {onuid, mode, sn (always, "" for loid), loid (loid mode), lineid, desc,
// action[, originData:{}]}.
func ontAuthBody(onuid, mode, info, lineid, desc, action string) map[string]any {
	if mode == "" {
		mode = "sn"
	}
	if lineid == "" {
		lineid = "0"
	}
	body := map[string]any{"onuid": onuid, "mode": mode, "sn": "", "lineid": lineid, "desc": desc, "action": action}
	if mode == "loid" {
		body["loid"] = info
	} else {
		body["sn"] = info
	}
	if action == "edit" {
		body["originData"] = map[string]any{}
	}
	return body
}

// ontAuthEdit edits one Auth Config column of a provisioned ONU.
func ontAuthEdit(field string) *Setter {
	return &Setter{Func: func(sc *SetCall) error {
		row := map[string]string{}
		for _, k := range []string{"onuid", "mode", "info", "lineid", "desc"} {
			row[k] = Str(sc.Row[k])
		}
		row[field] = wusp.ValueToString(sc.Value)
		if field == "mode" && row["mode"] != "sn" && row["mode"] != "loid" {
			return fmt.Errorf("olt: %s: mode must be sn or loid", sc.Path)
		}
		return postChecked(sc.Ctx, sc.Env.API, "/goform/setOntListConfig",
			ontAuthBody(row["onuid"], row["mode"], row["info"], row["lineid"], row["desc"], "edit"), true)
	}}
}

// listDelete posts {"list":[row]} (the web UI delete idiom).
func listDelete(endpoint string) func(sc *SetCall) error {
	return func(sc *SetCall) error {
		return postChecked(sc.Ctx, sc.Env.API, endpoint, map[string]any{"list": []any{rawRow(sc.Row)}}, true)
	}
}

// rawRow returns the vendor row as the getter returned it (synthesized
// rows keep it under "_raw").
func rawRow(row Doc) Doc {
	if raw, ok := row["_raw"].(Doc); ok {
		return raw
	}
	return row
}

// Tables lists every hand-written multi-instance Device.WUSP_OLT object.
var Tables = []Table{
	{
		Object: "PONPort", Source: "sysStatus", Count: "PONPortNumberOfEntries",
		Rows:      func(_ *Cycle, raw any) []Doc { return ListRows(raw, "port") },
		KeyFields: []string{"portName"},
		Skip:      func(row Doc) bool { return strings.TrimSpace(Str(row["portName"])) == "" },
		Columns: []Column{
			{Leaf: "Name", Get: Col(AsTrimmed, "portName")},
			{Leaf: "Type", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				return wusp.String(PortType(strings.TrimSpace(Str(row["portName"])))), true
			})},
			{Leaf: "Status", Get: rowFunc(func(row Doc) (wusp.Value, bool) { return wusp.String(PortUp(Str(row["portStatus"]))), true })},
			// Admin state: PON ports read it from PON.Port (getPonPortBasicList);
			// here only the write is bound (setPonPortBasicInfo, pon ports only).
			{Leaf: "Enable", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				return wusp.Bool(PortUp(Str(row["portStatus"])) == "up"), strings.HasPrefix(strings.TrimSpace(Str(row["portName"])), "pon")
			}), Set: &Setter{Func: ponPortEnable}},
			{Leaf: "Speed", Get: Col(AsUint, "portSpeed")},
			{Leaf: "OnlineONUs", Get: Col(AsUint, "online")},
			{Leaf: "TotalONUs", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				offline, err := strconv.ParseUint(strings.TrimSpace(Str(row["offline"])), 10, 64)
				if err != nil {
					return wusp.Value{}, false
				}
				if online, err := strconv.ParseUint(strings.TrimSpace(Str(row["online"])), 10, 64); err == nil {
					return wusp.Uint(online + offline), true
				}
				return wusp.Uint(offline), true
			})},
		},
	},
	{
		Object: "ONU", Source: "onus", Count: "ONUNumberOfEntries",
		Rows:          func(_ *Cycle, raw any) []Doc { return raw.([]Doc) },
		KeyFields:     []string{"onuid"},
		TrustSnapshot: true,
		Columns: []Column{
			{Leaf: "Index", Get: Col(AsString, "onuid")},
			{Leaf: "PONPort", Get: Col(AsString, "ponPort")},
			{Leaf: "SerialNumber", Get: Col(AsString, "sn")},
			{Leaf: "Model", Get: Col(AsNonEmpty, "model")},
			{Leaf: "Status", Get: Col(AsString, "status")},
			{Leaf: "Enable", Get: rowFunc(func(row Doc) (wusp.Value, bool) { return wusp.Bool(ONUEnabled(Str(row["status"]))), true }),
				Set: &Setter{Func: func(sc *SetCall) error {
					action := "deactive"
					if sc.Value.AsBool() {
						action = "active"
					}
					return sc.Env.API.OntActionRows(sc.Ctx, action, []Doc{rawRow(sc.Row)})
				}}},
			{Leaf: "UpTime", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				secs, ok := ParseUpTime(Str(row["upTime"]))
				return wusp.Uint(secs), ok
			})},
			{Leaf: "ConfigState", Get: Col(AsNonEmpty, "configState")},
			{Leaf: "RunState", Get: Col(AsNonEmpty, "memberState")},
			{Leaf: "RxPower", Get: Col(AsNonZeroFloat, "rx")},
			{Leaf: "TxPower", Get: Col(AsNonZeroFloat, "tx")},
			{Leaf: "Voltage", Get: Col(AsNonZeroFloat, "voltage")},
			{Leaf: "BiasCurrent", Get: Col(AsNonZeroFloat, "bias")},
			{Leaf: "Temperature", Get: Col(AsNonZeroFloat, "temp")},
			{Leaf: "EthPortUp", Get: Col(AsBool, "ethUp")},
			{Leaf: "LastDownCause", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				c := strings.TrimSpace(Str(row["downCause"]))
				return wusp.String(c), c != "" && c != "-"
			})},
		},
	},
	{
		Object: "LineProfile.Tcont", Source: "lineProfileDetail", Count: "LineProfile.TcontNumberOfEntries",
		Rows: lineDetailRows("tcont"),
		Key:  func(row Doc) string { return Str(row["profileid"]) + "/" + Str(row["tcontid"]) },
		Columns: []Column{
			{Leaf: "ProfileID", Get: Col(AsString, "profileid")},
			{Leaf: "TcontID", Get: Col(AsString, "tcontid")},
			{Leaf: "DBAProfile", Get: Col(AsString, "dbaprofile")},
		},
	},
	{
		Object: "LineProfile.Gemport", Source: "lineProfileDetail", Count: "LineProfile.GemportNumberOfEntries",
		Rows: lineDetailRows("gem"),
		Key:  func(row Doc) string { return Str(row["profileid"]) + "/" + Str(row["gemport"]) },
		Columns: []Column{
			{Leaf: "ProfileID", Get: Col(AsString, "profileid")},
			{Leaf: "Gemport", Get: Col(AsString, "gemport")},
			{Leaf: "TcontID", Get: Col(AsString, "tcontid")},
			{Leaf: "QueueID", Get: Col(AsString, "qid")},
			{Leaf: "USProfile", Get: Col(AsString, "usid")},
			{Leaf: "DSProfile", Get: Col(AsString, "dsid")},
		},
	},
	{
		Object: "LineProfile.Mapping", Source: "lineProfileDetail", Count: "LineProfile.MappingNumberOfEntries",
		Rows: lineDetailRows("mapping"),
		Key:  func(row Doc) string { return Str(row["profileid"]) + "/" + Str(row["mappingindex"]) },
		Columns: []Column{
			{Leaf: "ProfileID", Get: Col(AsString, "profileid")},
			{Leaf: "MappingIndex", Get: Col(AsString, "mappingindex")},
			{Leaf: "VLAN", Get: Col(AsString, "vlan")},
			{Leaf: "Gemport", Get: Col(AsString, "gemport")},
			{Leaf: "MappingPort", Get: Col(AsString, "mappingPort")},
			{Leaf: "MappingPortNum", Get: Col(AsString, "mappingPortNum")},
		},
	},
	{
		Object: "LineProfile.Flow", Source: "lineProfileDetail", Count: "LineProfile.FlowNumberOfEntries",
		Rows: lineDetailRows("flow"),
		Key:  func(row Doc) string { return Str(row["profileid"]) + "/" + Str(row["flowindex"]) },
		Columns: []Column{
			{Leaf: "ProfileID", Get: Col(AsString, "profileid")},
			{Leaf: "FlowIndex", Get: Col(AsString, "flowindex")},
			{Leaf: "Port", Get: Col(AsString, "port")},
			{Leaf: "FlowMode", Get: Col(AsString, "flowmode")},
			{Leaf: "CVID", Get: Col(AsString, "cvid")},
			{Leaf: "SVID", Get: Col(AsString, "svid")},
		},
	},
	{
		Object: "LineProfile.Multicast", Source: "lineProfileDetail", Count: "LineProfile.MulticastNumberOfEntries",
		Rows: lineDetailRows("mult"),
		Key:  func(row Doc) string { return Str(row["profileid"]) + "/" + Str(row["ont_port"]) },
		Columns: []Column{
			{Leaf: "ProfileID", Get: Col(AsString, "profileid")},
			{Leaf: "ONTPort", Get: Col(AsString, "ont_port")},
			{Leaf: "Mode", Get: Col(AsString, "mult_mode")},
			{Leaf: "VLAN", Get: Col(AsString, "mult_vlan")},
			{Leaf: "FastLeave", Get: Col(AsString, "fast_leave")},
			{Leaf: "MaxGroups", Get: Col(AsString, "max_groups")},
			{Leaf: "MaxBandwidth", Get: Col(AsString, "max_bw")},
			{Leaf: "DsTagAction", Get: Col(AsString, "dstag_action")},
			{Leaf: "DsTagVLAN", Get: Col(AsString, "dstag_vlan")},
			{Leaf: "DsTagPriority", Get: Col(AsString, "dstag_pri")},
		},
	},
	{
		Object: "Syslog", Source: "syslog", Count: "SyslogNumberOfEntries", Max: 64,
		Columns: []Column{
			{Leaf: "Time", Get: Col(AsString, "logTime")},
			{Leaf: "Type", Get: Col(AsString, "logType")},
			{Leaf: "Message", Get: Col(AsTrimmed, "logTips")},
		},
	},
	{
		Object: "LineProfile", Source: "lineProfiles", Count: "LineProfileNumberOfEntries",
		KeyFields: []string{"profileid"},
		Columns: []Column{
			{Leaf: "ID", Get: Col(AsString, "profileid")},
			{Leaf: "Name", Get: Col(AsString, "profilename")},
			{Leaf: "ONTType", Get: Col(AsString, "onttype")},
			{Leaf: "MappingMode", Get: Col(AsString, "mapping_mode")},
			{Leaf: "TrafficMode", Get: Col(AsString, "traffic_mode")},
		},
	},
	{
		// ONT List > Auth Config: getOntListConfig {list:[{onuid, mode,
		// info, lineid, desc}]}; setOntListConfig add/edit; delOntListConfig
		// {list:[rows]}.
		Object: "ProvisionedONU", Source: "ontAuth", Count: "ProvisionedONUNumberOfEntries",
		KeyFields: []string{"onuid"},
		Columns: []Column{
			{Leaf: "OnuID", Get: Col(AsString, "onuid")},
			{Leaf: "Mode", Get: Col(AsString, "mode"), Set: ontAuthEdit("mode")},
			{Leaf: "Info", Get: Col(AsString, "info"), Set: ontAuthEdit("info")},
			{Leaf: "LineID", Get: Col(AsString, "lineid"), Set: ontAuthEdit("lineid")},
			{Leaf: "Desc", Get: Col(AsString, "desc"), Set: ontAuthEdit("desc")},
		},
		Add: func(ac *AddCall) (string, error) {
			if ac.Initial == nil {
				return "", fmt.Errorf("olt: Add requires the provisioned ONU fields")
			}
			onuID := ac.In("OnuID")
			if onuID == "" {
				return "", fmt.Errorf("olt: Add requires OnuID (e.g. 0/1/1)")
			}
			if err := login(ac.Ctx, ac.Env.API); err != nil {
				return "", err
			}
			if err := postChecked(ac.Ctx, ac.Env.API, "/goform/setOntListConfig",
				ontAuthBody(onuID, ac.In("Mode"), ac.In("Info"), ac.In("LineID"), ac.In("Desc"), "add"), true); err != nil {
				return "", fmt.Errorf("olt: provision ONU: %w", err)
			}
			return onuID, nil
		},
		// Legacy result shape: the vendor ONU ID stands in for the instance.
		AddResult: func(key string) string { return wusp.WUSPOLTPrefix + "ProvisionedONU." + key },
		Delete: func(sc *SetCall) error {
			if err := listDelete("/goform/delOntListConfig")(sc); err != nil {
				return fmt.Errorf("olt: delete provisioned ONU: %w", err)
			}
			return nil
		},
	},
	{
		// DNS servers live on the device info form (preferredDNS /
		// alternateDNS of getSysStatus, written through setDeviceInfo).
		Object: "Network.DNS.Server", Source: "sysStatus", Count: "Network.DNS.ServerNumberOfEntries",
		Positional: true,
		// Both slots are always present (.1 preferred, .2 alternate); an
		// unset server reads "" so the console can offer the slot.
		Rows: func(_ *Cycle, raw any) []Doc {
			doc, _ := raw.(Doc)
			var rows []Doc
			for _, slot := range []string{"preferredDNS", "alternateDNS"} {
				addr := Str(doc[slot])
				if addr == "0.0.0.0" {
					addr = ""
				}
				rows = append(rows, Doc{"slot": slot, "address": addr})
			}
			return rows
		},
		Columns: []Column{
			{Leaf: "Address", Get: Col(AsString, "address"), Set: &Setter{Func: func(sc *SetCall) error {
				slots := map[uint64]string{1: "preferredDNS", 2: "alternateDNS"}
				field, ok := slots[sc.Inst[0]]
				if !ok {
					return wusp.ErrUSPPathUnsupported
				}
				s := deviceInfoSetter(field, "")
				s.Form = func(cur Doc) map[string]any {
					body := deviceInfoForm(cur)
					body["dnsType"] = "manual"
					return body
				}
				return runSetter(&SetCall{Ctx: sc.Ctx, Env: sc.Env, Path: sc.Path, Value: sc.Value, loggedIn: true}, s)
			}}},
		},
	},
	{
		// IP ACL list: getAclList {list:[{aclId, remark, type}]}.
		Object: "Network.ACL", Source: "acl", Count: "Network.ACLNumberOfEntries",
		KeyFields: []string{"aclId"},
		Columns: []Column{
			{Leaf: "ID", Get: Col(AsString, "aclId")},
			{Leaf: "Name", Get: Col(AsString, "remark")},
			{Leaf: "Type", Get: Col(AsString, "type")},
		},
	},
	{
		// Static routing: getStaticRouteList {list:[{destIp, mask, nextHop}]}.
		Object: "Network.Route", Source: "staticRoutes", Count: "Network.RouteNumberOfEntries",
		Key: func(row Doc) string { return Str(row["destIp"]) + "/" + Str(row["mask"]) },
		Columns: []Column{
			{Leaf: "Destination", Get: Col(AsString, "destIp")},
			{Leaf: "Mask", Get: Col(AsString, "mask")},
			{Leaf: "Gateway", Get: Col(AsString, "nextHop")},
		},
	},
	{
		// 802.1Q VLAN: getQvlanList {list:[{vlanId, remark, ip, mask, ipType, threeLayersEn}]}.
		Object: "Network.QVLAN", Source: "qvlans", Count: "Network.QVLANNumberOfEntries",
		KeyFields: []string{"vlanId"},
		Columns: []Column{
			{Leaf: "ID", Get: Col(AsString, "vlanId")},
			{Leaf: "Name", Get: Col(AsString, "remark")},
			{Leaf: "StartVLAN", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				a, _, _ := strings.Cut(Str(row["vlanId"]), "-")
				return wusp.String(a), true
			})},
			{Leaf: "EndVLAN", Get: rowFunc(func(row Doc) (wusp.Value, bool) {
				a, b, ok := strings.Cut(Str(row["vlanId"]), "-")
				if !ok {
					b = a
				}
				return wusp.String(b), true
			})},
		},
	},
}

// Operations lists every hand-written Device.WUSP_OLT Operate command.
var Operations = []OpBinding{
	{Command: wusp.WUSPOLTRebootCommand, Run: systemAction("reboot")},
	{Command: wusp.WUSPOLTFactoryRestoreCommand, Run: systemAction("restore")},
	{Command: wusp.WUSPOLTUpgradeCommand, Run: func(oc *OpCall) error {
		dir := oc.Env.StagingDir
		if dir == "" {
			dir = OperateStagingDir
		}
		return operateUpgrade(oc.Ctx, oc.Env.API, dir, oc.Input)
	}},
	{Command: wusp.WUSPOLTBackupConfigCommand, Run: func(oc *OpCall) error {
		text, err := OperateBackupConfig(oc.Ctx, oc.Env.API)
		if err != nil {
			return err
		}
		oc.Output.Set(wusp.WUSPOLTPrefix+"Config", wusp.String(text))
		return nil
	}},
	{Command: wusp.WUSPOLTRestoreConfigCommand, Run: func(oc *OpCall) error {
		return OperateRestoreConfig(oc.Ctx, oc.Env.API, oc.Input)
	}},
	{Command: wusp.WUSPOLTSaveConfigCommand, Run: func(oc *OpCall) error {
		if err := oc.Login(); err != nil {
			return err
		}
		return oc.Env.API.SaveConfig(oc.Ctx)
	}},
	{Command: wusp.WUSPOLTONURebootCommand, Run: onuAction("reboot")},
	{Command: wusp.WUSPOLTONUResetCommand, Run: onuAction("reset")},
	{Command: wusp.WUSPOLTONUEnableCommand, Saves: true, Run: onuAction("active")},
	{Command: wusp.WUSPOLTONUDisableCommand, Saves: true, Run: onuAction("deactive")},

	// ONT authorization: the same setOntListConfig / delOntListConfig
	// requests as the ProvisionedONU table Add/Delete.
	{Command: wusp.WUSPOLTProvisionedONUAddCommand, Saves: true, Run: func(oc *OpCall) error {
		id, err := onuIDInput(oc.In)
		if err != nil {
			return err
		}
		mode := oc.In("Mode")
		if mode != "" && mode != "sn" && mode != "loid" {
			return fmt.Errorf("olt: ProvisionedONU.Add(): Mode must be sn or loid")
		}
		if oc.In("Info") == "" {
			return fmt.Errorf("olt: ProvisionedONU.Add() requires Info (the serial number, or the logical ID in loid mode)")
		}
		if err := oc.Login(); err != nil {
			return err
		}
		return postChecked(oc.Ctx, oc.Env.API, "/goform/setOntListConfig",
			ontAuthBody(id, mode, oc.In("Info"), oc.In("LineID"), oc.In("Desc"), "add"), true)
	}},
	{Command: wusp.WUSPOLTProvisionedONUDeleteCommand, Saves: true, Run: deleteRowOp("ontAuth", "/goform/delOntListConfig", "OnuID",
		func(row Doc, in func(string) string) bool {
			return strings.TrimSpace(Str(row["onuid"])) == strings.TrimSpace(in("OnuID"))
		})},

	// IP ACL: setAclListInfo creates/deletes the ACL id only; rules are
	// setIpAclInfo (Security.ACL.IPRule table).
	{Command: wusp.WUSPOLTNetworkACLAddCommand, Saves: true, Run: func(oc *OpCall) error {
		id := oc.In("ID")
		if id == "" {
			return fmt.Errorf("olt: ACL.Add() requires an ID input (100-199)")
		}
		if n, err := strconv.Atoi(id); err != nil || n < 100 || n > 199 {
			return fmt.Errorf("olt: ACL.Add(): ID must be 100-199 for an IPv4 ACL")
		}
		typ := oc.In("Type")
		if typ == "" {
			typ = "ipv4"
		}
		if err := oc.Login(); err != nil {
			return err
		}
		return postChecked(oc.Ctx, oc.Env.API, "/goform/setAclListInfo",
			map[string]any{"aclId": id, "remark": oc.In("Name"), "type": typ, "action": "add"}, true)
	}},
	{Command: wusp.WUSPOLTNetworkACLDeleteCommand, Saves: true, Run: deleteRowOp("acl", "/goform/delAclList", "ID",
		func(row Doc, in func(string) string) bool { return Str(row["aclId"]) == in("ID") })},
	{Command: wusp.WUSPOLTNetworkRouteAddCommand, Saves: true, Run: PostOp{
		Endpoint: "/goform/setStaticRouteInfo", Missing: "olt: Route.Add() requires Destination, Mask and Gateway inputs", Strict: true,
		Fields: []FormField{{"destIp", "Destination", true}, {"mask", "Mask", true}, {"nextHop", "Gateway", true}},
		Extra:  map[string]any{"action": "add"},
	}.Run},
	{Command: wusp.WUSPOLTNetworkRouteDeleteCommand, Saves: true, Run: deleteRowOp("staticRoutes", "/goform/delStaticRouteList", "Destination",
		func(row Doc, in func(string) string) bool {
			return Str(row["destIp"]) == in("Destination") && (in("Mask") == "" || Str(row["mask"]) == in("Mask"))
		})},
	{Command: wusp.WUSPOLTNetworkQVLANAddCommand, Saves: true, Run: func(oc *OpCall) error {
		start, end := oc.In("StartVLAN"), oc.In("EndVLAN")
		if start == "" {
			return fmt.Errorf("olt: QVLAN.Add() requires a StartVLAN input")
		}
		vlan := start
		if end != "" && end != start {
			vlan = start + "-" + end
		}
		if err := oc.Login(); err != nil {
			return err
		}
		return postChecked(oc.Ctx, oc.Env.API, "/goform/setQvlanInfo",
			map[string]any{"vlanId": vlan, "vlanRemark": oc.In("Name"), "threeLayersEn": "0", "action": "add"}, true)
	}},
	{Command: wusp.WUSPOLTNetworkQVLANDeleteCommand, Saves: true, Run: func(oc *OpCall) error {
		if err := oc.Login(); err != nil {
			return err
		}
		if err := guardVLANDelete(oc.Ctx, oc.Env, oc.In("ID")); err != nil {
			return err
		}
		return deleteRowOp("qvlans", "/goform/delQvlanList", "ID",
			func(row Doc, in func(string) string) bool { return Str(row["vlanId"]) == in("ID") })(oc)
	}},
	{Command: wusp.WUSPOLTNetworkBackupConfigCommand, Run: func(oc *OpCall) error {
		if err := oc.Login(); err != nil {
			return err
		}
		text, err := oc.Env.API.DownloadConfig(oc.Ctx)
		if err != nil {
			return fmt.Errorf("olt: backup network config: %w", err)
		}
		oc.Output.Set(wusp.WUSPOLTPrefix+"Network.Config", wusp.String(text))
		return nil
	}},
}

// DescribeControls is registered in init: it serializes the tables above,
// so it cannot sit in their initializer.
func init() {
	Operations = append(Operations, OpBinding{Command: wusp.WUSPOLTDescribeControlsCommand, Run: func(oc *OpCall) error {
		raw, err := ControlSchemaJSON()
		if err != nil {
			return err
		}
		oc.Output.Set(wusp.WUSPOLTPrefix+"ControlSchema", wusp.String(string(raw)))
		return nil
	}})
}

// deleteRowOp finds the row matching the inputs in source and posts
// {"list":[row]} to endpoint (the web UI delete idiom).
func deleteRowOp(source, endpoint, required string, match func(row Doc, in func(string) string) bool) func(*OpCall) error {
	return func(oc *OpCall) error {
		if oc.In(required) == "" {
			return fmt.Errorf("olt: %s requires a %s input", strings.TrimPrefix(oc.Command, wusp.WUSPOLTPrefix), required)
		}
		if err := oc.Login(); err != nil {
			return err
		}
		raw, err := newCycle(oc.Ctx, oc.Env).Source(source)
		if err != nil {
			return err
		}
		for _, row := range ListRows(raw, "list") {
			if match(row, oc.In) {
				return postChecked(oc.Ctx, oc.Env.API, endpoint, map[string]any{"list": []any{row}}, true)
			}
		}
		return fmt.Errorf("%w: no %s row matches %s=%s", wusp.ErrUSPPathNotFound, source, required, oc.In(required))
	}
}

// ---- reusable binding helpers ------------------------------------------------

// rowFunc wraps a row-only column computation.
func rowFunc(fn func(row Doc) (wusp.Value, bool)) *Getter {
	return &Getter{Func: func(_ *Cycle, row Doc) (wusp.Value, bool) { return fn(row) }}
}

// FormField maps one Operate input onto one vendor form field.
type FormField struct {
	Form     string
	Input    string
	Required bool
}

// PostOp is the declarative Operate shape for goform add/delete style
// commands: validate required inputs, log in, post one form whose fields
// come from the inputs (absent optional inputs are sent as "").
type PostOp struct {
	Endpoint string
	Fields   []FormField
	Extra    map[string]any
	// Missing is the error text when a required input is absent (default
	// "olt: <command> requires <inputs>").
	Missing string
	// Strict checks the vendor reply errCode.
	Strict bool
	// OK lists extra success errCodes besides "0"/"success".
	OK []string
}

// Run implements OpBinding.Run.
func (p PostOp) Run(oc *OpCall) error {
	body := map[string]any{}
	var missing []string
	for _, f := range p.Fields {
		v := oc.In(f.Input)
		if f.Required && v == "" {
			missing = append(missing, f.Input)
		}
		body[f.Form] = v
	}
	if len(missing) > 0 {
		if p.Missing != "" {
			return fmt.Errorf("%s", p.Missing)
		}
		return fmt.Errorf("olt: %s requires %s", strings.TrimPrefix(oc.Command, wusp.WUSPOLTPrefix), strings.Join(missing, " and "))
	}
	for k, v := range p.Extra {
		body[k] = v
	}
	if err := oc.Login(); err != nil {
		return err
	}
	return postChecked(oc.Ctx, oc.Env.API, p.Endpoint, body, p.Strict, p.OK...)
}

func systemAction(action string) func(*OpCall) error {
	return func(oc *OpCall) error {
		if err := oc.Login(); err != nil {
			return err
		}
		return oc.Env.API.SystemAction(oc.Ctx, action)
	}
}

// onuAction runs a bulk ONU action on the ONUs named by the Index input
// (comma-separated ONU IDs). The web UI posts the full getOntListBrife rows.
func onuAction(action string) func(*OpCall) error {
	return func(oc *OpCall) error {
		ids := splitList(oc.In("Index"))
		if len(ids) == 0 {
			return fmt.Errorf("olt: %s requires an Index input (ONU ID like 0/1/1)", oc.Command)
		}
		if err := oc.Login(); err != nil {
			return err
		}
		return oc.Env.API.OntActionRows(oc.Ctx, action, onuRowsByID(oc.Ctx, oc.Env, ids))
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// onuRowsByID returns the getOntListBrife rows of the given ONU IDs; IDs
// the list does not know fall back to {onuid}.
func onuRowsByID(ctx context.Context, env *Env, ids []string) []Doc {
	byID := map[string]Doc{}
	if raw, err := newCycle(ctx, env).Source("ontBrief"); err == nil {
		for _, row := range ListRows(raw, "list") {
			byID[Str(row["onuid"])] = row
		}
	}
	rows := make([]Doc, 0, len(ids))
	for _, id := range ids {
		if row, ok := byID[id]; ok {
			rows = append(rows, row)
		} else {
			rows = append(rows, Doc{"onuid": id})
		}
	}
	return rows
}

// ponCounts returns the per-port online/offline ONU counters of
// getSysStatus (named ports only).
func ponCounts(c *Cycle) (online, offline map[string]uint64) {
	online, offline = map[string]uint64{}, map[string]uint64{}
	raw, err := c.Source("sysStatus")
	if err != nil {
		return
	}
	for _, port := range ListRows(raw, "port") {
		name := strings.TrimSpace(Str(port["portName"]))
		if name == "" {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(Str(port["online"])), 10, 64); err == nil {
			online[name] = n
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(Str(port["offline"])), 10, 64); err == nil {
			offline[name] = n
		}
	}
	return
}

// onlineONUs prefers the vendor per-port counters and falls back to the
// rows classified online.
func onlineONUs(c *Cycle, _ Doc) (wusp.Value, bool) {
	online, _ := ponCounts(c)
	total := uint64(0)
	for _, n := range online {
		total += n
	}
	if total == 0 {
		if raw, err := c.Source("onus"); err == nil {
			for _, row := range raw.([]Doc) {
				if row["rawStatus"] == "online" {
					total++
				}
			}
		}
	}
	return wusp.Uint(total), true
}

func parseFloatField(row Doc, keys ...string) float64 {
	raw, ok := Lookup(row, keys...)
	if !ok {
		return 0
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(Str(raw)), 64)
	if err != nil {
		return 0
	}
	return f
}

// fetchONUs builds the live ONU table from the web API: getOntListBrife
// (state, uptime, model) and getOntListOptical (optics for every ONU in
// one call). The telnet CLI is only a fallback: it adds unprovisioned ONUs
// and, when the web optical page fails, per-ONU optics.
func fetchONUs(c *Cycle) (any, error) {
	ctx, api, cli := c.Ctx, c.Env.API, c.Env.CLI
	type onuRow struct {
		id, portName, sn, model, status, upTime, configState, memberState, downCause string
		voltage, rx, tx, bias, temp                                                  float64
		ethKnown, ethUp                                                              bool
		raw                                                                          Doc
	}
	byID := map[string]*onuRow{}
	addRow := func(id, portName string) *onuRow {
		if row, ok := byID[id]; ok {
			if row.portName == "" && portName != "" {
				row.portName = portName
			}
			return row
		}
		row := &onuRow{id: id, portName: portName}
		byID[id] = row
		return row
	}
	brief, err := c.Source("ontBrief")
	if err != nil {
		log.Printf("[OLT] ontlist: %v", err)
	}
	for _, entry := range ListRows(brief, "list") {
		id := strings.TrimSpace(Str(entry["onuid"]))
		if id == "" {
			continue
		}
		row := addRow(id, strings.TrimSpace(Str(entry["ponPort"])))
		if row.portName == "" {
			row.portName = ONUPortFromID(id)
		}
		row.raw = entry
		row.sn = Str(entry["sn"])
		row.status = ONUStatus(Str(entry["status"]))
		row.upTime = Str(entry["updowntime"])
		row.configState = Str(entry["cfgstate"])
		row.downCause = Str(entry["downcause"])
		if m := Str(entry["equipid"]); m != "" && m != "-" {
			row.model = m
		}
	}
	opticalOK := false
	if optical, err := fetchPage(ctx, api, "/goform/getOntListOptical", nil, map[string]string{"PonPortName": "all"}); err == nil {
		opticalOK = true
		for _, o := range ListRows(optical, "list") {
			row, ok := byID[strings.TrimSpace(Str(o["onuid"]))]
			if !ok {
				continue
			}
			row.voltage = parseFloatField(o, "vol")
			row.rx = parseFloatField(o, "rxpower")
			row.tx = parseFloatField(o, "txpower")
			row.bias = parseFloatField(o, "bias")
			row.temp = parseFloatField(o, "temp")
		}
	}
	// CLI enumeration only when the web ONU list is unavailable.
	if cli != nil && brief == nil {
		ponOnline, ponTotal := ponCounts(c)
		for port := 1; port <= 8; port++ {
			name := "pon" + strconv.Itoa(port)
			if ponOnline[name] == 0 && ponTotal[name] == 0 {
				continue
			}
			rangeIDs := fmt.Sprintf("0/%d/1-0/%d/64", port, port)
			for _, cmd := range []string{"show ont info online " + rangeIDs, "show ont info offline " + rangeIDs} {
				out, err := cli.Run(cmd)
				if err != nil {
					log.Printf("[OLT] cli %q: %v", cmd, err)
					continue
				}
				for _, info := range ParseONUInfos(out) {
					row := addRow(info.ID, ONUPortFromID(info.ID))
					if row.sn == "" {
						row.sn = info.SN
					}
					if row.upTime == "" {
						row.upTime = info.UpTime
					}
					if row.configState == "" {
						row.configState = info.ConfigState
					}
					if row.memberState == "" {
						row.memberState = info.MemberState
					}
					if row.status == "" {
						row.status = "online"
					}
				}
			}
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	budget := 32
	rows := make([]Doc, 0, len(ids))
	for _, id := range ids {
		row := byID[id]
		if !opticalOK && cli != nil && budget > 0 {
			budget--
			if out, err := cli.Run("show ont optical-info " + id); err == nil {
				opt := ParseONUOptical(out)
				row.voltage, row.rx, row.tx, row.bias, row.temp = opt.VoltageV, opt.RxPowerDBm, opt.TxPowerDBm, opt.BiasCurrent, opt.TempC
				row.ethKnown, row.ethUp = opt.EthKnown, opt.EthPortUp
			}
		}
		status := row.status
		if status == "" {
			status = "offline"
		}
		doc := Doc{
			"onuid": row.id, "ponPort": row.portName, "sn": row.sn, "model": row.model,
			"status": status, "rawStatus": row.status,
			"upTime": row.upTime, "configState": row.configState, "memberState": row.memberState, "downCause": row.downCause,
			"rx": row.rx, "tx": row.tx, "voltage": row.voltage, "bias": row.bias, "temp": row.temp,
		}
		if row.raw != nil {
			doc["_raw"] = row.raw
		}
		if row.ethKnown {
			doc["ethUp"] = row.ethUp
		}
		rows = append(rows, doc)
	}
	return rows, nil
}
