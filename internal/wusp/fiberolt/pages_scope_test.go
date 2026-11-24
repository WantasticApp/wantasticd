package fiberolt

import (
	"context"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Operate commands added for the console (owner-approved scope): their
// request bodies are the vendor dialogs' bodies, byte for byte.

func scopeEnv(t *testing.T) (*fakeOLT, *Env, context.Context, string) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{
		map[string]any{"portNum": "1", "portName": "pon1", "portStatus": "1", "portSpeed": "2500", "online": "1", "offline": "0"},
		map[string]any{"portNum": "9", "portName": "ge1", "portStatus": "1", "portSpeed": "1000"},
	}, "preferredDNS": "8.8.8.8", "alternateDNS": "0.0.0.0", "mngvlan": "4000", "ip": "192.168.130.179"})
	return f, &Env{API: f.client()}, context.Background(), wusp.WUSPOLTPrefix
}

func TestScopeAutoAddRuleCommands(t *testing.T) {
	f, env, ctx, P := scopeEnv(t)
	rules := &prqListStore{key: "index", rows: []map[string]any{
		{"index": "0", "name": "r0", "type": "ALL-ONT", "param": "Null", "portbinding": "all", "lineprofile": "0", "globalswitch": "1", "autounique": "0"},
	}}
	rules.serve(f, "/goform/getOntAutoAddConfig", "/goform/setOntAutoAddConfig", "/goform/delOntAutoAddConfig")
	if _, err := Operate(ctx, env, P+"PON.AutoAdd.AddRule()", prqInputs("Index", "1", "Name", "r1", "Type", "ALL-HGU", "Param", "Null", "PortBinding", "pon1", "LineProfile", "2", "AutoUnique", "1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setOntAutoAddConfig", map[string]any{"index": "1", "name": "r1", "type": "ALL-HGU", "param": "Null", "portbinding": "pon1",
		"lineprofile": "2", "autounique": "1", "action": "add", "originData": map[string]any{}})
	if _, err := Operate(ctx, env, P+"PON.AutoAdd.DeleteRule()", prqInputs("Index", "0")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delOntAutoAddConfig", map[string]any{"list": []any{map[string]any{
		"index": "0", "name": "r0", "type": "ALL-ONT", "param": "Null", "portbinding": "all", "lineprofile": "0", "globalswitch": "1", "autounique": "0"}}})
	if _, err := Operate(ctx, env, P+"PON.AutoAdd.AddRule()", prqInputs("Index", "2", "Name", "bad", "Type", "All-ONT", "Param", "Null", "PortBinding", "all", "LineProfile", "0", "AutoUnique", "0")); err == nil {
		t.Fatal("Type must be one of the device's upper-case values")
	}
}

func TestScopeProfileCreateDeleteAndBindGuard(t *testing.T) {
	f, env, ctx, P := scopeEnv(t)
	dba := &prqListStore{key: "profileid", rows: []map[string]any{
		{"profileid": "1", "profilename": "dba1", "type": "3", "fix": "0", "assure": "1024", "max": "10240", "bind": "2"},
		{"profileid": "2", "profilename": "dba2", "type": "4", "fix": "0", "assure": "0", "max": "5000", "bind": "0"},
	}}
	dba.serve(f, "/goform/getDbaprofileList", "/goform/setDbaprofile", "/goform/delDbaprofile")
	wifi := &prqListStore{key: "profileId", rows: []map[string]any{{"profileId": "1", "profilename": "w1"}}}
	wifi.serve(f, "/goform/getWifiProfileList", "/goform/setWifiProfile", "/goform/delWifiProfile")

	if _, err := Operate(ctx, env, P+"Profile.DBA.Create()", prqInputs("ID", "7", "Name", "dba7", "Type", "4", "Max", "20000")); err != nil {
		t.Fatal(err)
	}
	// the dialog posts fix/assure/max for every type (empty when not given)
	prqWantBody(t, f, "/goform/setDbaprofile", map[string]any{"profileid": "7", "profilename": "dba7", "type": "4", "fix": "", "assure": "", "max": "20000", "action": "add", "originData": map[string]any{}})
	if _, err := Operate(ctx, env, P+"Profile.DBA.Delete()", prqInputs("Index", "1")); err == nil || !strings.Contains(err.Error(), "bound to 2") {
		t.Fatalf("bound profile must be refused: %v", err)
	}
	if n := len(f.callsTo("/goform/delDbaprofile")); n != 0 {
		t.Fatalf("guard must refuse before posting (%d posts)", n)
	}
	if _, err := Operate(ctx, env, P+"Profile.DBA.Delete()", prqInputs("Index", "2")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delDbaprofile", map[string]any{"list": []any{map[string]any{"profileid": "2", "profilename": "dba2", "type": "4", "fix": "0", "assure": "0", "max": "5000", "bind": "0"}}})
	// the table Delete carries the same guard
	if err := DeleteObject(ctx, env, P+"Profile.DBA.1."); err == nil {
		t.Fatal("DeleteObject on a bound profile must be refused")
	}
	// id/name profiles have no bind count: no guard, same body as the dialog
	if _, err := Operate(ctx, env, P+"Profile.WiFi.Create()", prqInputs("ID", "3", "Name", "w3")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setWifiProfile", map[string]any{"profileId": "3", "profilename": "w3", "action": "add", "originData": map[string]any{}})
	if _, err := Operate(ctx, env, P+"Profile.WiFi.Delete()", prqInputs("Index", "1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delWifiProfile", map[string]any{"list": []any{map[string]any{"profileId": "1", "profilename": "w1"}}})
	for _, cmd := range []string{"Profile.Line.Create()", "Profile.Line.Delete()", "Profile.Upstream.Create()", "Profile.Downstream.Delete()",
		"Profile.Unique.Create()", "Profile.Multicast.Delete()", "Profile.WiFi.Create()"} {
		found := false
		for _, c := range wusp.WUSPOLTCommands {
			if c.Path == P+cmd {
				found = true
				if strings.HasSuffix(cmd, "Delete()") && c.Effect != wusp.OLTEffectDestructive {
					t.Errorf("%s effect %s", cmd, c.Effect)
				}
			}
		}
		if !found {
			t.Errorf("%s not declared", cmd)
		}
	}
}

func TestScopeLAGAndManagementCommands(t *testing.T) {
	f, env, ctx, P := scopeEnv(t)
	lag := &prqListStore{key: "groupIndex", rows: []map[string]any{{"groupIndex": "po1", "type": "static", "algorithm": "src-mac", "port": []any{"ge5", "ge6"}}}}
	lag.serve(f, "/goform/getPortAggregatorList", "/goform/setPortAggregatorRule", "/goform/delPortAggregatorList")
	if _, err := Operate(ctx, env, P+"Switching.Port.LAG.Add()", prqInputs("GroupIndex", "2", "Mode", "dynamic", "Algorithm", "src-dst-mac", "MemberPorts", "ge3,ge4")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setPortAggregatorRule", map[string]any{"groupIndex": "2", "groupType": "dynamic", "algorithm": "src-dst-mac", "port": prqStrs("ge3", "ge4"), "action": "add"})
	if _, err := Operate(ctx, env, P+"Switching.Port.LAG.Delete()", prqInputs("Index", "po1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delPortAggregatorList", map[string]any{"list": []any{map[string]any{"groupIndex": "po1", "type": "static", "algorithm": "src-mac", "port": prqStrs("ge5", "ge6")}}})

	users := &prqListStore{key: "userName", rows: []map[string]any{{"userName": "guest1", "userType": "guest", "timeout": "300"}}}
	users.serve(f, "/goform/getUserList", "", "/goform/delUserList")
	if _, err := Operate(ctx, env, P+"Management.User.DeleteUser()", prqInputs("Index", "guest1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delUserList", map[string]any{"list": []any{map[string]any{"userName": "guest1", "userType": "guest", "timeout": "300"}}})

	f.handle("/goform/getAccessList", map[string]any{"accessStatus": "0", "list": []any{
		map[string]any{"svindex": "1", "real_index": "0", "service_name": "telnet", "ip_start": "10.0.0.1", "ip_end": "10.0.0.9", "action": "permit"}}})
	f.handle("/goform/delAccessList", map[string]any{"errCode": "0"})
	if _, err := Operate(ctx, env, P+"Management.AccessList.DeleteRule()", prqInputs("Index", "telnet|1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delAccessList", map[string]any{"list": []any{map[string]any{"svindex": "1", "real_index": "0", "service_name": "telnet", "ip_start": "10.0.0.1", "ip_end": "10.0.0.9", "action": "permit"}}})

	logs := &prqListStore{key: "serverIp", rows: []map[string]any{{"serverIp": "10.0.0.5", "port": "514"}}}
	logs.serve(f, "/goform/getSystemLogInfo", "", "/goform/delLogHost")
	if _, err := Operate(ctx, env, P+"Management.Syslog.DeleteServer()", prqInputs("Index", "10.0.0.5|514")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delLogHost", map[string]any{"list": []any{map[string]any{"serverIp": "10.0.0.5", "port": "514"}}})

	comm := &prqListStore{key: "communityName", rows: []map[string]any{{"communityName": "public", "accessRule": "read", "mibView": ""}}}
	f.handleFunc("/goform/getSnmpAccessList", func(map[string]any) any {
		out := comm.get(nil).(map[string]any)
		return map[string]any{"communityList": out["list"]}
	})
	f.handleFunc("/goform/setSnmpCommunityInfo", comm.set)
	f.handleFunc("/goform/delSnmpCommunityList", comm.del)
	if _, err := Operate(ctx, env, P+"Management.SNMP.AddCommunity()", prqInputs("Name", "s3cret", "Access", "readwrite")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setSnmpCommunityInfo", map[string]any{"communityName": "s3cret", "accessRule": "readwrite", "action": "add"})
	if _, err := Operate(ctx, env, P+"Management.SNMP.DeleteCommunity()", prqInputs("Index", "public")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delSnmpCommunityList", map[string]any{"list": []any{map[string]any{"communityName": "public", "accessRule": "read", "mibView": ""}}})

	traps := &prqListStore{key: "destHost", extra: map[string]any{"trapEn": "1"}, rows: []map[string]any{{"destHost": "10.0.0.6", "securityWord": "pub", "udpPort": "162", "securityMode": "v2c", "securityLevel": "--"}}}
	traps.serve(f, "/goform/getSnmpNoticeList", "/goform/setSnmpNoticeInfo", "/goform/delSnmpNoticeList")
	if _, err := Operate(ctx, env, P+"Management.SNMP.AddTrapHost()", prqInputs("Host", "10.0.0.7", "Community", "trapc", "UDPPort", "162", "Version", "v2c")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setSnmpNoticeInfo", map[string]any{"destHost": "10.0.0.7", "securityWord": "trapc", "udpPort": "162", "securityMode": "v2c", "action": "add"})
	if _, err := Operate(ctx, env, P+"Management.SNMP.DeleteTrapHost()", prqInputs("Index", "10.0.0.6|pub")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delSnmpNoticeList", map[string]any{"list": []any{map[string]any{"destHost": "10.0.0.6", "securityWord": "pub", "udpPort": "162", "securityMode": "v2c", "securityLevel": "--"}}})
}

func TestScopeProvisionedONUCommandsAndPONPort(t *testing.T) {
	f, env, ctx, P := scopeEnv(t)
	auth := &prqListStore{key: "onuid", rows: []map[string]any{{"onuid": "0/1/1", "mode": "sn", "info": "HWTC-00000001", "lineid": "0", "desc": "-"}}}
	auth.serve(f, "/goform/getOntListConfig", "/goform/setOntListConfig", "/goform/delOntListConfig")
	if _, err := Operate(ctx, env, P+"ProvisionedONU.Add()", prqInputs("Port", "pon2", "Index", "5", "Info", "HWTC-00000005", "LineID", "3", "Desc", "flat 5")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setOntListConfig", map[string]any{"onuid": "0/2/5", "mode": "sn", "sn": "HWTC-00000005", "lineid": "3", "desc": "flat 5", "action": "add"})
	if _, err := Operate(ctx, env, P+"ProvisionedONU.Add()", prqInputs("OnuID", "0/1/9", "Mode", "loid", "Info", "user9")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setOntListConfig", map[string]any{"onuid": "0/1/9", "mode": "loid", "sn": "", "loid": "user9", "lineid": "0", "desc": "", "action": "add"})
	if _, err := Operate(ctx, env, P+"ProvisionedONU.Add()", prqInputs("OnuID", "0/1/9")); err == nil {
		t.Fatal("Info is required")
	}
	if _, err := Operate(ctx, env, P+"ProvisionedONU.Delete()", prqInputs("OnuID", "0/1/1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delOntListConfig", map[string]any{"list": []any{map[string]any{"onuid": "0/1/1", "mode": "sn", "info": "HWTC-00000001", "lineid": "0", "desc": "-"}}})

	// PON port admin state and auth mode: one field per write, the rest -1.
	ports := &prqListStore{key: "portName", rows: []map[string]any{
		{"portNum": "1", "portName": "pon1", "portstate": "1", "portStatus": "1", "p2p": "0", "autoauth": "1", "authmode": "0", "loopdetect": "0", "autofind": "1", "loopbackshutdown": "0", "powerlimit": "0"}}}
	f.handleFunc("/goform/getPonPortBasicList", ports.get)
	f.handle("/goform/setPonPortBasicInfo", map[string]any{"errCode": "0"})
	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	if v, ok := msg.Get(P + "PON.Port.1.AuthMode"); !ok || wusp.ValueToString(v) != "0" {
		t.Fatalf("PON.Port.1.AuthMode = %v %v", v, ok)
	}
	if v, ok := msg.Get(P + "PONPort.1.Enable"); !ok || !v.AsBool() {
		t.Fatalf("PONPort.1.Enable = %v %v", v, ok)
	}
	if err := Set(ctx, env, P+"PONPort.1.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"port": prqStrs("pon1"), "portstate": "0", "autofind": "-1", "p2p": "-1", "autoauth": "-1", "authmode": "-1", "powerlimit": "-1", "loopbackdetect": "-1", "loopbackshutdown": "-1"}
	prqWantBody(t, f, "/goform/setPonPortBasicInfo", want)
	if err := Set(ctx, env, P+"PONPort.2.Enable", wusp.Bool(false)); err == nil {
		t.Fatal("uplink ports are not PON ports")
	}
	ports.rows[0]["authmode"] = "5"
	if err := Set(ctx, env, P+"PON.Port.1.AuthMode", wusp.String("5")); err != nil {
		t.Fatal(err)
	}
	want = map[string]any{"port": prqStrs("pon1"), "authmode": "5", "portstate": "-1", "autofind": "-1", "p2p": "-1", "autoauth": "-1", "powerlimit": "-1", "loopbackdetect": "-1", "loopbackshutdown": "-1"}
	prqWantBody(t, f, "/goform/setPonPortBasicInfo", want)

	// DNS: both slots present, the unset one empty; management VLAN bound.
	if v, ok := msg.Get(P + "Network.DNS.Server.2.Address"); !ok || wusp.ValueToString(v) != "" {
		t.Fatalf("Network.DNS.Server.2.Address = %v %v", v, ok)
	}
	if v, ok := msg.Get(P + "Network.DNS.ServerNumberOfEntries"); !ok || v.AsUint() != 2 {
		t.Fatalf("DNS count = %v", v)
	}
	if v, ok := msg.Get(P + "Network.Mgmt.VLAN"); !ok || wusp.ValueToString(v) != "4000" {
		t.Fatalf("Network.Mgmt.VLAN = %v %v", v, ok)
	}
}

func TestScopeLineProfileDetailTables(t *testing.T) {
	f, env, ctx, P := scopeEnv(t)
	f.handle("/goform/getLineprofileList", map[string]any{"list": []any{
		map[string]any{"profileid": "0", "profilename": "default", "onttype": "adaptive", "mapping_mode": "vlan", "traffic_mode": "car", "bind": "1"},
		map[string]any{"profileid": "5", "profilename": "lp5", "onttype": "hgu", "mapping_mode": "vlan", "traffic_mode": "car", "bind": "0"},
	}})
	detail := map[string]map[string]any{
		"/goform/getLineprofileTcontInfo":   {"0": []any{map[string]any{"tcontid": "1", "dbaprofile": "1"}}, "5": []any{map[string]any{"tcontid": "2", "dbaprofile": "3"}}},
		"/goform/getLineprofileGemInfo":     {"5": []any{map[string]any{"gemport": "100", "tcontid": "2", "qid": "-1", "usid": "1", "dsid": "-1"}}},
		"/goform/getLineprofileMappingInfo": {"5": []any{map[string]any{"mappingindex": "1", "vlan": "100", "gemport": "100", "mappingPort": "2", "mappingPortNum": "0"}}},
		"/goform/getLineprofileFlowInfo":    {"5": []any{map[string]any{"flowindex": "1", "port": "veip", "flowmode": "1", "cvid": "100", "svid": "0"}}},
		"/goform/getLineprofileMultInfo":    {"5": []any{map[string]any{"ont_port": "1", "mult_mode": "igmp-snooping", "mult_vlan": "200", "fast_leave": "enable", "max_groups": "-", "max_bw": "-", "dstag_action": "remove", "dstag_vlan": "-", "dstag_pri": "-"}}},
	}
	for path, byProfile := range detail {
		byProfile := byProfile
		f.handleFunc(path, func(b map[string]any) any {
			rows, _ := byProfile[Str(b["profileid"])].([]any)
			if rows == nil {
				rows = []any{}
			}
			return map[string]any{"list": rows}
		})
	}
	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	_ = env
	for path, want := range map[string]string{
		"LineProfile.TcontNumberOfEntries": "2", "LineProfile.Tcont.2.ProfileID": "5", "LineProfile.Tcont.2.DBAProfile": "3",
		"LineProfile.Gemport.1.Gemport": "100", "LineProfile.Gemport.1.USProfile": "1",
		"LineProfile.Mapping.1.VLAN": "100", "LineProfile.Flow.1.Port": "veip", "LineProfile.Flow.1.FlowMode": "1",
		"LineProfile.Multicast.1.Mode": "igmp-snooping", "LineProfile.MulticastNumberOfEntries": "1",
	} {
		if v, ok := msg.Get(P + path); !ok || wusp.ValueToString(v) != want {
			t.Errorf("%s = %v (%v), want %s", path, v, ok, want)
		}
	}
	// the flow getter is read with optype=line for every profile
	calls := f.callsTo("/goform/getLineprofileFlowInfo")
	if len(calls) != 2 || Str(calls[1].Body["optype"]) != "line" || Str(calls[1].Body["profileid"]) != "5" {
		t.Fatalf("flow getter calls: %+v", calls)
	}
}
