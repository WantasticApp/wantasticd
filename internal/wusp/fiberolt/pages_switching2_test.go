package fiberolt

import (
	"context"
	"reflect"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Switching part 2 (DHCP snooping, spanning tree, IGMP): every setter and
// command bound by olt_pages_switching2.go must post exactly the body the
// web UI posts (OLT-WEBUI-CONTROLS.md / setters.txt).

// sw2Form is a stateful form getter: setters merge their body into it.
func sw2Form(f *fakeOLT, get string, state map[string]any, sets ...string) {
	f.handleFunc(get, func(map[string]any) any { return state })
	for _, s := range sets {
		f.handleFunc(s, func(b map[string]any) any {
			for k, v := range b {
				state[k] = v
			}
			return map[string]any{"errCode": "0"}
		})
	}
}

func sw2Ok(f *fakeOLT, paths ...string) {
	for _, p := range paths {
		f.handle(p, map[string]any{"errCode": "0"})
	}
}

func sw2Body(t *testing.T, f *fakeOLT, path string, want map[string]any) {
	t.Helper()
	calls := f.callsTo(path)
	if len(calls) == 0 {
		t.Fatalf("%s was not called", path)
	}
	got := calls[len(calls)-1].Body
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s body =\n %v\nwant\n %v", path, got, want)
	}
}

func dhcpSnoopRow() map[string]any {
	return map[string]any{
		"portNum": "ge1", "portType": "trust", "optionStatusEn": "1", "optionPloyType": "replace", "optionFormat": "0", "optionDelimiter": "1",
		"circuitidType": "2", "circuitiddef": "", "circuitsysname": true, "circuitsysmac": true, "circuitvlanid": false, "circuitportname": true,
		"circuitontid": true, "circuitontmac": false, "circuitontsn": true, "circuitontmodel": false,
		"remoteidType": "1", "remoteiddef": "olt-a", "remotesysname": true, "remotesysmac": true, "remotevlanid": true, "remoteportname": true,
		"remoteontid": true, "remoteontmac": true, "remoteontsn": true, "remoteontmodel": true,
	}
}

func TestSwitching2DHCPSnoop(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	rows := []any{dhcpSnoopRow()}
	snoop := map[string]any{"dhcpSnoopEn": "1", "dhcpRelayEn": "0", "dhcpServerEn": "0", "vlanList": "10", "list": rows}
	sw2Form(f, "/goform/getDhcpSnoopList", snoop, "/goform/setDhcpSnoopEn", "/goform/setDhcpSnoopVlanEn")
	f.handleFunc("/goform/setDhcpSnoopInfo", func(b map[string]any) any {
		row := rows[0].(map[string]any)
		for k, v := range b {
			if k != "port" && k != "action" && k != "originData" {
				row[k] = v
			}
		}
		return map[string]any{"errCode": "0"}
	})
	clients := []any{
		map[string]any{"index": "1", "ipaddr": "10.0.0.5", "macaddr": "00:11:22:33:44:55", "interface": "pon1", "vlan": "100", "expire": "86400", "remaintime": "8000"},
	}
	f.handle("/goform/getDhcpClientList", map[string]any{"list": clients})
	sw2Ok(f, "/goform/delDhcpClientList")

	client := f.client()
	env := &Env{API: client}
	ctx := context.Background()
	p := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, client, nil, true, msg)
	if v, ok := msg.Get(p + "Switching.DHCPSnoop.Enable"); !ok || !v.AsBool() {
		t.Fatalf("DHCPSnoop.Enable = %v %v", v, ok)
	}
	if v, ok := msg.Get(p + "Switching.DHCPSnoop.RelayEnable"); !ok || v.AsBool() {
		t.Fatalf("DHCPSnoop.RelayEnable = %v %v", v, ok)
	}
	if v, ok := msg.Get(p + "Switching.DHCPSnoop.Port.1.RemoteID"); !ok || wusp.ValueToString(v) != "olt-a" {
		t.Fatalf("Port.1.RemoteID = %v %v", v, ok)
	}
	if v, ok := msg.Get(p + "Switching.DHCPSnoop.Client.1.MACAddress"); !ok || wusp.ValueToString(v) != "00:11:22:33:44:55" {
		t.Fatalf("Client.1.MACAddress = %v %v", v, ok)
	}

	// Global switch: posted alone, "1"/"0".
	if err := Set(ctx, env, p+"Switching.DHCPSnoop.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setDhcpSnoopEn", map[string]any{"dhcpSnoopEn": "0"})

	// VLAN list: Confirm posts {vlanList} only.
	if err := Set(ctx, env, p+"Switching.DHCPSnoop.VLANList", wusp.String("10,20-30")); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setDhcpSnoopVlanEn", map[string]any{"vlanList": "10,20-30"})

	// Row edit: whole dialog + action edit, port=[row.portNum], originData=row.
	orig := dhcpSnoopRow()
	if err := Set(ctx, env, p+"Switching.DHCPSnoop.Port.1.PortType", wusp.String("nontrust")); err != nil {
		t.Fatal(err)
	}
	want := dhcpSnoopRow()
	delete(want, "portNum")
	want["portType"] = "nontrust"
	want["action"] = "edit"
	want["port"] = []any{"ge1"}
	want["originData"] = orig
	sw2Body(t, f, "/goform/setDhcpSnoopInfo", want)

	// A checkbox is posted as a JSON boolean.
	if err := Set(ctx, env, p+"Switching.DHCPSnoop.Port.1.CircuitIDVLANID", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	got := f.callsTo("/goform/setDhcpSnoopInfo")[1].Body
	if got["circuitvlanid"] != true || got["portType"] != "nontrust" {
		t.Fatalf("checkbox edit body = %v", got)
	}
	if Set(ctx, env, p+"Switching.DHCPSnoop.Port.1.Option82Policy", wusp.String("bogus")) == nil {
		t.Fatal("Option82Policy accepted a value outside its enum")
	}

	// Binding delete: {list:[row]}.
	if err := DeleteObject(ctx, env, p+"Switching.DHCPSnoop.Client.1."); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/delDhcpClientList", map[string]any{"list": []any{
		map[string]any{"index": "1", "ipaddr": "10.0.0.5", "macaddr": "00:11:22:33:44:55", "interface": "pon1", "vlan": "100", "expire": "86400", "remaintime": "8000"},
	}})
}

func TestSwitching2SpanningTree(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	stp := map[string]any{
		"treeStatusEn": "1", "treeVersion": "RSTP", "agingTime": "20", "helloTime": "2", "forwardDelay": "15", "maxHopCount": "20",
		"bridgePriority": "32768", "domain": "region1", "correctionLevel": "0", "summary": "0xABCD",
		"bridgeId": "32768.0090.4c06.a427", "rootBridgeId": "32768.0090.4c06.a427", "rootDomainId": "-", "rootPort": "-",
		"rootPathCost": "0", "inRootPathCost": "0", "topoStatus": "stable", "topoChangeTime": "0d0h1m",
	}
	sw2Form(f, "/goform/getSpanningTreeInfo", stp, "/goform/setSpanningTreeInfo")

	msti := []any{
		map[string]any{"instanceId": "0", "vlanList": "1-4094", "bridgePriority": "32768"},
		map[string]any{"instanceId": "1", "vlanList": "10-12", "bridgePriority": "4096"},
	}
	f.handleFunc("/goform/getMstpInstanceList", func(map[string]any) any { return map[string]any{"list": msti} })
	f.handleFunc("/goform/setMstpInstanceInfo", func(b map[string]any) any {
		if b["action"] == "add" {
			msti = append(msti, map[string]any{"instanceId": b["instanceId"], "vlanList": b["vlanList"], "bridgePriority": b["bridgePriority"]})
		} else {
			for _, r := range msti {
				if row := r.(map[string]any); row["instanceId"] == b["instanceId"] {
					row["vlanList"], row["bridgePriority"] = b["vlanList"], b["bridgePriority"]
				}
			}
		}
		return map[string]any{"errCode": "0"}
	})
	sw2Ok(f, "/goform/delMstpInstanceList", "/goform/clearPortTreeStatistics", "/goform/setPortTreeStatusInfo")

	ports := []any{map[string]any{"portNum": "9", "portName": "ge1", "stpEn": "1", "edgePort": "0", "p2pPort": "1"}}
	f.handle("/goform/getPortTreeList", map[string]any{"list": ports})
	f.handleFunc("/goform/setPortTreeInfo", func(b map[string]any) any {
		ports[0].(map[string]any)["p2pPort"] = b["p2pPort"]
		return map[string]any{"errCode": "0"}
	})
	f.handle("/goform/getPortTreeStatisticsList", map[string]any{"list": []any{
		map[string]any{"portNum": "9", "portName": "ge1", "sendMstp": "0", "sendRstp": "120", "sendStp": "0", "sendTcn": "1",
			"receiveMstp": "0", "receiveRstp": "118", "receiveStp": "0", "dropTcn": "2", "dropUnknown": "0", "dropIllegal": "0"},
	}})
	f.handle("/goform/getPortTreeStatusList", map[string]any{"instanceList": []any{"0", "1"}, "list": []any{
		map[string]any{"portNum": "9", "portName": "ge1", "portRole": "2", "portStatus": "3", "domainRoot": "-", "bridgeId": "32768.0090.4c06.a427",
			"port": "128.9", "priority": "128", "portPathCost": "20000"},
	}})

	client := f.client()
	env := &Env{API: client}
	ctx := context.Background()
	p := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, client, nil, true, msg)
	checks := map[string]string{
		"Switching.STP.BridgeID":                 "32768.0090.4c06.a427",
		"Switching.STP.TopologyStatus":           "stable",
		"Switching.STP.MaxAge":                   "20",
		"Switching.STP.MSTI.2.VLANList":          "10-12",
		"Switching.STP.Port.1.P2P":               "1",
		"Switching.STP.PortStats.1.TxRSTP":       "120",
		"Switching.STP.PortStats.1.RxTCN":        "2",
		"Switching.STP.InstanceInfo.InstanceIDs": "0,1",
		"Switching.STP.CISTPort.1.PathCost":      "20000",
	}
	for path, wantV := range checks {
		if v, ok := msg.Get(p + path); !ok || wusp.ValueToString(v) != wantV {
			t.Errorf("%s = %v (%v), want %s", path, v, ok, wantV)
		}
	}
	// The instance table is read for instance 0 (CIST).
	if c := f.callsTo("/goform/getPortTreeStatusList"); len(c) == 0 || c[0].Body["instanceId"] != "0" {
		t.Fatalf("getPortTreeStatusList calls = %v", c)
	}

	// Status switch: {treeStatusEn} alone.
	if err := Set(ctx, env, p+"Switching.STP.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setSpanningTreeInfo", map[string]any{"treeStatusEn": "0"})

	// Confirm: the 8 bridge fields.
	if err := Set(ctx, env, p+"Switching.STP.HelloTime", wusp.Uint(3)); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setSpanningTreeInfo", map[string]any{
		"treeVersion": "RSTP", "agingTime": "20", "helloTime": "3", "forwardDelay": "15", "maxHopCount": "20",
		"bridgePriority": "32768", "domain": "region1", "correctionLevel": "0",
	})
	if err := Set(ctx, env, p+"Switching.STP.BridgePriority", wusp.String("1000")); err == nil {
		t.Fatal("BridgePriority accepted a non-multiple of 4096")
	}

	// MSTP instance add.
	in := wusp.NewMessage()
	in.Set("InstanceID", wusp.String("5"))
	in.Set("VLANList", wusp.String("100-102"))
	in.Set("BridgePriority", wusp.String("8192"))
	if _, err := AddObject(ctx, env, p+"Switching.STP.MSTI.", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setMstpInstanceInfo", map[string]any{"instanceId": "5", "vlanList": "100-102", "bridgePriority": "8192", "action": "add"})

	// Priority-only edit: originData + empty VLAN deltas.
	if err := Set(ctx, env, p+"Switching.STP.MSTI.2.BridgePriority", wusp.String("12288")); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setMstpInstanceInfo", map[string]any{
		"instanceId": "1", "vlanList": "10-12", "bridgePriority": "12288", "action": "edit",
		"addList": []any{}, "delList": []any{},
		"originData": map[string]any{"instanceId": "1", "vlanList": "10-12", "bridgePriority": "4096"},
	})

	// VLAN mapping edit through the command.
	in = wusp.NewMessage()
	in.Set("InstanceID", wusp.String("1"))
	in.Set("VLANList", wusp.String("10-11,20"))
	in.Set("BridgePriority", wusp.String("12288"))
	in.Set("AddList", wusp.String("20"))
	in.Set("DelList", wusp.String("12"))
	if _, err := Operate(ctx, env, p+"Switching.STP.EditMSTI()", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setMstpInstanceInfo", map[string]any{
		"instanceId": "1", "vlanList": "10-11,20", "bridgePriority": "12288", "action": "edit",
		"addList": []any{"20"}, "delList": []any{"12"},
	})
	// Empty deltas are posted as [].
	in = wusp.NewMessage()
	in.Set("InstanceID", wusp.String("1"))
	in.Set("VLANList", wusp.String("10-11,20"))
	in.Set("BridgePriority", wusp.String("0"))
	if _, err := Operate(ctx, env, p+"Switching.STP.EditMSTI()", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setMstpInstanceInfo", map[string]any{
		"instanceId": "1", "vlanList": "10-11,20", "bridgePriority": "0", "action": "edit",
		"addList": []any{}, "delList": []any{},
	})

	// MSTP instance delete: {list:[row]}.
	if err := DeleteObject(ctx, env, p+"Switching.STP.MSTI.2."); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/delMstpInstanceList", map[string]any{"list": []any{
		map[string]any{"instanceId": "1", "vlanList": "10-11,20", "bridgePriority": "0"},
	}})

	// Port P2P: {port:[row.portName], p2pPort}.
	if err := Set(ctx, env, p+"Switching.STP.Port.1.P2P", wusp.String("2")); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setPortTreeInfo", map[string]any{"port": []any{"ge1"}, "p2pPort": "2"})

	// Clear statistics.
	if _, err := Operate(ctx, env, p+"Switching.STP.ClearPortStats()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/clearPortTreeStatistics", map[string]any{"action": "clear"})

	// Instance port priority / path cost (multi-port Edit dialog).
	in = wusp.NewMessage()
	in.Set("Ports", wusp.String("ge1,xge1"))
	in.Set("InstanceID", wusp.String("1"))
	in.Set("Priority", wusp.String("32"))
	in.Set("PathCost", wusp.String("2000"))
	if _, err := Operate(ctx, env, p+"Switching.STP.SetInstancePort()", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setPortTreeStatusInfo", map[string]any{
		"srcPort": []any{"ge1", "xge1"}, "instanceId": "1", "priority": "32", "portPathCost": "2000", "action": "add",
	})
	in.Set("Priority", wusp.String("33"))
	if _, err := Operate(ctx, env, p+"Switching.STP.SetInstancePort()", in); err == nil {
		t.Fatal("Priority accepted a non-multiple of 16")
	}
}

func TestSwitching2IGMP(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	sw2Form(f, "/goform/getIgmpSnoopEn", map[string]any{"igmpSnoopingEn": "1"}, "/goform/setIgmpSnoopEn")
	f.handle("/goform/getIgmpVlanInfo", map[string]any{"mulVlanId": "100", "vlanList": []any{
		map[string]any{"vlanId": "100", "vlanEn": "1", "mulVlanEn": "0", "igmpVersion": "v2", "fastleave": "1", "reportsup": "0",
			"maxResponseTime": "10", "query": "0", "sourceip": "192.168.1.100"},
	}})
	f.handle("/goform/getMulGroupList", map[string]any{"list": []any{
		map[string]any{"portNum": "pon1", "vlanid": "100", "groups": "239.1.1.1;239.1.1.2;"},
	}})
	f.handle("/goform/getMulrouterList", map[string]any{"list": []any{map[string]any{"vlanid": "100", "portNum": "ge1"}}})
	routers := []any{map[string]any{"vlanId": "100", "port": "ge2"}}
	f.handleFunc("/goform/getMulRouterTab", func(map[string]any) any { return map[string]any{"list": routers} })
	f.handleFunc("/goform/setMulRouterTab", func(b map[string]any) any {
		routers = append(routers, map[string]any{"vlanId": b["vlanId"], "port": b["port"]})
		return map[string]any{"errCode": "0"}
	})
	f.handle("/goform/getIGSStatistics", map[string]any{"list": []any{
		map[string]any{"portName": "ge1", "vlan": "100", "txQuerygeneral": "7", "txQuerygroup": "0", "txReportV1": "0", "txReportV2": "3",
			"txReportV3": "0", "txLeaveV2": "0", "txOther": "0", "rxQuerygeneral": "0", "rxQuerygroup": "0", "rxReportV1": "0",
			"rxReportV2": "12", "rxReportV3": "0", "rxLeaveV2": "1", "rxOther": "0"},
	}})
	sw2Ok(f, "/goform/setIgmpVlanInfo", "/goform/delMulRouterTab")

	client := f.client()
	env := &Env{API: client}
	ctx := context.Background()
	p := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, client, nil, true, msg)
	checks := map[string]string{
		"Switching.IGMP.Enable":                 "true",
		"Switching.IGMP.VLAN.1.Version":         "v2",
		"Switching.IGMP.VLAN.1.MaxResponseTime": "10",
		"Switching.IGMP.Group.1.Groups":         "239.1.1.1;239.1.1.2;",
		"Switching.IGMP.DynamicRouter.1.Port":   "ge1",
		"Switching.IGMP.StaticRouter.1.Port":    "ge2",
		"Switching.IGMP.Stats.1.RxReportV2":     "12",
	}
	for path, wantV := range checks {
		if v, ok := msg.Get(p + path); !ok || wusp.ValueToString(v) != wantV {
			t.Errorf("%s = %v (%v), want %s", path, v, ok, wantV)
		}
	}

	// Snooping switch: {igmpSnoopingEn} alone.
	if err := Set(ctx, env, p+"Switching.IGMP.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setIgmpSnoopEn", map[string]any{"igmpSnoopingEn": "0"})

	// Global tab Confirm: all nine fields.
	in := wusp.NewMessage()
	for k, v := range map[string]string{
		"VLANID": "100", "Enable": "true", "MulticastVLANEnable": "false", "Version": "v3", "FastLeave": "true",
		"ReportSuppression": "false", "MaxResponseTime": "12", "Querier": "true", "QuerierSourceIP": "10.0.0.1",
	} {
		in.Set(k, wusp.String(v))
	}
	if _, err := Operate(ctx, env, p+"Switching.IGMP.SetVLAN()", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setIgmpVlanInfo", map[string]any{
		"mulVlanId": "100", "vlanEn": "1", "mulVlanEn": "0", "igmpVersion": "v3", "fastleave": "1", "reportsup": "0",
		"maxResponseTime": "12", "query": "1", "sourceip": "10.0.0.1",
	})
	// Every field is posted: a missing input is refused, not reset.
	partial := wusp.NewMessage()
	partial.Set("VLANID", wusp.String("100"))
	partial.Set("Querier", wusp.String("false"))
	if _, err := Operate(ctx, env, p+"Switching.IGMP.SetVLAN()", partial); err == nil {
		t.Fatal("SetVLAN accepted a partial input set")
	}
	if n := len(f.callsTo("/goform/setIgmpVlanInfo")); n != 1 {
		t.Fatalf("setIgmpVlanInfo calls = %d", n)
	}

	// Static router port add: port as a plain string.
	in = wusp.NewMessage()
	in.Set("VLANID", wusp.String("200"))
	in.Set("Port", wusp.String("xge1"))
	if _, err := AddObject(ctx, env, p+"Switching.IGMP.StaticRouter.", in); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/setMulRouterTab", map[string]any{"port": "xge1", "vlanId": "200", "action": "add"})

	// Static router port delete: {list:[row]}.
	if err := DeleteObject(ctx, env, p+"Switching.IGMP.StaticRouter.1."); err != nil {
		t.Fatal(err)
	}
	sw2Body(t, f, "/goform/delMulRouterTab", map[string]any{"list": []any{map[string]any{"vlanId": "100", "port": "ge2"}}})
}
