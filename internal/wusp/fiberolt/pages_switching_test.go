package fiberolt

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Switching menu, part 1 (internal/wusp/olt_pages_switching.go): every
// setter / add / delete / action posts exactly the body the web UI sends
// (OLT-WEBUI-CONTROLS.md, setters.txt B: lines), and the agent-safety
// guards (portStatus, vlanMember, vlanL3) refuse cutting the agent off.

// swRows is a stateful vendor list: the getter returns the rows, setters
// patch the row matched by match(body).
type swRows struct{ rows []map[string]any }

func (s *swRows) get(map[string]any) any {
	out := make([]any, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r)
	}
	return map[string]any{"list": out}
}

// patch copies body keys (except skip and "-1" no-change values) into the
// row whose key field equals want.
func (s *swRows) patch(key, want string, body map[string]any, skip ...string) {
	for _, r := range s.rows {
		if Str(r[key]) != want {
			continue
		}
	next:
		for k, v := range body {
			for _, x := range skip {
				if x == k {
					continue next
				}
			}
			if Str(v) == "-1" {
				continue
			}
			r[k] = v
		}
	}
}

func firstPort(body map[string]any) string {
	if arr, ok := body["port"].([]any); ok && len(arr) > 0 {
		return Str(arr[0])
	}
	return Str(body["port"])
}

var swOK = map[string]any{"errCode": "0"}

// swAgentFixture scripts getSysStatus (ge1 link up, ge2 down) and
// getQvlanList (VLAN 4000 carries 127.0.0.1, the fake server host, so it
// is the agent's VLAN).
func swAgentFixture(f *fakeOLT) *swRows {
	f.handle("/goform/getSysStatus", map[string]any{
		"deviceName": "OLT", "mngvlan": "",
		"port": []any{
			map[string]any{"portNum": "9", "portName": "ge1", "portStatus": "1"},
			map[string]any{"portNum": "10", "portName": "ge2", "portStatus": "2"},
		},
	})
	vlans := &swRows{rows: []map[string]any{
		{"vlanId": "1", "remark": "default", "ip": "192.168.1.100", "mask": "255.255.255.0", "ipType": "static", "threeLayersEn": "1"},
		{"vlanId": "4000", "remark": "VLAN4000", "ip": "127.0.0.1", "mask": "255.255.255.0", "ipType": "static", "threeLayersEn": "1"},
		{"vlanId": "300", "remark": "svc", "ip": "", "mask": "", "ipType": "", "threeLayersEn": "0"},
	}}
	f.handleFunc("/goform/getQvlanList", vlans.get)
	return vlans
}

func swWant(t *testing.T, f *fakeOLT, path string, n int, want map[string]any) {
	t.Helper()
	calls := f.callsTo(path)
	if len(calls) <= n {
		t.Fatalf("%s: %d calls, want call #%d", path, len(calls), n+1)
	}
	if got := calls[n].Body; !reflect.DeepEqual(got, want) {
		t.Fatalf("%s body #%d =\n  %v\nwant\n  %v", path, n+1, got, want)
	}
}

func swCollect(t *testing.T, env *Env) *wusp.Message {
	t.Helper()
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), env.API, nil, true, msg)
	return msg
}

func swParam(t *testing.T, msg *wusp.Message, rel, want string) {
	t.Helper()
	v, ok := msg.Get(wusp.WUSPOLTPrefix + rel)
	if !ok || wusp.ValueToString(v) != want {
		t.Fatalf("%s = %q (present %v), want %q", rel, wusp.ValueToString(v), ok, want)
	}
}

func TestSwitchingPortPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	swAgentFixture(f)
	ctx := context.Background()
	env := &Env{API: f.client()}
	P := wusp.WUSPOLTPrefix

	// ---- Port Config ------------------------------------------------------
	ge1 := map[string]any{"portNum": "9", "portName": "ge1", "desc": "uplink", "portIsolate": "0", "portStatus": "1", "portSpeed": "1000", "portDuplex": "1",
		"inletFlow": "6079881.0", "portbridge": "0", "outletFlow": "113224610.0", "jumboFrame": "1522", "negotiationMode": "1"}
	ge2 := map[string]any{"portNum": "10", "portName": "ge2", "desc": "--", "portIsolate": "1", "portStatus": "2", "portSpeed": "--", "portDuplex": "1",
		"inletFlow": "0", "portbridge": "0", "outletFlow": "0", "jumboFrame": "1522", "negotiationMode": "1"}
	basic := &swRows{rows: []map[string]any{ge1, ge2}}
	f.handleFunc("/goform/getPortBasicList", basic.get)
	f.handleFunc("/goform/setPortBasicInfo", func(b map[string]any) any {
		basic.patch("portName", firstPort(b), b, "port", "portName")
		return swOK
	})
	// ---- Mirror -----------------------------------------------------------
	mirror := &swRows{rows: []map[string]any{{"srcPort": []any{"pon1", "pon2"}, "destPort": "ge3", "direction": "both", "mirrorType": "local"}}}
	f.handleFunc("/goform/getPortMirrorList", mirror.get)
	f.handleFunc("/goform/setPortMirrorInfo", func(b map[string]any) any {
		mirror.patch("destPort", Str(b["destPort"]), b, "action", "originData")
		return swOK
	})
	f.handle("/goform/delPortMirrorList", swOK)
	// ---- LAG --------------------------------------------------------------
	f.handle("/goform/getPortAggregatorList", map[string]any{"list": []any{
		map[string]any{"groupIndex": "po1", "type": "static", "algorithm": "src-dst-mac", "port": []any{"ge5", "ge6"}},
	}})
	f.handle("/goform/setPortAggregatorRule", swOK)
	f.handle("/goform/delPortAggregatorList", swOK)
	// ---- Rate limit -------------------------------------------------------
	speed := &swRows{rows: []map[string]any{
		{"portNum": "1", "portName": "pon1", "exitRate": "0", "broadcastPacket": "0", "multicastPacket": "0", "unknownPacket": "0"},
		{"portNum": "9", "portName": "ge1", "exitRate": "500", "broadcastPacket": "100", "multicastPacket": "0", "unknownPacket": "0"},
	}}
	f.handleFunc("/goform/getPortSpeedList", speed.get)
	f.handleFunc("/goform/setPortSpeedInfo", func(b map[string]any) any {
		speed.patch("portName", firstPort(b), b, "port", "action", "originData", "speedLimit")
		return swOK
	})
	// ---- Statistics / optical ----------------------------------------------
	f.handle("/goform/getPackageStatisticsList", map[string]any{"list": []any{map[string]any{
		"portNum": "9", "portName": "ge1", "sendPacket": "5000000000", "sendBit": "123456789012", "receivePacket": "42", "receiveBit": "4200",
		"sendBroadcastNum": "1", "sendUnicastNum": "2", "sendErrorNum": "0", "sendDropNum": "0",
		"receiveBroadcastNum": "3", "receiveUnicastNum": "4", "receiveErrorNum": "5", "receiveDropNum": "6",
	}}})
	f.handle("/goform/clearPackageStatistics", swOK)
	f.handle("/goform/getPortOptical", map[string]any{"list": []any{map[string]any{
		"portNum": "15", "portName": "xge1", "temperature": "41.5", "supVol": "3.29", "txBiasCur": "6.1", "txPower": "-2.10", "rxPower": "-5.40",
		"name": "FS", "oui": "009065", "productname": "SFP-10GSR-85", "connector": "LC", "wavelen": "850", "version": "A", "sn": "S123", "date": "240101",
	}}})

	// Collect a few read-only values.
	msg := swCollect(t, env)
	swParam(t, msg, "Switching.Port.Config.1.Name", "ge1")
	swParam(t, msg, "Switching.Port.Config.2.Status", "2")
	swParam(t, msg, "Switching.Port.Config.1.Isolation", "false")
	swParam(t, msg, "Switching.Port.ConfigNumberOfEntries", "2")
	swParam(t, msg, "Switching.Port.Statistics.1.TxPackets", "5000000000")
	swParam(t, msg, "Switching.Port.Optical.1.ProductName", "SFP-10GSR-85")
	swParam(t, msg, "Switching.Port.LAG.1.Mode", "static")
	swParam(t, msg, "Switching.Port.LAG.1.MemberPorts", "ge5,ge6")
	swParam(t, msg, "Switching.Port.Mirror.1.SourcePorts", "pon1,pon2")

	// Port Config: description edit keeps speed/duplex/status unchanged ("-1").
	if err := Set(ctx, env, P+"Switching.Port.Config.1.Description", wusp.String("core uplink")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortBasicInfo", 0, map[string]any{
		"port": []any{"ge1"}, "portName": "ge1", "desc": "core uplink", "portSpeed": "-1", "portDuplex": "-1", "portStatus": "-1",
		"portIsolate": "0", "portbridge": "0", "jumboFrame": "1522",
	})
	if err := Set(ctx, env, P+"Switching.Port.Config.1.Isolation", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortBasicInfo", 1, map[string]any{
		"port": []any{"ge1"}, "portName": "ge1", "desc": "core uplink", "portSpeed": "-1", "portDuplex": "-1", "portStatus": "-1",
		"portIsolate": "1", "portbridge": "0", "jumboFrame": "1522",
	})
	// Shutting down ge2 (link down) is allowed.
	if err := Set(ctx, env, P+"Switching.Port.Config.2.Status", wusp.String("0")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortBasicInfo", 2, map[string]any{
		"port": []any{"ge2"}, "portName": "ge2", "desc": "--", "portSpeed": "-1", "portDuplex": "-1", "portStatus": "0",
		"portIsolate": "1", "portbridge": "0", "jumboFrame": "1522",
	})
	// Fixed speed: portDuplex "1" (FDX), status unchanged.
	if err := Set(ctx, env, P+"Switching.Port.Config.1.Speed", wusp.String("10000")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortBasicInfo", 3, map[string]any{
		"port": []any{"ge1"}, "portName": "ge1", "desc": "core uplink", "portSpeed": "10000", "portDuplex": "1", "portStatus": "-1",
		"portIsolate": "1", "portbridge": "0", "jumboFrame": "1522",
	})
	// Guard: ge1 is a link-up uplink; shutting it down is refused, nothing posted.
	n := len(f.callsTo("/goform/setPortBasicInfo"))
	if err := Set(ctx, env, P+"Switching.Port.Config.1.Status", wusp.String("0")); !errors.Is(err, ErrGuarded) {
		t.Fatalf("shut down ge1: err = %v, want guard", err)
	}
	if len(f.callsTo("/goform/setPortBasicInfo")) != n {
		t.Fatal("guarded write reached setPortBasicInfo")
	}
	if err := Set(ctx, env, P+"Switching.Port.Config.1.Status", wusp.String("2")); err == nil {
		t.Fatal("status 2 accepted")
	}

	// Mirror: edit (originData row), add, delete.
	if err := Set(ctx, env, P+"Switching.Port.Mirror.1.Direction", wusp.String("receive")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortMirrorInfo", 0, map[string]any{
		"srcPort": []any{"pon1", "pon2"}, "direction": "receive", "destPort": "ge3", "action": "edit",
		"originData": map[string]any{"srcPort": []any{"pon1", "pon2"}, "destPort": "ge3", "direction": "both", "mirrorType": "local"},
	})
	in := wusp.NewMessage()
	in.Set("DestinationPort", wusp.String("ge4"))
	in.Set("SourcePorts", wusp.String("pon3,ge1"))
	in.Set("Direction", wusp.String("transmit"))
	mirror.rows = append(mirror.rows, map[string]any{"srcPort": []any{"pon3", "ge1"}, "destPort": "ge4", "direction": "transmit", "mirrorType": "local"})
	if _, err := AddObject(ctx, env, P+"Switching.Port.Mirror.", in); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortMirrorInfo", 1, map[string]any{
		"srcPort": []any{"pon3", "ge1"}, "direction": "transmit", "destPort": "ge4", "action": "add",
	})
	if err := DeleteObject(ctx, env, P+"Switching.Port.Mirror.1."); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/delPortMirrorList", 0, map[string]any{"list": []any{
		map[string]any{"srcPort": []any{"pon1", "pon2"}, "destPort": "ge3", "direction": "receive", "mirrorType": "local"},
	}})

	// LAG: add posts groupType/number. This fake does not add the row, so
	// the new instance cannot be found (on a device it is the row whose key
	// was not there before the POST).
	in = wusp.NewMessage()
	in.Set("GroupIndex", wusp.String("2"))
	in.Set("Mode", wusp.String("dynamic"))
	in.Set("Algorithm", wusp.String("src-dst-ip"))
	in.Set("MemberPorts", wusp.String("ge3,ge4"))
	if _, err := AddObject(ctx, env, P+"Switching.Port.LAG.", in); err == nil || !strings.Contains(err.Error(), "not found on re-read") {
		t.Fatalf("LAG add: err = %v, want the known re-read limitation", err)
	}
	swWant(t, f, "/goform/setPortAggregatorRule", 0, map[string]any{
		"groupIndex": "2", "groupType": "dynamic", "algorithm": "src-dst-ip", "port": []any{"ge3", "ge4"}, "action": "add",
	})
	if err := DeleteObject(ctx, env, P+"Switching.Port.LAG.1."); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/delPortAggregatorList", 0, map[string]any{"list": []any{
		map[string]any{"groupIndex": "po1", "type": "static", "algorithm": "src-dst-mac", "port": []any{"ge5", "ge6"}},
	}})

	// Rate limit: row edit, port=[portName], action edit, originData row, speedLimit "".
	if err := Set(ctx, env, P+"Switching.Port.RateLimit.2.BroadcastLimit", wusp.Uint(200)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortSpeedInfo", 0, map[string]any{
		"port": []any{"ge1"}, "exitRate": "500", "broadcastPacket": "200", "multicastPacket": "0", "unknownPacket": "0", "speedLimit": "",
		"action": "edit", "originData": map[string]any{"portNum": "9", "portName": "ge1", "exitRate": "500", "broadcastPacket": "100", "multicastPacket": "0", "unknownPacket": "0"},
	})

	// Clear statistics.
	if _, err := Operate(ctx, env, P+"Switching.Port.ClearStatistics()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/clearPackageStatistics", 0, map[string]any{"action": "clear"})
}

func TestSwitchingVLANPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	vlans := swAgentFixture(f)
	ctx := context.Background()
	env := &Env{API: f.client()}
	P := wusp.WUSPOLTPrefix

	f.handleFunc("/goform/setQvlanInfo", func(b map[string]any) any {
		row := map[string]any{}
		for k, v := range b {
			switch k {
			case "vlanRemark":
				row["remark"] = v
			case "staticIp":
				row["ip"] = v
			case "action", "originData":
			default:
				row[k] = v
			}
		}
		vlans.patch("vlanId", Str(b["vlanId"]), row)
		return swOK
	})
	member := &swRows{rows: []map[string]any{
		{"portNum": "9", "portName": "ge1", "linkType": "trunk", "pvid": "1", "tagged": "100,4000", "untagged": "--"},
		{"portNum": "10", "portName": "ge2", "linkType": "access", "pvid": "1", "tagged": "--", "untagged": "1"},
	}}
	f.handleFunc("/goform/getPortMemberList", member.get)
	f.handleFunc("/goform/setPortMemberInfo", func(b map[string]any) any {
		member.patch("portName", firstPort(b), b, "port", "action", "originData")
		return swOK
	})
	qinqPort := &swRows{rows: []map[string]any{{"portName": "ge2", "qinqStatus": "0"}}}
	f.handleFunc("/goform/getQinqPortList", qinqPort.get)
	f.handleFunc("/goform/setQinqPortInfo", func(b map[string]any) any {
		qinqPort.patch("portName", firstPort(b), map[string]any{"qinqStatus": b["qinqenable"]})
		return swOK
	})
	f.handle("/goform/getQinqVlanList", map[string]any{"list": []any{
		map[string]any{"index": "1", "portName": "pon1", "startvlan": "100", "destvlan": "2000"},
	}})
	f.handle("/goform/setQinqVlanInfo", swOK)
	f.handle("/goform/delQinqVlanInfo", swOK)
	f.handle("/goform/getVlanTransformList", map[string]any{"list": []any{
		map[string]any{"index": "1", "portName": "pon2", "startvlan": "10", "destvlan": "20"},
	}})
	f.handle("/goform/setVlanTransformInfo", swOK)
	f.handle("/goform/delVlanTransformInfo", swOK)

	msg := swCollect(t, env)
	swParam(t, msg, "Switching.VLAN.List.2.IPAddress", "127.0.0.1")
	swParam(t, msg, "Switching.VLAN.List.2.L3Interface", "true")
	swParam(t, msg, "Switching.VLAN.PortMember.1.Tagged", "100,4000")
	swParam(t, msg, "Switching.VLAN.QinQPort.1.Mode", "0")
	swParam(t, msg, "Switching.VLAN.QinQ.1.DestVLAN", "2000")

	// 802.1Q VLAN edit on VLAN 300 (no L3 interface). The getter keys
	// remark/ip are re-posted as vlanRemark/staticIp ("set=get" Body).
	if err := Set(ctx, env, P+"Switching.VLAN.List.3.Description", wusp.String("service")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setQvlanInfo", 0, map[string]any{
		"vlanId": "300", "vlanRemark": "service", "threeLayersEn": "0", "ipType": "", "staticIp": "", "mask": "", "action": "edit",
		"originData": map[string]any{"vlanId": "300", "remark": "svc", "ip": "", "mask": "", "ipType": "", "threeLayersEn": "0"},
	})
	// vlanL3 guard: the agent's VLAN interface (127.0.0.1) keeps L3 and its address.
	n := len(f.callsTo("/goform/setQvlanInfo"))
	if err := Set(ctx, env, P+"Switching.VLAN.List.2.L3Interface", wusp.Bool(false)); !errors.Is(err, ErrGuarded) {
		t.Fatalf("disable agent VLAN L3: err = %v, want guard", err)
	}
	if err := Set(ctx, env, P+"Switching.VLAN.List.2.IPAddress", wusp.String("10.9.9.9")); !errors.Is(err, ErrGuarded) {
		t.Fatalf("move agent VLAN address: err = %v, want guard", err)
	}
	if len(f.callsTo("/goform/setQvlanInfo")) != n {
		t.Fatal("guarded write reached setQvlanInfo")
	}

	// Port member: ge2 (link down) edit posts the full row edit.
	if err := Set(ctx, env, P+"Switching.VLAN.PortMember.2.PVID", wusp.Uint(300)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortMemberInfo", 0, map[string]any{
		"port": []any{"ge2"}, "linkType": "access", "pvid": "300", "tagged": "--", "untagged": "1", "action": "edit",
		"originData": map[string]any{"portNum": "10", "portName": "ge2", "linkType": "access", "pvid": "1", "tagged": "--", "untagged": "1"},
	})
	// Adding a VLAN to the agent uplink is fine (4000 kept).
	if err := Set(ctx, env, P+"Switching.VLAN.PortMember.1.Tagged", wusp.String("100,200,4000")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setPortMemberInfo", 1, map[string]any{
		"port": []any{"ge1"}, "linkType": "trunk", "pvid": "1", "tagged": "100,200,4000", "untagged": "--", "action": "edit",
		"originData": map[string]any{"portNum": "9", "portName": "ge1", "linkType": "trunk", "pvid": "1", "tagged": "100,4000", "untagged": "--"},
	})
	// vlanMember guard: dropping VLAN 4000 (the agent's) from link-up ge1 is refused.
	n = len(f.callsTo("/goform/setPortMemberInfo"))
	if err := Set(ctx, env, P+"Switching.VLAN.PortMember.1.Tagged", wusp.String("100")); !errors.Is(err, ErrGuarded) {
		t.Fatalf("drop agent VLAN from ge1: err = %v, want guard", err)
	}
	if len(f.callsTo("/goform/setPortMemberInfo")) != n {
		t.Fatal("guarded write reached setPortMemberInfo")
	}

	// QinQ port: {port:[portName], qinqenable}.
	if err := Set(ctx, env, P+"Switching.VLAN.QinQPort.1.Mode", wusp.String("2")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setQinqPortInfo", 0, map[string]any{"port": []any{"ge2"}, "qinqenable": "2"})

	// QinQ rules / VLAN transform: add {port:[...], startvlan, endvlan, destvlan, action:add}, delete {list:[row]}.
	for _, c := range []struct{ obj, set, del string }{
		{"Switching.VLAN.QinQ.", "/goform/setQinqVlanInfo", "/goform/delQinqVlanInfo"},
		{"Switching.VLAN.Transform.", "/goform/setVlanTransformInfo", "/goform/delVlanTransformInfo"},
	} {
		in := wusp.NewMessage()
		in.Set("Port", wusp.String("pon3,pon4"))
		in.Set("StartVLAN", wusp.String("101"))
		in.Set("EndVLAN", wusp.String("101"))
		in.Set("DestVLAN", wusp.String("2001"))
		// This fake does not add the row, so the new instance cannot be
		// found (on a device: the key that appears after the POST).
		if _, err := AddObject(ctx, env, P+c.obj, in); err == nil || !strings.Contains(err.Error(), "not found on re-read") {
			t.Fatalf("%s add: err = %v, want the known re-read limitation", c.obj, err)
		}
		swWant(t, f, c.set, 0, map[string]any{"port": []any{"pon3", "pon4"}, "startvlan": "101", "endvlan": "101", "destvlan": "2001", "action": "add"})
		if err := DeleteObject(ctx, env, P+c.obj+"1."); err != nil {
			t.Fatal(err)
		}
		row := f.reply(map[string]string{
			"/goform/delQinqVlanInfo":      "/goform/getQinqVlanList",
			"/goform/delVlanTransformInfo": "/goform/getVlanTransformList",
		}[c.del]).(map[string]any)["list"].([]any)[0]
		swWant(t, f, c.del, 0, map[string]any{"list": []any{row}})
	}
	in := wusp.NewMessage()
	in.Set("Port", wusp.String("pon3"))
	if _, err := AddObject(ctx, env, P+"Switching.VLAN.QinQ.", in); err == nil {
		t.Fatal("QinQ add without StartVLAN/EndVLAN/DestVLAN accepted")
	}
}

func TestSwitchingMACLoopPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	swAgentFixture(f)
	ctx := context.Background()
	env := &Env{API: f.client()}
	P := wusp.WUSPOLTPrefix

	aging := "300"
	f.handleFunc("/goform/getMacAddrList", func(map[string]any) any {
		return map[string]any{"macagingtime": aging, "list": []any{
			map[string]any{"mac": "0090-4c06-a427", "type": "dynamic", "vlan": "100", "port": "pon1"},
			map[string]any{"mac": "0090-4c06-a428", "type": "static", "vlan": "200", "port": "ge2"},
		}}
	})
	f.handleFunc("/goform/setMacAgingCfg", func(b map[string]any) any { aging = Str(b["macagingtime"]); return swOK })
	f.handle("/goform/delMacAddrList", swOK)
	static := &swRows{rows: []map[string]any{{"vlanId": "200", "mac": "0090-4c06-a428", "port": "ge2"}}}
	f.handleFunc("/goform/getStaticMacList", static.get)
	f.handleFunc("/goform/setStaticMacInfo", func(b map[string]any) any {
		if b["action"] == "edit" {
			static.patch("mac", Str(b["mac"]), b, "action", "originData")
		} else {
			static.rows = append(static.rows, map[string]any{"vlanId": b["vlanId"], "mac": b["mac"], "port": b["port"]})
		}
		return swOK
	})
	f.handle("/goform/delStaticMacRule", swOK)
	loop := &swRows{rows: []map[string]any{
		{"portNum": "9", "portName": "ge1", "loopDetectEn": "0", "loopVid": "--", "txIntervalTime": "10", "resumeTime": "180"},
	}}
	f.handleFunc("/goform/getGlobalLoopDetection", loop.get)
	f.handleFunc("/goform/setGlobalLoopDetection", func(b map[string]any) any {
		loop.patch("portName", Str(b["portName"]), b, "port", "portName")
		return swOK
	})
	f.handle("/goform/getPonLoopDetectionList", map[string]any{"loopDetectEn": "1", "list": []any{
		map[string]any{"ontId": "0/3/5", "ontSn": "HWTC-00000005", "upRemainingTime": "120"},
	}})
	f.handle("/goform/setForcePonLoopDetection", swOK)
	f.handle("/goform/getUplinkLoopDetectionList", map[string]any{"list": []any{
		map[string]any{"portname": "ge4", "isloop": "1", "portState": "block", "upRemainingTime": "60"},
	}})
	f.handle("/goform/setForceUplinkLoopDetection", swOK)

	msg := swCollect(t, env)
	swParam(t, msg, "Switching.MAC.AgingTime", "300")
	swParam(t, msg, "Switching.MAC.Address.2.Type", "static")
	swParam(t, msg, "Switching.MAC.Static.1.Port", "ge2")
	swParam(t, msg, "Switching.Loop.Port.1.Enable", "false")
	swParam(t, msg, "Switching.Loop.PON.Enable", "true")
	swParam(t, msg, "Switching.Loop.LoopedONT.1.SerialNumber", "HWTC-00000005")
	swParam(t, msg, "Switching.Loop.Uplink.1.Looped", "true")
	swParam(t, msg, "Switching.Loop.Uplink.1.PortState", "block")

	// MAC aging: {macagingtime} only.
	if err := Set(ctx, env, P+"Switching.MAC.AgingTime", wusp.Uint(600)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setMacAgingCfg", 0, map[string]any{"macagingtime": "600"})
	if err := DeleteObject(ctx, env, P+"Switching.MAC.Address.1."); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/delMacAddrList", 0, map[string]any{"list": []any{
		map[string]any{"mac": "0090-4c06-a427", "type": "dynamic", "vlan": "100", "port": "pon1"},
	}})

	// Static MAC: port is a plain string; edit carries originData.
	if err := Set(ctx, env, P+"Switching.MAC.Static.1.Port", wusp.String("ge3")); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setStaticMacInfo", 0, map[string]any{
		"port": "ge3", "vlanId": "200", "mac": "0090-4c06-a428", "action": "edit",
		"originData": map[string]any{"vlanId": "200", "mac": "0090-4c06-a428", "port": "ge2"},
	})
	in := wusp.NewMessage()
	in.Set("VLANID", wusp.String("300"))
	in.Set("MACAddress", wusp.String("0011-2233-4455"))
	in.Set("Port", wusp.String("pon2"))
	if _, err := AddObject(ctx, env, P+"Switching.MAC.Static.", in); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setStaticMacInfo", 1, map[string]any{"port": "pon2", "vlanId": "300", "mac": "0011-2233-4455", "action": "add"})
	if err := DeleteObject(ctx, env, P+"Switching.MAC.Static.1."); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/delStaticMacRule", 0, map[string]any{"list": []any{
		map[string]any{"vlanId": "200", "mac": "0090-4c06-a428", "port": "ge3"},
	}})

	// Loop detection row edit: port=[portName] + portName, no action/originData.
	if err := Set(ctx, env, P+"Switching.Loop.Port.1.Enable", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setGlobalLoopDetection", 0, map[string]any{
		"port": []any{"ge1"}, "portName": "ge1", "loopDetectEn": "1", "loopVid": "--", "txIntervalTime": "10", "resumeTime": "180",
	})
	if err := Set(ctx, env, P+"Switching.Loop.Port.1.TxInterval", wusp.Uint(30)); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setGlobalLoopDetection", 1, map[string]any{
		"port": []any{"ge1"}, "portName": "ge1", "loopDetectEn": "1", "loopVid": "--", "txIntervalTime": "30", "resumeTime": "180",
	})

	// Recover actions.
	in = wusp.NewMessage()
	in.Set("ONTID", wusp.String("0/3/5"))
	in.Set("Port", wusp.String("pon3"))
	if _, err := Operate(ctx, env, P+"Switching.Loop.RecoverONT()", in); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setForcePonLoopDetection", 0, map[string]any{"ontId": "0/3/5", "port": "pon3"})
	in = wusp.NewMessage()
	in.Set("Port", wusp.String("ge4"))
	if _, err := Operate(ctx, env, P+"Switching.Loop.RecoverUplink()", in); err != nil {
		t.Fatal(err)
	}
	swWant(t, f, "/goform/setForceUplinkLoopDetection", 0, map[string]any{"port": "ge4"})
	if _, err := Operate(ctx, env, P+"Switching.Loop.RecoverUplink()", wusp.NewMessage()); err == nil {
		t.Fatal("RecoverUplink without Port accepted")
	}
}
