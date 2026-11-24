package fiberolt

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Golden bodies for the Profile, Routing and QoS Policy page specs: every
// setter/add/delete/operate posts exactly what the web UI sends
// (OLT-WEBUI-CONTROLS.md / setters.txt).

// prqListStore is a stateful goform list (getter + add/edit setter + delete).
type prqListStore struct {
	mu   sync.Mutex
	key  string
	rows []map[string]any
	// rename maps setter keys to getter keys (trafficmode -> traffic_mode).
	rename map[string]string
	extra  map[string]any // getter top-level fields besides list
}

func (s *prqListStore) get(map[string]any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]any, 0, len(s.rows))
	for _, r := range s.rows {
		cp := map[string]any{}
		for k, v := range r {
			cp[k] = v
		}
		list = append(list, cp)
	}
	out := map[string]any{"list": list}
	for k, v := range s.extra {
		out[k] = v
	}
	return out
}

func (s *prqListStore) set(b map[string]any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := map[string]any{}
	for k, v := range b {
		switch k {
		case "action", "originData", "item":
			continue
		}
		if n, ok := s.rename[k]; ok {
			k = n
		}
		row[k] = v
	}
	for _, r := range s.rows {
		if r[s.key] == row[s.key] {
			for k, v := range row {
				r[k] = v
			}
			return map[string]any{"errCode": "0"}
		}
	}
	s.rows = append(s.rows, row)
	return map[string]any{"errCode": "0"}
}

func (s *prqListStore) del(b map[string]any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, _ := b["list"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		for i, r := range s.rows {
			if r[s.key] == m[s.key] {
				s.rows = append(s.rows[:i], s.rows[i+1:]...)
				break
			}
		}
	}
	return map[string]any{"errCode": "0"}
}

func (s *prqListStore) serve(f *fakeOLT, get, set, del string) {
	f.handleFunc(get, s.get)
	if set != "" {
		f.handleFunc(set, s.set)
	}
	if del != "" {
		f.handleFunc(del, s.del)
	}
}

func prqLastBody(t *testing.T, f *fakeOLT, path string) map[string]any {
	t.Helper()
	calls := f.callsTo(path)
	if len(calls) == 0 {
		t.Fatalf("no request to %s", path)
	}
	return calls[len(calls)-1].Body
}

func prqWantBody(t *testing.T, f *fakeOLT, path string, want map[string]any) {
	t.Helper()
	if got := prqLastBody(t, f, path); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s body =\n  %v\nwant\n  %v", path, got, want)
	}
}

func prqStrs(v ...string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func prqInputs(kv ...string) *wusp.Message {
	m := wusp.NewMessage()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i], wusp.String(kv[i+1]))
	}
	return m
}

func prqStateful(f *fakeOLT, get, set string, state map[string]any) {
	var mu sync.Mutex
	f.handleFunc(get, func(map[string]any) any {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]any{}
		for k, v := range state {
			out[k] = v
		}
		return out
	})
	f.handleFunc(set, func(b map[string]any) any {
		mu.Lock()
		defer mu.Unlock()
		for k, v := range b {
			state[k] = v
		}
		return map[string]any{"errCode": "0"}
	})
}

func TestQoSPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	prqStateful(f, "/goform/getQoSScheduleInfo", "/goform/setQoSScheduleInfo",
		map[string]any{"qosMode": "WRR", "qosQueue": prqStrs("1", "2", "3", "4", "5", "6", "7", "8")})
	f.handle("/goform/getQoSDropQueueEn", map[string]any{"dropQueueExitEn": "1"})
	prqStateful(f, "/goform/getCosPriorityInfo", "/goform/setCosPriorityInfo",
		map[string]any{"cosPriority": prqStrs("0", "0", "1", "1", "2", "2", "3", "3")})
	dscp := make([]any, 64)
	for i := range dscp {
		dscp[i] = "1"
	}
	prqStateful(f, "/goform/getDscpQueueInfo", "/goform/setDscpQueueEn", map[string]any{"dscpEn": "1", "dscpQueue": dscp})
	f.handle("/goform/setDscpQueueInfo", map[string]any{"errCode": "0"})
	prio := &prqListStore{key: "portNum", rows: []map[string]any{
		{"portNum": "1", "cosPriority": "0", "trustMode": "unTrust"},
		{"portNum": "2", "cosPriority": "5", "trustMode": "dscp"},
	}}
	f.handleFunc("/goform/getPortPriorityList", prio.get)
	f.handleFunc("/goform/setPortPriorityInfo", func(b map[string]any) any {
		ports, _ := b["port"].([]any)
		for _, p := range ports {
			prio.set(map[string]any{"portNum": p, "cosPriority": b["cosPriority"], "trustMode": b["trustMode"]})
		}
		return map[string]any{"errCode": "0"}
	})
	env := &Env{API: f.client()}
	ctx := context.Background()
	P := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	for path, want := range map[string]string{
		"QoS.Scheduler.Mode": "WRR", "QoS.Scheduler.QueueWeights": "1,2,3,4,5,6,7,8",
		"QoS.Dot1p.PriorityQueue": "0,0,1,1,2,2,3,3", "QoS.PortPriority.2.TrustMode": "dscp",
	} {
		if v, ok := msg.Get(P + path); !ok || wusp.ValueToString(v) != want {
			t.Errorf("%s = %v, want %s", path, v, want)
		}
	}
	if v, ok := msg.Get(P + "QoS.DropQueue.Enable"); !ok || !v.AsBool() {
		t.Errorf("QoS.DropQueue.Enable = %v", v)
	}
	if v, ok := msg.Get(P + "QoS.PortPriorityNumberOfEntries"); !ok || v.AsUint() != 2 {
		t.Errorf("QoS.PortPriorityNumberOfEntries = %v", v)
	}

	// Mode re-posts the current weights.
	if err := Set(ctx, env, P+"QoS.Scheduler.Mode", wusp.String("SP")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setQoSScheduleInfo", map[string]any{"qosMode": "SP", "qosQueue": prqStrs("1", "2", "3", "4", "5", "6", "7", "8")})
	if err := Set(ctx, env, P+"QoS.Scheduler.Mode", wusp.String("RR")); err == nil {
		t.Fatal("QoS mode outside the enum accepted")
	}
	// Weights keep the current mode.
	if _, err := Operate(ctx, env, P+"QoS.Scheduler.SetQueueWeights()", prqInputs("Weights", "10,9,8,7,6,5,4,3")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setQoSScheduleInfo", map[string]any{"qosMode": "SP", "qosQueue": prqStrs("10", "9", "8", "7", "6", "5", "4", "3")})

	if _, err := Operate(ctx, env, P+"QoS.Dot1p.SetPriorityQueue()", prqInputs("Queues", "0,1,2,3,4,5,6,7")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setCosPriorityInfo", map[string]any{"cosPriority": prqStrs("0", "1", "2", "3", "4", "5", "6", "7")})

	if err := Set(ctx, env, P+"QoS.DSCP.Enable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setDscpQueueEn", map[string]any{"dscpEn": "0"})
	pm := make([]string, 64)
	for i := range pm {
		pm[i] = "-1"
	}
	pm[46] = "5"
	csv := ""
	for i, s := range pm {
		if i > 0 {
			csv += ","
		}
		csv += s
	}
	if _, err := Operate(ctx, env, P+"QoS.DSCP.SetPriorityMap()", prqInputs("Priorities", csv)); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setDscpQueueInfo", map[string]any{"dscpQueue": prqStrs(pm...)})

	// Row edit: action "one", port:[portNum].
	if err := Set(ctx, env, P+"QoS.PortPriority.1.TrustMode", wusp.String("dscp")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setPortPriorityInfo", map[string]any{"port": prqStrs("1"), "cosPriority": "0", "trustMode": "dscp", "action": "one"})
	if _, err := Operate(ctx, env, P+"QoS.PortPriority.SetPorts()", prqInputs("Ports", "1,2", "CoSPriority", "3", "TrustMode", "unTrust")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setPortPriorityInfo", map[string]any{"port": prqStrs("1", "2"), "cosPriority": "3", "trustMode": "unTrust", "action": "more"})
}

func TestRoutingPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	routes := &prqListStore{key: "destIp", rows: []map[string]any{
		{"destIp": "10.0.0.0", "mask": "255.0.0.0", "nextHop": "192.168.100.254"},
	}}
	routes.serve(f, "/goform/getStaticRouteList", "/goform/setStaticRouteInfo", "")
	arp := &prqListStore{key: "ip", extra: map[string]any{"agingTime": "1200"}, rows: []map[string]any{
		{"ip": "192.168.100.1", "mac": "00:11:22:33:44:55", "port": "4000", "type": "dhcp", "agingTime": "900", "staticLocal": "0"},
	}}
	arp.serve(f, "/goform/getArpTableList", "/goform/setArpTable", "/goform/delArpTable")
	f.handleFunc("/goform/setAgingTime", func(b map[string]any) any {
		arp.mu.Lock()
		arp.extra["agingTime"] = b["agingTime"]
		arp.mu.Unlock()
		return map[string]any{"errCode": "0"}
	})
	env := &Env{API: f.client()}
	ctx := context.Background()
	P := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	if v, ok := msg.Get(P + "Routing.ARP.AgingTime"); !ok || v.AsUint() != 1200 {
		t.Errorf("Routing.ARP.AgingTime = %v", v)
	}
	if v, ok := msg.Get(P + "Routing.ARP.Entry.1.MACAddress"); !ok || wusp.ValueToString(v) != "00:11:22:33:44:55" {
		t.Errorf("Routing.ARP.Entry.1.MACAddress = %v", v)
	}
	if v, ok := msg.Get(P + "Routing.StaticRoute.1.NextHop"); !ok || wusp.ValueToString(v) != "192.168.100.254" {
		t.Errorf("Routing.StaticRoute.1.NextHop = %v", v)
	}

	if err := Set(ctx, env, P+"Routing.StaticRoute.1.NextHop", wusp.String("192.168.100.250")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setStaticRouteInfo", map[string]any{
		"destIp": "10.0.0.0", "mask": "255.0.0.0", "nextHop": "192.168.100.250", "action": "edit",
		"originData": map[string]any{"destIp": "10.0.0.0", "mask": "255.0.0.0", "nextHop": "192.168.100.254"},
	})

	if err := Set(ctx, env, P+"Routing.ARP.AgingTime", wusp.Uint(600)); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setAgingTime", map[string]any{"agingTime": "600"})

	if _, err := AddObject(ctx, env, P+"Routing.ARP.Entry.", prqInputs("IPAddress", "192.168.100.9", "MACAddress", "00:aa:bb:cc:dd:ee", "VLAN", "4000")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setArpTable", map[string]any{"ip": "192.168.100.9", "mac": "00:aa:bb:cc:dd:ee", "port": "4000", "action": "add"})
	if _, err := AddObject(ctx, env, P+"Routing.ARP.Entry.", prqInputs("IPAddress", "192.168.100.8", "MACAddress", "00:aa:bb:cc:dd:ef", "VLAN", "5000")); err == nil {
		t.Fatal("ARP VLAN 5000 accepted")
	}
	if err := DeleteObject(ctx, env, P+"Routing.ARP.Entry.1."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delArpTable", map[string]any{"list": []any{
		map[string]any{"ip": "192.168.100.1", "mac": "00:11:22:33:44:55", "port": "4000", "type": "dhcp", "agingTime": "900", "staticLocal": "0"},
	}})
}

func TestProfilePagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	line := &prqListStore{key: "profileid", rename: map[string]string{"trafficmode": "traffic_mode"}, rows: []map[string]any{
		{"profileid": "0", "profilename": "default", "onttype": "sfu", "mapping_mode": "vlan", "traffic_mode": "car", "refMultProfileId": "-20", "bind": "0"},
	}}
	line.serve(f, "/goform/getLineprofileList", "/goform/setLineprofile", "/goform/delLineprofile")
	f.handle("/goform/setLineprofileMacAddrMax", map[string]any{"errCode": "0"})
	dba := &prqListStore{key: "profileid", rows: []map[string]any{
		{"profileid": "1", "profilename": "dba_1", "type": "4", "fix": "0", "assure": "0", "max": "1200000", "bind": "2"},
	}}
	dba.serve(f, "/goform/getDbaprofileList", "/goform/setDbaprofile", "/goform/delDbaprofile")
	us := &prqListStore{key: "profileid", rows: []map[string]any{
		{"profileid": "1", "profilename": "us_1", "cir": "1024", "cbs": "64", "pir": "2048", "pbs": "128", "bind": "0"},
	}}
	us.serve(f, "/goform/getUsprofileList", "/goform/setUsprofile", "/goform/delUsprofile")
	ds := &prqListStore{key: "profileid"}
	ds.serve(f, "/goform/getDsprofileList", "/goform/setDsprofile", "/goform/delDsprofile")
	uniq := &prqListStore{key: "profileId", rows: []map[string]any{
		{"profileId": "0/1/1", "profilename": "unique_0/1/1", "refWifiProfileId": "-20"},
	}}
	uniq.serve(f, "/goform/getOntUniqueProfileList", "/goform/setOntUniqueProfile", "/goform/delOntUniqueProfile")
	mc := &prqListStore{key: "profileId", rows: []map[string]any{{"profileId": "1", "profilename": "iptv"}}}
	mc.serve(f, "/goform/getOntMulticastProfileList", "/goform/setOntMulticastProfile", "/goform/delOntMulticastProfile")
	wifi := &prqListStore{key: "profileId", rows: []map[string]any{{"profileId": "1", "profilename": "home"}}}
	wifi.serve(f, "/goform/getWifiProfileList", "/goform/setWifiProfile", "/goform/delWifiProfile")
	env := &Env{API: f.client()}
	ctx := context.Background()
	P := wusp.WUSPOLTPrefix
	empty := map[string]any{}

	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	for path, want := range map[string]string{
		"Profile.Line.1.TrafficMode": "car", "Profile.Line.1.RefMulticastProfile": "-20",
		"Profile.DBA.1.Type": "4", "Profile.Upstream.1.PIR": "2048",
		"Profile.Unique.1.ONTID": "0/1/1", "Profile.WiFi.1.Name": "home",
	} {
		if v, ok := msg.Get(P + path); !ok || wusp.ValueToString(v) != want {
			t.Errorf("%s = %v, want %s", path, v, want)
		}
	}

	// Line profile: add (trafficmode key, item refmult), edit, delete.
	if _, err := AddObject(ctx, env, P+"Profile.Line.", prqInputs("ID", "5", "Name", "lp5", "ONTType", "hgu", "TrafficMode", "car", "RefMulticastProfile", "None")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setLineprofile", map[string]any{
		"profileid": "5", "profilename": "lp5", "onttype": "hgu", "trafficmode": "car", "refMultProfileId": "None",
		"item": "refmult", "action": "add", "originData": empty,
	})
	if _, err := AddObject(ctx, env, P+"Profile.Line.", prqInputs("ID", "6", "Name", "lp6")); err == nil {
		t.Fatal("line profile add without ONTType/TrafficMode accepted")
	}
	if _, err := Operate(ctx, env, P+"Profile.Line.Edit()", prqInputs("ID", "5", "Name", "lp5b", "ONTType", "sfu", "TrafficMode", "queue", "RefMulticastProfile", "1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setLineprofile", map[string]any{
		"profileid": "5", "profilename": "lp5b", "onttype": "sfu", "trafficmode": "queue", "refMultProfileId": "1",
		"item": "refmult", "action": "edit", "originData": empty,
	})
	if err := DeleteObject(ctx, env, P+"Profile.Line.1."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delLineprofile", map[string]any{"list": []any{map[string]any{
		"profileid": "0", "profilename": "default", "onttype": "sfu", "mapping_mode": "vlan", "traffic_mode": "car", "refMultProfileId": "-20", "bind": "0",
	}}})

	// Line profile detail adds (one setter, item selects the tab).
	ops := []struct {
		cmd  string
		in   *wusp.Message
		path string
		want map[string]any
	}{
		{"Profile.Line.AddFlow()", prqInputs("ProfileID", "5", "OptType", "line", "FlowIndex", "1", "Port", "veip", "FlowMode", "2", "CVID", "100", "SVID", "200"),
			"/goform/setLineprofile", map[string]any{"flowindex": "1", "port": "veip", "flowmode": "2", "cvid": "100", "svid": "200",
				"profileid": "5", "optype": "line", "item": "flow", "action": "add", "originData": empty}},
		{"Profile.Line.AddFlow()", prqInputs("ProfileID", "0/1/1", "OptType", "unique", "FlowIndex", "2", "Port", "1", "FlowMode", "1"),
			"/goform/setLineprofile", map[string]any{"flowindex": "2", "port": "1", "flowmode": "1", "cvid": "", "svid": "",
				"profileid": "0/1/1", "optype": "unique", "item": "flow", "action": "add", "originData": empty}},
		{"Profile.Line.AddTcont()", prqInputs("ProfileID", "5", "TcontID", "1", "DBAProfile", "1"),
			"/goform/setLineprofile", map[string]any{"tcontid": "1", "dbaprofile": "1", "profileid": "5", "item": "tcont", "action": "add", "originData": empty}},
		{"Profile.Line.AddGemport()", prqInputs("ProfileID", "5", "Gemport", "1", "TcontID", "1", "QueueID", "-1", "USProfile", "-1", "DSProfile", "1"),
			"/goform/setLineprofile", map[string]any{"gemport": "1", "tcontid": "1", "qid": "-1", "usid": "-1", "dsid": "1",
				"profileid": "5", "item": "gemport", "action": "add", "originData": empty}},
		{"Profile.Line.AddMapping()", prqInputs("ProfileID", "5", "MappingIndex", "0", "VLAN", "100", "MappingPort", "iphost", "Gemport", "1"),
			"/goform/setLineprofile", map[string]any{"mappingindex": "0", "vlan": "100", "mappingPort": "iphost", "gemport": "1",
				"profileid": "5", "item": "mapping", "action": "add", "originData": empty}},
		{"Profile.Line.AddMulticast()", prqInputs("ProfileID", "5", "ONTPort", "1", "Mode", "igmp-snooping", "VLAN", "300", "FastLeave", "enable",
			"MaxGroups", "Not_Required", "MaxBandwidth", "Not_Required", "DsTagAction", "Not_Required", "DsTagVLAN", "Not_Required", "DsTagPriority", "Not_Required"),
			"/goform/setLineprofile", map[string]any{"ont_port": "1", "mult_mode": "igmp-snooping", "mult_vlan": "300", "fast_leave": "enable",
				"max_groups": "Not_Required", "max_bw": "Not_Required", "dstag_action": "Not_Required", "dstag_vlan": "Not_Required", "dstag_pri": "Not_Required",
				"profileid": "5", "item": "mult", "action": "add", "originData": empty}},
		{"Profile.Line.SetMacLimit()", prqInputs("ProfileID", "5", "Port", "1", "MaxMAC", "16"),
			"/goform/setLineprofileMacAddrMax", map[string]any{"port": "1", "macCount": "16", "profileid": "5", "action": "add", "originData": empty}},
		{"Profile.Unique.Edit()", prqInputs("ONTID", "0/1/1", "Name", "u1", "RefWiFiProfile", "None"),
			"/goform/setOntUniqueProfile", map[string]any{"profileId": "0/1/1", "profilename": "u1", "refWifiProfileId": "None", "action": "edit"}},
	}
	for _, op := range ops {
		if _, err := Operate(ctx, env, P+op.cmd, op.in); err != nil {
			t.Fatalf("%s: %v", op.cmd, err)
		}
		prqWantBody(t, f, op.path, op.want)
	}
	if _, err := Operate(ctx, env, P+"Profile.Line.AddFlow()", prqInputs("OptType", "line", "FlowIndex", "1", "Port", "veip", "FlowMode", "1")); err == nil {
		t.Fatal("AddFlow without ProfileID accepted")
	}
	if _, err := Operate(ctx, env, P+"Profile.Line.AddFlow()", prqInputs("ProfileID", "5", "OptType", "srv", "FlowIndex", "1", "Port", "veip", "FlowMode", "1")); err == nil {
		t.Fatal("AddFlow with bad OptType accepted")
	}

	// DBA: per-column edit re-posts the whole row, originData {}.
	if err := Set(ctx, env, P+"Profile.DBA.1.Name", wusp.String("dba_be")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setDbaprofile", map[string]any{"profileid": "1", "profilename": "dba_be", "type": "4", "fix": "0", "assure": "0", "max": "1200000",
		"action": "edit", "originData": empty})
	if err := Set(ctx, env, P+"Profile.DBA.1.Type", wusp.String("9")); err == nil {
		t.Fatal("DBA type 9 accepted")
	}
	if _, err := AddObject(ctx, env, P+"Profile.DBA.", prqInputs("ID", "10", "Name", "dba_10", "Type", "3", "Assured", "1024", "Max", "4096")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setDbaprofile", map[string]any{"profileid": "10", "profilename": "dba_10", "type": "3", "fix": "", "assure": "1024", "max": "4096",
		"action": "add", "originData": empty})
	if err := DeleteObject(ctx, env, P+"Profile.DBA.2."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delDbaprofile", map[string]any{"list": []any{map[string]any{
		"profileid": "10", "profilename": "dba_10", "type": "3", "fix": "", "assure": "1024", "max": "4096"}}})

	// US / DS rate profiles.
	if err := Set(ctx, env, P+"Profile.Upstream.1.CIR", wusp.String("2048")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setUsprofile", map[string]any{"profileid": "1", "profilename": "us_1", "cir": "2048", "cbs": "64", "pir": "2048", "pbs": "128",
		"action": "edit", "originData": empty})
	if err := Set(ctx, env, P+"Profile.Upstream.1.CIR", wusp.String("10")); err == nil {
		t.Fatal("CIR 10 kbps accepted")
	}
	if _, err := AddObject(ctx, env, P+"Profile.Downstream.", prqInputs("ID", "2", "Name", "ds_2", "CIR", "100000", "CBS", "1000", "PIR", "200000", "PBS", "2000")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setDsprofile", map[string]any{"profileid": "2", "profilename": "ds_2", "cir": "100000", "cbs": "1000", "pir": "200000", "pbs": "2000",
		"action": "add", "originData": empty})
	if err := DeleteObject(ctx, env, P+"Profile.Upstream.1."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delUsprofile", map[string]any{"list": []any{map[string]any{
		"profileid": "1", "profilename": "us_1", "cir": "2048", "cbs": "64", "pir": "2048", "pbs": "128", "bind": "0"}}})

	// Unique: add without originData; delete posts the row.
	if _, err := AddObject(ctx, env, P+"Profile.Unique.", prqInputs("ONTID", "0/1/2", "Name", "unique_0/1/2", "RefWiFiProfile", "1")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setOntUniqueProfile", map[string]any{"profileId": "0/1/2", "profilename": "unique_0/1/2", "refWifiProfileId": "1", "action": "add"})
	if err := DeleteObject(ctx, env, P+"Profile.Unique.2."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delOntUniqueProfile", map[string]any{"list": []any{map[string]any{
		"profileId": "0/1/2", "profilename": "unique_0/1/2", "refWifiProfileId": "1"}}})

	// Multicast / WiFi id+name lists.
	if err := Set(ctx, env, P+"Profile.Multicast.1.Name", wusp.String("tv")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setOntMulticastProfile", map[string]any{"profileId": "1", "profilename": "tv", "action": "edit", "originData": empty})
	if _, err := AddObject(ctx, env, P+"Profile.WiFi.", prqInputs("ID", "2", "Name", "guest")); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/setWifiProfile", map[string]any{"profileId": "2", "profilename": "guest", "action": "add", "originData": empty})
	if err := DeleteObject(ctx, env, P+"Profile.WiFi.1."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delWifiProfile", map[string]any{"list": []any{map[string]any{"profileId": "1", "profilename": "home"}}})
	if err := DeleteObject(ctx, env, P+"Profile.Multicast.1."); err != nil {
		t.Fatal(err)
	}
	prqWantBody(t, f, "/goform/delOntMulticastProfile", map[string]any{"list": []any{map[string]any{"profileId": "1", "profilename": "tv"}}})
}
