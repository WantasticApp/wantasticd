package fiberolt

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"wantastic-agent/internal/wusp"
)

// jsonCopy round-trips v through JSON (what the fake OLT records).
func jsonCopy(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func lastBody(t *testing.T, f *fakeOLT, path string) map[string]any {
	t.Helper()
	calls := f.callsTo(path)
	if len(calls) == 0 {
		t.Fatalf("no request to %s", path)
	}
	return calls[len(calls)-1].Body
}

func wantBody(t *testing.T, f *fakeOLT, path string, want map[string]any) {
	t.Helper()
	got := lastBody(t, f, path)
	if !reflect.DeepEqual(got, jsonCopy(t, want)) {
		t.Fatalf("%s body =\n %v\nwant\n %v", path, got, want)
	}
}

// listHandler serves {list: rows} and lets setters mutate the rows.
func listReply(rows *[]map[string]any, extra map[string]any) func(map[string]any) any {
	return func(map[string]any) any {
		out := map[string]any{"list": *rows}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
}

func okReply(map[string]any) any { return map[string]any{"errCode": "0"} }

// ---- Basics ----------------------------------------------------------------

func TestBasicsPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	sys := map[string]any{
		"sysTime": "2026-11-24 13:14:44", "runTime": "72774", "cpuPercent": "13%", "memoryPercent": "34.95%",
		"temp1value": "52.0", "temp2value": "48.0", "power1": "      OFF      ", "power2": "      ON    ",
		"softwareVersion": "1.1.3.18(release-000530)", "hardwareVersion": "V4.0", "created": "2026-11-23 00:05:30",
		"productOid": "1.3.6.1.4.1.48409.4", "deviceName": "GPON-OLT", "mac": "0090.4C06.A427", "sn": "123456790",
		"deviceLocation": "MA==", "temphi": "60", "templo": "-30", "pon_not_start": 0, "dnsType": "manual",
		"preferredDNS": "223.5.5.5", "alternateDNS": "114.114.114.114", "ip": "192.168.100.100", "mask": "255.255.255.0",
		"ipType": "manul", "gateway": "192.168.100.1",
		// The agent reaches the fake OLT at 127.0.0.1: make that the in-band address.
		"inbandip": "127.0.0.1", "inbandmask": "255.255.255.0", "mngvlan": "4000", "mnghost": "",
	}
	f.handleFunc("/goform/getSysStatus", func(map[string]any) any { return sys })
	f.handleFunc("/goform/setDeviceInfo", func(b map[string]any) any {
		for _, k := range []string{"deviceName", "deviceLocation", "inbandip", "inbandmask"} {
			sys[k] = b[k]
		}
		return okReply(nil)
	})
	f.handle("/goform/getPackageStatisticsListGraph", map[string]any{"list": map[string]any{
		"SZHourTime":    "1700000000",
		"SZHourDataIn":  []any{[]any{map[string]any{"percent": "1", "rate": "10"}}},
		"SZHourDataOut": []any{[]any{map[string]any{"percent": "2", "rate": "20"}}},
	}})
	diy := map[string]any{"website": "www.example.com", "hotline": "123", "copyright": "(c) X", "deviceModel": "GP8X2G6", "hide": "0"}
	f.handleFunc("/goform/getDiyInfo", func(map[string]any) any { return diy })
	f.handleFunc("/goform/setDiyInfo", func(b map[string]any) any {
		for k, v := range b {
			diy[k] = v
		}
		return okReply(nil)
	})
	f.handleFunc("/goform/clearDiyInfo", okReply)
	env := &Env{API: f.client()}
	ctx := context.Background()
	P := wusp.WUSPOLTPrefix

	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	for path, want := range map[string]string{
		"System.Info.SerialNumber":     "123456790",
		"System.Info.ProductOID":       "1.3.6.1.4.1.48409.4",
		"System.Info.Created":          "2026-11-23 00:05:30",
		"System.Info.Location":         "0",
		"System.Info.InbandIPAddress":  "127.0.0.1",
		"System.PortTraffic.RxHistory": `[[{"percent":"1","rate":"10"}]]`,
		"System.Branding.DeviceModel":  "GP8X2G6",
	} {
		if v, ok := msg.Get(P + path); !ok || wusp.ValueToString(v) != want {
			t.Errorf("%s = %q (%v), want %q", path, wusp.ValueToString(v), ok, want)
		}
	}
	if v, ok := msg.Get(P + "System.PortTraffic.StartTime"); !ok || v.AsUint() != 1700000000 {
		t.Errorf("PortTraffic.StartTime = %v", v)
	}
	if v, ok := msg.Get(P + "System.Info.PONNotStarted"); !ok || v.AsBool() {
		t.Errorf("PONNotStarted = %v %v", v, ok)
	}

	// Device name: whole "Edit Device Info" form + editdevice + originData.
	origin := jsonCopy(t, sys)
	if err := Set(ctx, env, P+"System.Info.DeviceName", wusp.String("OLT-LAB")); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setDeviceInfo", map[string]any{
		"deviceName": "OLT-LAB", "deviceLocation": "MA==", "ip": "192.168.100.100", "dnsType": "manual",
		"preferredDNS": "223.5.5.5", "alternateDNS": "114.114.114.114", "ipType": "manul", "mask": "255.255.255.0",
		"inbandip": "127.0.0.1", "inbandmask": "255.255.255.0", "mngvlan": "4000", "gateway": "192.168.100.1", "mnghost": "",
		"editdevice": "1", "originData": origin,
	})
	// Location is Base64 on the wire.
	if err := Set(ctx, env, P+"System.Info.Location", wusp.String("Lab 1")); err != nil {
		t.Fatal(err)
	}
	if got := lastBody(t, f, "/goform/setDeviceInfo")["deviceLocation"]; got != "TGFiIDE=" {
		t.Fatalf("deviceLocation = %v", got)
	}
	// Guard: the in-band address the agent uses cannot be changed.
	n := len(f.callsTo("/goform/setDeviceInfo"))
	if err := Set(ctx, env, P+"System.Info.InbandSubnetMask", wusp.String("255.255.0.0")); !errors.Is(err, ErrGuarded) {
		t.Fatalf("inband mask change: err = %v, want guard", err)
	}
	if err := Set(ctx, env, P+"System.Info.InbandIPAddress", wusp.String("10.0.0.1")); !errors.Is(err, ErrGuarded) {
		t.Fatalf("inband ip change: err = %v, want guard", err)
	}
	if len(f.callsTo("/goform/setDeviceInfo")) != n {
		t.Fatal("guarded write reached the OLT")
	}
	// Read-only leaves refuse writes.
	if err := Set(ctx, env, P+"System.Info.SerialNumber", wusp.String("x")); err == nil {
		t.Fatal("SerialNumber accepted a write")
	}

	// DIY: whole form, hide as "1"/"0".
	if err := Set(ctx, env, P+"System.Branding.HideFooter", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setDiyInfo", map[string]any{
		"hide": "1", "website": "www.example.com", "deviceModel": "GP8X2G6", "hotline": "123", "copyright": "(c) X",
	})
	if err := Set(ctx, env, P+"System.Branding.Website", wusp.String("isp.example")); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setDiyInfo", map[string]any{
		"hide": "1", "website": "isp.example", "deviceModel": "GP8X2G6", "hotline": "123", "copyright": "(c) X",
	})
	if _, err := Operate(ctx, env, P+"System.Branding.Clear()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/clearDiyInfo", map[string]any{})
}

// ---- PON -------------------------------------------------------------------

func TestPONPagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	ponList := map[string]any{"ponPortList": []any{"pon1", "pon2", "all"}}
	versions := []map[string]any{
		{"onuid": "0/1/1", "sn": "HWTC-93bb0308", "status": "online", "equipid": "PTF2164Q", "vendor": "HWTC", "firmware": "V1", "software1": "V5R019", "software2": "V5R018"},
	}
	f.handleFunc("/goform/getOntListVersion", listReply(&versions, ponList))
	macs := []map[string]any{
		{"mac": "00:11:22:33:44:55", "vlan": "100", "onuid": "0/1/1", "sn": "HWTC-93bb0308", "gemidx": "1", "gemid": "129"},
		{"mac": "00:11:22:33:44:66", "vlan": "100", "onuid": "0/1/1", "sn": "HWTC-93bb0308", "gemidx": "1", "gemid": "129"},
	}
	f.handleFunc("/goform/getOntListMac", listReply(&macs, ponList))
	found := []map[string]any{
		{"port": "pon2", "index": "1", "sn": "ZTEG-00000009", "eid": "F660", "lastfind": "2026-11-24 10:00:00", "findcnt": "3", "reason": "sn mismatch"},
	}
	f.handleFunc("/goform/getOntAutoFindBrife", listReply(&found, ponList))

	afc := []map[string]any{
		{"portNum": "1", "find": "1", "interval": "20", "age": "1", "agetime": "300", "mindistance": "0", "maxdistance": "20"},
	}
	f.handleFunc("/goform/getOntAutoFindConfig", listReply(&afc, nil))
	f.handleFunc("/goform/setOntAutoFindConfig", func(b map[string]any) any {
		for _, k := range []string{"find", "age", "interval", "agetime", "mindistance", "maxdistance"} {
			afc[0][k] = b[k]
		}
		return okReply(nil)
	})

	autoAddOn := []map[string]any{{"globalswitch": "1"}}
	f.handleFunc("/goform/getOntAutoAddEnable", listReply(&autoAddOn, nil))
	f.handleFunc("/goform/setOntAutoAddEnable", func(b map[string]any) any {
		autoAddOn[0]["globalswitch"] = b["globalswitch"]
		return okReply(nil)
	})
	rules := []map[string]any{
		{"index": "1", "name": "INDEX_1", "type": "ALL-ONT", "param": "Null", "portbinding": "all", "lineprofile": "1", "autounique": "0"},
	}
	f.handleFunc("/goform/getOntAutoAddConfig", listReply(&rules, ponList))
	f.handleFunc("/goform/setOntAutoAddConfig", func(b map[string]any) any {
		row := map[string]any{}
		for _, k := range []string{"index", "name", "type", "param", "portbinding", "lineprofile", "autounique"} {
			row[k] = b[k]
		}
		if b["action"] == "add" {
			rules = append(rules, row)
		} else {
			for i := range rules {
				if rules[i]["index"] == b["index"] {
					rules[i] = row
				}
			}
		}
		return okReply(nil)
	})
	f.handleFunc("/goform/delOntAutoAddConfig", okReply)

	autoDel := []map[string]any{{"portnum": "pon1", "enable": "0", "timeout": "1440", "trigger": "128", "sum": "0"}}
	f.handleFunc("/goform/getOntAutoDelConfig", listReply(&autoDel, nil))
	f.handleFunc("/goform/setOntAutoDelConfig", func(b map[string]any) any {
		if b["portnum"] == autoDel[0]["portnum"] {
			for _, k := range []string{"enable", "timeout", "trigger"} {
				autoDel[0][k] = b[k]
			}
		}
		return okReply(nil)
	})

	images := []map[string]any{{"fname": "onu_v2.bin", "size": "8123", "ctime": "2026-11-20 08:00:00"}}
	f.handleFunc("/goform/getOntUpgradeImage", listReply(&images, nil))
	f.handleFunc("/goform/delOntUpgradeImage", okReply)
	f.handleFunc("/goform/setOntUpgradeOp", okReply)
	upStatus := []map[string]any{{"onuid": "0/1/1", "ver1": "V5R019", "ver2": "V5R018", "progress": "100%", "result": "success"}}
	f.handleFunc("/goform/getOntUpgradeOp", listReply(&upStatus, ponList))
	f.handleFunc("/goform/delOntUpgradeState", okReply)

	rogue := []map[string]any{{"port": "1", "enable": "enable", "type": "-", "interval": "60", "action": "none", "d_cnt": "0", "s_cnt": "2"}}
	f.handleFunc("/goform/getOntRogueConfig", listReply(&rogue, nil))
	f.handleFunc("/goform/setOntRogueConfig", func(b map[string]any) any {
		if b["port"] == rogue[0]["port"] {
			for _, k := range []string{"enable", "interval", "action"} {
				rogue[0][k] = b[k]
			}
		}
		return okReply(nil)
	})

	env := &Env{API: f.client()}
	ctx := context.Background()
	P := wusp.WUSPOLTPrefix

	// Collect: RO tables.
	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	for path, want := range map[string]string{
		"PON.ONTVersion.1.ActiveSoftware":  "V5R019",
		"PON.ONTVersion.1.EquipmentID":     "PTF2164Q",
		"PON.ONTMAC.2.MACAddress":          "00:11:22:33:44:66",
		"PON.AutoFind.List.1.SerialNumber": "ZTEG-00000009",
		"PON.AutoFind.Config.1.Port":       "1",
		"PON.AutoAdd.Rule.1.Name":          "INDEX_1",
		"PON.Upgrade.Image.1.FileName":     "onu_v2.bin",
		"PON.Upgrade.Status.1.Progress":    "100%",
		"PON.Rogue.Config.1.Enable":        "enable",
	} {
		if v, ok := msg.Get(P + path); !ok || wusp.ValueToString(v) != want {
			t.Errorf("%s = %q (%v), want %q", path, wusp.ValueToString(v), ok, want)
		}
	}
	if v, ok := msg.Get(P + "PON.ONTMACNumberOfEntries"); !ok || v.AsUint() != 2 {
		t.Errorf("PON.ONTMACNumberOfEntries = %v", v)
	}
	if v, ok := msg.Get(P + "PON.AutoAdd.Global.1.Enable"); !ok || !v.AsBool() {
		t.Errorf("PON.AutoAdd.Global.1.Enable = %v %v", v, ok)
	}
	if v, ok := msg.Get(P + "PON.AutoFind.List.1.FindCount"); !ok || v.AsUint() != 3 {
		t.Errorf("FindCount = %v", v)
	}
	// The PON-filtered getters ask for every PON.
	if q := lastBody(t, f, "/goform/getOntListVersion"); q["PonPortName"] != "all" {
		t.Errorf("getOntListVersion query = %v", q)
	}

	// Auto-find config: row edit with portNum, port:[portNum], action, originData.
	afcOrigin := jsonCopy(t, afc[0])
	if err := Set(ctx, env, P+"PON.AutoFind.Config.1.FindEnable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoFindConfig", map[string]any{
		"portNum": "1", "port": []any{"1"}, "find": "0", "age": "1", "interval": "20", "agetime": "300",
		"mindistance": "0", "maxdistance": "20", "action": "edit", "originData": afcOrigin,
	})

	// Auto-add global switch: {globalswitch} only.
	in := wusp.NewMessage()
	in.Set("Enable", wusp.String("false"))
	if _, err := Operate(ctx, env, P+"PON.AutoAdd.SetEnable()", in); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoAddEnable", map[string]any{"globalswitch": "0"})

	// Auto-add rules: add, edit, delete.
	init := wusp.NewMessage()
	for k, v := range map[string]string{"Index": "5", "Name": "hgu", "Type": "ALL-HGU", "Param": "Null", "PortBinding": "pon2", "LineProfile": "3", "AutoUnique": "1"} {
		init.Set(k, wusp.String(v))
	}
	paths, err := AddObject(ctx, env, P+"PON.AutoAdd.Rule.", init)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != P+"PON.AutoAdd.Rule.2." {
		t.Fatalf("Add paths = %v", paths)
	}
	wantBody(t, f, "/goform/setOntAutoAddConfig", map[string]any{
		"index": "5", "name": "hgu", "type": "ALL-HGU", "param": "Null", "portbinding": "pon2", "lineprofile": "3", "autounique": "1",
		"action": "add", "originData": map[string]any{},
	})
	if _, err := AddObject(ctx, env, P+"PON.AutoAdd.Rule.", wusp.NewMessage()); err == nil {
		t.Fatal("Add without required fields accepted")
	}
	if err := Set(ctx, env, P+"PON.AutoAdd.Rule.1.LineProfile", wusp.String("2")); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoAddConfig", map[string]any{
		"index": "1", "name": "INDEX_1", "type": "ALL-ONT", "param": "Null", "portbinding": "all", "lineprofile": "2", "autounique": "0",
		"action": "edit", "originData": map[string]any{},
	})
	if err := Set(ctx, env, P+"PON.AutoAdd.Rule.1.Type", wusp.String("bogus")); err == nil {
		t.Fatal("Type outside the enum accepted")
	}
	if err := DeleteObject(ctx, env, P+"PON.AutoAdd.Rule.2."); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/delOntAutoAddConfig", map[string]any{"list": []any{
		map[string]any{"index": "5", "name": "hgu", "type": "ALL-HGU", "param": "Null", "portbinding": "pon2", "lineprofile": "3", "autounique": "1"},
	}})

	// Auto-delete: row edit (timeout/trigger), enable only via commands.
	if err := Set(ctx, env, P+"PON.AutoDelete.Config.1.Timeout", wusp.Uint(60)); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoDelConfig", map[string]any{
		"portnum": "pon1", "enable": "0", "timeout": "60", "trigger": "128", "action": "edit", "originData": map[string]any{},
	})
	if err := Set(ctx, env, P+"PON.AutoDelete.Config.1.Enable", wusp.Bool(true)); err == nil {
		t.Fatal("AutoDelete Enable (destructive) accepted a parameter write")
	}
	in = wusp.NewMessage()
	for k, v := range map[string]string{"Port": "pon1", "Enable": "true", "Timeout": "30", "Trigger": "4"} {
		in.Set(k, wusp.String(v))
	}
	if _, err := Operate(ctx, env, P+"PON.AutoDelete.SetPort()", in); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoDelConfig", map[string]any{
		"portnum": "pon1", "enable": "1", "timeout": "30", "trigger": "4", "action": "edit", "originData": map[string]any{},
	})
	if _, err := Operate(ctx, env, P+"PON.AutoDelete.EnableAll()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoDelConfig", map[string]any{"portnum": "all", "enable": "1", "timeout": "1440", "trigger": "128"})
	if _, err := Operate(ctx, env, P+"PON.AutoDelete.DisableAll()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntAutoDelConfig", map[string]any{"portnum": "all", "enable": "0", "timeout": "1440", "trigger": "128"})

	// ONT upgrade: image delete, start, status delete.
	if err := DeleteObject(ctx, env, P+"PON.Upgrade.Image.1."); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/delOntUpgradeImage", map[string]any{"list": []any{
		map[string]any{"fname": "onu_v2.bin", "size": "8123", "ctime": "2026-11-20 08:00:00"},
	}})
	in = wusp.NewMessage()
	in.Set("ONTList", wusp.String("0/1/1,0/1/2"))
	in.Set("FileName", wusp.String("onu_v2.bin"))
	if _, err := Operate(ctx, env, P+"PON.Upgrade.Start()", in); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntUpgradeOp", map[string]any{"fname": "onu_v2.bin", "ontlist": "0/1/1,0/1/2", "action": "add"})
	if _, err := Operate(ctx, env, P+"PON.Upgrade.Start()", wusp.NewMessage()); err == nil {
		t.Fatal("Upgrade.Start without inputs accepted")
	}
	if err := DeleteObject(ctx, env, P+"PON.Upgrade.Status.1."); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/delOntUpgradeState", map[string]any{"list": []any{
		map[string]any{"onuid": "0/1/1", "ver1": "V5R019", "ver2": "V5R018", "progress": "100%", "result": "success"},
	}})

	// Rogue detect: plain {port, enable, interval, action} row edit + all-port buttons.
	if err := Set(ctx, env, P+"PON.Rogue.Config.1.Action", wusp.String("reboot")); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntRogueConfig", map[string]any{"port": "1", "enable": "enable", "interval": "60", "action": "reboot"})
	if err := Set(ctx, env, P+"PON.Rogue.Config.1.Interval", wusp.Uint(120)); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntRogueConfig", map[string]any{"port": "1", "enable": "enable", "interval": "120", "action": "reboot"})
	if err := Set(ctx, env, P+"PON.Rogue.Config.1.Action", wusp.String("explode")); err == nil {
		t.Fatal("rogue action outside the enum accepted")
	}
	if _, err := Operate(ctx, env, P+"PON.Rogue.EnableAll()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntRogueConfig", map[string]any{"port": "all", "enable": "enable", "interval": "60", "action": "none"})
	if _, err := Operate(ctx, env, P+"PON.Rogue.DisableAll()", wusp.NewMessage()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, f, "/goform/setOntRogueConfig", map[string]any{"port": "all", "enable": "disable", "interval": "60", "action": "none"})
}

// The orphan legacy page is metadata only.
func TestPONUnsupportedPages(t *testing.T) {
	for _, p := range wusp.OLTUnsupportedPages() {
		if p.Route == "(none - orphan chunk 116, module 669)" {
			return
		}
	}
	t.Fatal("srvprofilemulvlan not listed as unsupported")
}
