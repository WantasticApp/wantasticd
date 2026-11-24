package fiberolt

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Example of the per-page golden pattern: each setter's posted JSON body
// must equal what the web UI sends (OLT-WEBUI-CONTROLS.md).
func TestCorePagesBodies(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	ports := map[string]any{"telnetport": "23", "sshport": "22", "httpport": "80", "httpsport": "443", "snmpport": "161"}
	f.handleFunc("/goform/getServicePort", func(map[string]any) any { return ports })
	f.handle("/goform/setServicePort", map[string]any{"errCode": "0"})
	login := map[string]any{"telnetEn": true, "sshEn": true, "httpEn": true, "httpsEn": false, "snmpEn": true, "isShowverify": false}
	f.handleFunc("/goform/getVerifyCode", func(map[string]any) any { return login })
	f.handleFunc("/goform/setVerifyCode", func(b map[string]any) any {
		for k, v := range b {
			login[k] = v
		}
		return map[string]any{"errCode": "0"}
	})
	env := &Env{API: f.client()}
	ctx := context.Background()

	// Collect: RO service ports, login toggles.
	msg := wusp.NewMessage()
	CollectOLT(ctx, f.client(), nil, true, msg)
	if v, ok := msg.Get(wusp.WUSPOLTPrefix + "Management.ServicePorts.HTTP"); !ok || v.AsUint() != 80 {
		t.Fatalf("ServicePorts.HTTP = %v", v)
	}

	// SetPorts posts the whole form with only SSH changed.
	in := wusp.NewMessage()
	in.Set("SSH", wusp.String("2222"))
	if _, err := Operate(ctx, env, wusp.WUSPOLTPrefix+"Management.ServicePorts.SetPorts()", in); err != nil {
		t.Fatal(err)
	}
	got := f.callsTo("/goform/setServicePort")[0].Body
	want := map[string]any{"telnetport": "23", "sshport": "2222", "httpport": "80", "httpsport": "443", "snmpport": "161"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setServicePort body = %v want %v", got, want)
	}
	// Guard: the agent's own HTTP port (fake server port) cannot change.
	in = wusp.NewMessage()
	in.Set("HTTP", wusp.String("8080"))
	if _, err := Operate(ctx, env, wusp.WUSPOLTPrefix+"Management.ServicePorts.SetPorts()", in); !errors.Is(err, ErrGuarded) {
		t.Fatalf("http port change: err = %v, want guard", err)
	}

	// Login manage: whole form of JSON booleans; disabling HTTP is refused.
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Management.Login.SSHEnable", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	got = f.callsTo("/goform/setVerifyCode")[0].Body
	want = map[string]any{"telnetEn": true, "sshEn": false, "httpEn": true, "httpsEn": false, "snmpEn": true, "isShowverify": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setVerifyCode body = %v want %v", got, want)
	}
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Management.Login.HTTPEnable", wusp.Bool(false)); !errors.Is(err, ErrGuarded) {
		t.Fatalf("disable http: err = %v, want guard", err)
	}
}

// "set=get" Body entries re-post getter values under the setter key.
func TestSpecBodyRename(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	rows := []map[string]any{{"vlanId": "1", "remark": "default", "ip": "192.168.1.1", "mask": "255.255.255.0", "ipType": "static", "threeLayersEn": "1"}}
	f.handleFunc("/goform/getQvlanList", func(map[string]any) any { return map[string]any{"list": rows} })
	f.handleFunc("/goform/setQvlanInfo", func(b map[string]any) any {
		if b["action"] == "edit" {
			rows[0]["remark"] = b["vlanRemark"]
		}
		return map[string]any{"errCode": "0"}
	})
	env := &Env{API: f.client()}
	// Rename: editing the description re-posts the current address under
	// the setter key staticIp (not "").
	if err := Set(context.Background(), env, wusp.WUSPOLTPrefix+"Switching.VLAN.List.1.Description", wusp.String("core")); err != nil {
		t.Fatal(err)
	}
	b := f.callsTo("/goform/setQvlanInfo")[0].Body
	if b["staticIp"] != "192.168.1.1" || b["vlanRemark"] != "core" || b["mask"] != "255.255.255.0" {
		t.Fatalf("body = %v", b)
	}
}

// A spec Add whose created row has a server-assigned key is found as the
// key that appears after the POST.
func TestSpecAddServerIndex(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	rows := []map[string]any{{"index": "1", "portName": "pon1", "startvlan": "100", "endvlan": "100", "destvlan": "2000"}}
	f.handleFunc("/goform/getQinqVlanList", func(map[string]any) any { return map[string]any{"list": rows} })
	f.handleFunc("/goform/setQinqVlanInfo", func(b map[string]any) any {
		rows = append(rows, map[string]any{"index": "7", "portName": "pon3", "startvlan": b["startvlan"], "endvlan": b["endvlan"], "destvlan": b["destvlan"]})
		return map[string]any{"errCode": "0"}
	})
	in := wusp.NewMessage()
	for k, v := range map[string]string{"Port": "pon3", "StartVLAN": "101", "EndVLAN": "101", "DestVLAN": "2001"} {
		in.Set(k, wusp.String(v))
	}
	got, err := AddObject(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"Switching.VLAN.QinQ.", in)
	if err != nil || len(got) != 1 || got[0] != wusp.WUSPOLTPrefix+"Switching.VLAN.QinQ.2." {
		t.Fatalf("add = %v, %v", got, err)
	}
}
