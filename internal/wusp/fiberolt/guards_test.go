package fiberolt

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

// agentHost returns the fake server host (the agent's -olt-url host).
func agentHost(t *testing.T, f *fakeOLT) string {
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func TestGuardMgmtAddress(t *testing.T) {
	f := richOLT(t)
	sys := f.reply("/goform/getSysStatus").(map[string]any)
	sys["ip"] = agentHost(t, f) // the agent reaches the OLT at its mgmt IP
	f.handle("/goform/getSysStatus", sys)
	f.handle("/goform/setDeviceInfo", map[string]any{"errCode": "0"})
	env := &Env{API: f.client()}
	for _, leaf := range []string{"Network.Mgmt.IPAddress", "Network.Mgmt.SubnetMask", "Network.Mgmt.Gateway"} {
		err := Set(context.Background(), env, wusp.WUSPOLTPrefix+leaf, wusp.String("10.9.9.9"))
		if !errors.Is(err, ErrGuarded) {
			t.Fatalf("%s: err = %v, want guard", leaf, err)
		}
	}
	if n := len(f.callsTo("/goform/setDeviceInfo")); n != 0 {
		t.Fatalf("guarded write reached the OLT (%d calls)", n)
	}
}

func TestGuardVLANDelete(t *testing.T) {
	f := richOLT(t)
	host := agentHost(t, f)
	f.handle("/goform/getQvlanList", map[string]any{"list": []map[string]any{
		{"vlanId": "1", "remark": "default", "ip": "", "threeLayersEn": "0"},
		{"vlanId": "4000", "remark": "mgmt", "ip": host, "mask": "255.255.255.0", "threeLayersEn": "1"},
		{"vlanId": "300", "remark": "svc", "ip": "", "threeLayersEn": "0"},
		{"vlanId": "200", "remark": "x", "ip": "", "threeLayersEn": "0"},
	}})
	sys := f.reply("/goform/getSysStatus").(map[string]any)
	sys["mngvlan"] = "200"
	f.handle("/goform/getSysStatus", sys)
	f.handle("/goform/delQvlanList", map[string]any{"errCode": "0"})
	env := &Env{API: f.client()}
	in := func(id string) *wusp.Message {
		m := wusp.NewMessage()
		m.Set("ID", wusp.String(id))
		return m
	}
	for _, id := range []string{"1", "4000", "200"} {
		if _, err := Operate(context.Background(), env, wusp.WUSPOLTNetworkQVLANDeleteCommand, in(id)); !errors.Is(err, ErrGuarded) {
			t.Fatalf("delete VLAN %s: err = %v, want guard", id, err)
		}
	}
	if _, err := Operate(context.Background(), env, wusp.WUSPOLTNetworkQVLANDeleteCommand, in("300")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.callsTo("/goform/delQvlanList")); n != 1 {
		t.Fatalf("deletes = %d, want 1", n)
	}
}

func TestGuardPortStatusAndMember(t *testing.T) {
	f := richOLT(t)
	host := agentHost(t, f)
	f.handle("/goform/getQvlanList", map[string]any{"list": []map[string]any{
		{"vlanId": "4000", "ip": host, "threeLayersEn": "1"},
	}})
	env := &Env{API: f.client()}
	ctx := context.Background()
	// ge1 is a link-up uplink in richOLT; ge2 is down; pon1 is a PON port.
	if err := guardPortStatus(ctx, env, map[string]any{"portStatus": "0", "port": []any{"ge1"}}, nil); !errors.Is(err, ErrGuarded) {
		t.Fatalf("shutdown ge1: %v", err)
	}
	for _, p := range []string{"ge2", "pon1"} {
		if err := guardPortStatus(ctx, env, map[string]any{"portStatus": "0", "port": []any{p}}, nil); err != nil {
			t.Fatalf("shutdown %s: %v", p, err)
		}
	}
	row := Doc{"portName": "ge1", "linkType": "trunk", "pvid": "1", "tagged": "100,3990-4010", "untagged": "--"}
	if err := guardVLANMember(ctx, env, map[string]any{"port": []any{"ge1"}, "linkType": "trunk", "pvid": "1", "tagged": "100"}, row); !errors.Is(err, ErrGuarded) {
		t.Fatalf("drop VLAN 4000 from ge1: %v", err)
	}
	if err := guardVLANMember(ctx, env, map[string]any{"port": []any{"ge1"}, "linkType": "trunk", "pvid": "1", "tagged": "100,4000"}, row); err != nil {
		t.Fatalf("keep VLAN 4000: %v", err)
	}
}

func TestAutoSaveDebounced(t *testing.T) {
	old := AutoSaveDelay
	AutoSaveDelay = 50 * time.Millisecond
	t.Cleanup(func() { AutoSaveDelay = old })
	f := richOLT(t)
	stateful := f.reply("/goform/getSystemTimeInfo").(map[string]any)
	f.handleFunc("/goform/setSystemTimeInfo", func(b map[string]any) any {
		for k, v := range b {
			stateful[k] = v
		}
		return map[string]any{"errCode": "0"}
	})
	f.handle("/goform/setGlobalConfig", map[string]any{"errCode": "0"})
	auto := false
	env := &Env{API: f.client(), AutoSave: func() bool { return auto }, SetAutoSave: func(v bool) error { auto = v; return nil }}
	ctx := context.Background()
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"AutoSave", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	for _, srv := range []string{"a.ntp", "b.ntp", "c.ntp"} {
		if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Network.NTP.Server", wusp.String(srv)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	saves := f.callsTo("/goform/setGlobalConfig")
	if len(saves) != 1 || saves[0].Body["action"] != "all" {
		t.Fatalf("saves = %+v, want one debounced {action:all}", saves)
	}
	// Operate commands that change the config save too.
	f.reset()
	f.handle("/goform/setStaticRouteInfo", map[string]any{"errCode": "0"})
	in := wusp.NewMessage()
	for k, v := range map[string]string{"Destination": "10.9.0.0", "Mask": "255.255.0.0", "Gateway": "192.168.100.1"} {
		in.Set(k, wusp.String(v))
	}
	if _, err := Operate(ctx, env, wusp.WUSPOLTNetworkRouteAddCommand, in); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(f.callsTo("/goform/setGlobalConfig")); n != 1 {
		t.Fatalf("Route.Add(): saves = %d, want 1", n)
	}
	// Off: no save.
	auto = false
	f.reset()
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Network.NTP.Server", wusp.String("d.ntp")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if n := len(f.callsTo("/goform/setGlobalConfig")); n != 0 {
		t.Fatalf("AutoSave off but %d saves", n)
	}
}

func TestUnknownHandlerIsUnsupported(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getX", map[string]any{"errCode": "106"})
	_, err := fetchPage(context.Background(), f.client(), "/goform/getX", nil, nil)
	if !errors.Is(err, wusp.ErrUSPPathUnsupported) {
		t.Fatalf("err = %v", err)
	}
}
