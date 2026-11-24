package fiberolt

// Security and Device Settings pages (internal/wusp/olt_pages_security.go,
// olt_pages_device.go): every setter / action body must equal what the web
// UI posts (OLT-WEBUI-CONTROLS.md), secrets must not surface as params.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

const sdP = wusp.WUSPOLTPrefix

func sdB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// sdJSON deep-copies v through JSON (what the fake records after decoding).
func sdJSON(t *testing.T, v any) map[string]any {
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

// sdWant asserts the last request body posted to path.
func sdWant(t *testing.T, f *fakeOLT, path string, want map[string]any) {
	t.Helper()
	calls := f.callsTo(path)
	if len(calls) == 0 {
		t.Fatalf("%s: no request", path)
	}
	got := calls[len(calls)-1].Body
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(want)
		t.Fatalf("%s body\n got  %s\n want %s", path, gb, wb)
	}
}

// sdForm serves a stateful scalar form: set merges the posted keys.
func sdForm(f *fakeOLT, get, set string, state map[string]any) {
	f.handleFunc(get, func(map[string]any) any { return state })
	if set != "" {
		f.handleFunc(set, func(b map[string]any) any {
			for k, v := range b {
				state[k] = v
			}
			return map[string]any{"errCode": "0"}
		})
	}
}

// sdList serves {listKey: rows} plus extra top-level keys.
func sdList(f *fakeOLT, get, listKey string, rows *[]map[string]any, extra map[string]any) {
	f.handleFunc(get, func(map[string]any) any {
		out := map[string]any{}
		for k, v := range extra {
			out[k] = v
		}
		list := make([]any, 0, len(*rows))
		for _, r := range *rows {
			list = append(list, r)
		}
		out[listKey] = list
		return out
	})
}

func sdOK(f *fakeOLT, paths ...string) {
	for _, p := range paths {
		f.handle(p, map[string]any{"errCode": "0"})
	}
}

func sdIn(kv ...string) *wusp.Message {
	m := wusp.NewMessage()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i], wusp.String(kv[i+1]))
	}
	return m
}

func sdStrs(v ...string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func sdOperate(t *testing.T, env *Env, cmd string, in *wusp.Message) *wusp.Message {
	t.Helper()
	out, err := Operate(context.Background(), env, sdP+cmd, in)
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return out
}

func sdSet(t *testing.T, env *Env, rel string, v wusp.Value) {
	t.Helper()
	if err := Set(context.Background(), env, sdP+rel, v); err != nil {
		t.Fatalf("set %s: %v", rel, err)
	}
}

func sdCollect(f *fakeOLT) *wusp.Message {
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), nil, true, msg)
	return msg
}

func sdParam(t *testing.T, msg *wusp.Message, rel, want string) {
	t.Helper()
	v, ok := msg.Get(sdP + rel)
	if !ok {
		t.Fatalf("%s not collected", rel)
	}
	if got := wusp.ValueToString(v); got != want {
		t.Fatalf("%s = %q, want %q", rel, got, want)
	}
}

// sdNoSecret fails when any collected value carries a secret.
func sdNoSecret(t *testing.T, msg *wusp.Message, secrets ...string) {
	t.Helper()
	for _, fl := range msg.Fields {
		val := wusp.ValueToString(fl.Val)
		for _, s := range secrets {
			if strings.Contains(val, s) {
				t.Errorf("secret %q exposed by %s", s, fl.Path)
			}
		}
	}
}

func sdFake(t *testing.T) (*fakeOLT, *Env) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{"deviceName": "OLT", "port": []any{}})
	return f, &Env{API: f.client()}
}

// ---- Network Security --------------------------------------------------------------

func TestSecurityIPACLRuleAndBinding(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	rule := map[string]any{"aclId": "100", "priority": "1", "protocol": "6", "srcIpType": "all", "srcIp": "", "srcMask": "",
		"destIpType": "one", "destIp": "10.0.0.1", "destMask": "0.0.0.0", "srcPort": "-", "destPort": "22", "actionEn": "permit"}
	rules := []map[string]any{rule}
	sdList(f, "/goform/getIpAclList", "list", &rules, nil)
	binds := []map[string]any{{"port": "ge1", "aclId": "100", "aclType": "ipv4Acl", "filterDirection": "in"}}
	sdList(f, "/goform/getAppAclList", "list", &binds, map[string]any{"ipv4Acl": []any{map[string]any{"title": "100", "value": "100"}}, "ipv6Acl": []any{}, "macAcl": []any{}})
	sdOK(f, "/goform/setIpAclInfo", "/goform/delIpAclList", "/goform/setAppAclInfo", "/goform/delAppAclList")

	msg := sdCollect(f)
	sdParam(t, msg, "Security.ACL.IPRule.1.DestIP", "10.0.0.1")
	sdParam(t, msg, "Security.ACL.IPRule.1.Action", "permit")
	sdParam(t, msg, "Security.ACL.Binding.1.Port", "ge1")
	sdParam(t, msg, "Security.ACL.BindingNumberOfEntries", "1")

	// Add rule: every form key, priority empty, action add.
	sdOperate(t, env, "Security.ACL.AddIPRule()", sdIn("ACLID", "100", "Protocol", "17", "SourceType", "all",
		"DestType", "one", "DestIP", "10.0.0.2", "DestMask", "0.0.0.0", "DestPort", "53", "Action", "forbit"))
	sdWant(t, f, "/goform/setIpAclInfo", map[string]any{"aclId": "100", "priority": "", "protocol": "17", "srcIpType": "all",
		"srcIp": "", "srcMask": "", "destIpType": "one", "destIp": "10.0.0.2", "destMask": "0.0.0.0", "srcPort": "", "destPort": "53",
		"actionEn": "forbit", "action": "add"})
	if _, err := Operate(ctx, env, sdP+"Security.ACL.AddIPRule()", sdIn("ACLID", "100")); err == nil {
		t.Fatal("AddIPRule without required inputs succeeded")
	}
	if err := DeleteObject(ctx, env, sdP+"Security.ACL.IPRule.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delIpAclList", map[string]any{"list": []any{sdJSON(t, rule)}})

	// Bind: aclId mirrors ipv4Acl, port names array, fixed ingress/ipv4.
	sdOperate(t, env, "Security.ACL.Bind()", sdIn("Ports", "ge1,ge2", "ACLID", "101", "IPv4ACL", "101"))
	sdWant(t, f, "/goform/setAppAclInfo", map[string]any{"port": sdStrs("ge1", "ge2"), "filterDirection": "in", "aclType": "ipv4Acl",
		"ipv4Acl": "101", "ipv6Acl": "", "macAcl": "", "aclId": "101", "action": "add"})
	if err := DeleteObject(ctx, env, sdP+"Security.ACL.Binding.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delAppAclList", map[string]any{"list": []any{sdJSON(t, binds[0])}})
}

func TestSecurityPortSecurityAndFlapping(t *testing.T) {
	f, env := sdFake(t)
	ps := []map[string]any{{"portNum": "1", "portName": "pon1", "flapping": "0", "limit": "0"}}
	sdList(f, "/goform/getPortSecurity", "list", &ps, nil)
	f.handleFunc("/goform/setPortSecurity", func(b map[string]any) any {
		if b["action"] == "edit" {
			ps[0]["flapping"], ps[0]["limit"] = b["flapping"], b["limit"]
		}
		return map[string]any{"errCode": "0"}
	})
	fl := []map[string]any{{"portnum": "pon1", "enable": "0"}}
	sdList(f, "/goform/getOntMacFlappingConfig", "list", &fl, nil)
	f.handleFunc("/goform/setOntMacFlappingConfig", func(b map[string]any) any {
		if b["portnum"] == "pon1" {
			fl[0]["enable"] = b["enable"]
		}
		return map[string]any{"errCode": "0"}
	})

	msg := sdCollect(f)
	sdParam(t, msg, "Security.PortSecurity.Port.1.Name", "pon1")
	sdParam(t, msg, "Security.MACFlapping.Port.1.Enable", "false")

	orig := sdJSON(t, ps[0])
	sdSet(t, env, "Security.PortSecurity.Port.1.Flapping", wusp.String("1"))
	sdWant(t, f, "/goform/setPortSecurity", map[string]any{"port": sdStrs("pon1"), "flapping": "1", "limit": "0",
		"action": "edit", "originData": orig})
	sdOperate(t, env, "Security.PortSecurity.Apply()", sdIn("Ports", "pon1,ge1", "Flapping", "-1", "Limit", "64"))
	sdWant(t, f, "/goform/setPortSecurity", map[string]any{"port": sdStrs("pon1", "ge1"), "flapping": "-1", "limit": "64", "action": "add"})

	sdSet(t, env, "Security.MACFlapping.Port.1.Enable", wusp.Bool(true))
	sdWant(t, f, "/goform/setOntMacFlappingConfig", map[string]any{"portnum": "pon1", "enable": "1", "action": "edit", "originData": map[string]any{}})
	sdOperate(t, env, "Security.MACFlapping.EnableAll()", nil)
	sdWant(t, f, "/goform/setOntMacFlappingConfig", map[string]any{"portnum": "all", "enable": "1"})
	sdOperate(t, env, "Security.MACFlapping.DisableAll()", nil)
	sdWant(t, f, "/goform/setOntMacFlappingConfig", map[string]any{"portnum": "all", "enable": "0"})
}

func TestSecurityAPIOnlyFeatures(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	arp := map[string]any{"arpReceptRate": "100"}
	sdForm(f, "/goform/getPortArpAttackInfo", "/goform/setPortArpAttackInfo", arp)
	dos := map[string]any{"arpMacCheckEn": "1", "tcpPackageCheckEn": "0", "tcpFlagZeroEn": "1", "tcpPackageFlagsEn": "0",
		"tcpPackageSynEn": "0", "tcpPackageRstEn": "1", "tcpPortZeroEn": "0", "tcpSycDataEn": "0", "icmpFragEn": "1"}
	sdForm(f, "/goform/getDosAttackInfo", "/goform/setDosAttackInfo", dos)
	mac := []map[string]any{{"portNum": "9", "macDropEn": "0"}}
	sdList(f, "/goform/getPortMacAttackList", "list", &mac, nil)
	f.handleFunc("/goform/setPortMacAttackInfo", func(b map[string]any) any {
		mac[0]["macDropEn"] = b["macDropEn"]
		return map[string]any{"errCode": "0"}
	})
	filt := []map[string]any{{"mac": "0011-2233-4455", "vlanId": "10"}}
	sdList(f, "/goform/getIpMacFilterList", "list", &filt, nil)
	f.handleFunc("/goform/setIpMacFilterList", func(b map[string]any) any {
		filt = append(filt, map[string]any{"mac": b["mac"], "vlanId": b["vlanId"]})
		return map[string]any{"errCode": "0"}
	})
	sdOK(f, "/goform/delIpMacFilterList")
	auth := map[string]any{"authEn": "0"}
	sdForm(f, "/goform/getNetAuthEn", "/goform/setNetAuthEn", auth)
	srv := map[string]any{"authIp": "10.0.0.5", "shareKey": "dot1x-secret"}
	sdForm(f, "/goform/getAuthGlobalInfo", "/goform/setAuthGlobalInfo", srv)
	np := []map[string]any{{"portNum": "9", "portControlType": "auto", "portAuthStatus": "1", "reAuthEn": "0",
		"reAuthTimeout": "3600", "clientTimeout": "30", "reAuthMaxNum": "2"}}
	sdList(f, "/goform/getNetPortList", "list", &np, nil)
	f.handleFunc("/goform/setNetPortInfo", func(b map[string]any) any {
		for _, k := range []string{"portControlType", "reAuthEn", "reAuthTimeout", "clientTimeout", "reAuthMaxNum"} {
			np[0][k] = b[k]
		}
		return map[string]any{"errCode": "0"}
	})

	msg := sdCollect(f)
	sdParam(t, msg, "Security.AntiARP.ReceiveRate", "100")
	sdParam(t, msg, "Security.AntiDoS.ICMPFragment", "true")
	sdParam(t, msg, "Security.IPMACFilter.1.MAC", "0011-2233-4455")
	sdParam(t, msg, "Security.Dot1X.Server.Address", "10.0.0.5")
	sdParam(t, msg, "Security.Dot1X.Port.1.AuthStatus", "1")
	sdNoSecret(t, msg, "dot1x-secret")

	sdSet(t, env, "Security.AntiARP.ReceiveRate", wusp.Uint(200))
	sdWant(t, f, "/goform/setPortArpAttackInfo", map[string]any{"arpReceptRate": "200"})

	sdSet(t, env, "Security.AntiDoS.TCPSynFin", wusp.Bool(true))
	sdWant(t, f, "/goform/setDosAttackInfo", map[string]any{"arpMacCheckEn": "1", "tcpPackageCheckEn": "0", "tcpFlagZeroEn": "1",
		"tcpPackageFlagsEn": "0", "tcpPackageSynEn": "1", "tcpPackageRstEn": "1", "tcpPortZeroEn": "0", "tcpSycDataEn": "0", "icmpFragEn": "1"})

	sdSet(t, env, "Security.AntiMAC.Port.1.DropEnable", wusp.Bool(true))
	sdWant(t, f, "/goform/setPortMacAttackInfo", map[string]any{"port": sdStrs("9"), "macDropEn": "1"})

	in := wusp.NewMessage()
	in.Set("MAC", wusp.String("00aa-bbcc-ddee"))
	in.Set("VLAN", wusp.String("20"))
	paths, err := AddObject(ctx, env, sdP+"Security.IPMACFilter.", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != sdP+"Security.IPMACFilter.2." {
		t.Fatalf("add paths = %v", paths)
	}
	sdWant(t, f, "/goform/setIpMacFilterList", map[string]any{"vlanId": "20", "mac": "00aa-bbcc-ddee", "action": "action"})
	if err := DeleteObject(ctx, env, sdP+"Security.IPMACFilter.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delIpMacFilterList", map[string]any{"list": []any{map[string]any{"mac": "0011-2233-4455", "vlanId": "10"}}})

	sdSet(t, env, "Security.Dot1X.Enable", wusp.Bool(true))
	sdWant(t, f, "/goform/setNetAuthEn", map[string]any{"authEn": "1"})
	sdSet(t, env, "Security.Dot1X.Server.Address", wusp.String("10.0.0.6"))
	sdWant(t, f, "/goform/setAuthGlobalInfo", map[string]any{"authIp": "10.0.0.6", "shareKey": "dot1x-secret"})
	sdOperate(t, env, "Security.Dot1X.SetSharedKey()", sdIn("SharedKey", "new-key"))
	sdWant(t, f, "/goform/setAuthGlobalInfo", map[string]any{"authIp": "10.0.0.6", "shareKey": "new-key"})

	orig := sdJSON(t, np[0])
	sdSet(t, env, "Security.Dot1X.Port.1.ReAuthTimeout", wusp.Uint(600))
	sdWant(t, f, "/goform/setNetPortInfo", map[string]any{"port": sdStrs("9"), "portControlType": "auto", "reAuthEn": "0",
		"reAuthTimeout": "600", "clientTimeout": "30", "reAuthMaxNum": "2", "originData": orig})
}

// ---- Device Settings ---------------------------------------------------------------

func TestDeviceUsersAndMaintenance(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	users := []map[string]any{
		{"userName": "admin", "password": sdB64("admin-pw"), "userType": "admin", "timeout": "300"},
		{"userName": "ops", "password": sdB64("ops-pw"), "userType": "operate", "timeout": "120"},
	}
	sdList(f, "/goform/getUserList", "list", &users, nil)
	sdOK(f, "/goform/setUserInfo", "/goform/delUserList", "/goform/setUnlockUrl")
	f.handle("/goform/getSysMisc", map[string]any{"runningversion": "V1.1.3.18", "flashversion": "V1.1.3.18", "freetime": "0",
		"runday": "3", "runhour": "5", "pon_not_start": "0"})

	msg := sdCollect(f)
	sdParam(t, msg, "Management.User.2.UserName", "ops")
	sdParam(t, msg, "Management.User.2.Timeout", "120")
	sdParam(t, msg, "Management.UserNumberOfEntries", "2")
	sdParam(t, msg, "Management.System.RunDays", "3")
	sdParam(t, msg, "Management.System.RunningVersion", "V1.1.3.18")
	sdNoSecret(t, msg, sdB64("admin-pw"), "admin-pw", sdB64("ops-pw"), "ops-pw")

	sdOperate(t, env, "Management.User.AddUser()", sdIn("UserName", "bob", "Password", "secret1", "ConfirmPassword", "secret1",
		"UserType", "operate", "Timeout", "300"))
	sdWant(t, f, "/goform/setUserInfo", map[string]any{"userName": "bob", "newPwd": "secret1", "confirmPwd": "secret1",
		"userType": "operate", "timeout": "300", "action": "add"})
	sdOperate(t, env, "Management.User.SetUser()", sdIn("UserName", "ops", "OldPassword", "ops-pw", "NewPassword", "ops-pw2",
		"ConfirmPassword", "ops-pw2", "UserType", "guest", "Timeout", "60"))
	sdWant(t, f, "/goform/setUserInfo", map[string]any{"userName": "ops", "oldPwd": "ops-pw", "newPwd": "ops-pw2", "confirmPwd": "ops-pw2",
		"userType": "guest", "timeout": "60", "action": "edit"})
	// Type/timeout only: password keys go out empty (= keep).
	sdOperate(t, env, "Management.User.SetUser()", sdIn("UserName", "ops", "UserType", "operate", "Timeout", "300"))
	sdWant(t, f, "/goform/setUserInfo", map[string]any{"userName": "ops", "oldPwd": "", "newPwd": "", "confirmPwd": "",
		"userType": "operate", "timeout": "300", "action": "edit"})
	if err := DeleteObject(ctx, env, sdP+"Management.User.2."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delUserList", map[string]any{"list": []any{sdJSON(t, users[1])}})

	sdOperate(t, env, "Management.System.Unlock()", sdIn("UnlockKey", "LIC-123", "Days", "0"))
	sdWant(t, f, "/goform/setUnlockUrl", map[string]any{"unlockkey": sdB64("LIC-123"), "day": "0"})
}

func TestDeviceSNMPAndNMS(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	basic := map[string]any{"contactInfo": sdB64("noc@example.net"), "locationInfo": sdB64("rack 1")}
	sdForm(f, "/goform/getSnmpBasicInfo", "/goform/setSnmpBasicInfo", basic)
	comm := []map[string]any{{"communityName": "public", "accessRule": "read"}}
	sdList(f, "/goform/getSnmpAccessList", "communityList", &comm, nil)
	f.handleFunc("/goform/setSnmpCommunityInfo", func(b map[string]any) any {
		if b["action"] == "add" {
			comm = append(comm, map[string]any{"communityName": b["communityName"], "accessRule": b["accessRule"]})
		} else {
			comm[0]["accessRule"] = b["accessRule"]
		}
		return map[string]any{"errCode": "0"}
	})
	trapEn := "1"
	hosts := []map[string]any{{"destHost": "10.0.0.9", "securityWord": "public", "udpPort": "162", "securityMode": "v2c", "securityLevel": "0"}}
	f.handleFunc("/goform/getSnmpNoticeList", func(map[string]any) any {
		list := []any{}
		for _, h := range hosts {
			list = append(list, h)
		}
		return map[string]any{"trapEn": trapEn, "list": list}
	})
	f.handleFunc("/goform/setSnmpNoticeGlobal", func(b map[string]any) any {
		trapEn = Str(b["trapEn"])
		return map[string]any{"errCode": "0"}
	})
	f.handleFunc("/goform/setSnmpNoticeInfo", func(b map[string]any) any {
		if b["action"] == "add" {
			hosts = append(hosts, map[string]any{"destHost": b["destHost"], "securityWord": b["securityWord"], "udpPort": b["udpPort"],
				"securityMode": b["securityMode"], "securityLevel": "0"})
		} else {
			hosts[0]["securityMode"] = b["securityMode"]
		}
		return map[string]any{"errCode": "0"}
	})
	sdOK(f, "/goform/delSnmpCommunityList", "/goform/delSnmpNoticeList")
	nms := map[string]any{"cloudState": "enable", "serverIp": "203.0.113.7", "serverPort": "8080", "tenantId": "t1"}
	sdForm(f, "/goform/getNmsConfigInfo", "/goform/setNmsConfigInfo", nms)

	msg := sdCollect(f)
	sdParam(t, msg, "Management.SNMP.Contact", "noc@example.net")
	sdParam(t, msg, "Management.SNMP.Community.1.Access", "read")
	sdParam(t, msg, "Management.SNMP.Trap.Enable", "true")
	sdParam(t, msg, "Management.SNMP.TrapHost.1.Host", "10.0.0.9")
	sdParam(t, msg, "Management.NMS.ServerIP", "203.0.113.7")

	// SNMP basic: both fields Base64, the untouched one re-sent as read.
	sdSet(t, env, "Management.SNMP.Location", wusp.String("rack 2"))
	sdWant(t, f, "/goform/setSnmpBasicInfo", map[string]any{"contactInfo": sdB64("noc@example.net"), "locationInfo": sdB64("rack 2")})

	in := wusp.NewMessage()
	in.Set("Name", wusp.String("private"))
	in.Set("Access", wusp.String("readwrite"))
	if _, err := AddObject(ctx, env, sdP+"Management.SNMP.Community.", in); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/setSnmpCommunityInfo", map[string]any{"communityName": "private", "accessRule": "readwrite", "action": "add"})
	orig := sdJSON(t, comm[0])
	sdSet(t, env, "Management.SNMP.Community.1.Access", wusp.String("readwrite"))
	sdWant(t, f, "/goform/setSnmpCommunityInfo", map[string]any{"communityName": "public", "accessRule": "readwrite", "action": "edit", "originData": orig})
	if err := DeleteObject(ctx, env, sdP+"Management.SNMP.Community.2."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delSnmpCommunityList", map[string]any{"list": []any{map[string]any{"communityName": "private", "accessRule": "readwrite"}}})

	sdSet(t, env, "Management.SNMP.Trap.Enable", wusp.Bool(false))
	sdWant(t, f, "/goform/setSnmpNoticeGlobal", map[string]any{"trapEn": "0"})
	in = wusp.NewMessage()
	for k, v := range map[string]string{"Host": "10.0.0.10", "Community": "traps", "UDPPort": "162", "Version": "v1"} {
		in.Set(k, wusp.String(v))
	}
	if _, err := AddObject(ctx, env, sdP+"Management.SNMP.TrapHost.", in); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/setSnmpNoticeInfo", map[string]any{"destHost": "10.0.0.10", "securityWord": "traps", "udpPort": "162",
		"securityMode": "v1", "action": "add"})
	orig = sdJSON(t, hosts[0])
	sdSet(t, env, "Management.SNMP.TrapHost.1.Version", wusp.String("v1"))
	sdWant(t, f, "/goform/setSnmpNoticeInfo", map[string]any{"destHost": "10.0.0.9", "securityWord": "public", "udpPort": "162",
		"securityMode": "v1", "action": "edit", "originData": orig})
	if err := DeleteObject(ctx, env, sdP+"Management.SNMP.TrapHost.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delSnmpNoticeList", map[string]any{"list": []any{sdJSON(t, hosts[0])}})

	sdSet(t, env, "Management.NMS.TenantID", wusp.String("t2"))
	sdWant(t, f, "/goform/setNmsConfigInfo", map[string]any{"cloudState": "enable", "serverIp": "203.0.113.7", "serverPort": "8080", "tenantId": "t2"})
}

func TestDeviceTimeAccessListAAA(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	tm := map[string]any{"systemTime": "2026-11-24 13:14:47", "currentTime": "2026-11-24 13:14:47", "timeType": "network",
		"timeZone": "0", "sntppserver": "pool.ntp.org", "sntpsserver": ""}
	f.handleFunc("/goform/getSystemTimeInfo", func(map[string]any) any { return tm })
	f.handleFunc("/goform/setSystemTimeInfo", func(b map[string]any) any {
		// The device clock keeps running: systemTime never echoes the write.
		for k, v := range b {
			if k != "systemTime" {
				tm[k] = v
			}
		}
		return map[string]any{"errCode": "0"}
	})
	rule := map[string]any{"service_name": "http", "svindex": "1", "real_index": "5", "ip_start": "192.168.100.0", "ip_end": "192.168.100.255", "action": "permit"}
	acl := []map[string]any{rule}
	sdList(f, "/goform/getAccessList", "list", &acl, map[string]any{"accessStatus": "0"})
	sdOK(f, "/goform/setAccessDefaultAction", "/goform/addAccessList", "/goform/delAccessList", "/goform/resetRadiusInfo")
	aaa := map[string]any{"aaaMode": "local",
		"radiusPriServer": "10.1.1.1", "radiusPriSharedKey": "rad-pri-key", "radiusPriPort": "1812", "radiusPriTimeout": "5",
		"radiusSecServer": "", "radiusSecSharedKey": "rad-sec-key", "radiusSecPort": "1812", "radiusSecTimeout": "5",
		"tacacsPriServer": "", "tacPriSharedKey": "tac-pri-key", "tacPriPort": "49", "tacPriTimeout": "5",
		"tacacsSecServer": "", "tacSecSharedKey": "tac-sec-key", "tacSecPort": "49", "tacSecTimeout": "5",
		"enablePasswordCheckEn": "1", "enablepwd": sdB64("enable-pw")}
	sdForm(f, "/goform/getRadiusInfo", "/goform/setRadiusInfo", aaa)

	msg := sdCollect(f)
	sdParam(t, msg, "Management.Time.TimeZone", "0")
	sdParam(t, msg, "Management.Time.CurrentTime", "2026-11-24 13:14:47")
	sdParam(t, msg, "Management.AccessList.DefaultAction", "0")
	sdParam(t, msg, "Management.AccessList.Rule.1.StartIP", "192.168.100.0")
	sdParam(t, msg, "Management.AAA.Mode", "local")
	sdParam(t, msg, "Management.AAA.EnablePasswordCheck", "true")
	sdNoSecret(t, msg, "rad-pri-key", "rad-sec-key", "tac-pri-key", "tac-sec-key", sdB64("enable-pw"), "enable-pw")

	// System time: whole form {timeType, systemTime, timeZone, sntppserver, sntpsserver}.
	sdSet(t, env, "Management.Time.TimeZone", wusp.String("8"))
	sdWant(t, f, "/goform/setSystemTimeInfo", map[string]any{"timeType": "network", "systemTime": "2026-11-24 13:14:47",
		"timeZone": "8", "sntppserver": "pool.ntp.org", "sntpsserver": ""})
	sdSet(t, env, "Management.Time.SecondaryServer", wusp.String("time.google.com"))
	sdWant(t, f, "/goform/setSystemTimeInfo", map[string]any{"timeType": "network", "systemTime": "2026-11-24 13:14:47",
		"timeZone": "8", "sntppserver": "pool.ntp.org", "sntpsserver": "time.google.com"})
	sdSet(t, env, "Management.Time.SystemTime", wusp.String("2026-01-02 03:04:05")) // not verified (clock moves)
	sdWant(t, f, "/goform/setSystemTimeInfo", map[string]any{"timeType": "network", "systemTime": "2026-01-02 03:04:05",
		"timeZone": "8", "sntppserver": "pool.ntp.org", "sntpsserver": "time.google.com"})
	if err := Set(ctx, env, sdP+"Management.Time.TimeZone", wusp.String("9.5")); err == nil {
		t.Fatal("time zone outside the UI options accepted")
	}

	// Access list: add rule carries the current accessStatus.
	sdOperate(t, env, "Management.AccessList.AddRule()", sdIn("Service", "ssh", "StartIP", "10.0.0.1", "EndIP", "10.0.0.254", "Action", "permit"))
	sdWant(t, f, "/goform/addAccessList", map[string]any{"accessStatus": "0", "service": "ssh", "startIp": "10.0.0.1", "endIp": "10.0.0.254", "action": "permit"})
	sdOperate(t, env, "Management.AccessList.SetDefaultAction()", sdIn("DefaultAction", "1"))
	sdWant(t, f, "/goform/setAccessDefaultAction", map[string]any{"accessStatus": "1", "service": "telnet", "startIp": "", "endIp": "", "action": "permit"})
	if err := DeleteObject(ctx, env, sdP+"Management.AccessList.Rule.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delAccessList", map[string]any{"list": []any{sdJSON(t, rule)}})

	// AAA: whole form incl. current keys (as the UI), enablepwd stays Base64.
	want := sdJSON(t, aaa)
	want["aaaMode"] = "local-radius"
	sdSet(t, env, "Management.AAA.Mode", wusp.String("local-radius"))
	sdWant(t, f, "/goform/setRadiusInfo", want)
	want = sdJSON(t, aaa)
	want["radiusPriSharedKey"] = "new-rad-key"
	want["enablepwd"] = sdB64("new-enable")
	sdOperate(t, env, "Management.AAA.SetKeys()", sdIn("RADIUSPrimaryKey", "new-rad-key", "EnablePassword", "new-enable"))
	sdWant(t, f, "/goform/setRadiusInfo", want)
	sdOperate(t, env, "Management.AAA.Reset()", nil)
	sdWant(t, f, "/goform/resetRadiusInfo", map[string]any{})
}

func TestDeviceAutoTaskSyslogDiagnostics(t *testing.T) {
	f, env := sdFake(t)
	ctx := context.Background()
	f.handle("/goform/getTaskInfo", map[string]any{"oltrebootmode": "0", "weekday": "0", "monthday": "1", "oltreboothour": "3",
		"oltrebootmin": "0", "autosaveday": "1", "autosavehour": "0", "autosaveminute": "0", "autobackupday": "0",
		"autobackuphour": "0", "autobackupminute": "0", "autobackupserver": "10.0.0.30"})
	hosts := []map[string]any{{"serverIp": "10.0.0.20", "port": "514"}}
	sdList(f, "/goform/getSystemLogInfo", "list", &hosts, nil)
	sdOK(f, "/goform/setTaskInfo", "/goform/delSystemLog", "/goform/setSystemLogInfo", "/goform/delLogHost")
	f.handle("/goform/setPingInfo", map[string]any{"errCode": "2", "ipStr": "8.8.8.8", "ttl": "117", "time": "12"})
	f.handle("/goform/setTracertInfo", map[string]any{"errCode": "2", "result": " 1  192.168.100.1  1 ms"})

	msg := sdCollect(f)
	sdParam(t, msg, "Management.AutoTask.AutoBackupServer", "10.0.0.30")
	sdParam(t, msg, "Management.AutoTask.RebootMode", "0")
	sdParam(t, msg, "Management.Syslog.Server.1.Port", "514")

	// Reboot schedule: mode 1 (JSON number) + current values for empty inputs.
	sdOperate(t, env, "Management.AutoTask.SetRebootSchedule()", sdIn("RebootMode", "2", "Hour", "4"))
	sdWant(t, f, "/goform/setTaskInfo", map[string]any{"mode": float64(1), "oltrebootmode": "2", "weekday": "0", "monthday": "1",
		"oltreboothour": "4", "oltrebootmin": "0"})

	sdOperate(t, env, "Management.Log.Clear()", nil)
	sdWant(t, f, "/goform/delSystemLog", map[string]any{"action": "delete"})

	sdOperate(t, env, "Management.Syslog.AddServer()", sdIn("ServerIP", "10.0.0.21", "Port", "514"))
	sdWant(t, f, "/goform/setSystemLogInfo", map[string]any{"serverip": "10.0.0.21", "port": "514", "action": "add"})
	if err := DeleteObject(ctx, env, sdP+"Management.Syslog.Server.1."); err != nil {
		t.Fatal(err)
	}
	sdWant(t, f, "/goform/delLogHost", map[string]any{"list": []any{map[string]any{"serverIp": "10.0.0.20", "port": "514"}}})

	out := sdOperate(t, env, "Management.Diagnostics.Ping()", sdIn("Host", "8.8.8.8", "PacketSize", "56"))
	sdWant(t, f, "/goform/setPingInfo", map[string]any{"packageLen": "56", "destIp": "8.8.8.8"})
	if v, ok := out.Get(sdP + "Management.Diagnostics.PingResult"); !ok || !strings.Contains(wusp.ValueToString(v), `"ipStr":"8.8.8.8"`) {
		t.Fatalf("PingResult = %v", v)
	}
	out = sdOperate(t, env, "Management.Diagnostics.Traceroute()", sdIn("Host", "8.8.8.8", "MaxHops", "30", "TTL", "1"))
	sdWant(t, f, "/goform/setTracertInfo", map[string]any{"destIp": "8.8.8.8", "hopCount": "30", "ttl": "1"})
	if v, ok := out.Get(sdP + "Management.Diagnostics.TracerouteResult"); !ok || !strings.Contains(wusp.ValueToString(v), "192.168.100.1") {
		t.Fatalf("TracerouteResult = %v", v)
	}
}

// Declared metadata: effects of the risky controls, unsupported pages.
func TestSecurityDeviceSchema(t *testing.T) {
	cmds := map[string]wusp.OLTEffect{}
	for _, c := range wusp.WUSPOLTCommands {
		cmds[strings.TrimPrefix(c.Path, sdP)] = c.Effect
	}
	for cmd, want := range map[string]wusp.OLTEffect{
		"Management.AccessList.SetDefaultAction()": wusp.OLTEffectDisruptive,
		"Management.AccessList.AddRule()":          wusp.OLTEffectDisruptive,
		"Management.AutoTask.SetRebootSchedule()":  wusp.OLTEffectDestructive,
		"Management.Log.Clear()":                   wusp.OLTEffectDestructive,
		"Management.Diagnostics.Ping()":            wusp.OLTEffectNone,
		"Management.AAA.Reset()":                   wusp.OLTEffectDisruptive,
	} {
		if got, ok := cmds[cmd]; !ok || got != want {
			t.Errorf("%s effect = %q (declared %v), want %q", cmd, got, ok, want)
		}
	}
	params := map[string]wusp.OLTParamDef{}
	for _, d := range wusp.WUSPOLTAllParamDefs {
		params[strings.TrimPrefix(d.Path, sdP)] = d
	}
	for rel, d := range params {
		if !strings.HasPrefix(rel, "Management.") && !strings.HasPrefix(rel, "Security.") {
			continue
		}
		l := strings.ReplaceAll(strings.ToLower(rel), "passwordcheck", "")
		if strings.Contains(l, "password") || strings.Contains(l, "sharedkey") || strings.HasSuffix(l, ".key") {
			t.Errorf("secret exposed as parameter %s", d.Path)
		}
	}
	if d := params["Management.AAA.Mode"]; d.Effect != wusp.OLTEffectDisruptive {
		t.Errorf("AAA.Mode effect = %q", d.Effect)
	}
	unsupported := map[string]bool{}
	for _, p := range wusp.OLTUnsupportedPages() {
		unsupported[p.Route] = true
	}
	for _, r := range []string{"/network/acl/macacl", "/network/acl/ipv6acl", "/device/edfa/edfa", "/device/time/list", "/device/ims"} {
		if !unsupported[r] {
			t.Errorf("%s should be listed as unsupported", r)
		}
	}
}
