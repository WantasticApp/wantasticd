package fiberolt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// TestControlRequestsGolden pins the exact vendor requests (path + JSON body)
// every pre-existing setter and Operate command issues, so porting them onto
// the declarative registry cannot change what reaches the OLT.
func TestControlRequestsGolden(t *testing.T) {
	f := richOLT(t)
	f.handle("/cgi-bin/DownloadCfg/olt_config.txt", "hostname OLT\n")
	for _, p := range []string{
		"/goform/setQuickCfgNetwork", "/goform/setSystemTimeInfo", "/goform/setSystemReboot",
		"/goform/setSystemRestore", "/goform/setOntListReboot", "/goform/setOntListReset",
		"/goform/setOntListActive", "/goform/setOntListDeactive", "/goform/setAclListInfo",
		"/goform/delAclList", "/goform/setStaticRouteInfo", "/goform/delStaticRouteList",
		"/goform/setServicePort", "/goform/delPortOnu", "/goform/setQvlanInfo", "/goform/delQvlanList",
		"/cgi-bin/uploadCfg", "/goform/setDeviceInfo", "/goform/setGlobalConfig", "/goform/delOntListConfig", "/goform/getExportStatus",
	} {
		f.handle(p, map[string]any{"errCode": "success"})
	}
	// Stateful pages so read-modify-write setters can confirm.
	sys := map[string]any{}
	for k, v := range f.reply("/goform/getSysStatus").(map[string]any) {
		sys[k] = v
	}
	f.handleFunc("/goform/getSysStatus", func(map[string]any) any { return sys })
	merge := func(dst map[string]any) func(map[string]any) any {
		return func(body map[string]any) any {
			for k, v := range body {
				if k != "originData" && k != "editdevice" && k != "isAlarm" {
					dst[k] = v
				}
			}
			return map[string]any{"errCode": "0"}
		}
	}
	f.handleFunc("/goform/setDeviceInfo", merge(sys))
	f.handleFunc("/goform/setAlarmInfo", merge(sys))
	tm := map[string]any{}
	for k, v := range f.reply("/goform/getSystemTimeInfo").(map[string]any) {
		tm[k] = v
	}
	f.handleFunc("/goform/getSystemTimeInfo", func(map[string]any) any { return tm })
	f.handleFunc("/goform/setSystemTimeInfo", merge(tm))
	f.handle("/goform/getExportStatus", map[string]any{"errCode": "0"})
	f.handle("/goform/setSystemReboot", map[string]any{"errCode": "6"})
	f.handle("/goform/setSystemRestore", map[string]any{"errCode": "7"})
	api := f.client()
	ctx := context.Background()
	in := func(kv ...string) *wusp.Message {
		m := wusp.NewMessage()
		for i := 0; i+1 < len(kv); i += 2 {
			m.Set(kv[i], wusp.String(kv[i+1]))
		}
		return m
	}

	out := map[string]string{}
	record := func(name string, err error) {
		var parts []string
		f.mu.Lock()
		for _, c := range f.calls {
			if c.Path == "/login/Auth" {
				continue
			}
			body, _ := json.Marshal(c.Body)
			parts = append(parts, c.Path+" "+string(body))
		}
		f.calls = nil
		f.mu.Unlock()
		res := "ok"
		if err != nil {
			res = "err: " + err.Error()
		}
		out[name] = res + " | " + strings.Join(parts, " ; ")
	}

	sets := []struct {
		leaf string
		val  wusp.Value
	}{
		{"Network.Mgmt.IPAddress", wusp.String("10.0.0.2")},
		{"Network.Mgmt.SubnetMask", wusp.String("255.255.0.0")},
		{"Network.DNS.Server.1.Address", wusp.String("1.1.1.1")},
		{"Network.DNS.Server.2.Address", wusp.String("9.9.9.9")},
		{"Network.NTP.Server", wusp.String("time.example")},
		{"Network.NTP.Enabled", wusp.Bool(true)},
		{"Network.NTP.Enabled", wusp.Bool(false)},
		{"TemperatureAlarmHigh", wusp.Float(70)},
		{"Temperature", wusp.String("1")},
		{"Network.Mgmt.Gateway", wusp.String("1.2.3.4")},
	}
	for i, s := range sets {
		f.reset()
		err := SetOLTParam(ctx, api, wusp.WUSPOLTPrefix+s.leaf, s.val, nil)
		record(fmt.Sprintf("set %02d %s=%s", i, s.leaf, wusp.ValueToString(s.val)), err)
	}

	ops := []struct {
		cmd   string
		input *wusp.Message
	}{
		{wusp.WUSPOLTRebootCommand, nil},
		{wusp.WUSPOLTFactoryRestoreCommand, nil},
		{wusp.WUSPOLTONURebootCommand, in("Index", "0/1/2")},
		{wusp.WUSPOLTONUResetCommand, in("Index", "0/1/2")},
		{wusp.WUSPOLTONUEnableCommand, in("Index", "0/1/2")},
		{wusp.WUSPOLTONUDisableCommand, in("Index", "0/1/2")},
		{wusp.WUSPOLTONURebootCommand, nil},
		{wusp.WUSPOLTRestoreConfigCommand, in("Config", "hostname X\n")},
		{wusp.WUSPOLTRestoreConfigCommand, nil},
		{wusp.WUSPOLTUpgradeCommand, nil},
		{wusp.WUSPOLTNetworkACLAddCommand, in("ID", "100", "Name", "r1")},
		{wusp.WUSPOLTNetworkACLAddCommand, in("Name", "r1")},
		{wusp.WUSPOLTNetworkACLDeleteCommand, in("ID", "7")},
		{wusp.WUSPOLTNetworkRouteAddCommand, in("Destination", "10.1.0.0", "Mask", "255.255.0.0", "Gateway", "192.168.100.1", "Interface", "vlan1")},
		{wusp.WUSPOLTNetworkRouteDeleteCommand, in("Destination", "172.16.0.0")},
		{wusp.WUSPOLTNetworkQVLANAddCommand, in("StartVLAN", "300")},
		{wusp.WUSPOLTNetworkQVLANDeleteCommand, in("ID", "300")},
		{wusp.WUSPOLTNetworkQVLANDeleteCommand, in("ID", "1")},
		{wusp.WUSPOLTSaveConfigCommand, nil},
		{"Device.WUSP_OLT.Nope()", nil},
	}
	for i, o := range ops {
		f.reset()
		err := OLTOperate(ctx, api, o.cmd, o.input)
		record(fmt.Sprintf("op %02d %s", i, o.cmd), err)
	}

	// Result-producing commands write their output into the input message.
	for i, cmd := range []string{wusp.WUSPOLTBackupConfigCommand, wusp.WUSPOLTNetworkBackupConfigCommand} {
		f.reset()
		res := wusp.NewMessage()
		err := OLTOperate(ctx, api, cmd, res)
		record(fmt.Sprintf("result %02d %s", i, cmd), err)
		for _, fl := range res.Fields {
			out[fmt.Sprintf("result %02d %s", i, cmd)] += " => " + fl.Path + "=" + wusp.ValueToString(fl.Val)
		}
	}
	checkGolden(t, "control_calls.golden.json", out)
}
