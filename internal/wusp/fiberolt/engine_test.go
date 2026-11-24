package fiberolt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// withRegistry temporarily extends the binding tables (tests exercising
// engine features no shipped control uses yet).
func withRegistry(t *testing.T, sources []Source, bindings []Binding, tables []Table) {
	t.Helper()
	oldS, oldB, oldT := Sources, Bindings, Tables
	Sources = append(append([]Source{}, Sources...), sources...)
	Bindings = append(append([]Binding{}, Bindings...), bindings...)
	Tables = append(append([]Table{}, Tables...), tables...)
	resetIndex()
	t.Cleanup(func() {
		Sources, Bindings, Tables = oldS, oldB, oldT
		resetIndex()
	})
}

// One collection fetches each goform page once, however many params,
// tables and derived getters read it.
func TestCollectFetchesEachSourceOnce(t *testing.T) {
	f := richOLT(t)
	cli := newFakeCLI(t, richCLIOutputs())
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), cli.cli(), true, msg)
	for _, src := range Sources {
		if src.Endpoint == "" {
			continue
		}
		if n := len(f.callsTo(src.Endpoint)); n != 1 {
			t.Errorf("%s fetched %d times, want 1", src.Endpoint, n)
		}
	}
	if n := len(f.callsTo("/goform/getOntListBrife")); n != 1 {
		t.Errorf("getOntListBrife fetched %d times, want 1", n)
	}
}

// fooPage is a stateful goform page pair used to exercise ReadModifyWrite.
type fooPage struct {
	state map[string]any
	// ignore makes the device accept the write but not apply it.
	ignore bool
	reply  map[string]any
}

func (p *fooPage) install(f *fakeOLT) {
	f.handleFunc("/goform/getFoo", func(map[string]any) any {
		out := map[string]any{}
		for k, v := range p.state {
			out[k] = v
		}
		return out
	})
	f.handleFunc("/goform/setFoo", func(body map[string]any) any {
		if !p.ignore {
			for k, v := range body {
				p.state[k] = v
			}
		}
		if p.reply != nil {
			return p.reply
		}
		return map[string]any{"errCode": "success"}
	})
	f.handle("/goform/saveFoo", map[string]any{"errCode": "success"})
}

func rmwRegistry(t *testing.T) {
	withRegistry(t,
		[]Source{{Name: "foo", Endpoint: "/goform/getFoo"}},
		[]Binding{{Leaf: "Network.NTP.Server", Get: From("foo", AsString, "server"), Set: &Setter{
			ReadModifyWrite: true, Read: "foo", Endpoint: "/goform/setFoo", Field: "server",
			// The page returns a read-only status field the form must not post back.
			Form: func(cur Doc) map[string]any {
				out := map[string]any{}
				for k, v := range cur {
					if k != "status" {
						out[k] = v
					}
				}
				return out
			},
			Commit: &Request{Endpoint: "/goform/saveFoo"},
		}}},
		nil)
	// The test binding shadows the shipped Network.NTP.Server (last wins).
	buildIndex()
	for i := range Bindings {
		if Bindings[i].Leaf == "Network.NTP.Server" {
			bindingByLf["Network.NTP.Server"] = &Bindings[i]
		}
	}
}

func TestReadModifyWriteSetter(t *testing.T) {
	f := newFakeOLT(t)
	page := &fooPage{state: map[string]any{"server": "old.ntp", "zone": "UTC", "enable": "1", "status": "synced"}}
	page.install(f)
	rmwRegistry(t)

	err := Set(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"Network.NTP.Server", wusp.String("new.ntp"))
	if err != nil {
		t.Fatal(err)
	}
	writes := f.callsTo("/goform/setFoo")
	if len(writes) != 1 {
		t.Fatalf("setFoo calls = %d", len(writes))
	}
	want := map[string]any{"server": "new.ntp", "zone": "UTC", "enable": "1"}
	if !reflect.DeepEqual(writes[0].Body, want) {
		t.Fatalf("form = %v, want whole form %v", writes[0].Body, want)
	}
	if len(f.callsTo("/goform/saveFoo")) != 1 {
		t.Fatal("commit not called")
	}
	// Read before the write and re-read after it to confirm.
	if n := len(f.callsTo("/goform/getFoo")); n != 2 {
		t.Fatalf("getFoo calls = %d, want 2 (read + confirm)", n)
	}
}

func TestReadModifyWriteDetectsIgnoredWrite(t *testing.T) {
	f := newFakeOLT(t)
	page := &fooPage{state: map[string]any{"server": "old.ntp"}, ignore: true}
	page.install(f)
	rmwRegistry(t)
	err := Set(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"Network.NTP.Server", wusp.String("new.ntp"))
	if err == nil || !strings.Contains(err.Error(), "did not apply") {
		t.Fatalf("err = %v, want did-not-apply", err)
	}
}

func TestReadModifyWriteVendorError(t *testing.T) {
	f := newFakeOLT(t)
	page := &fooPage{state: map[string]any{"server": "old.ntp"}, reply: map[string]any{"errCode": "fail"}}
	page.install(f)
	rmwRegistry(t)
	err := Set(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"Network.NTP.Server", wusp.String("x"))
	if err == nil || !strings.Contains(err.Error(), "errCode=fail") {
		t.Fatalf("err = %v, want errCode failure", err)
	}
	if len(f.callsTo("/goform/saveFoo")) != 0 {
		t.Fatal("commit must not run after a failed write")
	}
}

// ONU instances follow the collected (sorted, CLI-merged) table, so a
// CLI-only ONU sorting before a web ONU must not shift writes onto the
// wrong device.
func TestONUEnableUsesCollectedKey(t *testing.T) {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", SysStatus{Ports: []Port{{PortName: "pon1", PortStatus: "1", Online: "2", Offline: "0"}}})
	// The web ONU list is unavailable: the CLI fallback enumerates ONUs.
	f.handle("/goform/setOntListActive", map[string]any{})
	f.handle("/goform/setOntListDeactive", map[string]any{})
	cli := newFakeCLI(t, map[string]string{
		"show ont info online 0/1/1-0/1/64": "0/1/1  HWTC-A  0d0h1m  Normal  working\n0/1/2  HWTC-B  0d0h1m  Normal  working\n",
	})
	api := f.client()
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), api, cli.cli(), true, msg)
	if v, _ := msg.Get(wusp.WUSPOLTPrefix + "ONU.1.Index"); wusp.ValueToString(v) != "0/1/1" {
		t.Fatalf("ONU.1 = %v, want the CLI-only 0/1/1", v)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{"ONU.1.Enable", "0/1/1"},
		{"ONU.2.Enable", "0/1/2"},
	} {
		f.reset()
		if err := SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+tc.path, wusp.Bool(false), nil); err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		calls := f.callsTo("/goform/setOntListDeactive")
		if len(calls) != 1 {
			t.Fatalf("%s: deactive calls = %d", tc.path, len(calls))
		}
		got := calls[0].Body["list"].([]any)[0].(map[string]any)["onuid"]
		if got != tc.want {
			t.Errorf("%s deactivated %v, want %s", tc.path, got, tc.want)
		}
	}
	if err := SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"ONU.3.Enable", wusp.Bool(true), nil); !errors.Is(err, wusp.ErrUSPPathNotFound) {
		t.Fatalf("ONU.3: err = %v, want not found", err)
	}
}

// A row that moved or vanished after the console's last Get is resolved
// by its vendor key, never by position.
func TestDeleteResolvesRowByKey(t *testing.T) {
	f := richOLT(t)
	rows := []map[string]any{
		{"onuid": "0/1/1", "mode": "sn", "info": "A", "lineid": "1", "desc": ""},
		{"onuid": "0/1/2", "mode": "sn", "info": "B", "lineid": "1", "desc": ""},
	}
	f.handleFunc("/goform/getOntListConfig", func(map[string]any) any { return map[string]any{"list": rows} })
	f.handle("/goform/delOntListConfig", map[string]any{})
	api := f.client()
	env := &Env{API: api}
	CollectOLT(context.Background(), api, nil, true, wusp.NewMessage())

	// Someone removed 0/1/1 on the OLT: instance 2 (0/1/2) is now first.
	rows = rows[1:]
	if err := DeleteObject(context.Background(), env, wusp.WUSPOLTPrefix+"ProvisionedONU.2."); err != nil {
		t.Fatal(err)
	}
	calls := f.callsTo("/goform/delOntListConfig")
	if len(calls) != 1 || calls[0].Body["list"].([]any)[0].(map[string]any)["onuid"] != "0/1/2" {
		t.Fatalf("delete calls = %+v, want onuid 0/1/2", calls)
	}
	if err := DeleteObject(context.Background(), env, wusp.WUSPOLTPrefix+"ProvisionedONU.1."); !errors.Is(err, wusp.ErrUSPPathNotFound) {
		t.Fatalf("deleting the vanished row: err = %v, want not found", err)
	}
	// Legacy path form (Object.N.Leaf) is still accepted.
	f.reset()
	if err := DeleteObject(context.Background(), env, wusp.WUSPOLTPrefix+"ProvisionedONU.2.OnuID"); err != nil {
		t.Fatal(err)
	}
	if len(f.callsTo("/goform/delOntListConfig")) != 1 {
		t.Fatal("legacy delete path not handled")
	}
}

func TestAddProvisionedONU(t *testing.T) {
	f := richOLT(t)
	f.handle("/goform/setOntListConfig", map[string]any{})
	initial := wusp.NewMessage()
	initial.Set("Device.WUSP_OLT.ProvisionedONU.{i}.OnuID", wusp.String("0/1/9"))
	initial.Set("Device.WUSP_OLT.ProvisionedONU.{i}.Info", wusp.String("HWTC00000009"))
	initial.Set("Device.WUSP_OLT.ProvisionedONU.{i}.Mode", wusp.String("sn"))
	paths, err := AddObject(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"ProvisionedONU.", initial)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{wusp.WUSPOLTPrefix + "ProvisionedONU.0/1/9"}) {
		t.Fatalf("paths = %v (legacy shape expected)", paths)
	}
	calls := f.callsTo("/goform/setOntListConfig")
	want := map[string]any{"onuid": "0/1/9", "mode": "sn", "sn": "HWTC00000009", "lineid": "0", "desc": "", "action": "add"}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0].Body, want) {
		t.Fatalf("calls = %+v", calls)
	}
	if _, err := AddObject(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"ProvisionedONU.", wusp.NewMessage()); err == nil || !strings.Contains(err.Error(), "OnuID") {
		t.Fatalf("missing OnuID: err = %v", err)
	}
	if _, err := AddObject(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTPrefix+"Network.ACL.", initial); !errors.Is(err, wusp.ErrUSPPathUnsupported) {
		t.Fatalf("non-addable table: err = %v", err)
	}
}

// A generic table with Add (re-read result path), a column setter doing
// read-modify-write of the row, and Delete.
func TestGenericTableAddSetDelete(t *testing.T) {
	f := newFakeOLT(t)
	rows := []map[string]any{{"vid": "10", "name": "a", "desc": "x"}}
	f.handleFunc("/goform/getVlanTable", func(map[string]any) any { return map[string]any{"list": rows} })
	f.handleFunc("/goform/setVlanRow", func(body map[string]any) any {
		for _, r := range rows {
			if r["vid"] == body["vid"] {
				for k, v := range body {
					r[k] = v
				}
				return map[string]any{"errCode": "success"}
			}
		}
		rows = append(rows, map[string]any{"vid": body["vid"], "name": body["name"], "desc": body["desc"]})
		return map[string]any{"errCode": "success"}
	})
	f.handle("/goform/delVlanRow", map[string]any{"errCode": "success"})
	withRegistry(t, []Source{{Name: "vlanTable", Endpoint: "/goform/getVlanTable"}}, nil, []Table{{
		Object: "Network.QVLAN", Source: "vlanTable", KeyFields: []string{"vid"},
		Columns: []Column{
			{Leaf: "ID", Get: Col(AsString, "vid")},
			{Leaf: "Name", Get: Col(AsString, "name"), Set: &Setter{Func: func(sc *SetCall) error {
				row := map[string]any{}
				for k, v := range sc.Row {
					row[k] = v
				}
				row["name"] = wusp.ValueToString(sc.Value)
				return postChecked(sc.Ctx, sc.Env.API, "/goform/setVlanRow", row, true)
			}}},
		},
		Add: func(ac *AddCall) (string, error) {
			vid := ac.In("ID")
			return vid, postChecked(ac.Ctx, ac.Env.API, "/goform/setVlanRow", map[string]any{"vid": vid, "name": ac.In("Name"), "desc": ""}, true)
		},
		Delete: func(sc *SetCall) error {
			return postChecked(sc.Ctx, sc.Env.API, "/goform/delVlanRow", map[string]any{"vid": sc.Key}, true)
		},
	}})
	// The test table shadows the shipped Network.QVLAN binding.
	buildIndex()
	tableByObj["Network.QVLAN"] = &Tables[len(Tables)-1]
	env := &Env{API: f.client()}
	ctx := context.Background()

	initial := wusp.NewMessage()
	initial.Set("ID", wusp.String("20"))
	initial.Set("Name", wusp.String("b"))
	paths, err := AddObject(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.", initial)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{wusp.WUSPOLTPrefix + "Network.QVLAN.2."}) {
		t.Fatalf("Add paths = %v", paths)
	}

	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.1.Name", wusp.String("renamed")); err != nil {
		t.Fatal(err)
	}
	last := f.callsTo("/goform/setVlanRow")
	body := last[len(last)-1].Body
	if !reflect.DeepEqual(body, map[string]any{"vid": "10", "name": "renamed", "desc": "x"}) {
		t.Fatalf("row write = %v, want the full row with one field changed", body)
	}
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.1.ID", wusp.String("99")); !errors.Is(err, wusp.ErrUSPPathUnsupported) {
		t.Fatalf("read-only column: err = %v", err)
	}
	if err := DeleteObject(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.2."); err != nil {
		t.Fatal(err)
	}
	if del := f.callsTo("/goform/delVlanRow"); len(del) != 1 || del[0].Body["vid"] != "20" {
		t.Fatalf("delete = %+v", del)
	}
}

func TestOperateReturnsOutput(t *testing.T) {
	f := richOLT(t)
	f.handle("/cgi-bin/DownloadCfg/olt_config.txt", "hostname OLT\n")
	out, err := Operate(context.Background(), &Env{API: f.client()}, wusp.WUSPOLTBackupConfigCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := out.Get(wusp.WUSPOLTPrefix + "Config"); !ok || wusp.ValueToString(v) != "hostname OLT\n" {
		t.Fatalf("Config output = %v", v)
	}
	if _, err := Operate(context.Background(), &Env{API: f.client()}, "Device.WUSP_OLT.Nope()", nil); err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("unknown command: %v", err)
	}
}

func TestPostOpDefaultMissingMessage(t *testing.T) {
	op := PostOp{Endpoint: "/x", Fields: []FormField{{"a", "A", true}, {"b", "B", true}}}
	err := op.Run(&OpCall{Ctx: context.Background(), Command: wusp.WUSPOLTPrefix + "Foo.Add()", Input: wusp.NewMessage()})
	if err == nil || err.Error() != "olt: Foo.Add() requires A and B" {
		t.Fatalf("err = %v", err)
	}
}

func TestDescribeControls(t *testing.T) {
	out, err := Operate(context.Background(), &Env{API: NewClient("http://127.0.0.1:1", "", "")}, wusp.WUSPOLTDescribeControlsCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := out.Get(wusp.WUSPOLTPrefix + "ControlSchema")
	if !ok {
		t.Fatal("no ControlSchema output")
	}
	var s ControlSchema
	if err := json.Unmarshal([]byte(wusp.ValueToString(v)), &s); err != nil {
		t.Fatal(err)
	}
	if s.Format != ControlSchemaFormat || s.Version == "" || s.Version != ControlSchemaVersion() {
		t.Fatalf("format/version = %q/%q (want %q)", s.Format, s.Version, ControlSchemaVersion())
	}
	if len(s.Params) != len(wusp.WUSPOLTAllParamDefs) || len(s.Operations) != len(wusp.WUSPOLTCommands) || len(s.Tables) != len(wusp.WUSPOLTTableDefs) {
		t.Fatalf("counts params=%d tables=%d ops=%d", len(s.Params), len(s.Tables), len(s.Operations))
	}
	params := map[string]SchemaParam{}
	for _, p := range s.Params {
		params[p.Path] = p
	}
	ntp := params[wusp.WUSPOLTPrefix+"Network.NTP.Server"]
	if !ntp.Settable || ntp.Group != "Network" || ntp.Section != "NTP" || ntp.MaxLength != 128 {
		t.Errorf("NTP.Server = %+v", ntp)
	}
	if v := params[wusp.WUSPOLTPrefix+"Network.Mgmt.VLAN"]; !v.Settable || v.Access != "readWrite" || v.Effect != "disruptive" {
		t.Errorf("Mgmt.VLAN = %+v (bound through setDeviceInfo mngvlan)", v)
	}
	if onu := params[wusp.WUSPOLTPrefix+"ONU.{i}.Enable"]; !onu.Settable || onu.Table != wusp.WUSPOLTPrefix+"ONU.{i}." || onu.Group != "ONU" {
		t.Errorf("ONU.Enable = %+v", onu)
	}
	if temp := params[wusp.WUSPOLTPrefix+"Temperature"]; temp.Units != "°C" || temp.Group != "System" || temp.Settable {
		t.Errorf("Temperature = %+v", temp)
	}
	if st := params[wusp.WUSPOLTPrefix+"Status"]; len(st.Enum) == 0 {
		t.Errorf("Status enum missing: %+v", st)
	}
	for _, op := range s.Operations {
		if !op.Supported {
			t.Errorf("%s not supported", op.Path)
		}
		if op.Path == wusp.WUSPOLTFactoryRestoreCommand && (op.Effect != "destructive" || !op.Confirm) {
			t.Errorf("FactoryRestore = %+v", op)
		}
	}
	for _, tb := range s.Tables {
		if tb.Path == wusp.WUSPOLTPrefix+"ProvisionedONU.{i}." && (!tb.Addable || !tb.Deletable || len(tb.AddArgs) == 0 || tb.Key != "OnuID") {
			t.Errorf("ProvisionedONU table = %+v", tb)
		}
	}
}

// WUSP_OLT_SCHEMA_OUT=<file> go test -run TestExportControlSchema writes the
// control schema for consoles that bundle it at build time.
func TestExportControlSchema(t *testing.T) {
	out := os.Getenv("WUSP_OLT_SCHEMA_OUT")
	if out == "" {
		t.Skip("set WUSP_OLT_SCHEMA_OUT to export")
	}
	raw, err := ControlSchemaJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(pretty.Bytes(), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The FOS add/edit/delete idioms: edit posts the whole row plus
// action/originData and is confirmed by re-reading the row by key; delete
// posts {list:[row]}; an expired session is re-established once.
func TestFOSRowIdioms(t *testing.T) {
	f := newFakeOLT(t)
	rows := []map[string]any{{"vlanId": "10", "serverIp": "1.1.1.1", "optionStatusEn": "0"}}
	expired := true
	f.handleFunc("/goform/getRelay", func(map[string]any) any {
		if expired {
			expired = false
			return map[string]any{"errCode": "timeout"}
		}
		return map[string]any{"list": rows}
	})
	f.handleFunc("/goform/setRelay", func(body map[string]any) any {
		for _, r := range rows {
			if r["vlanId"] == body["vlanId"] && body["action"] == "edit" {
				r["optionStatusEn"] = body["optionStatusEn"]
			}
		}
		if body["action"] == "add" {
			rows = append(rows, map[string]any{"vlanId": body["vlanId"], "serverIp": body["serverIp"], "optionStatusEn": "0"})
		}
		return map[string]any{"errCode": "0"}
	})
	f.handle("/goform/delRelay", map[string]any{"errCode": "0"})
	withRegistry(t, []Source{{Name: "relay", Endpoint: "/goform/getRelay"}}, nil, []Table{{
		Object: "Network.QVLAN", Source: "relay", KeyFields: []string{"vlanId"},
		Columns: []Column{
			{Leaf: "ID", Get: Col(AsString, "vlanId")},
			{Leaf: "Enabled", Get: Col(AsBool01, "optionStatusEn"), Set: RowEdit("/goform/setRelay", "optionStatusEn", boolForm)},
		},
		Add:    RowAdd("/goform/setRelay", "ID", []FormField{{"vlanId", "ID", true}, {"serverIp", "Server", false}}),
		Delete: RowDelete("/goform/delRelay"),
	}})
	env := &Env{API: f.client()}
	ctx := context.Background()

	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.1.Enabled", wusp.Bool(true)); err != nil {
		t.Fatal(err)
	}
	edit := f.callsTo("/goform/setRelay")[0].Body
	origin, _ := edit["originData"].(map[string]any)
	if edit["action"] != "edit" || edit["optionStatusEn"] != "1" || edit["serverIp"] != "1.1.1.1" || origin["optionStatusEn"] != "0" {
		t.Fatalf("edit body = %v", edit)
	}
	if n := len(f.callsTo("/login/Auth")); n < 2 {
		t.Fatalf("expired session not re-established (logins=%d)", n)
	}

	in := wusp.NewMessage()
	in.Set("ID", wusp.String("20"))
	paths, err := AddObject(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.", in)
	if err != nil || len(paths) != 1 || paths[0] != wusp.WUSPOLTPrefix+"Network.QVLAN.2." {
		t.Fatalf("add = %v, %v", paths, err)
	}
	if err := DeleteObject(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.2."); err != nil {
		t.Fatal(err)
	}
	del := f.callsTo("/goform/delRelay")[0].Body["list"].([]any)[0].(map[string]any)
	if del["vlanId"] != "20" {
		t.Fatalf("delete body = %v", del)
	}

	// A device error code surfaces to the console.
	f.handle("/goform/setRelay", map[string]any{"errCode": "205"})
	err = Set(ctx, env, wusp.WUSPOLTPrefix+"Network.QVLAN.1.Enabled", wusp.Bool(false))
	if err == nil || !strings.Contains(err.Error(), "errCode=205") {
		t.Fatalf("err = %v", err)
	}
}
