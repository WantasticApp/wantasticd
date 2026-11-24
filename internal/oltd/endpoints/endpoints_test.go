package endpoints

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/oltd/wire"
)

type sockCode struct {
	sock string
	code uint16
}

// fakeBackend answers from a table and applies the same read()+seq_pull_chk
// semantics the real client does.
type fakeBackend struct {
	replies map[sockCode]string
	errs    map[sockCode]error
	seen    []wire.Msg
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string { return "timeout" }
func (fakeTimeout) Timeout() bool { return true }

func (f *fakeBackend) Query(sock string, build func(string) (wire.Msg, error), bufSize int) (string, error) {
	m, err := build("/tmp/wo1_1_0")
	if err != nil {
		return "", err
	}
	f.seen = append(f.seen, append(wire.Msg(nil), m...)) // copy: setters reuse one buffer across items
	k := sockCode{sock, m.Code()}
	if err := f.errs[k]; err != nil {
		return "", err
	}
	text, ok := f.replies[k]
	if !ok {
		return "", fmt.Errorf("no fake reply for %s code %d", sock, m.Code())
	}
	got, _ := wire.ParseReply(wire.EncodeReply(m.Code(), wire.FinishText(text)), m.Code(), bufSize)
	return got, nil
}

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

func call(t *testing.T, b Backend, op, name string, p Params, env *Env) []byte {
	t.Helper()
	ep, ok := Lookup(op, name)
	if !ok {
		t.Fatalf("%s %s not registered", op, name)
	}
	out, err := ep.Call(b, p, env)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

func TestQvlanListMatchesLiveSample(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 300}: "1,default,1,static,192.168.1.100,255.255.255.0:4000,VLAN4000,1,static,192.168.130.179,255.255.255.0",
	}}
	got := call(t, fb, "get", "getQvlanList", nil, nil)
	if want := sample(t, "getQvlanList.json"); !bytes.Equal(got, want) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestOntListBrifeMatchesLiveSample(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockPON, 1011}: "0/1/1,HWTC-93bb0308,online,0d20h11m,PTF2164Q,Normal,-,-",
	}}
	got := call(t, fb, "get", "/goform/getOntListBrife", Params{"PonPortName": "all"}, nil)
	if want := sample(t, "getOntListBrife.json"); !bytes.Equal(got, want) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if p := wire.QuickParams(fb.seen[0].Bytes()); len(p) != 1 || p[0] != "all" {
		t.Fatalf("request params %q", p)
	}
	// "ERROR" from the daemon is an empty list (formQuickListStrToJson).
	fb.replies[sockCode{SockPON, 1011}] = "ERROR"
	if got := call(t, fb, "get", "getOntListBrife", nil, nil); !strings.HasPrefix(string(got), `{"list":[],"ponPortList":["pon1"`) {
		t.Fatalf("ERROR reply: %s", got)
	}
}

func TestKeyValueListCommon(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockPON, 1010}: "ontid:0/1/1,rxpower:-20.5,distance:1200",
	}}
	got := call(t, fb, "get", "getOntDetail", Params{"ontid": "0/1/1"}, nil)
	if want := `{"list":[{"ontid":"0/1/1","rxpower":"-20.5","distance":"1200"}]}`; string(got) != want {
		t.Fatalf("got %s", got)
	}
	// formQuickListStrToJson ignores formQuickStrToJson's -4: a malformed
	// token ends that line (keys before it stay) and the next line is read.
	fb.replies[sockCode{SockPON, 1010}] = "ontid:0/1/1,no-colon-here,rxpower:-20.5\ndistance:1200"
	if got := call(t, fb, "get", "getOntDetail", nil, nil); string(got) != `{"list":[{"ontid":"0/1/1"},{"distance":"1200"}]}` {
		t.Fatalf("bad token: %s", got)
	}
}

// Build the daemon text from the live JSON and check the port reproduces
// it byte for byte (validates every field position).
func TestPortBasicListMatchesLiveSample(t *testing.T) {
	want := sample(t, "getPortBasicList.json")
	var doc struct {
		List []map[string]string `json:"list"`
	}
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	var lines, pon []string
	for _, r := range doc.List {
		status := r["portStatus"]
		if strings.HasPrefix(r["portName"], "pon") {
			f0 := "1"
			if status == "2" {
				f0 = "0"
			}
			pon = append(pon, f0+":00:00")
			status = "1"
		}
		lines = append(lines, strings.Join([]string{r["portName"], r["desc"], r["portIsolate"], status, r["portSpeed"],
			r["portDuplex"], r["flowControlSendEn"], r["flowControlRecvEn"], r["inletFlow"], r["outletFlow"],
			r["jumboFrame"], r["portbridge"], r["negotiationMode"]}, ","))
	}
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 271}: strings.Join(lines, "\n"),
		{SockPON, 662}: strings.Join(pon, "\n"),
	}}
	got := call(t, fb, "get", "getPortBasicList", nil, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSysStatusMatchesLiveSampleDaemonFields(t *testing.T) {
	want := sample(t, "getSysStatus.json")
	var doc map[string]any
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	var ports, pon []string
	for _, p := range doc["port"].([]any) {
		r := p.(map[string]any)
		s := func(k string) string { v, _ := r[k].(string); return v }
		status := s("portStatus")
		if strings.HasPrefix(s("portName"), "pon") {
			pon = append(pon, s("portStatus")+":"+s("online")+":"+s("offline"))
		} else if status != "1" {
			status = "0"
		}
		ports = append(ports, strings.Join([]string{s("portName"), s("portDesc"), status, s("portSpeed"), s("portDuplex"), s("negotiationMode")}, ";"))
	}
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockUM, 156}:  "1.1.3.18(release-000530),V4.0,2026-11-23 00:05:30,1.3.6.1.4.1.48409.4",
		{SockUM, 157}:  "GPON-OLT,unused,0090.4C06.A427,123456790",
		{SockNSM, 417}: "0",
		{SockUM, 419}:  "60,-30",
		{SockNSM, 387}: "192.168.100.100,255.255.255.0,manul",
		{SockNSM, 386}: "Routing",
		{SockNSM, 272}: strings.Join(ports, "\n"),
		{SockPON, 662}: strings.Join(pon, "\n"),
	}}
	root := t.TempDir()
	for name, content := range map[string]string{
		"/proc/stat":       "cpu  100 0 100 800 0 0 0 0 0 0\n",
		"/proc/meminfo":    "MemTotal:        1000 kB\nMemFree:          500 kB\nBuffers:           50 kB\nCached:           100 kB\n",
		"/etc/resolv.conf": "nameserver 223.5.5.5\nnameserver 114.114.114.114\n",
	} {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	got := call(t, fb, "get", "getSysStatus", nil, &Env{Root: root})
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, got)
	}
	for _, k := range []string{"fan1", "fan2", "fan3", "softwareVersion", "hardwareVersion", "created", "productOid",
		"deviceName", "mac", "sn", "deviceLocation", "temphi", "templo", "pon_not_start", "dnsType", "preferredDNS",
		"alternateDNS", "ip", "mask", "ipType", "gateway"} {
		if fmt.Sprint(out[k]) != fmt.Sprint(doc[k]) {
			t.Errorf("%s = %v, want %v", k, out[k], doc[k])
		}
	}
	gp, _ := json.Marshal(out["port"])
	wp, _ := json.Marshal(doc["port"])
	if !bytes.Equal(gp, wp) {
		t.Errorf("port table:\n got  %s\n want %s", gp, wp)
	}
	if out["memoryPercent"] != "35.00%" {
		t.Errorf("memoryPercent %v", out["memoryPercent"])
	}
	if len(out["sysTime"].(string)) != len("2026-11-24 13:14:44") {
		t.Errorf("sysTime %v", out["sysTime"])
	}
	if fmt.Sprint(out["_helperUnsupported"]) != "[temp1value temp2value power1 power2]" {
		t.Errorf("_helperUnsupported %v", out["_helperUnsupported"])
	}
	// Key order follows the vendor handler.
	if !strings.HasPrefix(string(got), `{"sysTime":`) || !strings.Contains(string(got), `"gateway":"Routing","port":[`) {
		t.Errorf("order: %s", got)
	}
	// nsm 387 carries "mng0" at +58 with length 4 at +34 like the vendor.
	for _, m := range fb.seen {
		if m.Code() == 387 {
			if binary.LittleEndian.Uint16(m[34:]) != 4 || string(m[58:62]) != "mng0" || m[62] != 0 {
				t.Errorf("387 body % x", m[30:64])
			}
		}
	}
}

func TestQuickSetter(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{{SockPON, 1013}: "0"}}
	p := Params{"onuid": "0/1/1", "mode": "sn", "lineid": float64(1), "desc": "x", "sn": "HWTC-1", "pw": "", "loid": ""}
	if got := call(t, fb, "set", "setOntListConfig", p, nil); string(got) != `{"errCode":"0"}` {
		t.Fatalf("ok: %s", got)
	}
	if q := wire.QuickParams(fb.seen[0].Bytes()); strings.Join(q, "|") != "0/1/1|sn|1|x|HWTC-1||" {
		t.Fatalf("params %q", q)
	}
	fb.replies[sockCode{SockPON, 1013}] = "ont exist\x01"
	if got := call(t, fb, "set", "setOntListConfig", p, nil); string(got) != `{"errCode":"ont exist "}` {
		t.Fatalf("err: %s", got)
	}
	fb.errs = map[sockCode]error{{SockPON, 1013}: fakeTimeout{}}
	if got := call(t, fb, "set", "setOntListConfig", p, nil); string(got) != `{"errCode":"-1"}` {
		t.Fatalf("timeout: %s", got)
	}
}

func TestCatalog(t *testing.T) {
	var gets, sets int
	for _, e := range Catalog() {
		if e.Op == "get" {
			gets++
		} else {
			sets++
		}
	}
	wantGets, wantSets := len(listCommonSpecs)+len(listQuickSpecs)+len(rowSpecs)-1+4, len(quickSetterSpecs) // -1: getQvlanList is hand-ported
	for _, e := range portedEndpoints {
		if e.Op == "get" {
			wantGets++
		} else {
			wantSets++
		}
	}
	if gets != wantGets || sets != wantSets || gets < 42 || sets < 30 {
		t.Fatalf("gets=%d sets=%d want %d/%d", gets, sets, wantGets, wantSets)
	}
	if _, ok := Lookup("get", "getUserList"); ok {
		t.Fatal("webserver-local endpoint must not be served")
	}
}

func TestPosixZone(t *testing.T) {
	z := posixZone("CST-8")
	if z == nil {
		t.Fatal("parse")
	}
	if _, off := time.Date(2026, 1, 1, 0, 0, 0, 0, z).Zone(); off != 8*3600 {
		t.Fatalf("CST-8 offset %d", off)
	}
}

// The on-device failure: um_web (imi) does not answer. getSysStatus must
// still return the nsm/pon/local fields, list the um fields as
// unsupported, and not wait once per um field.
func TestSysStatusDegradesPerSubRequest(t *testing.T) {
	fb := &fakeBackend{
		replies: map[sockCode]string{
			{SockNSM, 417}: "lab",
			{SockNSM, 387}: "192.168.100.100,255.255.255.0,static",
			{SockNSM, 386}: "192.168.100.1",
			{SockNSM, 272}: "ge1;ge1;1;1000;1;1",
		},
		errs: map[sockCode]error{
			{SockUM, 156}:  fakeTimeout{},
			{SockPON, 662}: fmt.Errorf("boom"),
		},
	}
	got := call(t, fb, "get", "getSysStatus", nil, &Env{Root: t.TempDir()})
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	for _, k := range []string{"softwareVersion", "deviceName", "sn", "temphi"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s present although um_web failed", k)
		}
	}
	if out["ip"] != "192.168.100.100" || out["gateway"] != "192.168.100.1" || out["deviceLocation"] != "bGFi" {
		t.Errorf("nsm fields: %s", got)
	}
	if ports, _ := out["port"].([]any); len(ports) != 1 {
		t.Errorf("port: %v", out["port"])
	}
	want := "[temp1value temp2value power1 power2 softwareVersion hardwareVersion created productOid deviceName mac sn temphi templo port.ponStatus]"
	if fmt.Sprint(out["_helperUnsupported"]) != want {
		t.Errorf("_helperUnsupported %v", out["_helperUnsupported"])
	}
	umCalls := 0
	for _, m := range fb.seen {
		if m.Code() == 156 || m.Code() == 157 || m.Code() == 419 {
			umCalls++
		}
	}
	if umCalls != 1 {
		t.Errorf("um_web asked %d times after a timeout, want 1", umCalls)
	}

	// Every daemon down: the endpoint fails (the agent then uses the web UI).
	none := &fakeBackend{errs: map[sockCode]error{}}
	ep, _ := Lookup("get", "getSysStatus")
	if _, err := ep.Call(none, nil, &Env{Root: t.TempDir()}); err == nil {
		t.Fatal("all sub-requests failed but no error")
	}
}
