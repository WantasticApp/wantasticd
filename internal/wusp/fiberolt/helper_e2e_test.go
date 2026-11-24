//go:build linux || darwin

package fiberolt

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/oltd/dgram"
	"wantastic-agent/internal/oltd/fakedaemon"
	"wantastic-agent/internal/oltd/server"
	"wantastic-agent/internal/oltd/wire"
	"wantastic-agent/internal/wusp"
)

var e2eKey = []byte("fiberolt-e2e-key-0123456789abcdef")

// startHelper runs a real wantastic-oltd server (TCP, HMAC, dgram backend)
// against fake nsm/pon/um daemons on AF_UNIX datagram sockets.
func startHelper(t *testing.T) string { return startHelperWith(t, false) }

// startHelperWith(umDead=true) reproduces the OLT finding: imi (um_web)
// receives requests but never answers.
func startHelperWith(t *testing.T, umDead bool) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wof")
	if err != nil {
		t.Fatal(err)
	}
	ports := "pon1;pon1;1;2500;1;1\nge1;ge1;1;1000;1;1"
	daemons := map[string]map[uint16]string{
		"sm_web":  {417: "", 387: "192.168.100.100,255.255.255.0,static", 386: "1", 272: ports, 300: "1,default,1,static,192.168.1.100,255.255.255.0"},
		"pon_web": {662: "1:01:00", 1011: "0/1/1,HWTC-93bb0308,online,0d20h11m,PTF2164Q,Normal,-,-"},
		"um_web":  {156: "1.1.3.18(release-000530),V4.0,2026-11-23 00:05:30,1.3.6.1.4.1.48409.4", 157: "GPON-OLT,x,0090.4C06.A427,123456790", 419: "60,-30"},
	}
	if umDead {
		daemons["um_web"] = map[uint16]string{}
	}
	var ds []*fakedaemon.Daemon
	for name, replies := range daemons {
		d, err := fakedaemon.Start(dir+"/"+name, fakedaemon.Text(replies))
		if err != nil {
			t.Fatal(err)
		}
		ds = append(ds, d)
	}
	pool := dgram.NewPool(dir, os.Getpid())
	srv := server.New(server.Config{Key: e2eKey, Backend: &dgram.Backend{Pool: pool, Timeout: 500 * time.Millisecond,
		Map: func(s string) string { return dir + "/" + strings.TrimPrefix(s, "/tmp/") }}})
	port, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		srv.Stop()
		for _, d := range ds {
			d.Close()
		}
		pool.Close()
		os.RemoveAll(dir)
	})
	_ = wire.MsgLen
	return "127.0.0.1:" + strconv.Itoa(port)
}

func TestHelperPreferredNoWebLogin(t *testing.T) {
	addr := startHelper(t)
	web := newFakeOLT(t)
	c := web.client().WithHelper(addr, e2eKey)
	ctx := context.Background()
	c.BeginCycle(ctx)
	if err := c.EnsureLogin(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := c.SysStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.SN != "123456790" || st.SoftwareVer != "1.1.3.18(release-000530)" || len(st.Ports) != 2 || st.Ports[0].Online != "01" {
		t.Fatalf("sysStatus via helper: %+v", st)
	}
	ol, err := c.OntListBrife(ctx)
	if err != nil || len(ol.List) != 1 || RowString(ol.List[0], "sn") != "HWTC-93bb0308" || len(ol.PONPortList) != 9 {
		t.Fatalf("ont list via helper: %+v %v", ol, err)
	}
	if n := len(web.callsTo("/login/Auth")); n != 0 {
		t.Fatalf("web UI login happened %d times although the helper served everything", n)
	}
	// An endpoint the helper does not serve falls back to the web UI.
	web.handle("/goform/getSystemLogList", map[string]any{"list": []any{}})
	if _, err := c.SystemLog(ctx); err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if len(web.callsTo("/goform/getSystemLogList")) != 1 || len(web.callsTo("/login/Auth")) != 1 {
		t.Fatalf("fallback did not use the web UI: %+v", web.calls)
	}
	// Writes are disabled on the helper by default: the web UI does them.
	web.handle("/goform/setOntListReboot", map[string]any{"errCode": "0"})
	if err := c.OntAction(ctx, "reboot", []string{"0/1/1"}); err != nil {
		t.Fatal(err)
	}
	if len(web.callsTo("/goform/setOntListReboot")) != 1 {
		t.Fatal("set did not reach the web UI")
	}
}

func TestHelperDownFallsBackPerCycle(t *testing.T) {
	web := newFakeOLT(t)
	web.handle("/goform/getSysStatus", map[string]any{"sn": "WEB", "port": []any{}})
	// Nothing listens on this port.
	c := web.client().WithHelper("127.0.0.1:1", e2eKey)
	ctx := context.Background()
	c.BeginCycle(ctx)
	st, err := c.SysStatus(ctx)
	if err != nil || st.SN != "WEB" {
		t.Fatalf("web fallback: %+v %v", st, err)
	}
	if len(web.callsTo("/login/Auth")) != 1 {
		t.Fatal("expected a web login on fallback")
	}
}

func TestHelperWrongKeyFallsBack(t *testing.T) {
	addr := startHelper(t)
	web := newFakeOLT(t)
	web.handle("/goform/getSysStatus", map[string]any{"sn": "WEB", "port": []any{}})
	c := web.client().WithHelper(addr, []byte("this-is-not-the-right-key-at-all"))
	ctx := context.Background()
	c.BeginCycle(ctx)
	st, err := c.SysStatus(ctx)
	if err != nil || st.SN != "WEB" {
		t.Fatalf("wrong key must fall back to web: %+v %v", st, err)
	}
}

func TestConfigureHelperKeyFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/k"
	os.WriteFile(p, []byte(" 00112233445566778899aabbccddeeff\n"), 0o600)
	if err := ConfigureHelper("10.0.0.1:7071", p); err != nil {
		t.Fatal(err)
	}
	defer ConfigureHelper("", "")
	h := configuredHelper()
	if h == nil || h.addr != "10.0.0.1:7071" || len(h.key) != 16 {
		t.Fatalf("%+v", h)
	}
	os.WriteFile(p, []byte("short"), 0o600)
	if err := ConfigureHelper("10.0.0.1:7071", p); err == nil {
		t.Fatal("short key accepted")
	}
}

// um_web dead on the OLT: telemetry reads get the helper's partial
// getSysStatus completed from the last full web document; writes
// (read-modify-write setDeviceInfo) read the full web document and never
// post fields the helper could not provide.
func TestHelperPartialSysStatusWritesUseWeb(t *testing.T) {
	addr := startHelperWith(t, true)
	web := newFakeOLT(t)
	sys := map[string]any{
		"softwareVersion": "1.1.3.18(release-000530)", "hardwareVersion": "V4.0", "deviceName": "GPON-OLT",
		"mac": "0090.4C06.A427", "sn": "123456790", "deviceLocation": "MA==", "dnsType": "manual",
		"preferredDNS": "223.5.5.5", "alternateDNS": "114.114.114.114", "ip": "192.168.100.100",
		"mask": "255.255.255.0", "ipType": "manul", "gateway": "192.168.100.1",
		"inbandip": "127.0.0.1", "inbandmask": "255.255.255.0", "mngvlan": "4000", "mnghost": "", "port": []any{},
	}
	web.handleFunc("/goform/getSysStatus", func(map[string]any) any { return sys })
	var posted map[string]any
	web.handleFunc("/goform/setDeviceInfo", func(b map[string]any) any {
		posted = b
		sys["deviceLocation"] = b["deviceLocation"]
		return map[string]any{"errCode": "0"}
	})
	c := web.client().WithHelper(addr, e2eKey)
	ctx := context.Background()
	c.BeginCycle(ctx)

	st, err := c.SysStatus(ctx)
	if err != nil || st.DeviceName != "" || st.SN != "" || len(st.Ports) != 2 {
		t.Fatalf("partial helper read (no cache yet): %+v %v", st, err)
	}
	if n := len(web.callsTo("/goform/getSysStatus")); n != 0 {
		t.Fatalf("telemetry read hit the web getSysStatus %d times", n)
	}

	env := &Env{API: c}
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"System.Info.Location", wusp.String("Lab 1")); err != nil {
		t.Fatal(err)
	}
	if posted == nil || posted["deviceName"] != "GPON-OLT" || posted["ip"] != "192.168.100.100" {
		t.Fatalf("setDeviceInfo body not built from the full web document: %v", posted)
	}
	if n := len(web.callsTo("/goform/getSysStatus")); n == 0 {
		t.Fatal("write did not read getSysStatus from the web UI")
	}

	// The web read filled the cache: the next partial helper read is completed.
	c.BeginCycle(ctx)
	var doc map[string]any
	if err := c.post(ctx, "/goform/getSysStatus", map[string]any{}, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["deviceName"] != "GPON-OLT" || doc["sn"] != "123456790" {
		t.Fatalf("cache not applied: %v", doc)
	}
	if fmt.Sprint(doc["_helperCached"]) == "" || strings.Contains(fmt.Sprint(doc["_helperUnsupported"]), "deviceName") {
		t.Fatalf("markers: cached=%v unsupported=%v", doc["_helperCached"], doc["_helperUnsupported"])
	}
}

// The helper re-executes itself at its heap ceiling (GC off): it drains,
// closes the agent's connection, and the next process adopts the listening
// socket. The agent must retry reads on a fresh connection, not fall back
// to the web UI or mark the helper down.
func TestHelperRestartHandoverTransparent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "woh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	d, err := fakedaemon.Start(dir+"/sm_web", fakedaemon.Text(map[uint16]string{300: "1,default,1,static,192.168.1.100,255.255.255.0"}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pool := dgram.NewPool(dir, os.Getpid())
	defer pool.Close()
	cfg := server.Config{Key: e2eKey, Backend: &dgram.Backend{Pool: pool, Timeout: time.Second,
		Map: func(s string) string { return dir + "/" + strings.TrimPrefix(s, "/tmp/") }}}
	srv1 := server.New(cfg)
	port, err := srv1.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv1.Serve() }()

	web := newFakeOLT(t)
	c := web.client().WithHelper("127.0.0.1:"+strconv.Itoa(port), e2eKey)
	ctx := context.Background()
	c.BeginCycle(ctx)
	var out map[string]any
	if err := c.post(ctx, "/goform/getQvlanList", map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}

	srv1.RequestRestart()
	if err := <-done; err != server.ErrRestart {
		t.Fatalf("Serve: %v", err)
	}
	srv2 := server.New(cfg)
	if _, err := srv2.Adopt(srv1.ListenerFD()); err != nil {
		t.Fatal(err)
	}
	go srv2.Serve()
	defer srv2.Stop()

	out = nil
	if err := c.post(ctx, "/goform/getQvlanList", map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(out["list"]) == "" || len(web.calls) != 0 {
		t.Fatalf("after handover: out=%v web calls=%+v", out, web.calls)
	}
	if !c.helperActive(ctx) {
		t.Fatal("helper marked down by a restart handover")
	}
}
