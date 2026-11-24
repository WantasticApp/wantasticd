//go:build linux || darwin

package fiberolt

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

// goformCalls lists the goform/cgi requests the fake web UI received.
func goformCalls(f *fakeOLT) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c.Path, "/goform/") || strings.HasPrefix(c.Path, "/cgi-bin/") {
			out = append(out, c.Path)
		}
	}
	return out
}

func webCallCount(f *fakeOLT) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// pageCacheRows maps PageCache.{i}.Name -> Source.
func pageCacheRows(msg *wusp.Message) map[string]string {
	names := map[string]string{}
	src := map[string]string{}
	for _, f := range msg.Fields {
		rest, ok := strings.CutPrefix(f.Path, wusp.WUSPOLTPrefix+"PageCache.")
		if !ok {
			continue
		}
		i, leaf, _ := strings.Cut(rest, ".")
		switch leaf {
		case "Name":
			names[i] = wusp.ValueToString(f.Val)
		case "Source":
			src[i] = wusp.ValueToString(f.Val)
		}
	}
	out := map[string]string{}
	for i, n := range names {
		out[n] = src[i]
	}
	return out
}

const ipRuleSource = "page:/goform/getIpAclList"

func budgetFixture(t *testing.T) (*fakeOLT, *Env) {
	t.Helper()
	addr := startHelper(t)
	web := richOLT(t)
	web.handle("/goform/getIpAclList", map[string]any{"list": []any{
		map[string]any{"aclId": "100", "priority": "1", "protocol": "6", "actionEn": "permit"},
	}})
	// One hour: the background goroutine never fires during the test;
	// ticks are driven by refreshTick.
	c := web.client().WithHelper(addr, e2eKey).SetWebBudget(time.Hour)
	return web, &Env{API: c}
}

func TestBudgetHealthyHelperCycleMakesNoWebRequests(t *testing.T) {
	web, env := budgetFixture(t)
	ctx := context.Background()
	for cycle := 0; cycle < 2; cycle++ {
		msg := wusp.NewMessage()
		CollectOLTEnv(ctx, env, true, msg)
		if n := webCallCount(web); n != 0 {
			t.Fatalf("cycle %d: %d web requests with a healthy helper: %v", cycle, n, goformCalls(web))
		}
		if v, _ := msg.Get(wusp.WUSPOLTPrefix + "Status"); wusp.ValueToString(v) != "ok" {
			t.Fatalf("status %v", v)
		}
		rows := pageCacheRows(msg)
		if rows["sysStatus"] != "helper" {
			t.Fatalf("sysStatus source = %q", rows["sysStatus"])
		}
		if rows[ipRuleSource] != "none" {
			t.Fatalf("%s source = %q (want none: never read)", ipRuleSource, rows[ipRuleSource])
		}
	}
	env.API.budget.mu.Lock()
	pending := len(env.API.budget.pending)
	env.API.budget.mu.Unlock()
	if pending == 0 {
		t.Fatal("no page queued for the refresher")
	}
}

func TestBudgetOnDemandGetReadsExactlyThePage(t *testing.T) {
	web, env := budgetFixture(t)
	ctx := context.Background()
	CollectOLTEnv(ctx, env, true, wusp.NewMessage())

	msg, covered := RefreshPaths(ctx, env, []string{wusp.WUSPOLTPrefix + "Security.ACL.IPRule."})
	if got := goformCalls(web); len(got) != 1 || got[0] != "/goform/getIpAclList" {
		t.Fatalf("on-demand goform requests = %v, want exactly getIpAclList", got)
	}
	if msg == nil || len(covered) == 0 {
		t.Fatal("on-demand refresh returned nothing")
	}
	if v, ok := msg.Get(wusp.WUSPOLTPrefix + "Security.ACL.IPRule.1.ACLID"); !ok || wusp.ValueToString(v) != "100" {
		t.Fatalf("row not refreshed: %v %v", v, ok)
	}
	// Fresh now: a repeated Get (watched console) does not hit the web.
	if m, _ := RefreshPaths(ctx, env, []string{wusp.WUSPOLTPrefix + "Security.ACL.IPRule."}); m != nil || len(goformCalls(web)) != 1 {
		t.Fatalf("repeated Get re-read a fresh page: %v", goformCalls(web))
	}
	// Whole-model and wide Gets never trigger web reads.
	for _, p := range []string{"Device.", wusp.WUSPOLTPrefix, wusp.WUSPOLTPrefix + "Switching."} {
		if m, _ := RefreshPaths(ctx, env, []string{p}); m != nil {
			t.Fatalf("Get %s triggered an on-demand refresh", p)
		}
	}

	// The next cycle keeps the value (cached, stale-marked) without web.
	web.reset()
	cyc := wusp.NewMessage()
	CollectOLTEnv(ctx, env, true, cyc)
	if n := webCallCount(web); n != 0 {
		t.Fatalf("cycle after on-demand made %d web requests", n)
	}
	if v, ok := cyc.Get(wusp.WUSPOLTPrefix + "Security.ACL.IPRule.1.ACLID"); !ok || wusp.ValueToString(v) != "100" {
		t.Fatalf("cached row not re-emitted: %v %v", v, ok)
	}
	if src := pageCacheRows(cyc)[ipRuleSource]; src != "cached" {
		t.Fatalf("%s source = %q, want cached", ipRuleSource, src)
	}
}

func TestBudgetRefresherOnePagePerTickWithBackoff(t *testing.T) {
	web, env := budgetFixture(t)
	ctx := context.Background()
	api := env.API
	CollectOLTEnv(ctx, env, true, wusp.NewMessage())

	// One tick = at most one goform request.
	name := api.refreshTick(ctx)
	if name == "" {
		t.Fatal("refresher read nothing")
	}
	if got := goformCalls(web); len(got) > 1 {
		t.Fatalf("one tick sent %d goform requests: %v", len(got), got)
	}

	// A web write in flight: the tick is skipped.
	done := api.beginWrite()
	web.reset()
	if n := api.refreshTick(ctx); n != "" || webCallCount(web) != 0 {
		t.Fatalf("tick ran during a write: %q %v", n, goformCalls(web))
	}
	done()

	// The web UI ends the session (errCode timeout): no re-login, 10 min
	// backoff, then nothing is sent.
	for _, s := range Sources {
		if s.Endpoint != "" {
			web.handle(s.Endpoint, map[string]any{"errCode": "timeout"})
		}
	}
	web.reset()
	tickName := api.refreshTick(ctx)
	if got := goformCalls(web); len(got) != 1 || len(web.callsTo("/login/Auth")) != 0 {
		t.Fatalf("timeout reply: tick=%q goform=%v logins=%d (want 1 request, no login)", tickName, got, len(web.callsTo("/login/Auth")))
	}
	if api.backoffUntil().IsZero() {
		t.Fatal("no backoff after errCode timeout")
	}
	web.reset()
	for i := 0; i < 3; i++ {
		api.refreshTick(ctx)
	}
	if m, _ := RefreshPaths(ctx, env, []string{wusp.WUSPOLTPrefix + "Security.ACL.IPRule."}); m != nil {
		t.Fatal("on-demand refresh during backoff")
	}
	if n := webCallCount(web); n != 0 {
		t.Fatalf("%d web requests during backoff", n)
	}

	// Writes still go through during backoff.
	sys := map[string]any{"deviceName": "GPON-OLT", "deviceLocation": "MA==", "ip": "192.168.100.100", "port": []any{}}
	web.handleFunc("/goform/getSysStatus", func(map[string]any) any { return sys })
	web.handleFunc("/goform/setDeviceInfo", func(b map[string]any) any {
		sys["deviceLocation"] = b["deviceLocation"]
		return map[string]any{"errCode": "0"}
	})
	if err := Set(ctx, env, wusp.WUSPOLTPrefix+"System.Info.Location", wusp.String("Lab 1")); err != nil {
		t.Fatalf("write during backoff: %v", err)
	}
	if len(web.callsTo("/goform/setDeviceInfo")) != 1 {
		t.Fatal("write did not reach the web UI")
	}
}

func TestBudgetNoHelperCycleReadsEssentialsOnly(t *testing.T) {
	web := richOLT(t)
	env := &Env{API: web.client().SetWebBudget(time.Hour)}
	ctx := context.Background()
	msg := wusp.NewMessage()
	CollectOLTEnv(ctx, env, true, msg)
	for _, p := range goformCalls(web) {
		if !essentialEndpoints[p] {
			t.Fatalf("cycle without helper read non-essential %s", p)
		}
	}
	if len(web.callsTo("/goform/getSysStatus")) != 1 {
		t.Fatal("status not read on the cycle")
	}
	if v, _ := msg.Get(wusp.WUSPOLTPrefix + "Status"); wusp.ValueToString(v) != "ok" {
		t.Fatalf("status %v", v)
	}
	// Second cycle reuses the session (no second login).
	CollectOLTEnv(ctx, env, true, wusp.NewMessage())
	if n := len(web.callsTo("/login/Auth")); n != 1 {
		t.Fatalf("%d logins over two cycles, want 1 (session reuse)", n)
	}
	// The refresher walks the deferred pages one request per tick.
	web.reset()
	if env.API.refreshTick(ctx) == "" || len(goformCalls(web)) != 1 {
		t.Fatalf("tick: %v", goformCalls(web))
	}
}

func TestBudgetLoginFailureNotRetriedWithin5Min(t *testing.T) {
	web := newFakeOLT(t)
	web.handle("/login/Auth", map[string]any{"errCode": "badCredentials"})
	c := web.client().SetWebBudget(time.Hour)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.webLogin(ctx); err == nil {
			t.Fatal("login succeeded")
		}
	}
	if n := len(web.callsTo("/login/Auth")); n != 1 {
		t.Fatalf("%d login attempts, want 1 per 5 min", n)
	}
}

func TestBudgetPageCachePersists(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pages.json")
	web, env := budgetFixture(t)
	env.API.budget.cacheFile = file
	ctx := context.Background()
	CollectOLTEnv(ctx, env, true, wusp.NewMessage())
	if m, _ := RefreshPaths(ctx, env, []string{wusp.WUSPOLTPrefix + "Security.ACL.IPRule."}); m == nil {
		t.Fatal("on-demand refresh failed")
	}
	// A restarted agent (new client, same file) serves the page from disk.
	addr := startHelper(t)
	c2 := web.client().WithHelper(addr, e2eKey).SetWebBudget(time.Hour)
	c2.budget.cacheFile = file
	web.reset()
	msg := wusp.NewMessage()
	CollectOLTEnv(ctx, &Env{API: c2}, true, msg)
	if webCallCount(web) != 0 {
		t.Fatalf("restart cycle hit the web: %v", goformCalls(web))
	}
	if v, ok := msg.Get(wusp.WUSPOLTPrefix + "Security.ACL.IPRule.1.ACLID"); !ok || wusp.ValueToString(v) != "100" {
		t.Fatalf("persisted page not served: %v %v", v, ok)
	}
}
