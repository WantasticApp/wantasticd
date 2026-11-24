package fiberolt

// Web-traffic budget.
//
// The FOS web UI (GoAhead) is single-threaded and allows one login: a
// collection that reads every goform page each cycle starves it and kicks
// the human operator out. So:
//
//   - A collection cycle (collect) never reads non-essential pages from the
//     web. With a healthy wantastic-oltd helper it reads ONLY the helper;
//     without one (or while it is down) it reads only the status essentials
//     (getSysStatus, the ONT list and ONT optics) from the web. Every other
//     page keeps its last-known document (page cache, persisted on disk)
//     and is reported stale in Device.WUSP_OLT.PageCache.{i}.
//   - Non-essential pages are read from the web only (a) on an explicit
//     console Get of their subtree (RefreshPaths), (b) as the
//     read-before-write of Set/Add/Delete/Operate, or (c) by the slow
//     background refresher: one goform request per interval (default 60 s,
//     -olt-web-budget, 0 = never), strictly serialized, skipped while a web
//     write is in flight, and paused 10 min after a web timeout / refused
//     connection / errCode "timeout".
//   - A failed web login is not retried for 5 min.
//
// A negative interval turns the budget off (legacy: every page on every
// cycle); the test suites of the page specs use that.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wantastic-agent/internal/wusp"
)

const (
	// DefaultWebBudget is the default refresher interval (one goform request
	// per interval).
	DefaultWebBudget = 60 * time.Second
	// webBackoff pauses budgeted web reads after the web UI timed out,
	// refused the connection or dropped the session.
	webBackoff = 10 * time.Minute
	// webLoginRetry is the minimum gap between web logins after a failure.
	webLoginRetry = 5 * time.Minute
	// onDemandMaxPages bounds one console Get refresh (a Get of a large
	// subtree is answered from the cache).
	onDemandMaxPages = 4
	// onDemandMinAge skips pages refreshed this recently (a watched console
	// polls the same subtree every few seconds).
	onDemandMinAge = 30 * time.Second
	// refreshTimeout bounds one refresher / on-demand page read.
	refreshTimeout = 15 * time.Second
)

// essentialEndpoints may be read from the web on the collection cycle when
// no helper is healthy (status, port list, ONT list + optics).
var essentialEndpoints = map[string]bool{
	"/goform/getSysStatus":      true,
	"/goform/getOntListBrife":   true,
	"/goform/getOntListOptical": true,
}

// errWebDeferred marks a web read the budget did not allow (not a device
// error): the caller serves the last-known page instead.
var errWebDeferred = errors.New("olt web: deferred by the web budget")

type deferredError struct{ why string }

func (e *deferredError) Error() string { return "olt web: " + e.why }
func (e *deferredError) Unwrap() error { return errWebDeferred }

var webBudgetConfig = struct {
	mu        sync.Mutex
	interval  time.Duration
	cacheFile string
}{interval: DefaultWebBudget}

// ConfigureWebBudget sets the web budget of every Client created
// afterwards: interval is the background refresher period (one goform
// request per interval; 0 = never; negative = budget off, legacy
// behaviour), cacheFile persists the last-known web pages across restarts
// ("" = memory only).
func ConfigureWebBudget(interval time.Duration, cacheFile string) {
	webBudgetConfig.mu.Lock()
	defer webBudgetConfig.mu.Unlock()
	webBudgetConfig.interval, webBudgetConfig.cacheFile = interval, cacheFile
}

func configuredWebBudget() (time.Duration, string) {
	webBudgetConfig.mu.Lock()
	defer webBudgetConfig.mu.Unlock()
	return webBudgetConfig.interval, webBudgetConfig.cacheFile
}

// pageEntry is the last-known document of one source.
type pageEntry struct {
	Data any    `json:"data"`
	At   int64  `json:"at"`  // unix seconds
	Via  string `json:"via"` // helper | web
}

// webBudget is the per-Client budget state.
type webBudget struct {
	interval  time.Duration
	cacheFile string

	mu           sync.Mutex
	pages        map[string]*pageEntry
	loaded       bool
	dirty        bool
	pending      map[string]time.Time // deferred sources -> last refresher attempt
	backoffUntil time.Time
	loginFailAt  time.Time
	env          *Env

	writes  atomic.Int32
	readMu  sync.Mutex // one budgeted (refresher / on-demand) read at a time
	started sync.Once
}

// SetWebBudget overrides the budget interval of this client (see
// ConfigureWebBudget).
func (c *Client) SetWebBudget(interval time.Duration) *Client {
	c.budget.mu.Lock()
	c.budget.interval = interval
	c.budget.mu.Unlock()
	return c
}

func (c *Client) budgetOff() bool {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	return c.budget.interval < 0
}

func (c *Client) budgetInterval() time.Duration {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	return c.budget.interval
}

// ---- policies -------------------------------------------------------------

const (
	policyFree   = iota // writes and direct calls: unrestricted
	policyCycle         // collection cycle: helper only / essentials
	policyBudget        // refresher / on-demand: at most maxWeb goform requests
)

type webPolicy struct {
	mode     int
	maxWeb   int
	used     int
	webCalls int
}

type policyKey struct{}

func withPolicy(ctx context.Context, p *webPolicy) context.Context {
	return context.WithValue(ctx, policyKey{}, p)
}

func policyOf(ctx context.Context) *webPolicy {
	p, _ := ctx.Value(policyKey{}).(*webPolicy)
	return p
}

// webGate decides whether a goform web request may go out now.
func (c *Client) webGate(ctx context.Context, path string) error {
	if !strings.HasPrefix(path, "/goform/") {
		return nil
	}
	p := policyOf(ctx)
	if p == nil {
		return nil
	}
	if p.mode != policyFree && !c.budgetOff() {
		if until := c.backoffUntil(); !until.IsZero() {
			return &deferredError{"web UI backoff until " + until.Format(time.RFC3339)}
		}
		switch p.mode {
		case policyCycle:
			if c.helperHealthy() {
				return &deferredError{path + " not served by the helper (web read deferred)"}
			}
			if !essentialEndpoints[path] {
				return &deferredError{path + " is not read on the collection cycle"}
			}
		case policyBudget:
			if p.used >= p.maxWeb {
				return &deferredError{"web request budget spent"}
			}
			p.used++
		}
	}
	p.webCalls++
	return nil
}

// budgeted reports whether ctx is a budgeted read (cycle / refresher /
// on-demand) on a client with the budget on.
func (c *Client) budgeted(ctx context.Context) bool {
	p := policyOf(ctx)
	return p != nil && p.mode != policyFree && !c.budgetOff()
}

func (c *Client) helperHealthy() bool {
	c.helperMu.Lock()
	defer c.helperMu.Unlock()
	return c.helper != nil && c.helperState == helperUp
}

// ---- backoff / login limiter --------------------------------------------

func (c *Client) backoffUntil() time.Time {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	if time.Now().Before(c.budget.backoffUntil) {
		return c.budget.backoffUntil
	}
	return time.Time{}
}

func (c *Client) enterBackoff(reason string) {
	c.budget.mu.Lock()
	first := !time.Now().Before(c.budget.backoffUntil)
	c.budget.backoffUntil = time.Now().Add(webBackoff)
	c.budget.mu.Unlock()
	if first {
		log.Printf("[OLT] web UI %s: pausing background web reads for %v", reason, webBackoff)
	}
}

// webOverloaded reports transport errors that mean the web server is busy
// or gone (timeouts, refused/reset connections).
func webOverloaded(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") || strings.Contains(s, "connection reset") || strings.Contains(s, "eof")
}

// loginAllowed enforces one web login attempt per webLoginRetry after a
// failure.
func (c *Client) loginAllowed() error {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	if c.budget.interval >= 0 && !c.budget.loginFailAt.IsZero() && time.Since(c.budget.loginFailAt) < webLoginRetry {
		return &deferredError{"web login failed recently; next attempt after " + c.budget.loginFailAt.Add(webLoginRetry).Format(time.RFC3339)}
	}
	return nil
}

func (c *Client) noteLogin(err error) {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	if err != nil {
		c.budget.loginFailAt = time.Now()
	} else {
		c.budget.loginFailAt = time.Time{}
	}
}

// dropSession forgets the session cookie (the web UI ended it).
func (c *Client) dropSession() {
	c.reqMu.Lock()
	c.cookie = ""
	c.reqMu.Unlock()
}

// ---- writes in flight -----------------------------------------------------

func (c *Client) beginWrite() func() {
	c.budget.writes.Add(1)
	return func() { c.budget.writes.Add(-1) }
}

// ---- page cache -------------------------------------------------------------

func (c *Client) loadPagesLocked() {
	if c.budget.loaded {
		return
	}
	c.budget.loaded = true
	if c.budget.pages == nil {
		c.budget.pages = map[string]*pageEntry{}
	}
	if c.budget.cacheFile == "" {
		return
	}
	raw, err := os.ReadFile(c.budget.cacheFile)
	if err != nil {
		return
	}
	var file struct {
		Pages map[string]*pageEntry `json:"pages"`
	}
	if json.Unmarshal(raw, &file) != nil {
		return
	}
	for k, v := range file.Pages {
		if v != nil && v.Data != nil {
			v.Via = "web"
			c.budget.pages[k] = v
		}
	}
}

// cachedPage returns the last-known document of a source.
func (c *Client) cachedPage(name string) (*pageEntry, bool) {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	c.loadPagesLocked()
	e, ok := c.budget.pages[name]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

// storePage records a fresh document; a source read fresh is no longer
// pending for the refresher.
func (c *Client) storePage(name string, data any, via string) {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	c.loadPagesLocked()
	c.budget.pages[name] = &pageEntry{Data: data, At: time.Now().Unix(), Via: via}
	delete(c.budget.pending, name)
	if via == "web" {
		c.budget.dirty = true
	}
}

func (c *Client) markPending(name string) {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	if c.budget.pending == nil {
		c.budget.pending = map[string]time.Time{}
	}
	if _, ok := c.budget.pending[name]; !ok {
		c.budget.pending[name] = time.Time{}
	}
}

// savePages persists the web-sourced pages (helper pages are re-read
// every cycle and are not written, to spare flash).
func (c *Client) savePages() {
	c.budget.mu.Lock()
	if !c.budget.dirty || c.budget.cacheFile == "" {
		c.budget.mu.Unlock()
		return
	}
	c.budget.dirty = false
	out := map[string]*pageEntry{}
	for k, v := range c.budget.pages {
		if v.Via == "web" {
			out[k] = v
		}
	}
	raw, err := json.Marshal(map[string]any{"v": 1, "pages": out})
	path := c.budget.cacheFile
	c.budget.mu.Unlock()
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("[OLT] page cache: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(path)
		if err := os.Rename(tmp, path); err != nil {
			log.Printf("[OLT] page cache: %v", err)
		}
	}
}

// ---- background refresher -----------------------------------------------------

// startRefresher runs the slow page refresher (once per client).
func (c *Client) startRefresher(env *Env) {
	c.budget.mu.Lock()
	c.budget.env = env
	c.budget.mu.Unlock()
	if c.budgetInterval() <= 0 {
		return
	}
	c.budget.started.Do(func() {
		go func() {
			for {
				iv := c.budgetInterval()
				if iv <= 0 {
					return
				}
				time.Sleep(iv)
				c.refreshTick(context.Background())
			}
		}()
	})
}

// refreshTick reads the stalest pending page from the web (at most one
// goform request). It returns the source it read ("" when skipped).
func (c *Client) refreshTick(ctx context.Context) string {
	if c.budgetInterval() <= 0 || c.budget.writes.Load() > 0 || !c.backoffUntil().IsZero() || c.loginAllowed() != nil {
		return ""
	}
	if !c.budget.readMu.TryLock() {
		return ""
	}
	defer c.budget.readMu.Unlock()
	c.budget.mu.Lock()
	env := c.budget.env
	var name string
	var best time.Time
	for n, tried := range c.budget.pending {
		if src, ok := lookupSource(n); ok && src.Composite {
			continue // its pages are refreshed one by one
		}
		last := tried
		if e, ok := c.budget.pages[n]; ok && time.Unix(e.At, 0).After(last) {
			last = time.Unix(e.At, 0)
		}
		if name == "" || last.Before(best) || (last.Equal(best) && n < name) {
			name, best = n, last
		}
	}
	if name != "" {
		c.budget.pending[name] = time.Now()
	}
	c.budget.mu.Unlock()
	if name == "" || env == nil {
		return ""
	}
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	cy := newCycle(withPolicy(rctx, &webPolicy{mode: policyBudget, maxWeb: 1}), env)
	cy.allow = map[string]bool{name: true}
	cy.Source(name)
	c.savePages()
	return name
}

// ---- on-demand refresh --------------------------------------------------------

func matchBinding(req, leaf string) bool {
	return req == leaf || (strings.HasSuffix(req, ".") && strings.HasPrefix(leaf, req))
}

func matchTable(req, object string) bool {
	obj := object + "."
	return (strings.HasSuffix(req, ".") && strings.HasPrefix(obj, req)) || strings.HasPrefix(req, obj)
}

// RefreshPaths re-reads the pages behind the requested Device.WUSP_OLT
// subtrees (an explicit console Get) and returns their parameters plus the
// path prefixes the result replaces. It returns nil when nothing needs or
// may be read: the budget is off (the cycle reads everything), the
// subtree spans more than onDemandMaxPages pages, every page is fresh, the
// web UI is in backoff, or a read failed (the cached values stand).
func RefreshPaths(ctx context.Context, env *Env, paths []string) (*wusp.Message, []string) {
	if env == nil || env.API == nil || env.API.budgetOff() {
		return nil, nil
	}
	buildIndex()
	var reqs []string
	for _, p := range paths {
		rel, ok := strings.CutPrefix(strings.TrimSpace(p), wusp.WUSPOLTPrefix)
		if ok && rel != "" && strings.Trim(rel, ".") != "" {
			reqs = append(reqs, rel)
		}
	}
	if len(reqs) == 0 {
		return nil, nil
	}
	srcs := map[string]bool{}
	var covered []string
	match := func(rel string) bool {
		for _, r := range reqs {
			if strings.HasSuffix(rel, ".") {
				if matchTable(r, strings.TrimSuffix(rel, ".")) {
					return true
				}
			} else if matchBinding(r, rel) {
				return true
			}
		}
		return false
	}
	for i := range Bindings {
		b := &Bindings[i]
		if b.Get != nil && b.Get.Source != "" && match(b.Leaf) {
			srcs[b.Get.Source] = true
			covered = append(covered, wusp.WUSPOLTPrefix+b.Leaf)
		}
	}
	for i := range Tables {
		t := &Tables[i]
		if match(t.Object + ".") {
			srcs[t.Source] = true
			covered = append(covered, wusp.WUSPOLTPrefix+t.Object+".")
			if t.Count != "" {
				covered = append(covered, wusp.WUSPOLTPrefix+t.Count)
			}
		}
	}
	if len(srcs) == 0 || len(srcs) > onDemandMaxPages {
		return nil, nil
	}
	api := env.API
	stale := false
	for name := range srcs {
		if e, ok := api.cachedPage(name); !ok || time.Since(time.Unix(e.At, 0)) >= onDemandMinAge {
			stale = true
		}
	}
	if !stale || !api.backoffUntil().IsZero() {
		return nil, nil
	}
	api.budget.readMu.Lock()
	defer api.budget.readMu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	c := newCycle(withPolicy(rctx, &webPolicy{mode: policyBudget, maxWeb: len(srcs)}), env)
	c.allow = srcs
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, err := c.Source(n); err != nil || c.meta[n].via == "cached" {
			api.savePages()
			return nil, nil
		}
	}
	api.savePages()
	msg := wusp.NewMessage()
	snaps := emitBindings(c, msg, match)
	api.mergeSnapshots(snaps)
	return msg, covered
}

func (c *Client) mergeSnapshots(snaps map[string]tableSnap) {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	if c.snaps == nil {
		c.snaps = map[string]tableSnap{}
	}
	for k, v := range snaps {
		c.snaps[k] = v
	}
}

// ---- metadata -------------------------------------------------------------------

// pageMeta is how one cycle obtained a source.
type pageMeta struct {
	via string // helper | web | cached | none
	at  int64
}

var (
	sourceObjectsOnce sync.Once
	sourceObjects     map[string][]string
)

// objectsOf lists the Device.WUSP_OLT objects a source feeds.
func objectsOf(name string) string {
	sourceObjectsOnce.Do(func() {
		set := map[string]map[string]bool{}
		add := func(src, obj string) {
			if src == "" {
				return
			}
			if set[src] == nil {
				set[src] = map[string]bool{}
			}
			set[src][obj] = true
		}
		for _, b := range Bindings {
			if b.Get != nil {
				obj := b.Leaf
				if i := strings.LastIndexByte(obj, '.'); i >= 0 {
					obj = obj[:i]
				} else {
					obj = ""
				}
				add(b.Get.Source, obj)
			}
		}
		for _, t := range Tables {
			add(t.Source, t.Object)
		}
		sourceObjects = map[string][]string{}
		for src, objs := range set {
			for o := range objs {
				sourceObjects[src] = append(sourceObjects[src], o)
			}
			sort.Strings(sourceObjects[src])
		}
	})
	return strings.Join(sourceObjects[name], ",")
}

// emitPageCache writes Device.WUSP_OLT.PageCache.{i} (one row per source
// the cycle used) and the WebBudget state.
func emitPageCache(c *Cycle, msg *wusp.Message) {
	prefix := wusp.WUSPOLTPrefix
	api := c.Env.API
	names := make([]string, 0, len(c.meta))
	for n := range c.meta {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		m := c.meta[n]
		base := prefix + "PageCache." + strconv.Itoa(i+1) + "."
		endpoint := ""
		if src, ok := lookupSource(n); ok {
			endpoint = src.Endpoint
		}
		msg.Set(base+"Name", wusp.String(n))
		msg.Set(base+"Endpoint", wusp.String(endpoint))
		msg.Set(base+"Source", wusp.String(m.via))
		msg.Set(base+"LastRefreshed", wusp.Uint(uint64(max(m.at, 0))))
		msg.Set(base+"Objects", wusp.String(objectsOf(n)))
	}
	msg.Set(prefix+"PageCacheNumberOfEntries", wusp.Uint(uint64(len(names))))
	iv := api.budgetInterval()
	msg.Set(prefix+"WebBudget.Interval", wusp.Uint(uint64(max(iv, 0)/time.Second)))
	var until uint64
	if t := api.backoffUntil(); !t.IsZero() {
		until = uint64(t.Unix())
	}
	msg.Set(prefix+"WebBudget.BackoffUntil", wusp.Uint(until))
	api.budget.mu.Lock()
	pending := len(api.budget.pending)
	api.budget.mu.Unlock()
	msg.Set(prefix+"WebBudget.PendingPages", wusp.Uint(uint64(pending)))
}
