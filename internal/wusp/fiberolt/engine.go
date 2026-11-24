package fiberolt

// Declarative control engine for Device.WUSP_OLT.
//
// Every OLT web-UI control is one entry in the binding tables (bindings.go):
// a scalar Binding (getter + optional setter), a Table (rows keyed by a
// stable vendor id, per-column getters/setters, Add/Delete), or an OpBinding
// (Operate command). The parameter metadata (type, access, limits, units,
// grouping, side-effect class) lives next to the schema in
// internal/wusp/olt.go; TestRegistryConsistency keeps both sides in sync.
//
// Reads are batched: getters name a Source (one goform page), and a Cycle
// fetches each source at most once per collection. Writes either post the
// declared fields (PostFields, the style the original setters use) or read
// the page's current form, change one field, post the whole form back and
// re-read to confirm (ReadModifyWrite, the FOS goform convention).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"
)

// Doc is one decoded vendor JSON object (a goform page or a table row).
type Doc = map[string]any

// cliRunner is the FOS command line as the engine sees it (*CLI in
// production, a fake in tests).
type cliRunner interface {
	Run(cmd string) (string, error)
}

// Env is what bindings run against.
type Env struct {
	API *Client
	// CLI is optional (nil when the telnet CLI is not reachable/used).
	CLI cliRunner
	// EnableWrite persists the agent-side Enable flag ("Manage this OLT").
	EnableWrite func(bool) error
	// StagingDir holds files staged by the WUSP upload channel; empty
	// falls back to OperateStagingDir.
	StagingDir string
	// AutoSave reports the agent-local AutoSave flag; SetAutoSave persists
	// it. When on, a successful write schedules SaveConfig.
	AutoSave    func() bool
	SetAutoSave func(bool) error
}

func (e *Env) autoSave() bool { return e != nil && e.AutoSave != nil && e.AutoSave() }

// afterWrite runs the AutoSave policy after a successful device write.
func (e *Env) afterWrite() {
	if e.autoSave() {
		e.API.scheduleSave()
	}
}

// envFor wraps a *CLI without turning a nil pointer into a non-nil
// interface.
func envFor(api *Client, cli *CLI) *Env {
	env := &Env{API: api}
	if cli != nil {
		env.CLI = cli
	}
	return env
}

// ---- sources -------------------------------------------------------------

// Source is one batched read: a goform page (Endpoint + Body) or a custom
// Fetch (CLI output, derived data). Its result is shared by every getter
// that names it within one Cycle.
type Source struct {
	Name     string
	Endpoint string
	Body     map[string]any
	// Query sends the getter as GET <Endpoint>?<Query> like the web UI;
	// without it the page is read with POST {} (verified equivalent).
	Query map[string]string
	// Fetch replaces the web call. It may read other sources via c.
	Fetch func(c *Cycle) (any, error)
	// NeedsCLI skips the source (reported as an error) when Env.CLI is nil.
	NeedsCLI bool
	// Composite marks a Fetch that only combines other sources (page
	// sources it registers itself); the web budget refreshes those pages
	// one per tick and never the composite.
	Composite bool
}

// Cycle memoizes source reads for one collection (or one write).
type Cycle struct {
	Ctx  context.Context
	Env  *Env
	data map[string]any
	errs map[string]error
	// Fetches counts real source reads (tests assert batching).
	Fetches int
	// allow, when set, limits real reads to these sources (others are
	// served from the page cache).
	allow map[string]bool
	// meta records how each source was obtained (PageCache metadata).
	meta map[string]pageMeta
}

func newCycle(ctx context.Context, env *Env) *Cycle {
	if policyOf(ctx) == nil {
		ctx = withPolicy(ctx, &webPolicy{mode: policyFree})
	}
	return &Cycle{Ctx: ctx, Env: env, data: map[string]any{}, errs: map[string]error{}, meta: map[string]pageMeta{}}
}

// fromCache serves a deferred source from the page cache.
func (c *Cycle) fromCache(name string, cause error) (any, error) {
	api := c.Env.API
	api.markPending(name)
	if e, ok := api.cachedPage(name); ok {
		c.data[name] = e.Data
		c.meta[name] = pageMeta{via: "cached", at: e.At}
		return e.Data, nil
	}
	c.meta[name] = pageMeta{via: "none"}
	c.errs[name] = cause
	return nil, cause
}

var errNoCLI = errors.New("olt: command line not available")

// Source returns the (memoized) result of the named source.
func (c *Cycle) Source(name string) (any, error) {
	if v, ok := c.data[name]; ok {
		return v, nil
	}
	if err, ok := c.errs[name]; ok {
		return nil, err
	}
	src, ok := lookupSource(name)
	if !ok {
		err := fmt.Errorf("olt: unknown source %q", name)
		c.errs[name] = err
		return nil, err
	}
	if c.allow != nil && !c.allow[name] {
		return c.fromCache(name, &deferredError{name + " not part of this read"})
	}
	pol := policyOf(c.Ctx)
	webBefore := 0
	if pol != nil {
		webBefore = pol.webCalls
	}
	var (
		v   any
		err error
	)
	switch {
	case src.NeedsCLI && c.Env.CLI == nil:
		err = errNoCLI
	case src.Fetch != nil:
		c.Fetches++
		v, err = src.Fetch(c)
	default:
		c.Fetches++
		body := src.Body
		if body == nil {
			body = map[string]any{}
		}
		v, err = fetchPage(c.Ctx, c.Env.API, src.Endpoint, body, src.Query)
	}
	if err != nil && errors.Is(err, errWebDeferred) && c.Env.API.budgeted(c.Ctx) {
		return c.fromCache(name, err)
	}
	if err != nil {
		c.errs[name] = err
		if err != errNoCLI {
			log.Printf("[OLT] %s: %v", name, err)
		}
		return nil, err
	}
	via := "cli"
	switch {
	case pol != nil && pol.webCalls > webBefore:
		via = "web"
	case c.Env.API.helperHealthy():
		via = "helper"
	}
	c.data[name] = v
	c.meta[name] = pageMeta{via: via, at: nowUnix()}
	c.Env.API.storePage(name, v, via)
	return v, nil
}

// fetchPage reads one goform getter. A bare {"errCode":...} reply is an
// error, not data (an expired session would otherwise read as a page of
// empty values); an expired session is re-established once.
func fetchPage(ctx context.Context, api *Client, endpoint string, body map[string]any, query map[string]string) (any, error) {
	for attempt := 0; ; attempt++ {
		var out any
		var err error
		if query != nil {
			err = api.get(ctx, endpoint, query, &out)
		} else {
			if body == nil {
				body = map[string]any{}
			}
			err = api.post(ctx, endpoint, body, &out)
		}
		if err != nil {
			return nil, err
		}
		doc, ok := out.(Doc)
		code, hasCode := replyCode(out)
		if !ok || !hasCode || len(doc) != 1 {
			return out, nil
		}
		// Status-only getters (e.g. getExportStatus) answer a bare
		// success code: that is data.
		switch strings.ToLower(code) {
		case "0", "success":
			return out, nil
		}
		if code == errCodeTimeout && api.budgeted(ctx) {
			// The web UI ended the session (often: an operator logged
			// in). Do not log back in from a background read: back off.
			api.dropSession()
			api.enterBackoff("session ended (errCode=timeout)")
			return nil, &deferredError{endpoint + ": web session ended"}
		}
		if code == errCodeTimeout && attempt == 0 {
			if err := login(ctx, api); err != nil {
				return nil, err
			}
			continue
		}
		if code == errCodeNoHandler {
			return nil, fmt.Errorf("%w: olt api %s has no handler on this firmware (errCode=106)", wusp.ErrUSPPathUnsupported, endpoint)
		}
		return nil, fmt.Errorf("olt api %s: errCode=%s", endpoint, code)
	}
}

// Doc returns the named source as a JSON object.
func (c *Cycle) Doc(name string) (Doc, error) {
	v, err := c.Source(name)
	if err != nil {
		return nil, err
	}
	doc, ok := v.(Doc)
	if !ok {
		return nil, fmt.Errorf("olt: source %s is not an object", name)
	}
	return doc, nil
}

// ---- value extraction ------------------------------------------------------

// Lookup returns the first present key of doc. Keys may be dotted
// ("a.b") to reach nested objects.
func Lookup(doc Doc, keys ...string) (any, bool) {
	for _, key := range keys {
		cur := any(doc)
		found := true
		for _, part := range strings.Split(key, ".") {
			m, ok := cur.(Doc)
			if !ok {
				found = false
				break
			}
			if cur, ok = m[part]; !ok || cur == nil {
				found = false
				break
			}
		}
		if found {
			return cur, true
		}
	}
	return nil, false
}

// Str renders a raw vendor value as a string (vendor pages mix JSON
// strings and numbers).
func Str(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprint(v)
	}
}

// Conv converts a raw vendor value; ok=false omits the parameter.
type Conv func(raw any) (wusp.Value, bool)

// Converters shared by bindings.
var (
	// AsString emits the value verbatim.
	AsString Conv = func(raw any) (wusp.Value, bool) { return wusp.String(Str(raw)), true }
	// AsTrimmed emits the value with surrounding blanks removed.
	AsTrimmed Conv = func(raw any) (wusp.Value, bool) { return wusp.String(strings.TrimSpace(Str(raw))), true }
	// AsNonEmpty omits empty strings.
	AsNonEmpty Conv = func(raw any) (wusp.Value, bool) {
		s := Str(raw)
		return wusp.String(s), s != ""
	}
	// AsUint parses an unsigned integer; unparsable values are omitted.
	AsUint Conv = func(raw any) (wusp.Value, bool) {
		u, err := strconv.ParseUint(strings.TrimSpace(Str(raw)), 10, 64)
		return wusp.Uint(u), err == nil
	}
	// AsPercent parses "42%" (0 when unparsable, like the original).
	AsPercent Conv = func(raw any) (wusp.Value, bool) {
		return wusp.Uint(uint64(ParsePercent(Str(raw)))), true
	}
	// AsDecimal parses a float; unparsable values are omitted.
	AsDecimal Conv = func(raw any) (wusp.Value, bool) {
		f, ok := ParseDecimal(Str(raw))
		return wusp.Float(f), ok
	}
	// AsNonZeroFloat emits float64 values except 0 (vendor "no reading").
	AsNonZeroFloat Conv = func(raw any) (wusp.Value, bool) {
		f, ok := raw.(float64)
		return wusp.Float(f), ok && f != 0
	}
	// AsFanRPM parses "WORK RPM: 6600"; stopped/unknown is omitted.
	AsFanRPM Conv = func(raw any) (wusp.Value, bool) {
		rpm := ParseFanRPM(Str(raw))
		return wusp.Uint(uint64(rpm)), rpm > 0
	}
	// AsBool01 maps "1"/"true" to true, anything else to false.
	AsBool01 Conv = func(raw any) (wusp.Value, bool) {
		s := Str(raw)
		return wusp.Bool(s == "1" || strings.EqualFold(s, "true")), true
	}
	// AsBool emits native booleans only.
	AsBool Conv = func(raw any) (wusp.Value, bool) {
		b, ok := raw.(bool)
		return wusp.Bool(b), ok
	}
)

// Getter reads one parameter. Scalar getters name a Source; table column
// getters leave Source empty and read the row. Func overrides both.
type Getter struct {
	Source string
	Keys   []string
	Conv   Conv
	// Func computes the value from the cycle (scalars) or the row
	// (columns: row is non-nil).
	Func func(c *Cycle, row Doc) (wusp.Value, bool)
}

// From is the common getter: Source + key (+ alternates) + converter.
func From(source string, conv Conv, keys ...string) *Getter {
	return &Getter{Source: source, Keys: keys, Conv: conv}
}

// Col is the common column getter: row key (+ alternates) + converter.
func Col(conv Conv, keys ...string) *Getter {
	return &Getter{Keys: keys, Conv: conv}
}

func (g *Getter) value(c *Cycle, row Doc) (wusp.Value, bool) {
	if g.Func != nil {
		return g.Func(c, row)
	}
	doc := row
	if g.Source != "" {
		var err error
		if doc, err = c.Doc(g.Source); err != nil {
			return wusp.Value{}, false
		}
	}
	// A missing key reaches the converter as nil (rendered as ""), the
	// same as the original struct-decoded collector saw it; converters
	// decide whether that omits the parameter.
	raw, _ := Lookup(doc, g.Keys...)
	conv := g.Conv
	if conv == nil {
		conv = AsString
	}
	return conv(raw)
}

// ---- setters ----------------------------------------------------------------

// SetCall carries one write into a Setter.
type SetCall struct {
	Ctx   context.Context
	Env   *Env
	Path  string
	Value wusp.Value
	// Inst holds the instance numbers of a table path (Network.ACL.3.X -> [3]).
	Inst []uint64
	// Key/Row identify the resolved table row (empty for scalars and
	// positional tables).
	Key string
	Row Doc

	loggedIn bool
	table    *Table
}

// Setter writes one parameter.
type Setter struct {
	// Endpoint receives the write (POST JSON).
	Endpoint string
	// Field is the form field the new value goes into.
	Field string
	// Encode turns the WUSP value into the form value (default: string).
	Encode func(wusp.Value) (any, error)
	// Extra fixed fields merged into the body.
	Extra map[string]any

	// ReadModifyWrite reads source Read, copies the current form (Form
	// filters/renames it; nil copies every key), replaces Field, posts the
	// whole form, runs Commit, and re-reads Read to confirm the value
	// (VerifyKey, default Field). Replies are checked for errCode.
	ReadModifyWrite bool
	Read            string
	Form            func(current Doc) map[string]any
	VerifyKey       string
	NoVerify        bool

	// Strict checks the vendor reply errCode on PostFields writes too.
	Strict bool
	// OK lists extra success errCodes besides "0"/"success".
	OK []string
	// Commit is an optional post-save request (e.g. save to flash).
	Commit *Request

	// Local setters never touch the OLT (no login).
	Local bool
	// Guard names a safety check run on the final body (guards.go).
	Guard string
	// Func replaces the declarative write entirely.
	Func func(sc *SetCall) error
}

// Request is a fixed goform call.
type Request struct {
	Endpoint string
	Body     map[string]any
}

// ---- tables -----------------------------------------------------------------

// Column is one leaf of a table row.
type Column struct {
	Leaf string
	Get  *Getter
	Set  *Setter
}

// AddCall carries a USP Add into a Table.
type AddCall struct {
	Ctx     context.Context
	Env     *Env
	Object  string
	Initial *wusp.Message
}

// In returns an initial field by leaf name ("" when absent).
func (ac *AddCall) In(leaf string) string { return messageInput(ac.Initial, leaf) }

// Table binds one multi-instance object. Instance numbers are positional
// (1..N in Source order) for compatibility, but every write resolves the
// instance through the stable vendor Key captured at the last collection
// and re-reads the live table to find that row, so a table that changed
// since the console's last Get cannot make a write hit the wrong row.
type Table struct {
	// Object is the path relative to Device.WUSP_OLT. without ".{i}."
	// (e.g. "Network.ACL").
	Object string
	Source string
	// Rows extracts rows from the source (default: the "list" array).
	Rows func(c *Cycle, raw any) []Doc
	// KeyFields name the stable vendor id column(s) of a row; Key overrides.
	KeyFields []string
	Key       func(row Doc) string
	// Skip drops rows (e.g. unnamed ports).
	Skip func(row Doc) bool
	// Max bounds emitted rows (0 = all).
	Max int
	// Count is the NumberOfEntries leaf ("" = none).
	Count string
	// Positional tables map instance N straight to a fixed vendor slot
	// (no key resolution); setters get only Inst.
	Positional bool
	// TrustSnapshot acts on the key captured at collection without
	// re-reading the table (for expensive sources keyed by vendor ids).
	TrustSnapshot bool

	Columns []Column

	// Add creates a row and returns its vendor key.
	Add func(ac *AddCall) (string, error)
	// AddResult formats the created instance path (default
	// "<Object>.<n>." after re-reading the table).
	AddResult func(key string) string
	// Delete removes the resolved row.
	Delete func(sc *SetCall) error
}

func (t *Table) rows(c *Cycle) ([]Doc, error) {
	raw, err := c.Source(t.Source)
	if err != nil {
		return nil, err
	}
	var rows []Doc
	if t.Rows != nil {
		rows = t.Rows(c, raw)
	} else {
		rows = ListRows(raw, "list")
	}
	out := rows[:0:0]
	for _, row := range rows {
		if t.Skip != nil && t.Skip(row) {
			continue
		}
		out = append(out, row)
		if t.Max > 0 && len(out) >= t.Max {
			break
		}
	}
	return out, nil
}

func (t *Table) key(row Doc) string {
	if t.Key != nil {
		return t.Key(row)
	}
	if raw, ok := Lookup(row, t.KeyFields...); ok {
		return strings.TrimSpace(Str(raw))
	}
	return ""
}

// ListRows returns the objects of the array under key in raw.
func ListRows(raw any, key string) []Doc {
	doc, ok := raw.(Doc)
	if !ok {
		return nil
	}
	list, _ := doc[key].([]any)
	rows := make([]Doc, 0, len(list))
	for _, item := range list {
		if row, ok := item.(Doc); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

// ---- operations -------------------------------------------------------------

// OpCall carries one Operate into an OpBinding.
type OpCall struct {
	Ctx     context.Context
	Env     *Env
	Command string
	Input   *wusp.Message
	Output  *wusp.Message
}

// In returns an input argument by leaf name ("" when absent).
func (oc *OpCall) In(name string) string { return messageInput(oc.Input, name) }

// Login authenticates against the OLT with the standard error wrapping.
func (oc *OpCall) Login() error { return login(oc.Ctx, oc.Env.API) }

// OpBinding implements one Operate command.
type OpBinding struct {
	Command string
	Run     func(oc *OpCall) error
	// Saves marks a command that changes the running configuration: on
	// success it triggers the AutoSave policy like a Set.
	Saves bool
}

// ---- binding registry ---------------------------------------------------------

// Binding is one scalar parameter.
type Binding struct {
	// Leaf is the path relative to Device.WUSP_OLT.
	Leaf string
	Get  *Getter
	Set  *Setter
}

var (
	sourceMu     sync.RWMutex // guards Sources and sourceByName after init (dynamic page sources)
	sourceByName = map[string]*Source{}
	bindingByLf  = map[string]*Binding{}
	tableByObj   = map[string]*Table{}
	opByCommand  = map[string]*OpBinding{}
	indexOnce    sync.Once
)

// lookupSource finds a source by name (the index is built by the caller's
// entry point, as before; calling buildIndex here would make Sources
// depend on itself through the Fetch closures).
func lookupSource(name string) (*Source, bool) {
	sourceMu.RLock()
	defer sourceMu.RUnlock()
	src, ok := sourceByName[name]
	return src, ok
}

// registerSource adds a source at run time (per-profile detail pages
// whose query is only known once the profile list is read). An existing
// name is kept. Each registered page is one budget tick like any other.
func registerSource(src Source) {
	sourceMu.Lock()
	defer sourceMu.Unlock()
	if _, ok := sourceByName[src.Name]; ok {
		return
	}
	Sources = append(Sources, src)
	sourceByName[src.Name] = &Sources[len(Sources)-1]
	// Sources may have been reallocated: the index must point into it.
	for i := range Sources {
		sourceByName[Sources[i].Name] = &Sources[i]
	}
}

// resetIndex drops the lookup maps so they are rebuilt from the tables
// (tests that extend the registry).
func resetIndex() {
	sourceMu.Lock()
	defer sourceMu.Unlock()
	sourceByName = map[string]*Source{}
	bindingByLf = map[string]*Binding{}
	tableByObj = map[string]*Table{}
	opByCommand = map[string]*OpBinding{}
	indexOnce = sync.Once{}
	schemaOnce = sync.Once{}
}

func buildIndex() {
	indexOnce.Do(func() {
		sourceMu.Lock()
		defer sourceMu.Unlock()
		for i := range Sources {
			sourceByName[Sources[i].Name] = &Sources[i]
		}
		for i := range Bindings {
			bindingByLf[Bindings[i].Leaf] = &Bindings[i]
		}
		for i := range Tables {
			tableByObj[Tables[i].Object] = &Tables[i]
		}
		for i := range Operations {
			opByCommand[Operations[i].Command] = &Operations[i]
		}
	})
}

// ---- collection ---------------------------------------------------------------

// tableSnap is what one collection saw of a table: the vendor key of each
// emitted instance (index = instance-1) and the row itself.
type tableSnap struct {
	keys []string
	rows []Doc
}

func (c *Client) storeSnapshots(snaps map[string]tableSnap) {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	c.snaps = snaps
}

func (c *Client) snapshot(object string) (tableSnap, bool) {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	s, ok := c.snaps[object]
	return s, ok
}

// collect fills Device.WUSP_OLT.* for one cycle. The prologue (status,
// login, the getSysStatus gate) mirrors the original collector; the body
// walks the binding tables.
func collect(ctx context.Context, env *Env, enabled bool, msg *wusp.Message) *Cycle {
	buildIndex()
	prefix := wusp.WUSPOLTPrefix
	msg.Set(prefix+"Installed", wusp.Bool(true))
	msg.Set(prefix+"Platform", wusp.String("olt"))
	msg.Set(prefix+"SupportedOperations", wusp.String(SupportedOperations))
	msg.Set(prefix+"ControlSchemaVersion", wusp.String(ControlSchemaVersion()))
	msg.Set(prefix+"Enable", wusp.Bool(enabled))
	msg.Set(prefix+"AlarmNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"PONPortNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"ONUNumberOfEntries", wusp.Uint(0))
	if !enabled {
		msg.Set(prefix+"Status", wusp.String("disabled"))
		return nil
	}

	collectCtx, cancel := context.WithTimeout(ctx, CollectBudget)
	defer cancel()
	budgeted := !env.API.budgetOff()
	if budgeted {
		// The cycle reads the helper (or, without one, the status
		// essentials) only; see webbudget.go.
		collectCtx = withPolicy(collectCtx, &webPolicy{mode: policyCycle})
		env.API.startRefresher(env)
		defer env.API.savePages()
	}

	// Probe the wantastic-oltd helper once per cycle (no-op without one).
	env.API.BeginCycle(collectCtx)
	var loginErr error
	if budgeted && (env.API.helperActive(collectCtx) || env.API.sessionCookie() != "" || !env.API.backoffUntil().IsZero()) {
		// Helper healthy, web session already open (reused), or web UI in
		// backoff (everything comes from the cache): no login.
	} else if err := env.API.EnsureLogin(collectCtx); err != nil {
		log.Printf("[OLT] login: %v", err)
		if !budgeted {
			msg.Set(prefix+"Status", wusp.String("login_error"))
			msg.Set(prefix+"StatusDetail", wusp.String(TruncateStatus(err.Error())))
			return nil
		}
		loginErr = err
	}

	c := newCycle(collectCtx, env)
	if budgeted {
		defer emitPageCache(c, msg)
	}
	if _, err := c.Source(GateSource); err != nil {
		if loginErr != nil {
			err = loginErr
			msg.Set(prefix+"Status", wusp.String("login_error"))
		} else {
			msg.Set(prefix+"Status", wusp.String("api_error"))
		}
		msg.Set(prefix+"StatusDetail", wusp.String(TruncateStatus(err.Error())))
		if budgeted {
			// Last-known values of the other pages still stand.
			env.API.storeSnapshots(emitBindings(c, msg, nil))
		}
		return c
	}
	msg.Set(prefix+"Status", wusp.String("ok"))
	detail := ""
	if m := c.meta[GateSource]; m.via == "cached" {
		detail = "web UI unavailable or in backoff: status is the last-known value from " + time.Unix(m.at, 0).UTC().Format(time.RFC3339)
	} else {
		msg.Set(prefix+"LastCollectTime", wusp.Uint(uint64(nowUnix())))
	}
	if loginErr != nil {
		msg.Set(prefix+"Status", wusp.String("login_error"))
		detail = loginErr.Error()
	}
	msg.Set(prefix+"StatusDetail", wusp.String(TruncateStatus(detail)))
	env.API.storeSnapshots(emitBindings(c, msg, nil))
	return c
}

// emitBindings evaluates every scalar getter and table of the registry
// (only paths accepted by filter, when given) into msg and returns the
// table snapshots.
func emitBindings(c *Cycle, msg *wusp.Message, filter func(rel string) bool) map[string]tableSnap {
	prefix := wusp.WUSPOLTPrefix
	for i := range Bindings {
		b := &Bindings[i]
		if b.Get == nil || (filter != nil && !filter(b.Leaf)) {
			continue
		}
		if v, ok := b.Get.value(c, nil); ok {
			msg.Set(prefix+b.Leaf, v)
		}
	}

	snaps := map[string]tableSnap{}
	for i := range Tables {
		t := &Tables[i]
		if filter != nil && !filter(t.Object+".") {
			continue
		}
		rows, err := t.rows(c)
		if err != nil {
			continue
		}
		snap := tableSnap{keys: make([]string, 0, len(rows)), rows: rows}
		for n, row := range rows {
			base := prefix + t.Object + "." + strconv.Itoa(n+1) + "."
			for _, col := range t.Columns {
				if col.Get == nil {
					continue
				}
				if v, ok := col.Get.value(c, row); ok {
					msg.Set(base+col.Leaf, v)
				}
			}
			snap.keys = append(snap.keys, t.key(row))
		}
		if t.Count != "" {
			msg.Set(prefix+t.Count, wusp.Uint(uint64(len(rows))))
		}
		snaps[t.Object] = snap
	}
	return snaps
}

// ---- writes ---------------------------------------------------------------------

func login(ctx context.Context, api *Client) error {
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return nil
}

// tablePath splits "Object.N.Leaf" / "Object.N." into its table, instance
// and leaf ("" for the row itself). Longest object match wins.
func tablePath(rel string) (*Table, uint64, string, bool) {
	var best *Table
	for obj, t := range tableByObj {
		if strings.HasPrefix(rel, obj+".") && (best == nil || len(obj) > len(best.Object)) {
			best = t
		}
	}
	if best == nil {
		return nil, 0, "", false
	}
	rest := strings.TrimPrefix(rel, best.Object+".")
	numStr, leaf, _ := strings.Cut(rest, ".")
	n, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil || n == 0 || strings.Contains(leaf, ".") {
		return nil, 0, "", false
	}
	return best, n, leaf, true
}

// resolveRow maps instance n of t to the live vendor row: through the key
// captured at the last collection when there is one, by position
// otherwise. Returns ErrUSPPathNotFound when the row is gone.
func resolveRow(ctx context.Context, env *Env, t *Table, n uint64) (string, Doc, error) {
	snap, haveSnap := env.API.snapshot(t.Object)
	if haveSnap {
		if n > uint64(len(snap.keys)) {
			return "", nil, wusp.ErrUSPPathNotFound
		}
		key := snap.keys[n-1]
		if t.TrustSnapshot {
			if key == "" {
				return "", nil, wusp.ErrUSPPathNotFound
			}
			return key, snap.rows[n-1], nil
		}
		rows, err := t.rows(newCycle(ctx, env))
		if err != nil {
			return "", nil, err
		}
		for _, row := range rows {
			if t.key(row) == key && key != "" {
				return key, row, nil
			}
		}
		return "", nil, wusp.ErrUSPPathNotFound
	}
	rows, err := t.rows(newCycle(ctx, env))
	if err != nil || n > uint64(len(rows)) {
		return "", nil, wusp.ErrUSPPathNotFound
	}
	row := rows[n-1]
	key := t.key(row)
	if key == "" && len(t.KeyFields) > 0 {
		return "", nil, wusp.ErrUSPPathNotFound
	}
	return key, row, nil
}

// Set applies a console write to one Device.WUSP_OLT parameter.
// Unbound or read-only leaves return wusp.ErrUSPPathUnsupported.
func Set(ctx context.Context, env *Env, path string, value wusp.Value) error {
	if env != nil && env.API != nil {
		defer env.API.beginWrite()()
	}
	ctx = withWebOnly(ctx) // writes read the full web document, never a partial helper reply
	buildIndex()
	path = strings.TrimSpace(path)
	rel, ok := strings.CutPrefix(path, wusp.WUSPOLTPrefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	sc := &SetCall{Ctx: ctx, Env: env, Path: path, Value: value}
	if b, ok := bindingByLf[rel]; ok {
		if b.Set == nil {
			return wusp.ErrUSPPathUnsupported
		}
		if err := runSetter(sc, b.Set); err != nil {
			return err
		}
		if !b.Set.Local {
			env.afterWrite()
		}
		return nil
	}
	t, n, leaf, ok := tablePath(rel)
	if !ok || leaf == "" {
		return wusp.ErrUSPPathUnsupported
	}
	var col *Column
	for i := range t.Columns {
		if t.Columns[i].Leaf == leaf {
			col = &t.Columns[i]
		}
	}
	if col == nil || col.Set == nil {
		return wusp.ErrUSPPathUnsupported
	}
	sc.Inst = []uint64{n}
	sc.table = t
	if !col.Set.Local {
		if err := login(ctx, env.API); err != nil {
			return err
		}
		sc.loggedIn = true
	}
	if !t.Positional {
		key, row, err := resolveRow(ctx, env, t, n)
		if err != nil {
			return err
		}
		sc.Key, sc.Row = key, row
	}
	if err := runSetter(sc, col.Set); err != nil {
		return err
	}
	if !col.Set.Local {
		env.afterWrite()
	}
	return nil
}

func runSetter(sc *SetCall, s *Setter) error {
	if !s.Local && !sc.loggedIn {
		if err := login(sc.Ctx, sc.Env.API); err != nil {
			return err
		}
	}
	if s.Func != nil {
		return s.Func(sc)
	}
	var encoded any = wusp.ValueToString(sc.Value)
	if s.Encode != nil {
		var err error
		if encoded, err = s.Encode(sc.Value); err != nil {
			return fmt.Errorf("olt: %s: %w", sc.Path, err)
		}
	}
	body := map[string]any{}
	if s.ReadModifyWrite {
		current, err := newCycle(sc.Ctx, sc.Env).Doc(s.Read)
		if err != nil {
			return fmt.Errorf("olt: %s: read current form: %w", sc.Path, err)
		}
		if s.Form != nil {
			body = s.Form(current)
		} else {
			for k, v := range current {
				body[k] = v
			}
		}
	}
	for k, v := range s.Extra {
		body[k] = v
	}
	body[s.Field] = encoded
	if err := runGuard(sc.Ctx, sc.Env, s.Guard, s.Endpoint, body, sc.Row); err != nil {
		return err
	}
	if err := postChecked(sc.Ctx, sc.Env.API, s.Endpoint, body, s.Strict || s.ReadModifyWrite, s.OK...); err != nil {
		return err
	}
	if s.Commit != nil {
		if err := postChecked(sc.Ctx, sc.Env.API, s.Commit.Endpoint, s.Commit.Body, true); err != nil {
			return fmt.Errorf("olt: %s: commit: %w", sc.Path, err)
		}
	}
	if s.ReadModifyWrite && !s.NoVerify {
		after, err := newCycle(sc.Ctx, sc.Env).Doc(s.Read)
		if err != nil {
			return fmt.Errorf("olt: %s: re-read: %w", sc.Path, err)
		}
		key := s.VerifyKey
		if key == "" {
			key = s.Field
		}
		got, _ := Lookup(after, key)
		if Str(got) != Str(encoded) {
			return fmt.Errorf("olt: %s did not apply (device reports %q)", sc.Path, Str(got))
		}
	}
	return nil
}

// Vendor reply codes (OLT-WEBUI-CONTROLS.md conventions).
const (
	errCodeTimeout   = "timeout" // session expired
	errCodeNoHandler = "106"     // unknown goform handler
)

// replyCode returns the errCode of a bare vendor status reply.
func replyCode(v any) (string, bool) {
	doc, ok := v.(Doc)
	if !ok {
		return "", false
	}
	code, ok := doc["errCode"]
	if !ok {
		return "", false
	}
	return Str(code), true
}

// postChecked posts body; with check it fails on a vendor errCode other
// than "0"/"success" (or okCodes, e.g. "6" for reboot) and re-logs in once
// when the session expired.
func postChecked(ctx context.Context, api *Client, endpoint string, body map[string]any, check bool, okCodes ...string) error {
	if body == nil {
		body = map[string]any{}
	}
	if !check {
		return api.post(ctx, endpoint, body, nil)
	}
	for attempt := 0; ; attempt++ {
		var reply any
		if err := api.post(ctx, endpoint, body, &reply); err != nil {
			return err
		}
		code, ok := replyCode(reply)
		if !ok {
			return nil
		}
		switch strings.ToLower(code) {
		case "0", "success", "":
			return nil
		case errCodeTimeout:
			if attempt == 0 {
				if err := login(ctx, api); err != nil {
					return err
				}
				continue
			}
		}
		for _, okCode := range okCodes {
			if code == okCode {
				return nil
			}
		}
		if code == errCodeNoHandler {
			return fmt.Errorf("%w: olt api %s has no handler on this firmware (errCode=106)", wusp.ErrUSPPathUnsupported, endpoint)
		}
		return fmt.Errorf("olt api %s: errCode=%s", endpoint, code)
	}
}

// AddObject creates one row of a Device.WUSP_OLT table (USP Add).
func AddObject(ctx context.Context, env *Env, objectPath string, initial *wusp.Message) ([]string, error) {
	if env != nil && env.API != nil {
		defer env.API.beginWrite()()
	}
	ctx = withWebOnly(ctx) // writes read the full web document, never a partial helper reply
	buildIndex()
	rel, ok := strings.CutPrefix(strings.TrimSpace(objectPath), wusp.WUSPOLTPrefix)
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	rel = strings.TrimSuffix(strings.TrimSuffix(rel, "."), ".{i}")
	t, ok := tableByObj[rel]
	if !ok || t.Add == nil {
		return nil, wusp.ErrUSPPathUnsupported
	}
	key, err := t.Add(&AddCall{Ctx: ctx, Env: env, Object: objectPath, Initial: initial})
	if err != nil {
		return nil, err
	}
	env.afterWrite()
	if t.AddResult != nil {
		return []string{t.AddResult(key)}, nil
	}
	rows, err := t.rows(newCycle(ctx, env))
	if err == nil {
		for n, row := range rows {
			if t.key(row) == key {
				return []string{wusp.WUSPOLTPrefix + t.Object + "." + strconv.Itoa(n+1) + "."}, nil
			}
		}
	}
	return nil, fmt.Errorf("olt: %s: created row %q not found on re-read", t.Object, key)
}

// DeleteObject removes one row of a Device.WUSP_OLT table (USP Delete).
// Accepts "Object.N." and, for compatibility, "Object.N.Leaf".
func DeleteObject(ctx context.Context, env *Env, path string) error {
	if env != nil && env.API != nil {
		defer env.API.beginWrite()()
	}
	ctx = withWebOnly(ctx) // writes read the full web document, never a partial helper reply
	buildIndex()
	rel, ok := strings.CutPrefix(strings.TrimSpace(path), wusp.WUSPOLTPrefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	t, n, _, ok := tablePath(rel)
	if !ok || t.Delete == nil {
		return wusp.ErrUSPPathUnsupported
	}
	if err := login(ctx, env.API); err != nil {
		return err
	}
	key, row, err := resolveRow(ctx, env, t, n)
	if err != nil {
		return err
	}
	if err := t.Delete(&SetCall{Ctx: ctx, Env: env, Path: path, Inst: []uint64{n}, Key: key, Row: row, loggedIn: true, table: t}); err != nil {
		return err
	}
	env.afterWrite()
	return nil
}

// Operate runs one Device.WUSP_OLT command and returns its output
// message (empty when the command has no outputs).
func Operate(ctx context.Context, env *Env, cmd string, input *wusp.Message) (*wusp.Message, error) {
	if env != nil && env.API != nil {
		defer env.API.beginWrite()()
	}
	ctx = withWebOnly(ctx) // writes read the full web document, never a partial helper reply
	buildIndex()
	op, ok := opByCommand[strings.TrimSpace(cmd)]
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	oc := &OpCall{Ctx: ctx, Env: env, Command: op.Command, Input: input, Output: wusp.NewMessage()}
	if err := op.Run(oc); err != nil {
		return nil, err
	}
	if op.Saves {
		env.afterWrite()
	}
	return oc.Output, nil
}

// messageInput reads an input field by leaf name: exact path first, then
// a ".Leaf" suffix, then (compatibility) any suffix match.
func messageInput(msg *wusp.Message, leaf string) string {
	if msg == nil {
		return ""
	}
	for _, field := range msg.Fields {
		if field.Path == leaf {
			return wusp.ValueToString(field.Val)
		}
	}
	for _, field := range msg.Fields {
		if strings.HasSuffix(field.Path, "."+leaf) || strings.HasSuffix(field.Path, "."+leaf+".") {
			return wusp.ValueToString(field.Val)
		}
	}
	return OperateInputString(msg, leaf)
}
