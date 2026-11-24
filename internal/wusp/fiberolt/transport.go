package fiberolt

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// oltTransport is the device seam the goform getters/setters go through:
// the wantastic-oltd helper on the OLT (preferred) or the vendor web UI +
// telnet CLI (fallback). Both return the goform JSON verbatim, so the
// binding tables, schema and goldens never see which one answered.
type oltTransport interface {
	Get(ctx context.Context, path string, args map[string]any) (json.RawMessage, error)
	Set(ctx context.Context, path string, args map[string]any) (json.RawMessage, error)
	Cmd(ctx context.Context, line string) (string, error)
}

// webTransport is today's goform web client (+ telnet CLI for Cmd).
type webTransport struct {
	c   *Client
	cli cliRunner
}

func (w webTransport) Get(ctx context.Context, path string, args map[string]any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := w.c.webPost(ctx, goformPath(path), args, &raw)
	return raw, err
}

func (w webTransport) Set(ctx context.Context, path string, args map[string]any) (json.RawMessage, error) {
	return w.Get(ctx, path, args)
}

func (w webTransport) Cmd(_ context.Context, line string) (string, error) {
	if w.cli == nil {
		return "", errNoCLI
	}
	return w.cli.Run(line)
}

func goformPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/goform/" + p
}

// ---- helperTransport: wantastic-oltd line protocol ------------------------

// errHelperFallback marks helper answers that mean "use the web client for
// this call" (endpoint not served, writes disabled, daemon error) without
// marking the helper unhealthy.
var errHelperFallback = errors.New("olt helper: use web fallback")

type helperFallbackError struct{ code, msg string }

func (e *helperFallbackError) Error() string { return "olt helper: " + e.code + ": " + e.msg }
func (e *helperFallbackError) Unwrap() error { return errHelperFallback }

// helperTransport speaks wantastic-oltd's newline-JSON protocol: a hello
// with a per-connection nonce, then requests signed with
// HMAC-SHA256(key, nonce+"\n"+body) and a strictly increasing seq; replies
// are signed with HMAC-SHA256(key, nonce+"\nR\n"+body).
type helperTransport struct {
	addr string
	key  []byte

	mu       sync.Mutex
	conn     net.Conn
	rd       *bufio.Reader
	nonce    string
	seq      uint64
	lastUsed time.Time
}

// helperIdleReuse is how long an idle connection is reused; the server
// drops idle connections after 60 s, so older ones are replaced up front
// instead of failing (and flipping the helper to "down") on first use.
const helperIdleReuse = 30 * time.Second

func newHelperTransport(addr string, key []byte) *helperTransport {
	return &helperTransport{addr: addr, key: key}
}

type helperRequest struct {
	Seq  uint64         `json:"seq"`
	ID   string         `json:"id,omitempty"`
	Op   string         `json:"op"`
	Path string         `json:"path,omitempty"`
	Args map[string]any `json:"args,omitempty"`
}

type helperReply struct {
	Seq  uint64          `json:"seq"`
	OK   bool            `json:"ok"`
	Code string          `json:"code"`
	Err  string          `json:"err"`
	Data json.RawMessage `json:"data"`
}

type helperEnvelope struct {
	Body json.RawMessage `json:"body"`
	MAC  string          `json:"mac,omitempty"`
}

func helperMAC(key []byte, prefix string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prefix))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

const helperDefaultTimeout = 10 * time.Second

func (h *helperTransport) closeLocked() {
	if h.conn != nil {
		h.conn.Close()
		h.conn, h.rd = nil, nil
	}
}

func (h *helperTransport) connectLocked(ctx context.Context) error {
	if h.conn != nil && time.Since(h.lastUsed) > helperIdleReuse {
		h.closeLocked()
	}
	if h.conn != nil {
		return nil
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(conn)
	line, err := rd.ReadBytes('\n')
	if err != nil {
		conn.Close()
		return fmt.Errorf("olt helper hello: %w", err)
	}
	var hello struct {
		Hello string `json:"hello"`
		V     int    `json:"v"`
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(line, &hello) != nil || hello.Hello != "wantastic-oltd" || hello.V != 1 || hello.Nonce == "" {
		conn.Close()
		return fmt.Errorf("olt helper: unexpected hello %q", truncateBody(line))
	}
	h.conn, h.rd, h.nonce, h.seq = conn, rd, hello.Nonce, 0
	return nil
}

// call sends one request and returns the reply data. Transport/auth
// failures close the connection and are returned as-is; helper-side
// "use the web" answers wrap errHelperFallback.
func (h *helperTransport) call(ctx context.Context, op, path string, args map[string]any) (json.RawMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	reused := h.conn != nil
	data, err, ioFailed := h.callLocked(ctx, op, path, args)
	// The helper closes its connections when it re-executes itself at its
	// heap ceiling (it never runs the GC). A read on a reused connection
	// that fails at the I/O level is retried once on a fresh connection;
	// writes are never repeated.
	if err != nil && ioFailed && reused && op != "set" {
		data, err, _ = h.callLocked(ctx, op, path, args)
	}
	return data, err
}

// callLocked performs one request; ioFailed reports a connection-level
// failure (dial excluded) after which the connection was closed.
func (h *helperTransport) callLocked(ctx context.Context, op, path string, args map[string]any) (json.RawMessage, error, bool) {
	data, err := h.callOnce(ctx, op, path, args)
	var io *helperIOError
	if errors.As(err, &io) {
		return nil, io.err, true
	}
	return data, err, false
}

type helperIOError struct{ err error }

func (e *helperIOError) Error() string { return e.err.Error() }

func (h *helperTransport) callOnce(ctx context.Context, op, path string, args map[string]any) (json.RawMessage, error) {
	if err := h.connectLocked(ctx); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(helperDefaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	h.conn.SetDeadline(deadline)
	h.seq++
	body, err := json.Marshal(helperRequest{Seq: h.seq, Op: op, Path: path, Args: args})
	if err != nil {
		return nil, err
	}
	line, _ := json.Marshal(helperEnvelope{Body: body, MAC: helperMAC(h.key, h.nonce+"\n", body)})
	if _, err := h.conn.Write(append(line, '\n')); err != nil {
		h.closeLocked()
		return nil, &helperIOError{err}
	}
	raw, err := h.rd.ReadBytes('\n')
	if err != nil {
		h.closeLocked()
		return nil, &helperIOError{err}
	}
	h.lastUsed = time.Now()
	var env helperEnvelope
	var rep helperReply
	if json.Unmarshal(raw, &env) != nil || json.Unmarshal(env.Body, &rep) != nil {
		h.closeLocked()
		return nil, fmt.Errorf("olt helper: bad reply %q", truncateBody(raw))
	}
	if rep.Code == "auth" {
		h.closeLocked()
		return nil, fmt.Errorf("olt helper: authentication failed (check -olt-helper-key)")
	}
	if env.MAC == "" || !hmac.Equal([]byte(env.MAC), []byte(helperMAC(h.key, h.nonce+"\nR\n", env.Body))) || rep.Seq != h.seq {
		h.closeLocked()
		return nil, fmt.Errorf("olt helper: reply signature/sequence mismatch")
	}
	if !rep.OK {
		switch rep.Code {
		case "unsupported", "set_disabled", "daemon_error", "busy":
			return nil, &helperFallbackError{rep.Code, rep.Err}
		}
		return nil, fmt.Errorf("olt helper %s %s: %s: %s", op, path, rep.Code, rep.Err)
	}
	return rep.Data, nil
}

func (h *helperTransport) Get(ctx context.Context, path string, args map[string]any) (json.RawMessage, error) {
	return h.call(ctx, "get", strings.TrimPrefix(path, "/goform/"), args)
}

func (h *helperTransport) Set(ctx context.Context, path string, args map[string]any) (json.RawMessage, error) {
	return h.call(ctx, "set", strings.TrimPrefix(path, "/goform/"), args)
}

func (h *helperTransport) Cmd(ctx context.Context, line string) (string, error) {
	data, err := h.call(ctx, "cmd", "", map[string]any{"line": line})
	if err != nil {
		return "", err
	}
	var s string
	if json.Unmarshal(data, &s) != nil {
		s = string(data)
	}
	return s, nil
}

func (h *helperTransport) ping(ctx context.Context) error {
	_, err := h.call(ctx, "ping", "", nil)
	return err
}

// ---- configuration --------------------------------------------------------

var helperConfig struct {
	mu   sync.Mutex
	addr string
	key  []byte
}

// ConfigureHelper makes every Client created afterwards prefer the
// wantastic-oltd helper at addr (host:port), authenticated with the key in
// keyPath (hex, or raw bytes). An empty addr disables the helper.
func ConfigureHelper(addr, keyPath string) error {
	helperConfig.mu.Lock()
	defer helperConfig.mu.Unlock()
	helperConfig.addr, helperConfig.key = "", nil
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	key, err := readHelperKey(keyPath)
	if err != nil {
		return err
	}
	helperConfig.addr, helperConfig.key = strings.TrimSpace(addr), key
	return nil
}

func readHelperKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("olt helper: key file not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("olt helper key: %w", err)
	}
	s := strings.TrimSpace(string(raw))
	key := []byte(s)
	if k, err := hex.DecodeString(s); err == nil {
		key = k
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("olt helper key %s: too short (%d bytes, need >= 16)", path, len(key))
	}
	return key, nil
}

func configuredHelper() *helperTransport {
	helperConfig.mu.Lock()
	defer helperConfig.mu.Unlock()
	if helperConfig.addr == "" {
		return nil
	}
	return newHelperTransport(helperConfig.addr, helperConfig.key)
}

// ---- selection: helper first, web fallback --------------------------------

const (
	helperUnknown int32 = iota
	helperUp
	helperDown
)

// WithHelper attaches a helper transport to the client (tests and callers
// that do not use ConfigureHelper).
func (c *Client) WithHelper(addr string, key []byte) *Client {
	c.helperMu.Lock()
	defer c.helperMu.Unlock()
	c.helper = newHelperTransport(addr, key)
	c.helperState = helperUnknown
	return c
}

// BeginCycle starts a collection cycle: the helper is probed (ping) once and
// its health is kept for the whole cycle, so a flapping helper cannot turn
// one collection into a mix of retries.
func (c *Client) BeginCycle(ctx context.Context) {
	c.helperMu.Lock()
	h := c.helper
	if h != nil {
		c.helperState = helperUnknown
	}
	c.helperMu.Unlock()
	if h != nil {
		c.helperActive(ctx)
	}
}

// helperActive reports whether calls should go to the helper, probing it
// when its state is unknown.
func (c *Client) helperActive(ctx context.Context) bool {
	c.helperMu.Lock()
	h, state := c.helper, c.helperState
	c.helperMu.Unlock()
	if h == nil {
		return false
	}
	if state != helperUnknown {
		return state == helperUp
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := h.ping(pctx)
	cancel()
	c.setHelperState(err == nil, err)
	return err == nil
}

func (c *Client) setHelperState(up bool, err error) {
	c.helperMu.Lock()
	defer c.helperMu.Unlock()
	if up {
		c.helperState = helperUp
	} else {
		c.helperState = helperDown
	}
	if c.helperLogged != c.helperState {
		if up {
			log.Printf("[OLT] helper %s active (web UI used only for endpoints the helper does not serve)", c.helper.addr)
		} else {
			log.Printf("[OLT] helper %s unavailable (%v); using the web UI this cycle", c.helper.addr, err)
		}
		c.helperLogged = c.helperState
	}
}

type webOnlyKey struct{}

// withWebOnly marks ctx so every goform call under it uses the web UI.
// Write paths (Set/AddObject/DeleteObject/Operate) use it: read-modify-
// write forms such as setDeviceInfo post the whole current document back,
// so they must never be built from a partial helper reply.
func withWebOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, webOnlyKey{}, true)
}

func isWebOnly(ctx context.Context) bool {
	v, _ := ctx.Value(webOnlyKey{}).(bool)
	return v
}

// sysStatusCacheKeys are getSysStatus fields that change rarely (identity,
// versions, management address). When the helper cannot fill them (on the
// OLT, um_web is served by imi's single thread loop and may stop answering)
// the last value seen from any source is used for telemetry reads only.
var sysStatusCacheKeys = []string{"softwareVersion", "hardwareVersion", "created", "productOid",
	"deviceName", "mac", "sn", "deviceLocation", "temphi", "templo", "ip", "mask", "ipType", "gateway"}

// patchSysStatus records the cacheable fields of a getSysStatus reply and,
// for a partial helper reply, fills the missing ones from the cache. Filled
// fields are listed in "_helperCached" and removed from
// "_helperUnsupported". No web call is made: while imi is wedged a web
// getSysStatus would block the single-threaded GoAhead server for minutes.
func (c *Client) patchSysStatus(raw json.RawMessage) json.RawMessage {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return raw
	}
	missing := map[string]bool{}
	if l, ok := doc["_helperUnsupported"].([]any); ok {
		for _, v := range l {
			if s, ok := v.(string); ok {
				missing[s] = true
			}
		}
	}
	c.helperMu.Lock()
	defer c.helperMu.Unlock()
	if c.sysCache == nil {
		c.sysCache = map[string]any{}
	}
	var filled []any
	for _, k := range sysStatusCacheKeys {
		v, present := doc[k]
		switch {
		case present && !missing[k]:
			c.sysCache[k] = v
		case !present:
			if cv, ok := c.sysCache[k]; ok {
				doc[k] = cv
				filled = append(filled, k)
				delete(missing, k)
			}
		}
	}
	if len(filled) == 0 {
		return raw
	}
	var rest []any
	if l, ok := doc["_helperUnsupported"].([]any); ok {
		for _, v := range l {
			if s, _ := v.(string); missing[s] {
				rest = append(rest, v)
			}
		}
	}
	if len(rest) > 0 {
		doc["_helperUnsupported"] = rest
	} else {
		delete(doc, "_helperUnsupported")
	}
	doc["_helperCached"] = filled
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// viaHelper tries the helper for one goform call. handled=false means the
// caller must use the web client (helper absent/down, web-only context,
// or the helper asked for the web fallback).
func (c *Client) viaHelper(ctx context.Context, path string, args map[string]any, out any) (handled bool, err error) {
	if isWebOnly(ctx) || !c.helperActive(ctx) {
		return false, nil
	}
	name := strings.TrimPrefix(path, "/goform/")
	var raw json.RawMessage
	if strings.HasPrefix(name, "get") {
		raw, err = c.helper.Get(ctx, path, args)
	} else {
		raw, err = c.helper.Set(ctx, path, args)
	}
	if err != nil {
		if !errors.Is(err, errHelperFallback) {
			c.setHelperState(false, err)
		}
		return false, nil
	}
	if name == "getSysStatus" {
		raw = c.patchSysStatus(raw)
	}
	if out == nil {
		return true, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return true, fmt.Errorf("olt helper %s: %v", path, err)
	}
	return true, nil
}

// transport returns the transport the next call would use (helper when
// healthy, else web).
func (c *Client) transport(ctx context.Context, cli cliRunner) oltTransport {
	if c.helperActive(ctx) {
		return c.helper
	}
	return webTransport{c: c, cli: cli}
}

// argsOf turns a request body / query into helper args.
func helperArgs(in any) map[string]any {
	switch v := in.(type) {
	case nil:
		return nil
	case map[string]any:
		return v
	case map[string]string:
		out := make(map[string]any, len(v))
		for k, s := range v {
			out[k] = s
		}
		return out
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}
