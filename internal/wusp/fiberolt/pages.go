package fiberolt

// Interpreter for the web-UI page specs (internal/wusp/olt_spec.go): every
// OLTPage becomes Sources, Bindings, Tables and Operations of the engine.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"wantastic-agent/internal/wusp"
)

func init() {
	for _, p := range wusp.OLTPages {
		if p.Unsupported != "" {
			continue
		}
		for _, f := range p.Forms {
			registerForm(f)
		}
		for i := range p.Tables {
			registerTable(p.Tables[i])
		}
		for _, a := range p.Actions {
			registerAction(a)
		}
	}
}

// pageSourceName is the source name of a getter call: "page:<path>?<query>".
func pageSourceName(path string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	name := "page:" + path
	for i, k := range keys {
		sep := "&"
		if i == 0 {
			sep = "?"
		}
		name += sep + k + "=" + params[k]
	}
	return name
}

// pageSource registers (once, at init) the source for a getter call.
func pageSource(call wusp.OLTCall) string {
	name := pageSourceName(call.Path, call.Params)
	for _, s := range Sources {
		if s.Name == name {
			return name
		}
		// Reuse a source that already reads the same page (one fetch per
		// cycle).
		if s.Fetch == nil && s.Body == nil && s.Endpoint == call.Path && sameQuery(s.Query, call.Params) {
			return s.Name
		}
	}
	src := Source{Name: name, Endpoint: call.Path}
	if call.Params != nil {
		src.Query = call.Params
	}
	Sources = append(Sources, src)
	return name
}

// ---- codecs -----------------------------------------------------------------

func decodeField(f wusp.OLTField) Conv {
	return func(raw any) (wusp.Value, bool) {
		if raw == nil {
			return wusp.Value{}, false
		}
		s := strings.TrimSpace(Str(raw))
		switch f.Codec {
		case "bool01", "bool":
			if b, ok := raw.(bool); ok {
				return wusp.Bool(b), true
			}
			l := strings.ToLower(s)
			return wusp.Bool(l == "1" || l == "true" || l == "enable" || l == "on"), s != ""
		case "uint":
			u, err := strconv.ParseUint(s, 10, 64)
			return wusp.Uint(u), err == nil
		case "int":
			i, err := strconv.ParseInt(s, 10, 64)
			return wusp.Int(i), err == nil
		case "decimal":
			v, err := strconv.ParseFloat(s, 64)
			return wusp.Float(v), err == nil
		case "base64":
			if dec, err := base64.StdEncoding.DecodeString(s); err == nil && printable(string(dec)) {
				return wusp.String(string(dec)), true
			}
			return wusp.String(s), true
		case "list":
			if arr, ok := raw.([]any); ok {
				parts := make([]string, 0, len(arr))
				for _, a := range arr {
					parts = append(parts, Str(a))
				}
				return wusp.String(strings.Join(parts, ",")), true
			}
			return wusp.String(s), true
		}
		if _, isObj := raw.(Doc); isObj {
			b, _ := json.Marshal(raw)
			return wusp.String(string(b)), true
		}
		if arr, isArr := raw.([]any); isArr {
			b, _ := json.Marshal(arr)
			return wusp.String(string(b)), true
		}
		return wusp.String(Str(raw)), true
	}
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func encodeField(f wusp.OLTField, v wusp.Value) (any, error) {
	s := wusp.ValueToString(v)
	switch f.Codec {
	case "bool01":
		if v.AsBool() {
			return "1", nil
		}
		return "0", nil
	case "bool":
		return v.AsBool(), nil
	case "uint", "int", "decimal":
		n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("value %q is not a number", s)
		}
		if (f.Min != nil && n < float64(*f.Min)) || (f.Max != nil && n > float64(*f.Max)) {
			return nil, fmt.Errorf("value %s out of range", s)
		}
		return s, nil
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(s)), nil
	case "list":
		out := []any{}
		for _, p := range splitList(s) {
			out = append(out, p)
		}
		return out, nil
	}
	if len(f.Enum) > 0 {
		ok := false
		for _, e := range f.Enum {
			if e == s {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("value %q not in %v", s, f.Enum)
		}
	}
	if f.Min != nil || f.Max != nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			if (f.Min != nil && n < *f.Min) || (f.Max != nil && n > *f.Max) {
				return nil, fmt.Errorf("value %s out of range", s)
			}
		}
	}
	return s, nil
}

func formKey(f wusp.OLTField) string {
	if f.SetKey != "" {
		return f.SetKey
	}
	return f.Vendor
}

// ---- body building ---------------------------------------------------------------

// buildBody applies an OLTWrite spec to the current form/row.
func buildBody(w *wusp.OLTWrite, cur Doc) map[string]any {
	body := map[string]any{}
	for _, k := range w.Body {
		set, get := wusp.OLTBodyKey(k)
		if v, ok := cur[get]; ok {
			body[set] = v
		} else {
			body[set] = ""
		}
	}
	for k, v := range w.Extra {
		body[k] = v
	}
	switch w.Origin {
	case "row":
		body["originData"] = copyRow(rawRow(cur))
	case "empty":
		body["originData"] = map[string]any{}
	}
	if w.Port != "" {
		key := "portName"
		if w.Port == "num" {
			key = "portNum"
		}
		if w.PortScalar {
			body["port"] = Str(cur[key])
		} else {
			body["port"] = []any{Str(cur[key])}
		}
	}
	if w.PortName {
		body["portName"] = Str(cur["portName"])
	}
	// The device-info dialog posts unset DNS servers as "" (the getter
	// reports them as "0.0.0.0").
	if w.Path == "/goform/setDeviceInfo" {
		for _, k := range []string{"preferredDNS", "alternateDNS"} {
			if body[k] == "0.0.0.0" {
				body[k] = ""
			}
		}
	}
	return body
}

// writeAndVerify posts body (guarded) and, unless disabled, re-reads the
// form/row via reread and checks key holds want.
func writeAndVerify(ctx context.Context, env *Env, w *wusp.OLTWrite, body map[string]any, row Doc, path, key string, want any, reread func() (Doc, error)) error {
	if err := runGuard(ctx, env, w.Guard, w.Path, body, row); err != nil {
		return err
	}
	if err := postChecked(ctx, env.API, w.Path, body, true, w.OK...); err != nil {
		return err
	}
	if w.NoVerify || reread == nil {
		return nil
	}
	after, err := reread()
	if err != nil {
		return fmt.Errorf("olt: %s: re-read: %w", path, err)
	}
	got, _ := Lookup(after, key)
	if !sameValue(got, want) {
		return fmt.Errorf("olt: %s did not apply (device reports %q)", path, Str(got))
	}
	return nil
}

func sameValue(got, want any) bool {
	norm := func(v any) string {
		if arr, ok := v.([]any); ok {
			parts := make([]string, 0, len(arr))
			for _, a := range arr {
				parts = append(parts, Str(a))
			}
			return strings.Join(parts, ",")
		}
		return strings.TrimSpace(Str(v))
	}
	return norm(got) == norm(want)
}

// ---- forms ------------------------------------------------------------------------

func registerForm(f wusp.OLTForm) {
	src := pageSource(f.Get)
	for _, fl := range f.Fields {
		fl := fl
		b := Binding{Leaf: f.Object + "." + fl.Leaf, Get: From(src, decodeField(fl), fl.Vendor)}
		w := fl.Set
		if w == nil {
			w = f.Set
		}
		if fl.Write && w != nil {
			w := w
			b.Set = &Setter{Func: func(sc *SetCall) error {
				cur, err := newCycle(sc.Ctx, sc.Env).Doc(src)
				if err != nil {
					return fmt.Errorf("olt: %s: read current form: %w", sc.Path, err)
				}
				enc, err := encodeField(fl, sc.Value)
				if err != nil {
					return fmt.Errorf("olt: %s: %w", sc.Path, err)
				}
				body := buildBody(w, cur)
				body[formKey(fl)] = enc
				return writeAndVerify(sc.Ctx, sc.Env, w, body, cur, sc.Path, fl.Vendor, enc, func() (Doc, error) {
					return newCycle(sc.Ctx, sc.Env).Doc(src)
				})
			}}
		}
		Bindings = append(Bindings, b)
	}
}

// ---- tables -----------------------------------------------------------------------

func registerTable(t wusp.OLTTable) {
	src := pageSource(t.Get)
	list := t.List
	if list == "" {
		list = "list"
	}
	tb := Table{
		Object: t.Object, Source: src, KeyFields: t.Key,
		Count: t.TableCountLeaf(),
		Rows:  func(_ *Cycle, raw any) []Doc { return ListRows(raw, list) },
	}
	if len(t.Key) > 1 {
		keys := t.Key
		tb.KeyFields = nil
		tb.Key = func(row Doc) string {
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, Str(row[k]))
			}
			return strings.Join(parts, "|")
		}
	}
	tbl := &tb
	for _, c := range t.Columns {
		c := c
		col := Column{Leaf: c.Leaf, Get: Col(decodeField(c), c.Vendor)}
		w := c.Set
		if w == nil {
			w = t.Edit
		}
		if c.Write && w != nil {
			w := w
			col.Set = &Setter{Func: func(sc *SetCall) error {
				enc, err := encodeField(c, sc.Value)
				if err != nil {
					return fmt.Errorf("olt: %s: %w", sc.Path, err)
				}
				body := buildBody(w, sc.Row)
				body[formKey(c)] = enc
				key := sc.Key
				return writeAndVerify(sc.Ctx, sc.Env, w, body, sc.Row, sc.Path, c.Vendor, enc, func() (Doc, error) {
					rows, err := tbl.rows(newCycle(sc.Ctx, sc.Env))
					if err != nil {
						return nil, err
					}
					for _, r := range rows {
						if tbl.key(r) == key {
							return r, nil
						}
					}
					return nil, fmt.Errorf("row %q gone after write", key)
				})
			}}
		}
		tb.Columns = append(tb.Columns, col)
	}
	if t.Add != nil {
		add := t.Add
		tb.Add = func(ac *AddCall) (string, error) {
			body := map[string]any{}
			for _, k := range add.Body {
				set, _ := wusp.OLTBodyKey(k)
				body[set] = ""
			}
			var missing []string
			for _, c := range t.Columns {
				in := ac.In(c.Leaf)
				if c.Required && in == "" {
					missing = append(missing, c.Leaf)
				}
				if _, wanted := body[formKey(c)]; !wanted && !bodyHas(add.Body, c.Vendor) {
					continue
				}
				if in == "" {
					continue
				}
				enc, err := encodeField(c, wusp.String(in))
				if c.Codec == "bool01" || c.Codec == "bool" {
					enc, err = encodeField(c, wusp.Bool(in == "1" || strings.EqualFold(in, "true")))
				}
				if err != nil {
					return "", fmt.Errorf("olt: add %s: %s: %w", t.Object, c.Leaf, err)
				}
				body[formKey(c)] = enc
			}
			if len(missing) > 0 {
				return "", fmt.Errorf("olt: add %s requires %s", t.Object, strings.Join(missing, ", "))
			}
			for k, v := range add.Extra {
				body[k] = v
			}
			if err := login(ac.Ctx, ac.Env.API); err != nil {
				return "", err
			}
			if err := runGuard(ac.Ctx, ac.Env, add.Guard, add.Path, body, nil); err != nil {
				return "", err
			}
			// Keys before the write: the new row is the one that appears
			// (the vendor may assign an index or reformat the key).
			before := map[string]bool{}
			if rows, err := tbl.rows(newCycle(ac.Ctx, ac.Env)); err == nil {
				for _, r := range rows {
					before[tbl.key(r)] = true
				}
			}
			if err := postChecked(ac.Ctx, ac.Env.API, add.Path, body, true, add.OK...); err != nil {
				return "", err
			}
			if rows, err := tbl.rows(newCycle(ac.Ctx, ac.Env)); err == nil {
				for _, r := range rows {
					if k := tbl.key(r); !before[k] {
						return k, nil
					}
				}
			}
			key := Doc{}
			for k, v := range body {
				key[k] = v
			}
			return tbl.key(key), nil
		}
	}
	if t.Delete != nil {
		del := t.Delete
		tb.Delete = func(sc *SetCall) error {
			row := copyRow(rawRow(sc.Row))
			for k, v := range del.Extra {
				row[k] = v
			}
			body := map[string]any{"list": []any{row}}
			if err := runGuard(sc.Ctx, sc.Env, del.Guard, del.Path, body, sc.Row); err != nil {
				return err
			}
			return postChecked(sc.Ctx, sc.Env.API, del.Path, body, true, del.OK...)
		}
	}
	Tables = append(Tables, tb)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- actions ----------------------------------------------------------------------

func registerAction(a wusp.OLTAction) {
	cmd := wusp.WUSPOLTPrefix + a.Command
	var rowsSrc string
	var rowsList string
	var rowsKey []string
	if a.Rows != nil {
		rowsSrc = pageSource(a.Rows.Get)
		rowsList = a.Rows.List
		if rowsList == "" {
			rowsList = "list"
		}
		rowsKey = a.Rows.Key
	}
	// Actions returning a result (diagnostics) change nothing to save.
	saves := !a.Result
	Operations = append(Operations, OpBinding{Command: cmd, Saves: saves, Run: func(oc *OpCall) error {
		w := a.Write
		body := map[string]any{}
		for _, k := range w.Body {
			set, _ := wusp.OLTBodyKey(k)
			body[set] = ""
		}
		var missing []string
		for _, in := range a.Inputs {
			v := oc.In(in.Leaf)
			if in.Required && v == "" {
				missing = append(missing, in.Leaf)
			}
			if v == "" && !bodyHas(w.Body, in.Vendor) {
				continue
			}
			enc, err := encodeField(in, wusp.String(v))
			if in.Codec == "bool01" || in.Codec == "bool" {
				enc, err = encodeField(in, wusp.Bool(v == "1" || strings.EqualFold(v, "true")))
			}
			if err != nil && v != "" {
				return fmt.Errorf("olt: %s: %s: %w", a.Command, in.Leaf, err)
			}
			body[formKey(in)] = enc
		}
		if a.Rows != nil && oc.In("Index") == "" {
			missing = append([]string{"Index"}, missing...)
		}
		if len(missing) > 0 {
			return fmt.Errorf("olt: %s requires %s", a.Command, strings.Join(missing, ", "))
		}
		for k, v := range w.Extra {
			body[k] = v
		}
		if err := oc.Login(); err != nil {
			return err
		}
		var cur Doc
		if a.Read != nil {
			var err error
			cur, err = newCycle(oc.Ctx, oc.Env).Doc(pageSource(*a.Read))
			if err != nil {
				return fmt.Errorf("olt: %s: read current form: %w", a.Command, err)
			}
			given := map[string]bool{}
			for _, in := range a.Inputs {
				if oc.In(in.Leaf) != "" {
					given[formKey(in)] = true
				}
			}
			for _, k := range w.Body {
				set, get := wusp.OLTBodyKey(k)
				if !given[set] {
					body[set] = cur[get]
				}
			}
		}
		if a.Rows != nil {
			raw, err := newCycle(oc.Ctx, oc.Env).Source(rowsSrc)
			if err != nil {
				return err
			}
			want := map[string]bool{}
			for _, id := range splitList(oc.In("Index")) {
				want[id] = true
			}
			var rows []any
			for _, row := range ListRows(raw, rowsList) {
				parts := make([]string, 0, len(rowsKey))
				for _, k := range rowsKey {
					parts = append(parts, Str(row[k]))
				}
				if want[strings.Join(parts, "|")] {
					rows = append(rows, row)
				}
			}
			if len(rows) == 0 {
				return fmt.Errorf("%w: no row matches Index %s", wusp.ErrUSPPathNotFound, oc.In("Index"))
			}
			body["list"] = rows
		}
		if err := runGuard(oc.Ctx, oc.Env, w.Guard, w.Path, body, cur); err != nil {
			return err
		}
		reply, err := postReply(oc.Ctx, oc.Env.API, w.Path, body, w.OK...)
		if err != nil {
			return err
		}
		if a.Result {
			b, _ := json.Marshal(reply)
			oc.Output.Set(wusp.WUSPOLTPrefix+wusp.OLTActionResultLeaf(a.Command), wusp.String(string(b)))
		}
		return nil
	}})
}

// postReply is postChecked that also returns the decoded reply.
func postReply(ctx context.Context, api *Client, endpoint string, body map[string]any, okCodes ...string) (any, error) {
	var reply any
	for attempt := 0; ; attempt++ {
		reply = nil
		if err := api.post(ctx, endpoint, body, &reply); err != nil {
			return nil, err
		}
		code, ok := replyCode(reply)
		if !ok {
			return reply, nil
		}
		switch strings.ToLower(code) {
		case "0", "success", "":
			return reply, nil
		case errCodeTimeout:
			if attempt == 0 {
				if err := login(ctx, api); err != nil {
					return nil, err
				}
				continue
			}
		}
		for _, c := range okCodes {
			if c == code {
				return reply, nil
			}
		}
		if code == errCodeNoHandler {
			return nil, fmt.Errorf("%w: olt api %s has no handler on this firmware (errCode=106)", wusp.ErrUSPPathUnsupported, endpoint)
		}
		return nil, fmt.Errorf("olt api %s: errCode=%s", endpoint, code)
	}
}

func sameQuery(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// bodyHas reports whether a Body list posts key (either side of "set=get").
func bodyHas(body []string, key string) bool {
	for _, k := range body {
		if set, get := wusp.OLTBodyKey(k); set == key || get == key {
			return true
		}
	}
	return false
}
