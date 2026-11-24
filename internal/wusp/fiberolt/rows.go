package fiberolt

// Helpers for the FOS web-UI table idioms (OLT-WEBUI-CONTROLS.md,
// "Common body idioms"): one setter serves add and edit
// ({...fields, action:"add"} / {...row, action:"edit", originData:row}),
// deletes post {"list":[<full rows as returned by the getter>]}, and
// setGlobalConfig {"action":"all"} is the only persist step.

import (
	"fmt"

	"wantastic-agent/internal/wusp"
)

// SaveConfig is the FOS "Save" (write memory) request. Every set*/del*
// call changes only the running configuration until it is sent. Use it as
// a Setter.Commit / after an Operate when a control must persist.
var SaveConfigRequest = &Request{Endpoint: "/goform/setGlobalConfig", Body: map[string]any{"action": "all"}}

func copyRow(row Doc) map[string]any {
	out := make(map[string]any, len(row)+2)
	for k, v := range row {
		out[k] = v
	}
	return out
}

// RowEdit is a column setter for add/edit tables: it posts the live row
// with field replaced, action "edit" and originData set to the original
// row, then re-reads the table and confirms the row (found by its key)
// carries the new value. encode nil sends the value as a string.
func RowEdit(endpoint, field string, encode func(wusp.Value) (any, error)) *Setter {
	return &Setter{Func: func(sc *SetCall) error {
		if sc.Row == nil {
			return fmt.Errorf("olt: %s: row not resolved", sc.Path)
		}
		var value any = wusp.ValueToString(sc.Value)
		if encode != nil {
			var err error
			if value, err = encode(sc.Value); err != nil {
				return fmt.Errorf("olt: %s: %w", sc.Path, err)
			}
		}
		body := copyRow(sc.Row)
		body[field] = value
		body["action"] = "edit"
		body["originData"] = copyRow(sc.Row)
		if err := postChecked(sc.Ctx, sc.Env.API, endpoint, body, true); err != nil {
			return err
		}
		if sc.table == nil || sc.Key == "" {
			return nil
		}
		rows, err := sc.table.rows(newCycle(sc.Ctx, sc.Env))
		if err != nil {
			return fmt.Errorf("olt: %s: re-read: %w", sc.Path, err)
		}
		for _, row := range rows {
			if sc.table.key(row) == sc.Key {
				if Str(row[field]) != Str(value) {
					return fmt.Errorf("olt: %s did not apply (device reports %q)", sc.Path, Str(row[field]))
				}
				return nil
			}
		}
		return fmt.Errorf("olt: %s: row %q gone after edit", sc.Path, sc.Key)
	}}
}

// RowDelete is a Table.Delete posting {"list":[row]}.
func RowDelete(endpoint string) func(sc *SetCall) error {
	return func(sc *SetCall) error {
		return postChecked(sc.Ctx, sc.Env.API, endpoint, map[string]any{"list": []any{sc.Row}}, true)
	}
}

// RowAdd is a Table.Add posting {fields..., action:"add"}; the new row's
// key is the value of the keyInput field.
func RowAdd(endpoint string, keyInput string, fields []FormField) func(ac *AddCall) (string, error) {
	return func(ac *AddCall) (string, error) {
		body := map[string]any{"action": "add"}
		var missing []string
		for _, f := range fields {
			v := ac.In(f.Input)
			if f.Required && v == "" {
				missing = append(missing, f.Input)
			}
			body[f.Form] = v
		}
		if len(missing) > 0 {
			return "", fmt.Errorf("olt: add %s requires %v", ac.Object, missing)
		}
		if err := login(ac.Ctx, ac.Env.API); err != nil {
			return "", err
		}
		if err := postChecked(ac.Ctx, ac.Env.API, endpoint, body, true); err != nil {
			return "", err
		}
		return ac.In(keyInput), nil
	}
}
