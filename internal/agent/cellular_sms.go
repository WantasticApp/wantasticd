package agent

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"wantastic-agent/internal/wusp"
)

// capSMSInboxJSON keeps an inbox payload within the SMSInboxJSON schema
// limit. The controller decodes replies strictly, so one oversized inbox (a
// full SIM plus ME store easily passes 16 KiB) failed the whole ListSMS
// reply and the inbox never loaded. Rows are dropped from the front, where
// the backends put the oldest messages, so the newest stay visible. Both the
// native row array and sms_tool's {"msg":[...]} object are handled.
func capSMSInboxJSON(payload string, maxLen int) string {
	if maxLen <= 0 || len(payload) <= maxLen {
		return payload
	}
	var rows []json.RawMessage
	if err := json.Unmarshal([]byte(payload), &rows); err == nil {
		return marshalCappedRows(rows, maxLen, func(kept []json.RawMessage) any { return kept })
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &object); err == nil {
		for key, value := range object {
			if err := json.Unmarshal(value, &rows); err != nil {
				continue
			}
			return marshalCappedRows(rows, maxLen, func(kept []json.RawMessage) any {
				out := make(map[string]json.RawMessage, len(object))
				for k, v := range object {
					out[k] = v
				}
				encoded, _ := json.Marshal(kept)
				out[key] = encoded
				return out
			})
		}
	}
	return "[]"
}

func marshalCappedRows(rows []json.RawMessage, maxLen int, wrap func([]json.RawMessage) any) string {
	// Drop whole rows until the encoding fits; start from an estimate so a
	// large inbox does not re-encode once per dropped row.
	total := 2
	for _, row := range rows {
		total += len(row) + 1
	}
	start := 0
	for start < len(rows) && total > maxLen {
		total -= len(rows[start]) + 1
		start++
	}
	for ; start <= len(rows); start++ {
		encoded, err := json.Marshal(wrap(rows[start:]))
		if err == nil && len(encoded) <= maxLen {
			return string(encoded)
		}
	}
	return "[]"
}

// truncateUTF8 shortens value to at most maxLen bytes on a rune boundary.
func truncateUTF8(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	cut := maxLen
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// cachedString reads one cached parameter as a string without collecting.
func (r *uspRuntime) cachedString(path string) string {
	if r == nil || r.dataModelCache == nil {
		return ""
	}
	value, ok := r.dataModelCache.Value(path)
	if !ok {
		return ""
	}
	return strings.TrimSpace(wusp.ValueToString(value))
}
