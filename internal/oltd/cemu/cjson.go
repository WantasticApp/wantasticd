package cemu

import (
	"math"
	"strconv"
)

// JSON is a cJSON item: an ordered object (duplicate keys allowed, as
// cJSON_AddStringToObject never replaces), an array, a string or a number.
// Print emits the same tokens as cJSON_Print in compact form (cJSON_Print
// only adds indentation whitespace, which JSON consumers ignore).
type JSON struct {
	kind  byte // 'o' object, 'a' array, 's' string, 'n' number, 't'/'f' booleans
	keys  []string
	items []*JSON
	str   string
	num   float64
}

func Object() *JSON { return &JSON{kind: 'o'} }
func Array() *JSON  { return &JSON{kind: 'a'} }

// AddString mirrors cJSON_AddStringToObject. On an array the key is
// ignored (the vendor uses this to append strings to ponPortList).
func (j *JSON) AddString(key, val string) { j.add(key, &JSON{kind: 's', str: val}) }

// AddNumber mirrors cJSON_AddNumberToObject.
func (j *JSON) AddNumber(key string, v float64) { j.add(key, &JSON{kind: 'n', num: v}) }

// AddBool mirrors cJSON_AddTrueToObject / cJSON_AddFalseToObject.
func (j *JSON) AddBool(key string, v bool) {
	k := byte('f')
	if v {
		k = 't'
	}
	j.add(key, &JSON{kind: k})
}

// AddItem mirrors cJSON_AddItemToObject / cJSON_AddItemToArray.
func (j *JSON) AddItem(key string, item *JSON) { j.add(key, item) }

func (j *JSON) add(key string, item *JSON) {
	j.keys = append(j.keys, key)
	j.items = append(j.items, item)
}

// Print renders the item.
func (j *JSON) Print() []byte { return j.appendTo(nil) }

func (j *JSON) appendTo(b []byte) []byte {
	switch j.kind {
	case 'o':
		b = append(b, '{')
		for i, it := range j.items {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, j.keys[i])
			b = append(b, ':')
			b = it.appendTo(b)
		}
		return append(b, '}')
	case 'a':
		b = append(b, '[')
		for i, it := range j.items {
			if i > 0 {
				b = append(b, ',')
			}
			b = it.appendTo(b)
		}
		return append(b, ']')
	case 'n':
		return appendNumber(b, j.num)
	case 't':
		return append(b, "true"...)
	case 'f':
		return append(b, "false"...)
	default:
		return appendString(b, j.str)
	}
}

// appendNumber follows cJSON print_number: integral values within int
// range print as %d, others as %1.15g (or %1.17g when %1.15g does not
// round-trip).
func appendNumber(b []byte, d float64) []byte {
	if math.IsNaN(d) || math.IsInf(d, 0) {
		return append(b, "null"...)
	}
	if d == math.Trunc(d) && d >= math.MinInt32 && d <= math.MaxInt32 {
		return strconv.AppendInt(b, int64(d), 10)
	}
	s := strconv.FormatFloat(d, 'g', 15, 64)
	if v, err := strconv.ParseFloat(s, 64); err != nil || v != d {
		s = strconv.FormatFloat(d, 'g', 17, 64)
	}
	return append(b, s...)
}

// appendString follows cJSON print_string_ptr: escapes " \ \b \f \n \r \t,
// other bytes below 0x20 as \u00XX, everything else passes through raw.
func appendString(b []byte, s string) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
			} else {
				b = append(b, c)
			}
		}
	}
	return append(b, '"')
}
