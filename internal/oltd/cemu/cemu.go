// Package cemu reproduces the exact C-library behaviour the vendor
// webserver relies on when it turns a daemon reply into JSON: sscanf into
// fixed stack buffers (including the overlap between adjacent buffers),
// strtok_r splitting, strncpy, and cJSON's ordered object model and string
// escaping. Using it, a Go port of a goform handler produces byte-for-byte
// the same keys and values the GoAhead handler would.
//
// It is pure Go (no syscalls) and builds everywhere.
package cemu

import "sync"

// Frame is a C stack frame. Offsets are distances below the frame pointer
// exactly as they appear in the disassembly (a buffer at "fp-0x2730" is
// offset 0x2730), so a handler port can use the disassembled offsets
// verbatim and inherit the vendor's buffer overlaps.
type Frame struct {
	mem []byte
}

// NewFrame returns a zeroed frame able to hold offsets up to size.
func NewFrame(size int) *Frame { return &Frame{mem: make([]byte, size+1)} }

// The helper runs with the GC off (see memguard), so large frames are
// recycled instead of allocated per request.
var (
	framePoolMu sync.Mutex
	framePool   = map[int][]*Frame{}
)

// GetFrame returns a zeroed frame of the given size from the pool.
func GetFrame(size int) *Frame {
	framePoolMu.Lock()
	l := framePool[size]
	var f *Frame
	if n := len(l); n > 0 {
		f = l[n-1]
		framePool[size] = l[:n-1]
	}
	framePoolMu.Unlock()
	if f == nil {
		return NewFrame(size)
	}
	clear(f.mem)
	return f
}

// Release returns a frame obtained from GetFrame to the pool.
func (f *Frame) Release() {
	size := len(f.mem) - 1
	framePoolMu.Lock()
	if len(framePool[size]) < 4 {
		framePool[size] = append(framePool[size], f)
	}
	framePoolMu.Unlock()
}

func (f *Frame) idx(off int) int { return len(f.mem) - 1 - off }

// Zero clears n bytes starting at the buffer at off (memset(buf, 0, n)).
func (f *Frame) Zero(off, n int) {
	i := f.idx(off)
	for k := 0; k < n && i+k < len(f.mem); k++ {
		if i+k >= 0 {
			f.mem[i+k] = 0
		}
	}
}

// Write stores s plus a terminating NUL at off (strcpy). Bytes that would
// land above the frame pointer are dropped.
func (f *Frame) Write(off int, s string) {
	i := f.idx(off)
	for k := 0; k <= len(s); k++ {
		p := i + k
		if p < 0 || p >= len(f.mem) {
			continue
		}
		if k == len(s) {
			f.mem[p] = 0
		} else {
			f.mem[p] = s[k]
		}
	}
}

// Strncpy copies at most n bytes of s to off without adding a NUL when s
// is n bytes or longer (C strncpy), padding with NULs otherwise.
func (f *Frame) Strncpy(off int, s string, n int) {
	i := f.idx(off)
	for k := 0; k < n; k++ {
		p := i + k
		if p < 0 || p >= len(f.mem) {
			continue
		}
		if k < len(s) {
			f.mem[p] = s[k]
		} else {
			f.mem[p] = 0
		}
	}
}

// U32 reads the little-endian 32-bit integer at off.
func (f *Frame) U32(off int) uint32 {
	i := f.idx(off)
	if i < 0 || i+4 > len(f.mem) {
		return 0
	}
	return uint32(f.mem[i]) | uint32(f.mem[i+1])<<8 | uint32(f.mem[i+2])<<16 | uint32(f.mem[i+3])<<24
}

// WriteU32 stores v little-endian at off.
func (f *Frame) WriteU32(off int, v uint32) {
	i := f.idx(off)
	for k := 0; k < 4; k++ {
		if p := i + k; p >= 0 && p < len(f.mem) {
			f.mem[p] = byte(v >> (8 * k))
		}
	}
}

// Str reads the C string at off.
func (f *Frame) Str(off int) string {
	i := f.idx(off)
	if i < 0 {
		return ""
	}
	j := i
	for j < len(f.mem) && f.mem[j] != 0 {
		j++
	}
	return string(f.mem[i:j])
}

// CString returns b up to (not including) the first NUL.
func CString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Strtok returns the tokens strtok_r(s, delim) would return in sequence:
// runs of delimiter bytes are skipped and never yield empty tokens.
func Strtok(s, delim string) []string {
	isDelim := func(c byte) bool {
		for i := 0; i < len(delim); i++ {
			if delim[i] == c {
				return true
			}
		}
		return false
	}
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && isDelim(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		j := i
		for j < len(s) && !isDelim(s[j]) {
			j++
		}
		out = append(out, s[i:j])
		i = j + 1
	}
	return out
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// Sscanf implements the subset of C sscanf the vendor handlers use —
// literal characters, whitespace, %s, %[...] / %[^...] scan sets and
// %d / %u integers, each with an optional maximum width ("%4s") — storing each converted string at the matching frame
// offset (integers as 32-bit little-endian values). It returns the number
// of assignments, or -1 when the input ends before the first conversion
// (C's EOF), exactly like uClibc.
func (f *Frame) Sscanf(input, format string, offs ...int) int {
	kinds := convKinds(format)
	return Sscanf(input, format, func(i int, v string) {
		if i >= len(offs) {
			return
		}
		if i < len(kinds) && (kinds[i] == 'd' || kinds[i] == 'u') {
			f.WriteU32(offs[i], parseCInt(v))
			return
		}
		f.Write(offs[i], v)
	})
}

// convKinds lists the conversion characters of format in order.
func convKinds(format string) []byte {
	var out []byte
	for p := 0; p < len(format); p++ {
		if format[p] != '%' || p+1 >= len(format) {
			continue
		}
		p++
		if format[p] == '%' {
			continue
		}
		out = append(out, format[p])
	}
	return out
}

// parseCInt converts the digits matched by %d / %u like strtol/strtoul
// into the 32-bit value stored (a leading '-' wraps, as in C).
func parseCInt(s string) uint32 {
	neg := false
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	var n uint64
	for ; i < len(s); i++ {
		n = n*10 + uint64(s[i]-'0')
		if n > 0xFFFFFFFF {
			n = 0xFFFFFFFF // strtoul saturates at ULONG_MAX
		}
	}
	if neg {
		return uint32(-int64(n))
	}
	return uint32(n)
}

// Sscanf is the frame-less form: store(i, v) receives the i-th conversion.
func Sscanf(input, format string, store func(i int, v string)) int {
	in := 0
	n := 0
	eofBeforeFirst := func() int {
		if n == 0 {
			return -1
		}
		return n
	}
	for p := 0; p < len(format); {
		c := format[p]
		switch {
		case isSpace(c):
			for p < len(format) && isSpace(format[p]) {
				p++
			}
			for in < len(input) && isSpace(input[in]) {
				in++
			}
		case c != '%':
			if in >= len(input) {
				return eofBeforeFirst()
			}
			if input[in] != c {
				return n
			}
			in++
			p++
		default:
			p++
			if p >= len(format) {
				return n
			}
			if format[p] == '%' {
				if in >= len(input) {
					return eofBeforeFirst()
				}
				if input[in] != '%' {
					return n
				}
				in++
				p++
				continue
			}
			width := 0 // maximum field width ("%4s"); 0 = unlimited
			for p < len(format) && format[p] >= '0' && format[p] <= '9' {
				width = width*10 + int(format[p]-'0')
				p++
			}
			if p >= len(format) {
				return n
			}
			limit := func(st int) int {
				if width > 0 && st+width < len(input) {
					return st + width
				}
				return len(input)
			}
			switch format[p] {
			case 's':
				p++
				for in < len(input) && isSpace(input[in]) {
					in++
				}
				if in >= len(input) {
					return eofBeforeFirst()
				}
				st := in
				end := limit(st)
				for in < end && !isSpace(input[in]) {
					in++
				}
				store(n, input[st:in])
				n++
			case '[':
				p++
				neg := false
				if p < len(format) && format[p] == '^' {
					neg = true
					p++
				}
				set := map[byte]bool{}
				if p < len(format) && format[p] == ']' {
					set[']'] = true
					p++
				}
				for p < len(format) && format[p] != ']' {
					set[format[p]] = true
					p++
				}
				p++ // closing ]
				if in >= len(input) {
					return eofBeforeFirst()
				}
				st := in
				end := limit(st)
				for in < end && set[input[in]] != neg {
					in++
				}
				if in == st {
					return n
				}
				store(n, input[st:in])
				n++
			case 'd', 'u':
				p++
				for in < len(input) && isSpace(input[in]) {
					in++
				}
				if in >= len(input) {
					return eofBeforeFirst()
				}
				st := in
				if input[in] == '+' || input[in] == '-' {
					in++
				}
				digits := in
				end := limit(st)
				for in < end && input[in] >= '0' && input[in] <= '9' {
					in++
				}
				if in == digits {
					return n // no digits: matching failure
				}
				store(n, input[st:in])
				n++
			default:
				return n // unsupported conversion: stop like a matching failure
			}
		}
	}
	return n
}
