// Package wire is the vendor webserver <-> daemon datagram protocol of the
// CyberAntennas / Photon GP8X2G6 OLT firmware, reproduced from the
// disassembly of /tmp/app/webserver (getCmdResultWebService @0x30f2c,
// web_service_cmd @0x23d1c, formQuickParamToBuf @0x952d8) and libfos.so
// (seq_push @0x162ae4, seq_pull_chk @0x162ba8, web_service_response
// @0x163010, web_service_finish @0x1634e8, web_service_read @0x163138).
//
// Request (client -> daemon), one AF_UNIX SOCK_DGRAM datagram of exactly
// MsgLen (0x43a = 1082) bytes sent to the daemon socket (/tmp/sm_web,
// /tmp/pon_web, /tmp/um_web, /tmp/sntp_web, ...):
//
//	off  0  u16 LE   command code (switch value in <daemon>_web_service_process)
//	off  2  char[32] reply socket path, NUL terminated. The daemon sends the
//	                 reply to exactly this path (webserver: "/tmp/web_service").
//	off 34  ...      code-specific body. The generic "formQuick" body is:
//	off 34  u16 LE   parameter count
//	off 36  u16[32]  parameter offsets, relative to off 100
//	off 100 char[]   NUL-terminated parameter strings, packed
//
// The daemon recv()s at most 1024 bytes (web_service_read), so anything
// past byte 1024 of the request is never seen.
//
// Reply (daemon -> client), one datagram to the reply path:
//
//	off 0  u16 LE  the request's command code (seq_push)
//	off 2  ...     payload: text, NUL terminated by the client's zeroed buffer
//
// web_service_finish sends either "0\0\0\x01" padded to 128 bytes (plain
// success), the accumulated text buffer, or the text followed by four NULs.
// There is no multi-datagram reassembly: seq_pull_chk only verifies the
// leading code and strips it; on a mismatch it empties the buffer.
package wire

import (
	"encoding/binary"
	"errors"
)

const (
	MsgLen        = 0x43a // bytes sent per request (sendto length)
	MsgBufLen     = 0x464 // size of the request struct in webserver
	PathOff       = 2
	PathLen       = 32
	QuickCountOff = 34
	QuickOffsOff  = 36
	QuickMaxParam = 32
	QuickDataOff  = 100
	QuickDataLen  = 1024
	DaemonRecvLen = 1024 // web_service_read recv() size
	ReplyHdrLen   = 2
)

var (
	ErrPathTooLong = errors.New("wire: reply path longer than 31 bytes")
	ErrParams      = errors.New("wire: formQuick parameters exceed 1024 bytes or 32 entries")
)

// Msg is one request buffer (MsgBufLen bytes; Bytes() returns the MsgLen
// prefix that goes on the wire).
type Msg []byte

// NewMsg returns a zeroed request with the command code and reply path set,
// as every getter does: memset(msg,0,0x43a); msg.code = code; and
// getCmdResultWebService copies the reply path to msg+2.
func NewMsg(code uint16, replyPath string) (Msg, error) {
	if len(replyPath) > PathLen-1 {
		return nil, ErrPathTooLong
	}
	m := make(Msg, MsgBufLen)
	binary.LittleEndian.PutUint16(m, code)
	copy(m[PathOff:PathOff+PathLen], replyPath)
	return m, nil
}

// Code returns the command code.
func (m Msg) Code() uint16 { return binary.LittleEndian.Uint16(m) }

// ReplyPath returns the reply socket path stored in the request.
func (m Msg) ReplyPath() string { return cstr(m[PathOff : PathOff+PathLen]) }

// PutU16 stores a little-endian u16 at off.
func (m Msg) PutU16(off int, v uint16) { binary.LittleEndian.PutUint16(m[off:], v) }

// PutString copies s (plus NUL) to off.
func (m Msg) PutString(off int, s string) {
	n := copy(m[off:], s)
	if off+n < len(m) {
		m[off+n] = 0
	}
}

// PutQuick packs parameters exactly like formQuickParamToBuf: count at 34,
// offsets at 36+2i, NUL-terminated strings packed from 100. Like the
// vendor it stops (returning ErrParams) when the next string would push
// the data past 1024 bytes or past 32 entries, keeping what was packed.
func (m Msg) PutQuick(vals []string) error {
	m.PutU16(QuickCountOff, 0)
	for i := QuickOffsOff; i < QuickOffsOff+64; i++ {
		m[i] = 0
	}
	for i := QuickDataOff; i < QuickDataOff+QuickDataLen && i < len(m); i++ {
		m[i] = 0
	}
	used := 0
	for i, v := range vals {
		n := len(v) + 1
		if used+n > QuickDataLen {
			return ErrParams
		}
		if i > QuickMaxParam-1 {
			return ErrParams
		}
		copy(m[QuickDataOff+used:], v)
		m[QuickDataOff+used+len(v)] = 0
		m.PutU16(QuickOffsOff+2*i, uint16(used))
		used += n
		m.PutU16(QuickCountOff, uint16(i+1))
	}
	return nil
}

// QuickParams decodes a formQuick body (daemon side; used by the fake
// daemon in tests and by diagnostics). Only the first DaemonRecvLen bytes
// are considered, as the daemon would.
func QuickParams(req []byte) []string {
	if len(req) > DaemonRecvLen {
		req = req[:DaemonRecvLen]
	}
	if len(req) < QuickDataOff {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(req[QuickCountOff:]))
	var out []string
	for i := 0; i < n && i < QuickMaxParam; i++ {
		off := QuickDataOff + int(binary.LittleEndian.Uint16(req[QuickOffsOff+2*i:]))
		if off >= len(req) {
			out = append(out, "")
			continue
		}
		out = append(out, cstr(req[off:]))
	}
	return out
}

// Bytes returns the MsgLen bytes that are sent.
func (m Msg) Bytes() []byte { return m[:MsgLen] }

// ParseReply applies the webserver's read()+seq_pull_chk() to one received
// datagram: the client buffer is bufSize bytes (larger datagrams are
// truncated by read()), the leading u16 must equal code, and the payload is
// the C string that follows. ok is false on a code mismatch (the vendor
// then sees an empty string).
func ParseReply(dgram []byte, code uint16, bufSize int) (payload string, ok bool) {
	if len(dgram) > bufSize {
		dgram = dgram[:bufSize]
	}
	if len(dgram) < ReplyHdrLen || binary.LittleEndian.Uint16(dgram) != code {
		return "", false
	}
	// memmove(buf, buf+2, len) leaves the last two bytes of the C buffer
	// undefined; a payload filling the whole buffer is cut there.
	body := dgram[ReplyHdrLen:]
	if len(body) > bufSize-ReplyHdrLen {
		body = body[:bufSize-ReplyHdrLen]
	}
	return cstr(body), true
}

// EncodeReply is seq_push: the daemon prefixes the payload with the code.
func EncodeReply(code uint16, payload []byte) []byte {
	out := make([]byte, ReplyHdrLen+len(payload))
	binary.LittleEndian.PutUint16(out, code)
	copy(out[ReplyHdrLen:], payload)
	return out
}

// FinishOK is the payload web_service_finish(ws, 0, 0, ...) sends: "0",
// NUL, NUL, 0x01, zero padded to 128 bytes.
func FinishOK() []byte {
	b := make([]byte, 0x80)
	b[0], b[3] = '0', 1
	return b
}

// FinishText is the payload web_service_finish sends for an error/text
// result: the text followed by four NUL bytes.
func FinishText(text string) []byte {
	return append([]byte(text), 0, 0, 0, 0)
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
