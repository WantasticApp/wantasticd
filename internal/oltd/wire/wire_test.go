package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNewMsgLayout(t *testing.T) {
	m, err := NewMsg(271, "/tmp/wo123_1_0")
	if err != nil {
		t.Fatal(err)
	}
	b := m.Bytes()
	if len(b) != 0x43a {
		t.Fatalf("len %d", len(b))
	}
	if binary.LittleEndian.Uint16(b) != 271 || m.Code() != 271 {
		t.Fatal("code")
	}
	if m.ReplyPath() != "/tmp/wo123_1_0" || b[2+len("/tmp/wo123_1_0")] != 0 {
		t.Fatal("reply path")
	}
	if _, err := NewMsg(1, "/tmp/this/path/is/definitely/too/long"); err != ErrPathTooLong {
		t.Fatalf("want ErrPathTooLong, got %v", err)
	}
}

// formQuickParamToBuf layout: count@34, offsets@36, strings@100.
func TestPutQuick(t *testing.T) {
	m, _ := NewMsg(1011, "/tmp/x")
	if err := m.PutQuick([]string{"all", "", "0/1/1"}); err != nil {
		t.Fatal(err)
	}
	b := m.Bytes()
	if binary.LittleEndian.Uint16(b[34:]) != 3 {
		t.Fatal("count")
	}
	offs := []uint16{binary.LittleEndian.Uint16(b[36:]), binary.LittleEndian.Uint16(b[38:]), binary.LittleEndian.Uint16(b[40:])}
	if offs[0] != 0 || offs[1] != 4 || offs[2] != 5 {
		t.Fatalf("offsets %v", offs)
	}
	if !bytes.Equal(b[100:111], []byte("all\x00\x000/1/1\x00")) {
		t.Fatalf("data %q", b[100:111])
	}
	got := QuickParams(b)
	if len(got) != 3 || got[0] != "all" || got[1] != "" || got[2] != "0/1/1" {
		t.Fatalf("decode %q", got)
	}
	big := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		big = append(big, "x")
	}
	if err := m.PutQuick(big); err != ErrParams {
		t.Fatalf("want ErrParams, got %v", err)
	}
	if binary.LittleEndian.Uint16(m.Bytes()[34:]) != 32 {
		t.Fatal("vendor keeps the first 32 params")
	}
}

// Recorded-shape replies: seq_push header + web_service_finish payloads.
func TestParseReply(t *testing.T) {
	text := "pon1;pon1;1;2500;1;1\nge1;ge1;0;1000;1;1"
	dg := EncodeReply(272, FinishText(text))
	if got, ok := ParseReply(dg, 272, 2048); !ok || got != text {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	// Code mismatch -> seq_pull_chk empties the buffer.
	if got, ok := ParseReply(dg, 271, 2048); ok || got != "" {
		t.Fatalf("mismatch: %q %v", got, ok)
	}
	// read() truncates to the caller's buffer; memmove leaves 2 bytes.
	if got, _ := ParseReply(dg, 272, 10); got != "pon1;pon" {
		t.Fatalf("truncated: %q", got)
	}
	ok := EncodeReply(1013, FinishOK())
	if len(ok) != 2+128 {
		t.Fatal("finish ok length")
	}
	if got, _ := ParseReply(ok, 1013, 512); got != "0" {
		t.Fatalf("finish ok payload %q", got)
	}
	if _, ok := ParseReply([]byte{1}, 1, 10); ok {
		t.Fatal("short datagram accepted")
	}
}
