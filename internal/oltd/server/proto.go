// Package server is the wantastic-oltd LAN API: newline-delimited JSON over
// TCP, every line HMAC-SHA256 authenticated, served with raw syscalls only
// (no package net, no os.File, no Go timers) so the Go network poller is
// never started on the OLT's epoll-less 3.6.5 kernel.
//
// Protocol v1 (one JSON object per line, "\n" terminated):
//
//	server -> client on connect:
//	  {"hello":"wantastic-oltd","v":1,"nonce":"<32 hex>"}
//	client -> server:
//	  {"body":{"seq":N,"id":"..","op":"get|set|cmd|ping","path":"getSysStatus","args":{...}},
//	   "mac":"<hex HMAC-SHA256(key, nonce + "\n" + <body bytes as sent>)>"}
//	server -> client:
//	  {"body":{"seq":N,"id":"..","ok":true,"data":<goform JSON>} | {..,"ok":false,"code":"..","err":".."},
//	   "mac":"<hex HMAC-SHA256(key, nonce + "\nR\n" + <body bytes as sent>)>"}
//
// seq must strictly increase per connection (replay protection without
// relying on the OLT clock). A bad MAC or seq gets one unsigned
// {"body":{"ok":false,"code":"auth"}} line and the connection is closed.
package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	ProtoName    = "wantastic-oltd"
	ProtoVersion = 1
	MaxLine      = 1 << 20
)

// Hello is the server greeting.
type Hello struct {
	Hello string `json:"hello"`
	V     int    `json:"v"`
	Nonce string `json:"nonce"`
}

// Envelope wraps every request and reply line.
type Envelope struct {
	Body json.RawMessage `json:"body"`
	MAC  string          `json:"mac,omitempty"`
}

// Request is the signed request body.
type Request struct {
	Seq  uint64         `json:"seq"`
	ID   string         `json:"id,omitempty"`
	Op   string         `json:"op"`
	Path string         `json:"path,omitempty"`
	Args map[string]any `json:"args,omitempty"`
}

// Reply is the signed reply body.
type Reply struct {
	Seq  uint64          `json:"seq"`
	ID   string          `json:"id,omitempty"`
	OK   bool            `json:"ok"`
	Code string          `json:"code,omitempty"`
	Err  string          `json:"err,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Reply codes.
const (
	CodeUnsupported = "unsupported"  // endpoint not served: use the web client
	CodeSetDisabled = "set_disabled" // writes off on this helper: use the web client
	CodeBadRequest  = "bad_request"
	CodeDaemon      = "daemon_error" // daemon round trip failed
	CodeBusy        = "busy"
	CodeAuth        = "auth"
)

// RequestMAC signs a request body.
func RequestMAC(key []byte, nonce string, body []byte) string {
	return sign(key, nonce+"\n", body)
}

// ReplyMAC signs a reply body.
func ReplyMAC(key []byte, nonce string, body []byte) string {
	return sign(key, nonce+"\nR\n", body)
}

func sign(key []byte, prefix string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prefix))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyMAC compares in constant time.
func VerifyMAC(want, got string) bool {
	a, err1 := hex.DecodeString(want)
	b, err2 := hex.DecodeString(got)
	return err1 == nil && err2 == nil && hmac.Equal(a, b)
}
