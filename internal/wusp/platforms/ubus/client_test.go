package ubus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode request: %v", err)
		}
		if req.Method != "call" {
			t.Fatalf("method=%q want call", req.Method)
		}
		if got, ok := req.Params[1].(string); !ok || got != "system" {
			t.Fatalf("object=%v want system", req.Params[1])
		}
		if got, ok := req.Params[2].(string); !ok || got != "board" {
			t.Fatalf("method=%v want board", req.Params[2])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[0,{"hostname":"openwrt-node"}]}`))
	}))
	defer server.Close()

	client := NewClient(Options{URL: server.URL})
	data, err := client.Call(context.Background(), "system", "board", nil, time.Second)
	if err != nil {
		t.Fatalf("Call returned error: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	if payload["hostname"] != "openwrt-node" {
		t.Fatalf("hostname=%q want openwrt-node", payload["hostname"])
	}
}

func TestClientUCIHelpers(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode request: %v", err)
		}

		object, _ := req.Params[1].(string)
		method, _ := req.Params[2].(string)
		seen = append(seen, object+"."+method)

		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "add":
			_, _ = w.Write([]byte(`{"result":[0,{"section":"cfg1234"}]}`))
		default:
			_, _ = w.Write([]byte(`{"result":[0,{}]}`))
		}
	}))
	defer server.Close()

	client := NewClient(Options{URL: server.URL})
	ctx := context.Background()

	if err := client.UCISet(ctx, "network", "globals", map[string]any{"ula_prefix": "fd12:3456::/48"}, time.Second); err != nil {
		t.Fatalf("UCISet returned error: %v", err)
	}
	if err := client.UCIDelete(ctx, "network", "globals", "ula_prefix", time.Second); err != nil {
		t.Fatalf("UCIDelete returned error: %v", err)
	}
	section, err := client.UCIAdd(ctx, "wireless", "wifi-iface", "guest", map[string]any{"ssid": "Guest"}, time.Second)
	if err != nil {
		t.Fatalf("UCIAdd returned error: %v", err)
	}
	if section != "cfg1234" {
		t.Fatalf("section=%q want cfg1234", section)
	}
	if err := client.UCICommit(ctx, "wireless", time.Second); err != nil {
		t.Fatalf("UCICommit returned error: %v", err)
	}
	if err := client.UCIApply(ctx, false, time.Second); err != nil {
		t.Fatalf("UCIApply returned error: %v", err)
	}
	if err := client.UCIReloadConfig(ctx, time.Second); err != nil {
		t.Fatalf("UCIReloadConfig returned error: %v", err)
	}

	want := []string{
		"uci.set",
		"uci.delete",
		"uci.add",
		"uci.commit",
		"uci.apply",
		"uci.reload_config",
	}
	if len(seen) != len(want) {
		t.Fatalf("seen=%v want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen[%d]=%q want %q", i, seen[i], want[i])
		}
	}
}

func TestClientCallReturnsUbusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[4]}`))
	}))
	defer server.Close()

	client := NewClient(Options{URL: server.URL})
	if _, err := client.Call(context.Background(), "uci", "commit", nil, time.Second); err == nil {
		t.Fatal("Call returned nil error, want ubus error")
	}
}
