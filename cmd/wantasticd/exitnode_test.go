package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

func TestParseExitCommand(t *testing.T) {
	ok := []struct {
		cmd  string
		args []string
		want exitCommand
	}{
		{"exit-node", []string{"on"}, exitCommand{Kind: "offer", On: true, Wait: 12 * time.Second}},
		{"exit-node", []string{"OFF"}, exitCommand{Kind: "offer", Wait: 12 * time.Second}},
		{"exit-node", []string{"status", "--json"}, exitCommand{Kind: "status", JSON: true, Wait: 12 * time.Second}},
		{"jumpto", []string{"10.255.255.36"}, exitCommand{Kind: "jumpto", Target: "10.255.255.36", Wait: 12 * time.Second}},
		{"jumpto", []string{"10.255.255.36", "--wait", "3s"}, exitCommand{Kind: "jumpto", Target: "10.255.255.36", Wait: 3 * time.Second}},
		{"comeback", nil, exitCommand{Kind: "comeback", Wait: 12 * time.Second}},
	}
	for _, c := range ok {
		got, err := parseExitCommand(c.cmd, c.args)
		if err != nil || got != c.want {
			t.Errorf("%s %v: got %+v %v", c.cmd, c.args, got, err)
		}
	}
	for _, bad := range [][]string{{"exit-node"}, {"exit-node", "maybe"}, {"jumpto"}, {"jumpto", "a", "b"}, {"comeback", "x"}} {
		if _, err := parseExitCommand(bad[0], bad[1:]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestDaemonPostSendsControlHeader(t *testing.T) {
	var gotHeader, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader, gotMethod = r.Header.Get(agent.ControlHeader), r.Method
		json.NewEncoder(w).Encode(agent.ExitNodeResponse{OK: true})
	}))
	defer srv.Close()
	var resp agent.ExitNodeResponse
	if err := daemonPostTo(srv.URL, "/api/exitnode/comeback", time.Second, &resp); err != nil || !resp.OK {
		t.Fatal(err)
	}
	if gotHeader != "1" || gotMethod != http.MethodPost {
		t.Fatalf("header=%q method=%q", gotHeader, gotMethod)
	}
}

func TestExitStatusLines(t *testing.T) {
	st := &device.ExitNodeStatus{Supported: true, Offering: true, Backend: "pf", Users: []device.ExitUser{{IP: "10.255.255.44"}},
		Using: &device.ExitUse{IP: "10.255.255.36", Hostname: "mini", State: "active", Path: "direct", Endpoint: "198.51.100.7:51820"}}
	if got := exitOfferLine(st); got != "on (pf), used by 1 peer(s)" {
		t.Errorf("offer line %q", got)
	}
	if got := exitUseLine(st); got != "10.255.255.36 (mini) — active, direct via 198.51.100.7:51820" {
		t.Errorf("use line %q", got)
	}
	st.Using.State, st.Using.Path, st.Using.Reason = "standby", "relay", "no direct path"
	if got := exitUseLine(st); !strings.HasSuffix(got, "standby, relay (no direct path)") {
		t.Errorf("standby line %q", got)
	}
	if exitUseLine(&device.ExitNodeStatus{}) != "none" || exitOfferLine(&device.ExitNodeStatus{UnsupportedReason: "x"}) != "unsupported: x" {
		t.Error("empty lines")
	}
	var b bytes.Buffer
	printExitStatus(&b, *st)
	if !strings.Contains(b.String(), "Peers using this device as exit:") {
		t.Errorf("status output:\n%s", b.String())
	}
}
