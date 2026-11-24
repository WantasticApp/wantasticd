package fiberolt

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"wantastic-agent/internal/wusp"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

// messageMap flattens a collected message into path -> "type:value" so the
// golden comparison also catches type changes (Uint vs String, ...).
// LastCollectTime is wall-clock and is only checked for presence.
func messageMap(t *testing.T, msg *wusp.Message) map[string]string {
	t.Helper()
	out := make(map[string]string, len(msg.Fields))
	for _, f := range msg.Fields {
		if _, dup := out[f.Path]; dup {
			t.Errorf("duplicate field %s", f.Path)
		}
		v := wusp.ValueToString(f.Val)
		switch f.Path {
		case wusp.WUSPOLTPrefix + "LastCollectTime":
			v = "<time>"
		case wusp.WUSPOLTPrefix + "ControlSchemaVersion":
			v = "<ver>"
		}
		out[f.Path] = fmt.Sprintf("%d:%s", f.Val.Tag, v)
	}
	return out
}

func checkGolden(t *testing.T, name string, got map[string]string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		raw, _ := json.MarshalIndent(got, "", "  ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if got[k] != want[k] {
			t.Errorf("%s: got %q want %q", k, got[k], want[k])
		}
	}
}

// The collector output on a rich fake OLT (web API + CLI) is pinned so the
// declarative engine stays byte-for-byte compatible with the original
// hand-written collector.
func TestCollectOLTGoldenFull(t *testing.T) {
	f := richOLT(t)
	cli := newFakeCLI(t, richCLIOutputs())
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), cli.cli(), true, msg)
	checkGolden(t, "collect_full.golden.json", messageMap(t, msg))
}

func TestCollectOLTGoldenNoCLI(t *testing.T) {
	f := richOLT(t)
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), nil, true, msg)
	checkGolden(t, "collect_nocli.golden.json", messageMap(t, msg))
}

// Optional pages failing must only drop their own params.
func TestCollectOLTGoldenPartialFailure(t *testing.T) {
	f := richOLT(t)
	for _, p := range []string{"/goform/getSystemLogList", "/goform/getAclList", "/goform/getSysMisc", "/goform/getSystemTimeInfo", "/goform/getOntListBrife"} {
		f.handleFunc(p, func(map[string]any) any { return "not json" })
	}
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), nil, true, msg)
	checkGolden(t, "collect_partial.golden.json", messageMap(t, msg))
}

func TestCollectOLTGoldenSysStatusDown(t *testing.T) {
	f := richOLT(t)
	f.handleFunc("/goform/getSysStatus", func(map[string]any) any { return "oops" })
	msg := wusp.NewMessage()
	CollectOLT(context.Background(), f.client(), nil, true, msg)
	got := messageMap(t, msg)
	got[wusp.WUSPOLTPrefix+"StatusDetail"] = "<detail>"
	checkGolden(t, "collect_sysdown.golden.json", got)
}
