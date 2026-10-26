package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func smsRows(n int) string {
	rows := make([]map[string]string, 0, n)
	for i := 1; i <= n; i++ {
		rows = append(rows, map[string]string{"storage": "SM", "index": fmt.Sprint(i), "body": strings.Repeat("x", 300)})
	}
	encoded, _ := json.Marshal(rows)
	return string(encoded)
}

func TestCapSMSInboxJSONKeepsNewestRowsWithinSchema(t *testing.T) {
	full := smsRows(120)
	if len(full) <= wusp.WUSPSMSInboxMaxLength {
		t.Fatalf("fixture too small: %d", len(full))
	}
	capped := capSMSInboxJSON(full, wusp.WUSPSMSInboxMaxLength)
	if len(capped) > wusp.WUSPSMSInboxMaxLength {
		t.Fatalf("capped length %d", len(capped))
	}
	var rows []map[string]string
	if err := json.Unmarshal([]byte(capped), &rows); err != nil || len(rows) == 0 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if rows[len(rows)-1]["index"] != "120" {
		t.Fatalf("newest row dropped: last=%v", rows[len(rows)-1])
	}

	msg := wusp.NewMessage()
	msg.Set("Device.WUSP_CellularControl.Interface.1.SMSInboxJSON", wusp.String(capped))
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("capped inbox fails the schema: %v", err)
	}

	small := smsRows(2)
	if got := capSMSInboxJSON(small, wusp.WUSPSMSInboxMaxLength); got != small {
		t.Fatal("an inbox within the limit must be returned unchanged")
	}
}

func TestCapSMSInboxJSONSMSToolObject(t *testing.T) {
	payload := `{"msg":` + smsRows(80) + `}`
	capped := capSMSInboxJSON(payload, 8192)
	var object struct {
		Msg []map[string]string `json:"msg"`
	}
	if len(capped) > 8192 || json.Unmarshal([]byte(capped), &object) != nil || len(object.Msg) == 0 || object.Msg[len(object.Msg)-1]["index"] != "80" {
		t.Fatalf("capped=%d rows=%d", len(capped), len(object.Msg))
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncateUTF8("héllo", 2); got != "h" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("é", 3000)
	msg := cellularOperateStatus(1, "Error", long, "")
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("long command output fails the schema: %v", err)
	}
}

func newCellularTestRuntime(t *testing.T) *uspRuntime {
	t.Helper()
	cache := newPersistentDataModelCache(staticCacheBackend{msg: func() *wusp.Message {
		msg := wusp.NewMessage()
		msg.Set("Device.WUSP_CellularControl.Interface.1.SMSInboxJSON", wusp.String(`[{"index":"1","body":"old"}]`))
		return msg
	}()}, t.TempDir()+"/model.cache", time.Minute)
	if _, err := cache.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &uspRuntime{dataModelCache: cache}
}

func TestSlowListSMSAnswersInTimeAndPatchesCacheLater(t *testing.T) {
	r := newCellularTestRuntime(t)
	release := make(chan struct{})
	var calls atomic.Int32
	old := cellularOperateRunner
	cellularOperateRunner = func(int, string, *wusp.Message) (string, string, string) {
		calls.Add(1)
		<-release
		return "Success", "SMS inbox refreshed", `[{"index":"2","body":"new"}]`
	}
	t.Cleanup(func() { cellularOperateRunner = old })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const cmd = "Device.WUSP_CellularControl.Interface.1.ListSMS()"
	started := time.Now()
	msg, err := r.handleCellularOperate(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("slow ListSMS must not fail the request: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("reply took %s, past the request deadline", elapsed)
	}
	if inbox, _ := msg.Get("Device.WUSP_CellularControl.Interface.1.SMSInboxJSON"); !strings.Contains(wusp.ValueToString(inbox), "old") {
		t.Fatalf("interim reply should carry the last inbox, got %v", msg.Fields)
	}

	// A controller retry joins the running listing instead of queueing.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := r.handleCellularOperate(ctx2, cmd, nil); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("modem listed %d times", n)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.cachedString("Device.WUSP_CellularControl.Interface.1.SMSInboxJSON"), "new") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("finished inbox was never patched into the cache")
}

func TestFastCellularOperateReturnsResult(t *testing.T) {
	r := newCellularTestRuntime(t)
	old := cellularOperateRunner
	cellularOperateRunner = func(_ int, operation string, _ *wusp.Message) (string, string, string) {
		return "Success", operation + " done", ""
	}
	t.Cleanup(func() { cellularOperateRunner = old })

	msg, err := r.handleCellularOperate(context.Background(), "Device.WUSP_CellularControl.Interface.1.DeleteSMS()", nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := msg.Get("Device.WUSP_CellularControl.Interface.1.LastCommandStatus"); wusp.ValueToString(status) != "Success" {
		t.Fatalf("fields=%v", msg.Fields)
	}
	if _, err := r.handleCellularOperate(context.Background(), "Device.WUSP_CellularControl.Interface.1.FormatModem()", nil); err == nil {
		t.Fatal("unsupported operation accepted")
	}
}
