package platforms

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

func TestRunCollectorContinuesAfterErrorAndPanic(t *testing.T) {
	continued := 0
	if err := runCollector("test.error", func() error { return errors.New("unavailable") }); err == nil {
		t.Fatal("expected collector error")
	}
	continued++
	if err := runCollector("test.panic", func() error { panic("broken source") }); err == nil {
		t.Fatal("expected recovered collector panic")
	}
	continued++
	if err := runCollector("test.success", func() error { continued++; return nil }); err != nil {
		t.Fatalf("successful collector: %v", err)
	}
	if continued != 3 {
		t.Fatalf("continued=%d want 3", continued)
	}
}

func TestIsMissingToolOnlyMatchesAbsentCommands(t *testing.T) {
	notFound := &exec.Error{Name: "iptables-save", Err: exec.ErrNotFound}
	if !isMissingTool(fmt.Errorf("iptables-save : %w", notFound)) {
		t.Fatal("a wrapped not-found error must count as a missing tool")
	}
	if !isMissingTool(errors.New(`iptables-save : exec: "iptables-save": executable file not found in $PATH`)) {
		t.Fatal("the flattened message must count as a missing tool")
	}
	if isMissingTool(errors.New("iptables-save: permission denied")) || isMissingTool(nil) {
		t.Fatal("real failures must still be reported")
	}
}
