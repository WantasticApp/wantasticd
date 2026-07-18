package platforms

import (
	"errors"
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
