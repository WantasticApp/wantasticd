package agent

import (
	"fmt"
	"os"
	"testing"
)

// TestMain keeps the data model cache and other state out of the real
// Wantastic folder on the machine running the tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "wantastic-agent-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent tests: temp state dir:", err)
		os.Exit(1)
	}
	os.Setenv("WANTASTIC_STATE_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
