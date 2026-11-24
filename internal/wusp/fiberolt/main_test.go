package fiberolt

import (
	"os"
	"testing"
)

// The page/golden suites pin the legacy collector (every page on every
// cycle); budget tests opt in with Client.SetWebBudget.
func TestMain(m *testing.M) {
	ConfigureWebBudget(-1, "")
	os.Exit(m.Run())
}
