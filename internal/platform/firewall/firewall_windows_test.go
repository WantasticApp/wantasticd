//go:build windows

package firewall

import (
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Changes the real Windows Firewall, so it needs an elevated runner (CI).
func TestRulesRoundTrip(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs Administrator")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Remove() })
	for i := 0; i < 2; i++ { // the second pass replaces, never duplicates
		if err := AllowApp(exe); err != nil {
			t.Fatal(err)
		}
		if err := AllowOverlay([]netip.Prefix{netip.MustParsePrefix("10.255.255.45/32")}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{AppRuleID, OverlayRuleID} {
		if !exists(name) {
			t.Fatalf("rule %q missing", name)
		}
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{AppRuleID, OverlayRuleID} {
		if exists(name) {
			t.Fatalf("rule %q still present", name)
		}
	}
}
