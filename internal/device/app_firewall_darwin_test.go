//go:build darwin
// +build darwin

package device

import "testing"

func TestAppFirewallEnabled(t *testing.T) {
	cases := map[string]bool{
		"Firewall is enabled. (State = 1)\n":  true,
		"Firewall is enabled. (State = 2)\n":  true,
		"Firewall is disabled. (State = 0)\n": false,
		"":                                    false,
	}
	for output, want := range cases {
		if got := appFirewallEnabled(output); got != want {
			t.Errorf("appFirewallEnabled(%q) = %v, want %v", output, got, want)
		}
	}
}
