//go:build !linux

package platforms

import "errors"

func readNativeFirewallRuleCounters() ([]firewallRuleCounter, string, error) {
	return nil, "", errors.New("native firewall counters are Linux only")
}
