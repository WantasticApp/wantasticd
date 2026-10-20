package device

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestTenantFirewallRulesUseConfiguredNonDefaultPrefixes(t *testing.T) {
	addresses := []netip.Prefix{
		netip.MustParsePrefix("10.255.255.43/32"),
		netip.MustParsePrefix("fd12:3456::43/128"),
	}
	allowedIPs := []string{
		"10.0.0.0/8",
		"10.23.1.4/8", // Canonical duplicate of 10.0.0.0/8.
		"fd12:3456::/48",
		"0.0.0.0/0",
		"::/0",
		"not-a-prefix",
	}

	rules := tenantFirewallRules("utun8", addresses, allowedIPs)
	if len(rules) != 2 {
		t.Fatalf("got %d firewall rules, want 2: %#v", len(rules), rules)
	}
	if rules[0].Interface != "utun8" || rules[0].Local != netip.MustParseAddr("10.255.255.43") {
		t.Fatalf("unexpected IPv4 tunnel rule: %#v", rules[0])
	}
	if got, want := rules[0].Remote, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 remote prefixes = %v, want %v", got, want)
	}
	if rules[1].Interface != "utun8" || rules[1].Local != netip.MustParseAddr("fd12:3456::43") {
		t.Fatalf("unexpected IPv6 tunnel rule: %#v", rules[1])
	}
	if got, want := rules[1].Remote, []netip.Prefix{netip.MustParsePrefix("fd12:3456::/48")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 remote prefixes = %v, want %v", got, want)
	}
}
