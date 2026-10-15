//go:build darwin

package device

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestBuildDarwinLocalAccessRules(t *testing.T) {
	t.Parallel()
	rules, err := buildDarwinLocalAccessRules(
		"utun7",
		[]string{"192.168.50.42/32", "172.16.4.0/24"},
		[]string{"10.255.255.32/27"},
		func(prefix netip.Prefix) (string, error) {
			if prefix.Addr().IsPrivate() {
				return "en0", nil
			}
			return "", errors.New("not routed")
		},
	)
	if err != nil {
		t.Fatalf("buildDarwinLocalAccessRules() error = %v", err)
	}
	for _, want := range []string{
		"nat on en0 inet from 10.255.255.32/27 to 172.16.4.0/24 -> (en0)",
		"pass in quick on utun7 inet from 10.255.255.32/27 to 172.16.4.0/24 keep state",
		"nat on en0 inet from 10.255.255.32/27 to 192.168.50.42/32 -> (en0)",
		"pass in quick on utun7 inet from 10.255.255.32/27 to 192.168.50.42/32 keep state",
	} {
		if !strings.Contains(rules, want+"\n") {
			t.Errorf("rules missing %q:\n%s", want, rules)
		}
	}
}

func TestBuildDarwinLocalAccessRulesRejectsUnsafeRouting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tun    string
		route  string
		source string
		egress string
	}{
		{name: "interface injection", tun: "utun0; block all", route: "192.168.1.0/24", source: "10.255.255.32/27", egress: "en0"},
		{name: "overlapping overlay", tun: "utun0", route: "10.255.255.36/32", source: "10.255.255.32/27", egress: "en0"},
		{name: "route loops into tunnel", tun: "utun0", route: "192.168.1.0/24", source: "10.255.255.32/27", egress: "utun0"},
		{name: "egress injection", tun: "utun0", route: "192.168.1.0/24", source: "10.255.255.32/27", egress: "en0; block all"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildDarwinLocalAccessRules(
				test.tun,
				[]string{test.route},
				[]string{test.source},
				func(netip.Prefix) (string, error) { return test.egress, nil },
			)
			if err == nil {
				t.Fatal("buildDarwinLocalAccessRules() accepted unsafe routing input")
			}
		})
	}
}
