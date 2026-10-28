package device

import "testing"

func TestEffectiveTunnelMTUFitsTheLink(t *testing.T) {
	cases := []struct {
		name             string
		configured, link int
		ipv6             bool
		want             int
	}{
		{"ethernet keeps the default", 1420, 1500, false, 1420},
		{"PPPoE has room for the default", 1420, 1492, false, 1420},
		{"LTE", 1420, 1400, false, 1340},
		{"IPv6 outer path", 1420, 1500, true, 1420},
		{"IPv6 over PPPoE", 1420, 1492, true, 1412},
		{"explicit lower setting stands", 1300, 1500, false, 1300},
		{"never below 1280", 1420, 1300, false, 1280},
		{"unknown link", 1420, 0, false, 1420},
		{"unset configured", 0, 1500, false, 1420},
	}
	for _, c := range cases {
		if got := effectiveTunnelMTU(c.configured, c.link, c.ipv6); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}
