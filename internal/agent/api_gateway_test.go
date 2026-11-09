package agent

import "testing"

func TestTunnelGateway(t *testing.T) {
	cases := map[string][]string{
		"10.6.81.33":   {"10.6.81.33", "1.1.1.1"},
		"100.70.0.1":   {"1.1.1.1", " 100.70.0.1 "},
		"":             {"1.1.1.1", "8.8.8.8"},
		"192.168.10.1": {"fd00::1", "192.168.10.1"},
	}
	for want, dns := range cases {
		if got := tunnelGateway(dns); got != want {
			t.Errorf("tunnelGateway(%v) = %q, want %q", dns, got, want)
		}
	}
	if got := tunnelGateway(nil); got != "" {
		t.Errorf("empty list: %q", got)
	}
}
