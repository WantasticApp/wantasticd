package dns

import "testing"

func TestNormalizeServers(t *testing.T) {
	got, err := NormalizeServers([]string{" 1.1.1.1", "1.1.1.1", "2606:4700:4700::1111", ""})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{{"dns.google"}, {"0.0.0.0"}, {"224.0.0.1"}, {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}} {
		if _, err := NormalizeServers(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
