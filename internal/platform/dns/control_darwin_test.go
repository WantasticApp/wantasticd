//go:build darwin

package dns

import "testing"

func TestMacServiceForDevice(t *testing.T) {
	order := `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
`
	if got, err := macServiceForDevice(order, "en0"); err != nil || got != "Wi-Fi" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := macServiceForDevice(order, "en9"); err == nil {
		t.Fatal("unknown device resolved")
	}
}
