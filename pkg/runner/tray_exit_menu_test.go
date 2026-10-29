package runner

import (
	"testing"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

func TestDeriveExitMenuNoDaemon(t *testing.T) {
	m := deriveExitMenu(nil)
	if m.OfferEnabled || m.UseEnabled || !m.NoneChecked || len(m.Items) != 0 {
		t.Fatalf("%+v", m)
	}
	m = deriveExitMenu(&agent.StatusResponse{Running: true}) // older daemon
	if m.OfferEnabled || m.UseEnabled || m.OfferTooltip == "" {
		t.Fatalf("older daemon: %+v", m)
	}
}

func TestDeriveExitMenuActive(t *testing.T) {
	st := &agent.StatusResponse{Running: true, ExitNodeState: &device.ExitNodeStatus{
		Supported: true, ClientSupported: true,
		Using: &device.ExitUse{IP: "10.255.255.36", Hostname: "mini", State: "active", Path: "direct"},
		Candidates: []device.ExitCandidate{
			{IP: "10.255.255.36", Hostname: "mini", Path: "direct", Offers: "yes", Online: true},
			{IP: "10.255.255.50", Path: "relay", Offers: "unknown", Online: true},
			{IP: "10.255.255.60", Path: "direct", Offers: "no", Online: true},
			{IP: "10.255.255.70", Path: "relay", Offers: "yes", Online: false},
		},
	}}
	m := deriveExitMenu(st)
	if m.Header != "Exit node: via mini (direct)" || m.NoneChecked || !m.OfferEnabled || m.OfferChecked {
		t.Fatalf("%+v", m)
	}
	want := []exitMenuItem{
		{IP: "10.255.255.36", Title: "mini (10.255.255.36) · direct, offers exit", Checked: true, Enabled: true},
		{IP: "10.255.255.50", Title: "10.255.255.50 · relay", Enabled: true},
		{IP: "10.255.255.60", Title: "10.255.255.60 · direct, not an exit", Enabled: false},
		{IP: "10.255.255.70", Title: "10.255.255.70 · offline, offers exit", Enabled: false},
	}
	for i, w := range want {
		g := m.Items[i]
		if g.IP != w.IP || g.Title != w.Title || g.Checked != w.Checked || g.Enabled != w.Enabled || g.Tooltip == "" {
			t.Errorf("item %d: got %+v want %+v", i, g, w)
		}
	}
}

func TestDeriveExitMenuUnsupportedAndOffering(t *testing.T) {
	m := deriveExitMenu(&agent.StatusResponse{Running: true, ExitNodeState: &device.ExitNodeStatus{
		UnsupportedReason: "exit-node NAT is not supported on this platform", ClientSupported: true,
	}})
	if m.OfferEnabled || m.OfferTooltip == "" || !m.UseEnabled {
		t.Fatalf("unsupported: %+v", m)
	}
	m = deriveExitMenu(&agent.StatusResponse{Running: true, ExitNodeState: &device.ExitNodeStatus{
		Supported: true, Offering: true, Users: []device.ExitUser{{IP: "10.255.255.44"}}, ClientSupported: true,
	}})
	if !m.OfferChecked || m.Header != "Exit node: sharing this device" || m.OfferTooltip != "In use by 1 peer(s)" {
		t.Fatalf("offering: %+v", m)
	}
	m = deriveExitMenu(&agent.StatusResponse{Running: true, ExitNodeState: &device.ExitNodeStatus{
		Supported: true, ClientSupported: true, Using: &device.ExitUse{IP: "10.255.255.36", State: "standby", Path: "relay"},
	}})
	if m.Header != "Exit node: 10.255.255.36 (standby)" {
		t.Fatalf("standby: %q", m.Header)
	}
}
