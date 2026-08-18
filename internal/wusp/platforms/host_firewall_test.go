package platforms

import (
	"context"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestCollectHostFirewallStatic(t *testing.T) {
	raw := `*nat
-A POSTROUTING -o rmnet_data1 -j MASQUERADE --random
COMMIT
*filter
-A INPUT -i rmnet_data1 -p tcp --dport 443 -j DROP
-A FORWARD -i rmnet_data1 -o bridge0 -j ACCEPT
COMMIT
`
	runner := func(context.Context, string, ...string) ([]byte, error) { return []byte(raw), nil }
	msg := wusp.NewMessage()
	collectHostFirewallStatic(context.Background(), runner, msg)
	assertUintField(t, msg, "Device.Firewall.ChainNumberOfEntries", 3)
	assertStringField(t, msg, "Device.Firewall.Chain.2.Name", "filter/INPUT")
	assertStringField(t, msg, "Device.Firewall.Chain.2.Rule.1.Target", "Drop")
	assertIntField(t, msg, "Device.Firewall.Chain.2.Rule.1.Protocol", 6)
	assertIntField(t, msg, "Device.Firewall.Chain.2.Rule.1.DestPort", 443)
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatal(err)
	}
}

func TestHostFirewallAddEditDeleteCommands(t *testing.T) {
	fixture := "*filter\n-A INPUT -p tcp --dport 80 -j DROP\nCOMMIT\n"
	var calls []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if name == "iptables-save" {
			return []byte(fixture), nil
		}
		return nil, nil
	}
	b := newHostBackend(KindLinux, Options{CommandRunner: runner})
	initial := wusp.NewMessage()
	initial.Set("Target", wusp.String("Accept"))
	initial.Set("Protocol", wusp.Int(17))
	paths, err := b.Add(context.Background(), "Device.Firewall.Chain.1.Rule.", initial)
	if err != nil || len(paths) != 1 {
		t.Fatalf("Add paths=%v err=%v", paths, err)
	}
	if err := b.Set(context.Background(), "Device.Firewall.Chain.1.Rule.1.Target", wusp.String("Accept")); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), "Device.Firewall.Chain.1.Rule.1."); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		"iptables -t filter -A INPUT -j ACCEPT -p udp",
		"iptables -t filter -R INPUT 1 -p tcp --dport 80 -j ACCEPT",
		"iptables -t filter -D INPUT 1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
}

func TestHostFirewallEditClearsOptionalMatches(t *testing.T) {
	fixture := "*filter\n-A INPUT -s 10.0.0.0/8 -p tcp --dport 443 -j DROP\nCOMMIT\n"
	var calls []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if name == "iptables-save" {
			return []byte(fixture), nil
		}
		return nil, nil
	}
	b := newHostBackend(KindLinux, Options{CommandRunner: runner})
	if err := b.Set(context.Background(), "Device.Firewall.Chain.1.Rule.1.DestPort", wusp.String("")); err != nil {
		t.Fatal(err)
	}
	if err := b.Set(context.Background(), "Device.Firewall.Chain.1.Rule.1.SourceIP", wusp.String("Any")); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		"iptables -t filter -R INPUT 1 -s 10.0.0.0/8 -p tcp -j DROP",
		"iptables -t filter -R INPUT 1 -p tcp --dport 443 -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "--dport 0") || strings.Contains(joined, "-s Any") {
		t.Fatalf("optional match was not cleared cleanly:\n%s", joined)
	}
}

func TestHostFirewallDeleteUsesRequestedRuleIndex(t *testing.T) {
	fixture := "*filter\n-A INPUT -p tcp --dport 443 -j DROP\n-A INPUT -p tcp --dport 80 -j DROP\nCOMMIT\n"
	var calls []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if name == "iptables-save" {
			return []byte(fixture), nil
		}
		return nil, nil
	}
	b := newHostBackend(KindLinux, Options{CommandRunner: runner})
	if err := b.Delete(context.Background(), "Device.Firewall.Chain.1.Rule.2."); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "iptables -t filter -D INPUT 2") {
		t.Fatalf("delete did not use requested index:\n%s", joined)
	}
}

func TestSetIPInterfaceParamUsesLiveIndex(t *testing.T) {
	var gotName string
	var gotMTU int
	b := newHostBackend(KindLinux, Options{})
	b.linkSetMTU = func(name string, mtu int) error {
		gotName, gotMTU = name, mtu
		return nil
	}
	if err := b.Set(context.Background(), "Device.IP.Interface.1.MaxMTUSize", wusp.Uint(1400)); err != nil {
		t.Fatal(err)
	}
	if gotName == "" || gotMTU != 1400 {
		t.Fatalf("native link update=(%q,%d), want a live interface and MTU 1400", gotName, gotMTU)
	}
}

func TestParseIPTablesSavePortRangeAndIPv6(t *testing.T) {
	chains := parseIPTablesSave("*filter\n-A INPUT -p udp -s 2001:db8::/64 --sport 500:510 --dport 600-620 -j ACCEPT\nCOMMIT\n")
	if len(chains) != 1 || len(chains[0].rules) != 1 {
		t.Fatalf("chains=%+v", chains)
	}
	rule := chains[0].rules[0]
	if rule.sourcePort != 500 || rule.sourcePortMax != 510 || rule.destPort != 600 || rule.destPortMax != 620 {
		t.Fatalf("ports=%+v", rule)
	}
	if iptablesIPVersion(rule) != 6 || mapFirewallProtocol(rule.protocol) != 17 {
		t.Fatalf("protocol/family=%+v", rule)
	}
}

func TestInterfaceTypeUsesTR181Enums(t *testing.T) {
	cases := map[string]string{"bridge0": "Normal", "eth0": "Normal", "rmnet_data1": "Normal", "tun0": "Tunnel", "lo": "Loopback"}
	for name, want := range cases {
		if got := ifaceType(name); got != want {
			t.Fatalf("ifaceType(%q)=%q want %q", name, got, want)
		}
	}
}
