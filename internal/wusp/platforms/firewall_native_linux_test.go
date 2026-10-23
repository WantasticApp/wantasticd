//go:build linux

package platforms

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"sort"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestDecodeNFTRule(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.String(unix.NFTA_RULE_TABLE, "fw4")
	ae.String(unix.NFTA_RULE_CHAIN, "input_wan")
	ae.Uint64(unix.NFTA_RULE_HANDLE, 42)
	ae.Nested(unix.NFTA_RULE_EXPRESSIONS, func(list *netlink.AttributeEncoder) error {
		list.Nested(unix.NFTA_LIST_ELEM, func(expr *netlink.AttributeEncoder) error {
			expr.String(unix.NFTA_EXPR_NAME, "counter")
			expr.Nested(unix.NFTA_EXPR_DATA, func(c *netlink.AttributeEncoder) error {
				c.ByteOrder = binary.BigEndian
				c.Uint64(unix.NFTA_COUNTER_BYTES, 9000)
				c.Uint64(unix.NFTA_COUNTER_PACKETS, 12)
				return nil
			})
			return nil
		})
		list.Nested(unix.NFTA_LIST_ELEM, func(expr *netlink.AttributeEncoder) error {
			expr.String(unix.NFTA_EXPR_NAME, "immediate")
			expr.Nested(unix.NFTA_EXPR_DATA, func(imm *netlink.AttributeEncoder) error {
				imm.ByteOrder = binary.BigEndian
				imm.Uint32(unix.NFTA_IMMEDIATE_DREG, 0)
				imm.Nested(unix.NFTA_IMMEDIATE_DATA, func(data *netlink.AttributeEncoder) error {
					data.Nested(unix.NFTA_DATA_VERDICT, func(v *netlink.AttributeEncoder) error {
						v.ByteOrder = binary.BigEndian
						v.Uint32(unix.NFTA_VERDICT_CODE, uint32(nfAccept))
						return nil
					})
					return nil
				})
				return nil
			})
			return nil
		})
		return nil
	})
	comment := "!fw4: Allow-Ping"
	ae.Bytes(unix.NFTA_RULE_USERDATA, append([]byte{0, byte(len(comment) + 1)}, append([]byte(comment), 0)...))
	attrs, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := decodeNFTRule(append([]byte{1, 0, 0, 0}, attrs...))
	if !ok {
		t.Fatal("rule not decoded")
	}
	if rule.Table != "inet fw4" || rule.Chain != "input_wan" || rule.Name != comment || rule.Target != "ACCEPT" || rule.Packets != 12 || rule.Bytes != 9000 {
		t.Fatalf("rule=%+v", rule)
	}
	if rule.Key != firewallRuleKey("inet fw4", "input_wan", comment, "42") {
		t.Fatalf("key %s differs from the nft -j parser's", rule.Key)
	}
}

// TestNativeFirewallCountersMatchCLI installs real rules and checks the
// native readers against iptables-save -c and nft -j. It needs root and the
// CLIs, so it runs only when WANTASTIC_FIREWALL_IT=1 (in a privileged
// container).
func TestNativeFirewallCountersMatchCLI(t *testing.T) {
	if os.Getenv("WANTASTIC_FIREWALL_IT") != "1" {
		t.Skip("set WANTASTIC_FIREWALL_IT=1 in a privileged container")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("iptables-legacy", "-N", "zone_wan")
	run("iptables-legacy", "-A", "INPUT", "-p", "icmp", "-m", "comment", "--comment", "!fw3: Allow-Ping", "-j", "ACCEPT")
	run("iptables-legacy", "-A", "INPUT", "-j", "zone_wan")
	run("iptables-legacy", "-A", "zone_wan", "-p", "tcp", "--dport", "22", "-j", "DROP")
	run("iptables-legacy", "-t", "nat", "-A", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE")
	run("ping", "-c", "2", "-W", "1", "127.0.0.1")

	native, err := readIPTablesCounters()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("iptables-legacy-save", "-c").Output()
	if err != nil {
		t.Fatal(err)
	}
	compareFirewallRules(t, native, parseIPTablesSaveCounters(string(out)), false)

	run("nft", "add", "table", "inet", "fw4")
	run("nft", "add", "chain", "inet", "fw4", "input", "{ type filter hook input priority 0; }")
	run("nft", "add", "rule", "inet", "fw4", "input", "ip", "protocol", "icmp", "counter", "accept", "comment", "\"!fw4: Allow-Ping\"")
	run("nft", "add", "chain", "inet", "fw4", "input_wan")
	run("nft", "add", "rule", "inet", "fw4", "input", "counter", "jump", "input_wan")
	run("nft", "add", "rule", "inet", "fw4", "input_wan", "tcp", "dport", "22", "counter", "reject")
	run("ping", "-c", "2", "-W", "1", "127.0.0.1")
	nativeNFT, err := readNFTCounters()
	if err != nil {
		t.Fatal(err)
	}
	jsonOut, err := exec.Command("nft", "-j", "list", "ruleset").Output()
	if err != nil {
		t.Fatal(err)
	}
	compareFirewallRules(t, nativeNFT, parseNFTJSONCounters(jsonOut), true)
	_ = context.Background
}

func compareFirewallRules(t *testing.T, native, cli []firewallRuleCounter, sameKeys bool) {
	t.Helper()
	norm := func(rules []firewallRuleCounter) []firewallRuleCounter {
		out := append([]firewallRuleCounter(nil), rules...)
		for i := range out {
			if !sameKeys {
				out[i].Key = ""
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Table+out[i].Chain != out[j].Table+out[j].Chain {
				return out[i].Table+out[i].Chain < out[j].Table+out[j].Chain
			}
			return out[i].Name < out[j].Name
		})
		return out
	}
	a, b := norm(native), norm(cli)
	if len(a) != len(b) {
		t.Fatalf("native %d rules, CLI %d\nnative=%+v\ncli=%+v", len(a), len(b), a, b)
	}
	for i := range a {
		// Counters can move between the two reads; identity must not.
		a[i].Packets, a[i].Bytes, b[i].Packets, b[i].Bytes = 0, 0, 0, 0
		if a[i] != b[i] {
			t.Errorf("rule %d\nnative=%+v\ncli   =%+v", i, a[i], b[i])
		}
	}
	for _, rule := range native {
		if rule.Name == "Allow-Ping" && rule.Packets == 0 {
			t.Errorf("Allow-Ping counter did not move: %+v", rule)
		}
	}
}
