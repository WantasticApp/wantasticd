package platforms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestOpenWrtDNSControlUsesDnsmasqUpstreams(t *testing.T) {
	dir := t.TempDir()
	conf := `config dnsmasq
	option domainneeded '1'
	list server '/lan.example/10.0.0.53'

config dhcp 'lan'
	option interface 'lan'
`
	if err := os.WriteFile(filepath.Join(dir, "dhcp"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	var commands []string
	b := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: dir,
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return nil, nil
		},
	})
	st, _, _, err := b.openWrtDNSControl()
	if err != nil || st.Manual || !st.Supported || st.Method != "openwrt-dnsmasq" {
		t.Fatalf("initial state %+v %v", st, err)
	}
	if err := b.Set(context.Background(), wusp.WUSPDNSPrefix+"Servers", wusp.String("1.1.1.1, 2606:4700:4700::1111")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "dhcp"))
	text := string(data)
	for _, want := range []string{"list server '1.1.1.1'", "list server '2606:4700:4700::1111'", "list server '/lan.example/10.0.0.53'", "option noresolv '1'"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	st, _, _, _ = b.openWrtDNSControl()
	if !st.Manual || len(st.Servers) != 2 || st.Servers[0] != "1.1.1.1" {
		t.Fatalf("manual state %+v", st)
	}
	// Back to automatic: manual entries and noresolv go, domain forwarders stay.
	if err := b.Set(context.Background(), wusp.WUSPDNSPrefix+"Servers", wusp.String("")); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "dhcp"))
	if strings.Contains(string(data), "1.1.1.1") || strings.Contains(string(data), "noresolv") || !strings.Contains(string(data), "/lan.example/10.0.0.53") {
		t.Fatalf("automatic config wrong:\n%s", data)
	}
	if err := b.Set(context.Background(), wusp.WUSPDNSPrefix+"Servers", wusp.String("not-an-ip")); err == nil {
		t.Fatal("invalid server accepted")
	}
	reloads := 0
	for _, c := range commands {
		if strings.Contains(c, "dnsmasq") {
			reloads++
		}
		if strings.Contains(c, "network") {
			t.Fatalf("DNS change must not reload the network: %s", c)
		}
	}
	_ = reloads
}
