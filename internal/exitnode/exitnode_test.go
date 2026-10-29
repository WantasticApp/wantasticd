package exitnode

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ma(s string) netip.Addr   { return netip.MustParseAddr(s) }

func TestPlanClientRoutes(t *testing.T) {
	lan := mp("192.168.1.0/24")
	got := PlanClientRoutes(ClientPlan{
		Bypass: []netip.Addr{
			ma("203.0.113.9"),   // hub
			ma("198.51.100.7"),  // exit peer endpoint
			ma("203.0.113.9"),   // duplicate
			ma("192.168.1.20"),  // same LAN: must stay on-link
			ma("10.255.255.36"), // overlay: carried by the tunnel
			ma("127.0.0.1"),
			ma("::ffff:198.51.100.8"), // v4-mapped
			ma("2001:db8::1"),         // IPv6 endpoints are not pinned
			{},
		},
		OnLink:    lan.Contains,
		Overlay:   []netip.Prefix{mp("10.255.255.0/24")},
		BlockIPv6: true,
	})
	want := []Route{
		{Dst: mp("198.51.100.7/32"), Kind: RouteBypass},
		{Dst: mp("198.51.100.8/32"), Kind: RouteBypass},
		{Dst: mp("203.0.113.9/32"), Kind: RouteBypass},
		{Dst: mp("0.0.0.0/1"), Kind: RouteTunnel},
		{Dst: mp("128.0.0.0/1"), Kind: RouteTunnel},
		{Dst: mp("::/1"), Kind: RouteReject},
		{Dst: mp("8000::/1"), Kind: RouteReject},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan\n got %v\nwant %v", got, want)
	}
	// Never a 0.0.0.0/0: the original default route stays untouched.
	for _, r := range got {
		if r.Dst.Bits() == 0 {
			t.Fatalf("plan replaces the default route: %v", r)
		}
	}
}

func TestPlanClientRoutesCapsBypass(t *testing.T) {
	var many []netip.Addr
	for i := 1; i <= 10; i++ {
		many = append(many, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	got := PlanClientRoutes(ClientPlan{Bypass: many, MaxBypass: 3})
	if len(got) != 5 || got[2].Dst != mp("198.51.100.3/32") || got[3].Kind != RouteTunnel {
		t.Fatalf("cap not applied: %v", got)
	}
}

func TestDiffRoutesIdempotentAndComeback(t *testing.T) {
	plan := PlanClientRoutes(ClientPlan{Bypass: []netip.Addr{ma("203.0.113.9")}, BlockIPv6: true})
	add, del := DiffRoutes(nil, plan)
	if !reflect.DeepEqual(add, plan) || len(del) != 0 {
		t.Fatalf("first apply: add=%v del=%v", add, del)
	}
	add, del = DiffRoutes(plan, plan)
	if len(add) != 0 || len(del) != 0 {
		t.Fatalf("re-apply not idempotent: add=%v del=%v", add, del)
	}
	// comeback: everything removed, split default before the bypass.
	add, del = DiffRoutes(plan, nil)
	if len(add) != 0 || len(del) != len(plan) {
		t.Fatalf("comeback: add=%v del=%v", add, del)
	}
	if del[len(del)-1].Kind != RouteBypass || del[0].Kind == RouteBypass {
		t.Fatalf("comeback order wrong: %v", del)
	}
	add, del = DiffRoutes(nil, nil)
	if len(add)+len(del) != 0 {
		t.Fatal("second comeback did something")
	}
}

func TestDiffRoutesEndpointRebind(t *testing.T) {
	old := PlanClientRoutes(ClientPlan{Bypass: []netip.Addr{ma("203.0.113.9"), ma("198.51.100.7")}})
	cur := PlanClientRoutes(ClientPlan{Bypass: []netip.Addr{ma("203.0.113.9"), ma("198.51.100.99")}})
	add, del := DiffRoutes(old, cur)
	if len(add) != 1 || add[0].Dst != mp("198.51.100.99/32") || len(del) != 1 || del[0].Dst != mp("198.51.100.7/32") {
		t.Fatalf("rebind: add=%v del=%v", add, del)
	}
}

func TestRouteCommands(t *testing.T) {
	gw := Gateway{Interface: "en0", Addr: ma("192.168.1.1"), IfIndex: 7}
	tunnel := Route{Dst: mp("0.0.0.0/1"), Kind: RouteTunnel}
	bypass := Route{Dst: mp("203.0.113.9/32"), Kind: RouteBypass}
	reject := Route{Dst: mp("8000::/1"), Kind: RouteReject}
	cases := []struct {
		goos string
		r    Route
		add  bool
		want string
	}{
		{"darwin", tunnel, true, "/sbin/route -n add -inet 0.0.0.0/1 -interface utun5"},
		{"darwin", tunnel, false, "/sbin/route -n delete -inet 0.0.0.0/1 -interface utun5"},
		{"darwin", bypass, true, "/sbin/route -n add -inet 203.0.113.9/32 192.168.1.1"},
		{"darwin", bypass, false, "/sbin/route -n delete -inet 203.0.113.9/32 192.168.1.1"},
		{"darwin", reject, true, "/sbin/route -n add -inet6 8000::/1 ::1 -reject"},
		{"darwin", reject, false, "/sbin/route -n delete -inet6 8000::/1"},
		{"linux", tunnel, true, "ip route replace 0.0.0.0/1 dev utun5"},
		{"linux", tunnel, false, "ip route del 0.0.0.0/1 dev utun5"},
		{"linux", bypass, true, "ip route replace 203.0.113.9/32 via 192.168.1.1 dev en0"},
		{"linux", bypass, false, "ip route del 203.0.113.9/32 via 192.168.1.1 dev en0"},
		{"linux", reject, true, "ip -6 route replace unreachable 8000::/1"},
		{"linux", reject, false, "ip -6 route del unreachable 8000::/1"},
		{"windows", tunnel, true, "netsh interface ipv4 add route prefix=0.0.0.0/1 interface=utun5 metric=5 store=active"},
		{"windows", tunnel, false, "netsh interface ipv4 delete route prefix=0.0.0.0/1 interface=utun5"},
		{"windows", bypass, true, "netsh interface ipv4 add route prefix=203.0.113.9/32 interface=7 nexthop=192.168.1.1 store=active"},
		{"windows", bypass, false, "netsh interface ipv4 delete route prefix=203.0.113.9/32 interface=7 nexthop=192.168.1.1"},
	}
	for _, c := range cases {
		var cmd Cmd
		var err error
		if c.add {
			cmd, err = RouteAddCmd(c.goos, c.r, "utun5", gw)
		} else {
			cmd, err = RouteDelCmd(c.goos, c.r, "utun5", gw)
		}
		if err != nil || cmd.String() != c.want {
			t.Errorf("%s %v add=%v: got %q err=%v, want %q", c.goos, c.r, c.add, cmd.String(), err, c.want)
		}
	}
	if _, err := RouteAddCmd("windows", reject, "utun5", gw); err == nil {
		t.Error("windows reject route should be unsupported")
	}
	// PPP-style gateway without an address goes via the interface.
	cmd, _ := RouteAddCmd("darwin", bypass, "utun5", Gateway{Interface: "ppp0"})
	if cmd.String() != "/sbin/route -n add -inet 203.0.113.9/32 -interface ppp0" {
		t.Errorf("interface gateway: %q", cmd.String())
	}
	cmd, _ = RouteAddCmd("linux", bypass, "wt0", Gateway{Interface: "pppoe-wan"})
	if cmd.String() != "ip route replace 203.0.113.9/32 dev pppoe-wan" {
		t.Errorf("linux interface gateway: %q", cmd.String())
	}
	if _, err := RouteAddCmd("linux", bypass, "wt0", Gateway{}); err == nil {
		t.Error("bypass without gateway must fail")
	}
}

func TestGatewayParsers(t *testing.T) {
	gw, err := ParseDarwinRouteGet("   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n")
	if err != nil || gw.Interface != "en0" || gw.Addr != ma("192.168.1.1") {
		t.Fatalf("darwin: %+v %v", gw, err)
	}
	proc := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wt0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" + // tunnel: ignored
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	gw, err = ParseLinuxProcRoute(proc, "wt0")
	if err != nil || gw.Interface != "eth0" || gw.Addr != ma("192.168.0.1") {
		t.Fatalf("linux: %+v %v", gw, err)
	}
	if _, err := ParseLinuxProcRoute("Iface\n", ""); err == nil {
		t.Fatal("linux: want error without default")
	}
	gw, err = ParseWindowsGateway("12 192.168.1.1 Wi-Fi 2\r\n")
	if err != nil || gw.IfIndex != 12 || gw.Addr != ma("192.168.1.1") || gw.Interface != "Wi-Fi 2" {
		t.Fatalf("windows: %+v %v", gw, err)
	}
}

var exitPlan = NATPlan{Mode: ModeExit, Tun: "utun5", Uplink: "en0", Sources: []netip.Prefix{mp("10.255.255.0/24")}}

func TestNATBuilders(t *testing.T) {
	if got := PFRules(exitPlan); got != "nat on en0 inet from 10.255.255.0/24 to any -> (en0)\n" {
		t.Errorf("pf rules: %q", got)
	}
	c := PFLoadCmd(exitPlan)
	if c.String() != "/sbin/pfctl -a com.apple/wantasticd-exit -f -" || c.Stdin != PFRules(exitPlan) {
		t.Errorf("pf load: %q", c.String())
	}
	if PFFlushCmd().String() != "/sbin/pfctl -a com.apple/wantasticd-exit -F all" ||
		PFReleaseCmd("42").String() != "/sbin/pfctl -X 42" || PFEnableCmd().String() != "/sbin/pfctl -E" {
		t.Error("pf commands")
	}
	if tok := ParsePFToken("No ALTQ support in kernel\npf enabled\nToken : 13871204771258097411\n"); tok != "13871204771258097411" {
		t.Errorf("token %q", tok)
	}

	lp := exitPlan
	lp.Tun, lp.Uplink = "wantastic0", "eth0"
	var got []string
	for _, r := range IPTablesRules(lp) {
		got = append(got, r.CheckCmd("iptables").String(), r.AddCmd("iptables").String(), r.DelCmd("iptables").String())
	}
	want := []string{
		"iptables -t nat -C POSTROUTING -s 10.255.255.0/24 -o eth0 -j MASQUERADE",
		"iptables -t nat -A POSTROUTING -s 10.255.255.0/24 -o eth0 -j MASQUERADE",
		"iptables -t nat -D POSTROUTING -s 10.255.255.0/24 -o eth0 -j MASQUERADE",
		"iptables -t filter -C FORWARD -i wantastic0 -o eth0 -s 10.255.255.0/24 -j ACCEPT",
		"iptables -t filter -I FORWARD 1 -i wantastic0 -o eth0 -s 10.255.255.0/24 -j ACCEPT",
		"iptables -t filter -D FORWARD -i wantastic0 -o eth0 -s 10.255.255.0/24 -j ACCEPT",
		"iptables -t filter -C FORWARD -i eth0 -o wantastic0 -d 10.255.255.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -t filter -I FORWARD 1 -i eth0 -o wantastic0 -d 10.255.255.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -t filter -D FORWARD -i eth0 -o wantastic0 -d 10.255.255.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("iptables\n got %q\nwant %q", got, want)
	}
	client := NATPlan{Mode: ModeClient, Tun: "wantastic0", Own: ma("10.255.255.44")}
	if r := IPTablesRules(client); len(r) != 1 || r[0].AddCmd("iptables").String() != "iptables -t nat -A POSTROUTING -o wantastic0 ! -s 10.255.255.44/32 -j MASQUERADE" {
		t.Errorf("client iptables: %v", r)
	}

	fw4 := FW4Script(lp)
	wantFW4 := `insert rule inet fw4 forward iifname "wantastic0" oifname "eth0" ip saddr 10.255.255.0/24 counter accept comment "wantasticd-exit"
insert rule inet fw4 forward iifname "eth0" oifname "wantastic0" ip daddr 10.255.255.0/24 ct state established,related counter accept comment "wantasticd-exit"
insert rule inet fw4 srcnat oifname "eth0" ip saddr 10.255.255.0/24 counter masquerade comment "wantasticd-exit"
`
	if fw4 != wantFW4 {
		t.Errorf("fw4 script:\n%s", fw4)
	}
	if c := NftScriptCmd(fw4); c.String() != "nft -f -" || c.Stdin != fw4 {
		t.Error("nft script cmd")
	}
	if !strings.Contains(FW4Script(client), `srcnat oifname "wantastic0" ip saddr != 10.255.255.44 counter masquerade comment "wantasticd-client"`) {
		t.Errorf("fw4 client: %s", FW4Script(client))
	}
	tbl := NftTableScript(lp)
	for _, s := range []string{"table ip wantasticd_exit {\n}\ndelete table ip wantasticd_exit\n", "type nat hook postrouting priority 100", `oifname "eth0" ip saddr 10.255.255.0/24 masquerade`} {
		if !strings.Contains(tbl, s) {
			t.Errorf("nft table script lacks %q:\n%s", s, tbl)
		}
	}
	if NftTableDeleteCmd(lp).String() != "nft delete table ip wantasticd_exit" {
		t.Error("nft delete")
	}
}

func TestParseNftHandles(t *testing.T) {
	out := `table inet fw4 { # handle 3
	chain forward { # handle 2
		type filter hook forward priority filter; policy drop;
		iifname "wantastic0" oifname "eth0" ip saddr 10.255.255.0/24 counter packets 0 bytes 0 accept comment "wantasticd-exit" # handle 412
		ct state vmap { established : accept } # handle 5
	}
	chain srcnat { # handle 9
		oifname "eth0" ip saddr 10.255.255.0/24 counter packets 0 bytes 0 masquerade comment "wantasticd-exit" # handle 413
		oifname "wantastic0" masquerade comment "wantasticd-client" # handle 414
	}
}`
	got := ParseNftHandles(out, "wantasticd-exit")
	want := []NftHandle{{"forward", 412}, {"srcnat", 413}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("handles %v", got)
	}
	if FW4DeleteCmd("forward", 412).String() != "nft delete rule inet fw4 forward handle 412" {
		t.Error("delete cmd")
	}
}

func TestPlanValidation(t *testing.T) {
	bad := []NATPlan{
		{Mode: ModeExit, Tun: "utun5; rm", Uplink: "en0", Sources: exitPlan.Sources},
		{Mode: ModeExit, Tun: "utun5", Uplink: "", Sources: exitPlan.Sources},
		{Mode: ModeExit, Tun: "utun5", Uplink: "en0"},
		{Mode: ModeExit, Tun: "utun5", Uplink: "en0", Sources: []netip.Prefix{mp("0.0.0.0/0")}},
		{Mode: ModeClient, Tun: "wt0"},
		{Mode: "x", Tun: "wt0"},
	}
	for _, p := range bad {
		if err := p.validate(); err == nil {
			t.Errorf("plan %+v accepted", p)
		}
	}
}

// fakeHost records commands; fail maps a command prefix to an error.
type fakeHost struct {
	cmds  []string
	out   map[string]string
	fail  map[string]bool
	files map[string]string
	bins  map[string]bool
}

func (f *fakeHost) host(goos string) Host {
	return Host{
		OS: goos,
		Run: func(c Cmd) ([]byte, error) {
			s := c.String()
			f.cmds = append(f.cmds, s)
			for p := range f.fail {
				if strings.HasPrefix(s, p) {
					return nil, errors.New("exit status 1")
				}
			}
			return []byte(f.out[s]), nil
		},
		ReadFile: func(p string) ([]byte, error) {
			v, ok := f.files[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(v), nil
		},
		WriteFile: func(p string, b []byte) error { f.files[p] = string(b); f.cmds = append(f.cmds, "write "+p+"="+string(b)); return nil },
		Exists:    func(p string) bool { return f.bins[p] },
	}
}

func TestEnableDisableNATDarwin(t *testing.T) {
	f := &fakeHost{out: map[string]string{
		"/usr/sbin/sysctl -n net.inet.ip.forwarding": "0\n",
		"/sbin/pfctl -E": "pf enabled\nToken : 99\n",
	}}
	h := f.host("darwin")
	b, err := DetectBackend(h)
	if err != nil || b != BackendPF {
		t.Fatalf("backend %v %v", b, err)
	}
	p := exitPlan
	p.Backend = b
	st, err := EnableNAT(h, p)
	if err != nil {
		t.Fatal(err)
	}
	if st.PFToken != "99" || st.PrevForward != "0" {
		t.Fatalf("state %+v", st)
	}
	want := []string{
		"/usr/sbin/sysctl -n net.inet.ip.forwarding",
		"/usr/sbin/sysctl -w net.inet.ip.forwarding=1",
		"/sbin/pfctl -a com.apple/wantasticd-exit -f -",
		"/sbin/pfctl -E",
	}
	if !reflect.DeepEqual(f.cmds, want) {
		t.Fatalf("enable cmds %q", f.cmds)
	}
	f.cmds = nil
	if err := DisableNAT(h, st); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"/sbin/pfctl -a com.apple/wantasticd-exit -F all",
		"/sbin/pfctl -X 99",
		"/usr/sbin/sysctl -w net.inet.ip.forwarding=0",
	}
	if !reflect.DeepEqual(f.cmds, want) {
		t.Fatalf("disable cmds %q", f.cmds)
	}
	// Forwarding that was already on stays on.
	f.out["/usr/sbin/sysctl -n net.inet.ip.forwarding"] = "1"
	f.cmds = nil
	st, _ = EnableNAT(h, p)
	_ = DisableNAT(h, st)
	for _, c := range f.cmds {
		if strings.Contains(c, "forwarding=") {
			t.Fatalf("touched pre-enabled forwarding: %q", f.cmds)
		}
	}
	// EnsureNAT reloads an emptied anchor.
	f.cmds = nil
	repaired, err := EnsureNAT(h, &st)
	if err != nil || !repaired || f.cmds[1] != "/sbin/pfctl -a com.apple/wantasticd-exit -f -" {
		t.Fatalf("ensure: %v %v %q", repaired, err, f.cmds)
	}
}

func TestEnableNATLinuxIPTablesAndRollback(t *testing.T) {
	f := &fakeHost{
		files: map[string]string{linuxIPForward: "0\n"},
		bins:  map[string]bool{"/usr/sbin/iptables": true},
		fail:  map[string]bool{"/usr/sbin/iptables -t nat -C": true, "/usr/sbin/iptables -t filter -C": true},
	}
	h := f.host("linux")
	b, err := DetectBackend(h)
	if err != nil || b != BackendIPTables {
		t.Fatalf("backend %v %v", b, err)
	}
	p := NATPlan{Backend: b, Mode: ModeExit, Tun: "wantastic0", Uplink: "eth0", Sources: exitPlan.Sources}
	st, err := EnableNAT(h, p)
	if err != nil {
		t.Fatal(err)
	}
	if f.files[linuxIPForward] != "1" || st.PrevForward != "0" {
		t.Fatalf("forwarding not enabled: %v", f.files)
	}
	adds := 0
	for _, c := range f.cmds {
		if strings.Contains(c, " -A ") || strings.Contains(c, " -I ") {
			adds++
		}
		if strings.Contains(c, "sh -c") {
			t.Fatal("shell used")
		}
	}
	if adds != 3 {
		t.Fatalf("want 3 rule adds, got %q", f.cmds)
	}
	// Add failure rolls back and restores forwarding.
	f.files[linuxIPForward] = "0"
	f.fail["/usr/sbin/iptables -t filter -I"] = true
	if _, err := EnableNAT(h, p); err == nil {
		t.Fatal("want error")
	}
	if f.files[linuxIPForward] != "0" {
		t.Fatal("forwarding left on after failed enable")
	}
}

func TestDetectBackendLinuxPrefersFW4(t *testing.T) {
	f := &fakeHost{bins: map[string]bool{"/usr/sbin/nft": true, "/usr/sbin/iptables": true}}
	if b, _ := DetectBackend(f.host("linux")); b != BackendFW4 {
		t.Fatalf("got %v", b)
	}
	f = &fakeHost{bins: map[string]bool{"/usr/sbin/nft": true}, fail: map[string]bool{"nft list table inet fw4": true}}
	if b, _ := DetectBackend(f.host("linux")); b != BackendNft {
		t.Fatalf("got %v", b)
	}
	f = &fakeHost{}
	if _, err := DetectBackend(f.host("linux")); err == nil {
		t.Fatal("want error without iptables/nft")
	}
	if _, err := DetectBackend(f.host("windows")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("windows: %v", err)
	}
}

func TestFW4DisableDeletesTaggedRules(t *testing.T) {
	f := &fakeHost{out: map[string]string{"nft -a list table inet fw4": "table inet fw4 {\n chain forward {\n  x comment \"wantasticd-exit\" # handle 7\n }\n}\n"}}
	h := f.host("linux")
	p := NATPlan{Backend: BackendFW4, Mode: ModeExit, Tun: "wantastic0", Uplink: "eth0", Sources: exitPlan.Sources}
	if err := DisableNAT(h, NATState{Plan: p}); err != nil {
		t.Fatal(err)
	}
	if f.cmds[len(f.cmds)-1] != "nft delete rule inet fw4 forward handle 7" {
		t.Fatalf("cmds %q", f.cmds)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "exitnode.json")
	if _, exists, err := LoadState(path); exists || err != nil {
		t.Fatalf("missing file: %v %v", exists, err)
	}
	in := State{Offer: true, Use: "10.255.255.36", RouteTun: "utun5",
		RouteGW: Gateway{Interface: "en0", Addr: ma("192.168.1.1")},
		Routes:  []Route{{Dst: mp("203.0.113.9/32"), Kind: RouteBypass}, {Dst: mp("0.0.0.0/1"), Kind: RouteTunnel}},
		NAT:     &NATState{Plan: exitPlan, PFToken: "9", PrevForward: "0"}}
	if err := SaveState(path, in); err != nil {
		t.Fatal(err)
	}
	out, exists, err := LoadState(path)
	if err != nil || !exists || !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip\n in %+v\nout %+v (%v)", in, out, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", fi.Mode().Perm())
	}
}

func TestNextPhase(t *testing.T) {
	now := time.Now()
	yes, no := true, false
	live := PathHealth{Listed: true, Direct: true, LastHandshake: now.Add(-30 * time.Second), Offered: &yes, Granted: true}
	cases := []struct {
		name string
		mod  func(*PathHealth)
		want ClientPhase
	}{
		{"active", func(*PathHealth) {}, PhaseActive},
		{"offline", func(h *PathHealth) { h.Listed = false }, PhaseStandby},
		{"refused", func(h *PathHealth) { h.Offered = &no }, PhaseStandby},
		{"relay only", func(h *PathHealth) { h.Direct = false }, PhaseStandby},
		{"stale", func(h *PathHealth) { h.LastHandshake = now.Add(-HandshakeStaleAfter - time.Second) }, PhaseStandby},
		{"unconfirmed", func(h *PathHealth) { h.Granted = false; h.Offered = nil }, PhasePending},
	}
	for _, c := range cases {
		h := live
		c.mod(&h)
		if got, reason := NextPhase(h, now); got != c.want || (got != PhaseActive && reason == "") {
			t.Errorf("%s: got %v %q", c.name, got, reason)
		}
	}
}

func TestIsInternet(t *testing.T) {
	for s, want := range map[string]bool{
		"1.1.1.1": true, "8.8.8.8": true, "2606:4700::1111": true,
		"10.255.255.36": false, "192.168.1.1": false, "172.16.0.1": false, "100.64.1.1": false,
		"127.0.0.1": false, "169.254.1.1": false, "224.0.0.251": false, "255.255.255.255": false,
		"fd00::1": false, "fe80::1": false, "ff02::1": false, "0.0.0.0": false,
	} {
		if got := IsInternet(ma(s)); got != want {
			t.Errorf("IsInternet(%s)=%v", s, got)
		}
	}
}
