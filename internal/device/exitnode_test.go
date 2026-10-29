package device

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"wantastic-agent/internal/device/wireguard-go/tun"
)

func ipv4Packet(src, dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

func TestExitGuardRequiresOptIn(t *testing.T) {
	g := newExitGuard()
	g.setTenant([]netip.Prefix{netip.MustParsePrefix("10.255.255.36/32")}, []string{"10.255.255.0/24", "0.0.0.0/0"})
	cases := []struct {
		dst  string
		want bool
	}{
		{"10.255.255.36", true}, // device <-> peer: never filtered
		{"10.255.255.50", true}, // other overlay peers
		{"192.168.1.10", true},  // LAN (local access)
		{"224.0.0.251", true},
		{"1.1.1.1", false}, // internet: refused without opt-in
	}
	for _, c := range cases {
		if got := g.forwardable(ipv4Packet("10.255.255.44", c.dst), 100); got != c.want {
			t.Errorf("dst %s: got %v want %v", c.dst, got, c.want)
		}
	}
	if g.dropped.Load() != 1 {
		t.Fatalf("dropped=%d", g.dropped.Load())
	}
	var announced []netip.Addr
	done := make(chan struct{}, 4)
	fn := func(a netip.Addr) { announced = append(announced, a); done <- struct{}{} }
	g.onNew.Store(&fn)
	g.allow.Store(true)
	if !g.forwardable(ipv4Packet("10.255.255.44", "1.1.1.1"), 200) {
		t.Fatal("internet refused after opt-in")
	}
	<-done
	g.forwardable(ipv4Packet("10.255.255.44", "8.8.8.8"), 201) // same user: no new announcement
	if len(announced) != 1 || announced[0] != netip.MustParseAddr("10.255.255.44") {
		t.Fatalf("announced %v", announced)
	}
	if users := g.recentUsers(1 << 62); len(users) != 1 {
		t.Fatalf("users %v", users)
	}
	g.resetUsers()
	if users := g.recentUsers(1 << 62); len(users) != 0 {
		t.Fatalf("users after reset %v", users)
	}
}

type recordTUN struct {
	tun.Device
	got [][]byte
}

func (r *recordTUN) Write(bufs [][]byte, offset int) (int, error) {
	r.got = append(r.got, bufs...)
	return len(bufs), nil
}
func (r *recordTUN) File() *os.File { return nil }

func TestExitGuardTUNWriteFiltersBatch(t *testing.T) {
	g := newExitGuard()
	g.setTenant(nil, []string{"10.255.255.0/24"})
	rec := &recordTUN{}
	w := &exitGuardTUN{Device: rec, guard: g}
	const off = 16
	mk := func(dst string) []byte { return append(make([]byte, off), ipv4Packet("10.255.255.44", dst)...) }
	a, b, c := mk("10.255.255.36"), mk("1.1.1.1"), mk("10.255.255.1")
	n, err := w.Write([][]byte{a, b, c}, off)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !reflect.DeepEqual(rec.got, [][]byte{a, c}) {
		t.Fatalf("passed %d packets", len(rec.got))
	}
	rec.got = nil
	if n, _ := w.Write([][]byte{b}, off); n != 1 || len(rec.got) != 0 {
		t.Fatal("all-dropped batch must report success and write nothing")
	}
}

func TestParseIPCPeers(t *testing.T) {
	ipc := "private_key=aa\nlisten_port=51820\npublic_key=01\nendpoint=203.0.113.9:51820\nlast_handshake_time_sec=1700000000\nallowed_ip=10.255.255.0/24\npublic_key=02\nendpoint=198.51.100.7:4500\nallowed_ip=10.255.255.36/32\nallowed_ip=0.0.0.0/0\n"
	got := parseIPCPeers(ipc)
	if got["01"].endpoint != "203.0.113.9:51820" || got["01"].lastHandshake != 1700000000 {
		t.Fatalf("server: %+v", got["01"])
	}
	if !reflect.DeepEqual(got["02"].allowedIPs, []string{"10.255.255.36/32", "0.0.0.0/0"}) {
		t.Fatalf("peer: %+v", got["02"])
	}
	if a, ok := endpointAddr("[::ffff:198.51.100.7]:4500"); !ok || a != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("endpointAddr %v %v", a, ok)
	}
}

func TestSortCandidates(t *testing.T) {
	cs := []ExitCandidate{
		{IP: "10.0.0.9", Offers: "unknown", Online: true, Path: "direct"},
		{IP: "10.0.0.3", Offers: "yes", Online: false, Path: "relay"},
		{IP: "10.0.0.5", Offers: "yes", Online: true, Path: "relay"},
		{IP: "10.0.0.4", Offers: "yes", Online: true, Path: "direct"},
	}
	sortCandidates(cs)
	var got []string
	for _, c := range cs {
		got = append(got, c.IP)
	}
	if !reflect.DeepEqual(got, []string{"10.0.0.4", "10.0.0.5", "10.0.0.3", "10.0.0.9"}) {
		t.Fatalf("order %v", got)
	}
}

func TestExitStatePathNextToConfig(t *testing.T) {
	if p := exitStatePath("/etc/wantasticd/config.json"); p != "/etc/wantasticd/exitnode.json" {
		t.Fatal(p)
	}
}
