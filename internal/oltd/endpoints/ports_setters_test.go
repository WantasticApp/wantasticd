package endpoints

import (
	"encoding/binary"
	"strings"
	"testing"

	"wantastic-agent/internal/oltd/wire"
)

// legacyFields decodes the legacy request layout: u16 lengths at +34.. and
// NUL separated strings from +58.
func legacyFields(m wire.Msg, n int) ([]int, []string) {
	lens := make([]int, n)
	strs := make([]string, n)
	off := 58
	for i := 0; i < n; i++ {
		lens[i] = int(binary.LittleEndian.Uint16(m[34+2*i:]))
		end := off
		for m[end] != 0 {
			end++
		}
		strs[i] = string(m[off:end])
		off = end + 1
	}
	return lens, strs
}

func TestPlainReply(t *testing.T) {
	for _, c := range []struct {
		reply, want string
		ok          bool
	}{
		{"0", "", true},
		{"0 anything", "", true},
		{"105", `{"errCode":"105"}`, false},    // digits only: the code is echoed
		{"-1", `{"errCode":"102"}`, false},     // daemon timeout (web_service_cmd's "-1")
		{"ERROR", `{"errCode":"102"}`, false},  // no number: code 0 -> out of range
		{"1500 x", `{"errCode":"102"}`, false}, // above 1499
		{"200 vlan|ge1", `{"errCode":"200","param":["vlan","ge1"]}`, false},
		{"7 a|b", `{"errCode":"102"}`, false}, // below 100 with params
	} {
		out, ok := plainReply(c.reply)
		if ok != c.ok || string(out) != c.want {
			t.Errorf("%q: got %q ok=%v, want %q ok=%v", c.reply, out, ok, c.want, c.ok)
		}
	}
}

func TestLegacySetterLayout(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{{SockNSM, 96}: "0"}}
	got := call(t, fb, "set", "setMulRouterTab", Params{"port": "ge1", "vlanId": "100"}, nil)
	if string(got) != `{"errCode":"0"}` {
		t.Fatalf("reply %s", got)
	}
	m := reqOf(t, fb, 0)
	lens, strs := legacyFields(m, 2)
	if m.Code() != 96 || lens[0] != 3 || lens[1] != 3 || strs[0] != "ge1" || strs[1] != "100" {
		t.Fatalf("layout code=%d lens=%v strs=%q", m.Code(), lens, strs)
	}
	// defaults: cJSON_GetString(json, name, def)
	fb.replies[sockCode{SockNSM, 424}] = "0"
	call(t, fb, "set", "setServicePort", Params{"sshport": "2222"}, nil)
	_, strs = legacyFields(reqOf(t, fb, 1), 5)
	if strings.Join(strs, ",") != "23,2222,80,443,161" {
		t.Fatalf("defaults %q", strs)
	}
	// a daemon error reply is passed through as the vendor formats it
	// (sscanf "%d%s": the parameter list is the second word only)
	fb.replies[sockCode{SockNSM, 96}] = "300 vlan|ge1 not found"
	if got := string(call(t, fb, "set", "setMulRouterTab", Params{"port": "ge1", "vlanId": "100"}, nil)); got != `{"errCode":"300","param":["vlan","ge1"]}` {
		t.Fatalf("error reply %s", got)
	}
	fb.errs = map[sockCode]error{{SockNSM, 96}: fakeTimeout{}}
	if got := string(call(t, fb, "set", "setMulRouterTab", Params{"port": "ge1"}, nil)); got != `{"errCode":"102"}` {
		t.Fatalf("timeout %s", got)
	}
}

func TestBoolSetters(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 348}: "0", {SockNSM, 349}: "0", {SockNSM, 71}: "0", {SockNSM, 72}: "0",
	}}
	call(t, fb, "set", "setDscpQueueEn", Params{"dscpEn": "1x"}, nil)
	call(t, fb, "set", "setDscpQueueEn", Params{"dscpEn": "0"}, nil)
	call(t, fb, "set", "setDscpQueueEn", Params{}, nil)
	call(t, fb, "set", "setIgmpSnoopEn", Params{"igmpSnoopingEn": "1"}, nil)
	call(t, fb, "set", "setIgmpSnoopEn", Params{"igmpSnoopingEn": "1x"}, nil) // strcmp, not first byte
	var codes []uint16
	for _, m := range fb.seen {
		codes = append(codes, m.Code())
		if m[34] != 0 || m[58] != 0 {
			t.Fatalf("boolean setter must not carry a body")
		}
	}
	if want := []uint16{348, 349, 349, 71, 72}; strings.Join(strings.Fields(strings.Trim(fmtCodes(codes), "[]")), ",") != strings.Trim(fmtCodes(want), "[]") {
		t.Fatalf("codes %v want %v", codes, want)
	}
}

func fmtCodes(c []uint16) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, v := range c {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(strings.TrimSpace(strings.Repeat(" ", 0) + itoa(int(v))))
	}
	sb.WriteString("]")
	return sb.String()
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Replace(string(rune('0'+i%10)), "", "", 0)[:0] + intToString(i))
}

func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestQuickJoinAndEachSetters(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{{SockPON, 1028}: "0", {SockPON, 1066}: "0"}}
	got := call(t, fb, "set", "delDbaprofile", Params{"list": []any{
		map[string]any{"profileid": "3"}, map[string]any{"profileid": "7"}}}, nil)
	if string(got) != `{"errCode":"0"}` {
		t.Fatalf("reply %s", got)
	}
	m := reqOf(t, fb, 0)
	if p := wire.QuickParams(m.Bytes()); len(p) != 1 || p[0] != "3,7" || m.Code() != 1028 {
		t.Fatalf("join request %q code %d", p, m.Code())
	}
	if got := string(call(t, fb, "set", "delDbaprofile", Params{}, nil)); got != `{"errCode":"103"}` {
		t.Fatalf("missing list: %s", got)
	}
	fb.seen = nil
	call(t, fb, "set", "delOntAutoAddConfig", Params{"list": []any{map[string]any{"index": "1"}, map[string]any{"index": "2"}}}, nil)
	if len(fb.seen) != 2 || wire.QuickParams(fb.seen[1].Bytes())[0] != "2" {
		t.Fatalf("one request per item: %d", len(fb.seen))
	}
	// the WithString formatting of an error reply
	fb.replies[sockCode{SockPON, 1028}] = "profile 3 in use\x01"
	if got := string(call(t, fb, "set", "delDbaprofile", Params{"list": []any{map[string]any{"profileid": "3"}}}, nil)); got != `{"errCode":"profile 3 in use "}` {
		t.Fatalf("error reply %s", got)
	}
}

func TestSetNmsConfigAndGlobalLoopDetection(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{{SockMQTT, 232}: "0", {SockNLDP, 212}: "0"}}
	call(t, fb, "set", "setNmsConfigInfo", Params{"serverIp": "cloud.example"}, nil)
	if p := wire.QuickParams(reqOf(t, fb, 0).Bytes()); strings.Join(p, "|") != "disable|cloud.example|1883|" {
		t.Fatalf("nms params %q", p)
	}
	fb.seen = nil
	call(t, fb, "set", "setGlobalLoopDetection", Params{"port": []any{"ge1", "ge2"}, "loopDetectEn": "1", "loopVid": "4000"}, nil)
	if len(fb.seen) != 2 {
		t.Fatalf("one request per port: %d", len(fb.seen))
	}
	if p := wire.QuickParams(fb.seen[1].Bytes()); strings.Join(p, "|") != "ge2|1|4000|0|0" {
		t.Fatalf("loop params %q", p)
	}
}

func TestListSetters(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 429}: "0", {SockNSM, 296}: "0", {SockDHCPS, 55}: "0", {SockNSM, 384}: "0", {SockNSM, 358}: "0", {SockNSM, 295}: "0", {SockNSM, 357}: "0",
	}}
	// delAccessList walks the list backwards and stops at an item without svindex
	call(t, fb, "set", "delAccessList", Params{"list": []any{
		map[string]any{"service_name": "telnet"},
		map[string]any{"service_name": "http", "svindex": "2"},
		map[string]any{"service_name": "telnet-x", "svindex": "10"}}}, nil)
	if len(fb.seen) != 2 {
		t.Fatalf("requests %d", len(fb.seen))
	}
	if _, strs := legacyFields(fb.seen[0], 2); strs[0] != "telnet-x" || strs[1] != "10" {
		t.Fatalf("order %q", strs)
	}
	// one buffer across items: the shorter second item leaves the first one's tail behind its NULs
	if _, strs := legacyFields(fb.seen[1], 2); strs[0] != "http" || strs[1] != "2" || string(fb.seen[1][58:67]) != "http\x002\x00x\x00" {
		t.Fatalf("reused buffer %q %q", strs, fb.seen[1][58:67])
	}
	fb.seen = nil
	call(t, fb, "set", "delArpTable", Params{"list": []any{map[string]any{"ip": "10.0.0.1", "type": "dhcp"}, map[string]any{"ip": "10.0.0.2", "type": "static"}, map[string]any{"ip": "10.0.0.3"}}}, nil)
	if len(fb.seen) != 3 || binary.LittleEndian.Uint16(fb.seen[0][36:]) != 7 || binary.LittleEndian.Uint16(fb.seen[1][36:]) != 6 || binary.LittleEndian.Uint16(fb.seen[2][36:]) != 0 {
		t.Fatalf("arp type flags")
	}
	if ep, _ := Lookup("set", "delArpTable"); ep != nil {
		if _, err := ep.Call(fb, Params{}, nil); err == nil {
			t.Fatal("missing list must be an error (the vendor answers the bare text ERROR)")
		}
	}
	fb.seen = nil
	call(t, fb, "set", "delDhcpClientList", Params{"list": []any{map[string]any{"ipaddr": "10.0.0.9 (lease)"}}}, nil)
	if _, strs := legacyFields(fb.seen[0], 1); strs[0] != "10.0.0.9" {
		t.Fatalf("ip cut at space: %q", strs)
	}
	fb.seen = nil
	call(t, fb, "set", "delStaticMacRule", Params{"list": []any{map[string]any{"mac": "00:11:22:33:44:55", "vlanId": "100", "port": "ge1"}}}, nil)
	if _, strs := legacyFields(fb.seen[0], 3); strings.Join(strs, "|") != "0011.2233.4455|100|ge1" {
		t.Fatalf("dotted mac %q", strs)
	}
	fb.seen = nil
	call(t, fb, "set", "setIpMacFilterList", Params{"mac": "0011-2233-4455", "vlanId": "7"}, nil)
	if _, strs := legacyFields(fb.seen[0], 2); strs[0] != "0011.2233.4455" {
		t.Fatalf("mac dots %q", strs)
	}
	fb.seen = nil
	call(t, fb, "set", "setArpTable", Params{"ip": "10.0.0.1", "mac": "0011-2233-4455", "port": "100"}, nil)
	if _, strs := legacyFields(fb.seen[0], 3); strings.Join(strs, "|") != "10.0.0.1|0011.2233.4455|vlan1.100" {
		t.Fatalf("arp add %q", strs)
	}
	// the first failing item stops the loop and its error is the answer
	fb.seen = nil
	fb.replies[sockCode{SockNSM, 296}] = "301 busy|x"
	if got := string(call(t, fb, "set", "delArpTable", Params{"list": []any{map[string]any{"ip": "a"}, map[string]any{"ip": "b"}}}, nil)); got != `{"errCode":"301","param":["busy","x"]}` || len(fb.seen) != 1 {
		t.Fatalf("stop on error: %s after %d", got, len(fb.seen))
	}
}

func TestSettersAreSetOps(t *testing.T) {
	for _, e := range portedEndpoints {
		if strings.HasPrefix(e.Name, "get") != (e.Op == "get") {
			t.Errorf("%s registered as %s", e.Name, e.Op)
		}
	}
}
