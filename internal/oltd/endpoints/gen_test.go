package endpoints

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// The generated getQvlanList row spec must reproduce the hand port
// (formGetVlanList) byte for byte: same request, same per-record zeroing,
// same buffer offsets. This validates the row engine and the extractor.
func TestRowSpecReproducesHandPortedQvlanList(t *testing.T) {
	var spec *rowSpec
	for i := range rowSpecs {
		if rowSpecs[i].Name == "getQvlanList" {
			spec = &rowSpecs[i]
		}
	}
	if spec == nil {
		t.Fatal("no generated getQvlanList row spec")
	}
	for _, reply := range []string{
		"1,default,1,static,192.168.1.100,255.255.255.0:4000,VLAN4000,1,static,192.168.130.179,255.255.255.0",
		// a record with fewer fields must not inherit the previous record's values
		"1,default,1,static,192.168.1.100,255.255.255.0:300,svc,0:7,a-very-long-remark-that-exceeds-thirty-two-characters-xx,1,dhcp,10.0.0.1,255.0.0.0",
		"",
		"ERROR",
	} {
		fb := &fakeBackend{replies: map[sockCode]string{{SockNSM, 300}: reply}}
		hand := call(t, fb, "get", "getQvlanList", nil, nil)
		gen, err := spec.get(fb, Params{}, &Env{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hand, gen) {
			t.Fatalf("reply %q:\nhand %s\ngen  %s", reply, hand, gen)
		}
		if !bytes.Equal(fb.seen[0].Bytes(), fb.seen[1].Bytes()) {
			t.Fatalf("requests differ")
		}
	}
	if want := sample(t, "getQvlanList.json"); !bytes.Equal(call(t, &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 300}: "1,default,1,static,192.168.1.100,255.255.255.0:4000,VLAN4000,1,static,192.168.130.179,255.255.255.0",
	}}, "get", "getQvlanList", nil, nil), want) {
		t.Fatal("live sample")
	}
}

var convRE = regexp.MustCompile(`%(\[[^\]]*\]|[a-zA-Z])`)

// Every generated row spec must be self-consistent: one sscanf destination
// per conversion, offsets inside the frame, column offsets known.
func TestRowSpecsConsistent(t *testing.T) {
	for _, s := range rowSpecs {
		if n := len(convRE.FindAllString(s.Fmt, -1)); n != len(s.Offs) {
			t.Errorf("%s: %d conversions, %d offsets", s.Name, n, len(s.Offs))
		}
		for _, o := range s.Offs {
			if o <= 0 || o > s.Frame {
				t.Errorf("%s: sscanf offset %#x outside frame %#x", s.Name, o, s.Frame)
			}
		}
		for _, c := range s.Cols {
			if !c.IsConst && !c.Counter && (c.Off <= 0 || c.Off > s.Frame) {
				t.Errorf("%s: column %s offset %#x outside frame", s.Name, c.Key, c.Off)
			}
			if c.Counter && s.Counter == 0 {
				t.Errorf("%s: counter column without counter buffer", s.Name)
			}
		}
		if s.Socket == "" || s.Code == 0 || s.Buf == 0 || s.ListKey == "" || s.Delim == "" || len(s.Cols) == 0 {
			t.Errorf("%s: incomplete spec", s.Name)
		}
	}
	for _, s := range listQuickSpecs {
		if s.Socket == "" || s.Buf == 0 || s.Code == 0 || s.Desc == nil {
			t.Errorf("%s: incomplete listQuick spec", s.Name)
		}
	}
}

// getPackageStatisticsList (formGetPortStatisticsList @0x3dc80): nsm 284,
// comma records, portNum is a running counter, all buffers zeroed per row.
func TestPackageStatisticsList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 284}: "ge1,5000000000,123456789012,1,2,0,0,42,4200,3,4,5,6\nge2,1,2,3,4,5,6,7,8,9,10,11\n",
	}}
	got := call(t, fb, "get", "getPackageStatisticsList", nil, nil)
	want := `{"list":[` +
		`{"portNum":"1","portName":"ge1","sendPacket":"5000000000","sendBit":"123456789012","sendBroadcastNum":"1","sendUnicastNum":"2","sendErrorNum":"0","sendDropNum":"0","receivePacket":"42","receiveBit":"4200","receiveBroadcastNum":"3","receiveUnicastNum":"4","receiveErrorNum":"5","receiveDropNum":"6"},` +
		`{"portNum":"2","portName":"ge2","sendPacket":"1","sendBit":"2","sendBroadcastNum":"3","sendUnicastNum":"4","sendErrorNum":"5","sendDropNum":"6","receivePacket":"7","receiveBit":"8","receiveBroadcastNum":"9","receiveUnicastNum":"10","receiveErrorNum":"11","receiveDropNum":""}]}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if m := fb.seen[0]; m.Code() != 284 || len(fb.seen) != 1 {
		t.Fatalf("request %d", m.Code())
	}
}

// getNetPortList (formGetNetPortList @0x6a338): authd 467, whitespace
// records; the row buffers are 16 bytes and zeroed per row.
func TestNetPortList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockAUTHD, 467}: "ge1 auto authorized 1 3600 30 2\nge2 force-authorized\n",
	}}
	got := call(t, fb, "get", "getNetPortList", nil, nil)
	want := `{"list":[{"portNum":"ge1","portControlType":"auto","portAuthStatus":"authorized","reAuthEn":"1","reAuthTimeout":"3600","clientTimeout":"30","reAuthMaxNum":"2"},` +
		`{"portNum":"ge2","portControlType":"force-authorized","portAuthStatus":"","reAuthEn":"","reAuthTimeout":"","clientTimeout":"","reAuthMaxNum":""}]}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// getIGSStatistics (formgetIGSStatistics @0x5adf0): nsm 95; the 32-byte
// buffers are zeroed once before the loop, so a short line keeps the
// previous line's trailing values (as the vendor does).
func TestIGSStatisticsStaleFields(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 95}: "ge1 100 7 0 0 3 0 0 0 0 0 0 12 0 1 0\nge2 200\n",
	}}
	got := string(call(t, fb, "get", "getIGSStatistics", nil, nil))
	if !strings.Contains(got, `{"portNum":"2","portName":"ge2","vlan":"200","txQuerygeneral":"7",`) || !strings.HasSuffix(got, `"rxLeaveV2":"1","rxOther":"0"}]}`) {
		t.Fatalf("got %s", got)
	}
}

// getDbaprofileList (formGetDbaprofileList @0x961c4): pon 1026 with a 12
// KiB buffer, formQuickListStrToJson with the descGetDbaprofileList
// columns and no ponPortList.
func TestListQuickDbaprofileList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockPON, 1026}: "1,dba1,type3,0,1024,10240,2\n2,dba2,type1,512,0,0,0",
	}}
	got := call(t, fb, "get", "getDbaprofileList", nil, nil)
	want := `{"list":[{"profileid":"1","profilename":"dba1","type":"type3","fix":"0","assure":"1024","max":"10240","bind":"2"},` +
		`{"profileid":"2","profilename":"dba2","type":"type1","fix":"512","cbs":"0","pir":"0","pbs":"0"}]}`
	// the second record deliberately has the overflow shape: 7 columns then
	// the words after the desc table ("profileid","profilename","cir",...)
	want = `{"list":[{"profileid":"1","profilename":"dba1","type":"type3","fix":"0","assure":"1024","max":"10240","bind":"2"},` +
		`{"profileid":"2","profilename":"dba2","type":"type1","fix":"512","assure":"0","max":"0","bind":"0"}]}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	fb.replies[sockCode{SockPON, 1026}] = "1,a,b,c,d,e,f,g,h"
	if got := string(call(t, fb, "get", "getDbaprofileList", nil, nil)); got != `{"list":[{"profileid":"1","profilename":"a","type":"b","fix":"c","assure":"d","max":"e","bind":"f","profileid":"g","profilename":"h"}]}` {
		t.Fatalf("overflow: %s", got)
	}
	if n := len(fb.seen); n == 0 || fb.seen[0].Code() != 1026 {
		t.Fatal("request")
	}
	if p, ok := Lookup("get", "getUplinkLoopDetectionList"); !ok || p.Handler != "formGetUplinkLoopDetectInfo" {
		t.Fatal("listQuick registration")
	}
}
