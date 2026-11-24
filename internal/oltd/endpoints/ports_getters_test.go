package endpoints

import (
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/oltd/wire"
)

func reqOf(t *testing.T, fb *fakeBackend, i int) wire.Msg {
	t.Helper()
	if i >= len(fb.seen) {
		t.Fatalf("only %d requests", len(fb.seen))
	}
	return fb.seen[i]
}

func TestGetAccessList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 427}: "1",
		{SockNSM, 426}: "1,0,telnet,192.168.1.1,192.168.1.254,permit\n2,1,http,10.0.0.1,10.0.0.9,deny",
	}}
	got := string(call(t, fb, "get", "getAccessList", nil, nil))
	want := `{"accessStatus":"1","list":[{"svindex":"1","real_index":"0","service_name":"telnet","ip_start":"192.168.1.1","ip_end":"192.168.1.254","action":"permit"},` +
		`{"svindex":"2","real_index":"1","service_name":"http","ip_start":"10.0.0.1","ip_end":"10.0.0.9","action":"deny"}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if reqOf(t, fb, 0).Code() != 427 || reqOf(t, fb, 1).Code() != 426 {
		t.Fatal("request order")
	}
}

func TestGetArpTableList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 293}: "300",
		{SockNSM, 294}: "20 192.168.1.10 00:11:22:33:44:55 ge1 dynamic\n0 192.168.1.1 aa:bb:cc:dd:ee:ff ge2 static\nfinish\n1 9.9.9.9 00:00:00:00:00:01 ge3 dynamic",
	}}
	got := string(call(t, fb, "get", "getArpTableList", nil, nil))
	want := `{"agingTime":"300","list":[{"ip":"192.168.1.10","mac":"00:11:22:33:44:55","type":"dynamic","port":"ge1","agingTime":"20"},` +
		`{"ip":"192.168.1.1","mac":"aa:bb:cc:dd:ee:ff","type":"static","port":"ge2","agingTime":"0"}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// legacy request layout: code, strlen("brief") at +34, "brief" at +58
	m := reqOf(t, fb, 0)
	if m.Code() != 293 || m[34] != 5 || m[35] != 0 || string(m[58:64]) != "brief\x00" {
		t.Fatalf("request %x", m[:64])
	}
}

func TestGetPortTreeStatusList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockMSTP, 584}: "0\n1\n",
		{SockMSTP, 582}: "ge1 1 Root Forwarding 32768.00aabbccddee 128.1 128 20000\nge2 0 Designated Discarding 32768.00aabbccddee 128.2 128 20000",
	}}
	if got := string(call(t, fb, "get", "getPortTreeStatusList", Params{}, nil)); got != `{"errCode":"105"}` {
		t.Fatalf("missing instanceId: %s", got)
	}
	fb.seen = nil
	got := string(call(t, fb, "get", "getPortTreeStatusList", Params{"instanceId": "1"}, nil))
	want := `{"list":[{"portNum":"1","portName":"ge1","portRole":"Root","portStatus":"Forwarding","domainRoot":"1","bridgeId":"32768.00aabbccddee","port":"128.1","priority":"128","portPathCost":"20000"},` +
		`{"portNum":"2","portName":"ge2","portRole":"Designated","portStatus":"Discarding","domainRoot":"0","bridgeId":"32768.00aabbccddee","port":"128.2","priority":"128","portPathCost":"20000"}],"instanceList":["0","1"]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	m := reqOf(t, fb, 1)
	if m.Code() != 582 || m[34] != 1 || string(m[58:60]) != "1\x00" {
		t.Fatalf("instance request %x", m[:64])
	}
}

func TestGetIgmpVlanInfo(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 85}: "100 v2 10 1 1 0 x 1 1 0.0.0.0\n200 v3 5 0 1 1 y 0 0 10.1.1.1",
	}}
	got := string(call(t, fb, "get", "getIgmpVlanInfo", Params{}, nil))
	want := `{"vlanList":[{"igmpVersion":"v2","fastleave":"0","maxResponseTime":"10","mulVlanEn":"1","vlanEn":"1","vlanId":"100","reportsup":"1","query":"1","sourceip":"0.0.0.0"},` +
		`{"igmpVersion":"v3","fastleave":"1","maxResponseTime":"5","mulVlanEn":"0","vlanEn":"1","vlanId":"200","reportsup":"0","query":"0","sourceip":"10.1.1.1"}],"mulVlanId":""}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if got := string(call(t, fb, "get", "getIgmpVlanInfo", Params{"vlanId": "100"}, nil)); !strings.HasSuffix(got, `"mulVlanId":"100"}`) {
		t.Fatalf("vlanId echo: %s", got)
	}
	if n := len(wire.QuickParams(fb.seen[0].Bytes())); n != 0 {
		t.Fatalf("request must carry no parameters, got %d", n)
	}
}

func TestGetPortOptical(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 792}: "pon1,41.5,3.29,6.1,-2.10,-5.40,FS,009065,SFP-10GSR-85,A,S123,240101,LC,850\nxge1,40.0,3.30,6.2,-2.00,-6.00,FS,009065,SFP-10GSR-85,A,S124,240102,LC,850",
	}}
	got := string(call(t, fb, "get", "getPortOptical", nil, nil))
	want := `{"list":[{"portNum":"1","portName":"pon1","temperature":"41.5","supVol":"3.29","txBiasCur":"6.1","txPower":"-2.10","rxPower":"--","name":"FS","oui":"009065","productname":"SFP-10GSR-85","version":"A","sn":"S123","date":"240101","connector":"LC","wavelen":"850"},` +
		`{"portNum":"2","portName":"xge1","temperature":"40.0","supVol":"3.30","txBiasCur":"6.2","txPower":"-2.00","rxPower":"-6.00","name":"FS","oui":"009065","productname":"SFP-10GSR-85","version":"A","sn":"S124","date":"240102","connector":"LC","wavelen":"850"}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetSpanningTreeInfo(t *testing.T) {
	// 90061 s = 1d 1h 1m 1s
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockMSTP, 561}: "1 mstp 20 2 15 20 32768 32768.00aabbccddee 32768.00aabbccddee 32768.00aabbccddee ge1 20000 0 0 90061 dom 0 summary",
	}}
	got := string(call(t, fb, "get", "getSpanningTreeInfo", nil, nil))
	want := `{"treeStatusEn":"1","treeVersion":"mstp","agingTime":"20","helloTime":"2","forwardDelay":"15","maxHopCount":"20","bridgePriority":"32768",` +
		`"bridgeId":"32768.00aabbccddee","rootBridgeId":"32768.00aabbccddee","rootDomainId":"32768.00aabbccddee","rootPort":"ge1","rootPathCost":"20000","inRootPathCost":"0","topoStatus":"0",` +
		`"topoChangeTime":"1d 1h 1m 1s","domain":"dom","correctionLevel":"0","summary":"summary"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetRadiusInfo(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockUM, 227}: "radius;10.0.0.1;secret;1812;5;-;-;1812;5;-;-;49;5;-;-;49;5;pw;1",
	}}
	got := string(call(t, fb, "get", "getRadiusInfo", nil, nil))
	want := `{"aaaMode":"radius","radiusPriServer":"10.0.0.1","radiusPriSharedKey":"secret","radiusPriPort":"1812","radiusPriTimeout":"5",` +
		`"radiusSecServer":"","radiusSecSharedKey":"","radiusSecPort":"1812","radiusSecTimeout":"5",` +
		`"tacacsPriServer":"","tacPriSharedKey":"","tacPriPort":"49","tacPriTimeout":"5","tacacsSecServer":"","tacSecSharedKey":"","tacSecPort":"49","tacSecTimeout":"5",` +
		`"enablepwd":"cHc=","enablePasswordCheckEn":"1"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetTaskInfo(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockUM, 218}: "1,3,30,7,4,0,192.168.1.9",
		{SockUM, 239}: "weekly,sun,1,2,30",
	}}
	got := string(call(t, fb, "get", "getTaskInfo", nil, nil))
	want := `{"autosaveday":"1","autosavehour":"3","autosaveminute":"30","autobackupday":"7","autobackuphour":"4","autobackupminute":"0","autobackupserver":"192.168.1.9",` +
		`"oltrebootmode":"weekly","weekday":"sun","monthday":"1","oltreboothour":"2","oltrebootmin":"30"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetServicePortAndSnmpNoticeList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 423}: "23,22,80,443,161",
		{SockUM, 411}:  "1\n10.0.0.5 public 162 v2c none\n10.0.0.6 priv 162 v3 authPriv",
	}}
	if got := string(call(t, fb, "get", "getServicePort", nil, nil)); got != `{"telnetport":"23","sshport":"22","httpport":"80","httpsport":"443","snmpport":"161"}` {
		t.Fatalf("servicePort: %s", got)
	}
	got := string(call(t, fb, "get", "getSnmpNoticeList", nil, nil))
	want := `{"trapEn":"1","list":[{"destHost":"10.0.0.5","securityWord":"public","udpPort":"162","securityMode":"v2c","securityLevel":"--"},` +
		`{"destHost":"10.0.0.6","securityWord":"priv","udpPort":"162","securityMode":"v3","securityLevel":"authPriv"}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	fb.replies[sockCode{SockUM, 411}] = ""
	if got := string(call(t, fb, "get", "getSnmpNoticeList", nil, nil)); got != `{"trapEn":"","list":[]}` {
		t.Fatalf("empty: %s", got)
	}
}

func TestGetNmsConfigInfoAndMacAddrList(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockMQTT, 231}: "1,cloud.example,8883,tenant-7",
		{SockNSM, 287}:  "300\n",
		{SockNSM, 286}:  "ge1 100 00:11:22:33:44:55 dynamic\nvl10 200 00:11:22:33:44:66 static",
	}}
	if got := string(call(t, fb, "get", "getNmsConfigInfo", nil, nil)); got != `{"cloudState":"1","serverIp":"cloud.example","serverPort":"8883","tenantId":"tenant-7"}` {
		t.Fatalf("nms: %s", got)
	}
	if p := wire.QuickParams(fb.seen[0].Bytes()); len(p) != 0 || fb.seen[0][34] != 0 {
		t.Fatalf("nms request params %q", p)
	}
	got := string(call(t, fb, "get", "getMacAddrList", nil, nil))
	want := `{"list":[{"port":"ge1","mac":"00:11:22:33:44:55","vlan":"100","type":"dynamic"},{"port":"vlvl10  ","mac":"00:11:22:33:44:66","vlan":"200","type":"static"}],"macagingtime":"300"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetSystemTimeInfo(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{}}
	for _, c := range []struct{ reply, tz string }{
		{"2026-11-24,01:02:03,n,-0800,pool.ntp.org,time.nist.gov", "-8"},
		{"2026-11-24,01:02:03,n,+0530,pool.ntp.org,time.nist.gov", "5.5"},
		{"2026-11-24,01:02:03,n,-1000,a,b", "-10"},
		{"2026-11-24,01:02:03,n,0,a,b", "0"},
		{"2026-11-24,01:02:03,local,+0800,a,b", ""},
	} {
		fb.replies[sockCode{SockSNTP, 166}] = c.reply
		got := string(call(t, fb, "get", "getSystemTimeInfo", nil, nil))
		if !strings.Contains(got, `"systemTime":"2026-11-24 01:02:03","currentTime":"2026-11-24 01:02:03"`) || !strings.Contains(got, `"timeZone":"`+c.tz+`"`) {
			t.Fatalf("%s: %s", c.reply, got)
		}
	}
	fb.replies[sockCode{SockSNTP, 166}] = "error: no sntp"
	if got := string(call(t, fb, "get", "getSystemTimeInfo", nil, nil)); got != `{"errCode":"101"}` {
		t.Fatalf("error reply: %s", got)
	}
}

func TestGetDhcpClientList(t *testing.T) {
	old := unixNow
	unixNow = func() int64 { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC).Unix() }
	defer func() { unixNow = old }()
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockDHCPS, 54}: "192.168.1.50,00:11:22:33:44:55,3600,x,100,vlan100\n192.168.1.51,00:11:22:33:44:56,90,x,100,vlan100",
	}}
	got := string(call(t, fb, "get", "getDhcpClientList", nil, nil))
	want := `{"list":[{"ipaddr":"192.168.1.50","macaddr":"00:11:22:33:44:55","interface":"vlan100","vlan":"100","expire":"2026-11-24 11:00","remaintime":"3600","index":1},` +
		`{"ipaddr":"192.168.1.51","macaddr":"00:11:22:33:44:56","interface":"vlan100","vlan":"100","expire":"2026-11-24 10:01","remaintime":"90","index":2}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestGetDhcpSnoopList(t *testing.T) {
	flags := "1,0,1,0,1,0,1,0"
	row := "ge1,uplink,1,policy,fmt,:,type," + flags + ",null,sub1,rtype,0,1,0,1,0,1,0,1,null"
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockDHCPS, 40}: "1\n100,200\n" + row,
	}}
	got := string(call(t, fb, "get", "getDhcpSnoopList", nil, nil))
	want := `{"list":[{"portNum":"ge1","portType":"uplink","optionStatusEn":"1","optionPloyType":"policy","circuitidType":"type",` +
		`"circuitsysname":true,"circuitsysmac":false,"circuitvlanid":true,"circuitportname":false,"circuitontid":true,"circuitontmac":false,"circuitontsn":true,"circuitontmodel":false,` +
		`"remotesysname":false,"remotesysmac":true,"remotevlanid":false,"remoteportname":true,"remoteontid":false,"remoteontmac":true,"remoteontsn":false,"remoteontmodel":true,` +
		`"optionFormat":"fmt","optionDelimiter":":","circuitiddef":"","subscriberid":"sub1","remoteidType":"rtype","remoteiddef":""}],"dhcpRelayEn":"0","dhcpSnoopEn":"1","vlanList":"100,200"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSecondBatchGetters(t *testing.T) {
	fb := &fakeBackend{replies: map[sockCode]string{
		{SockNSM, 344}:   "0 1 2 3 4 5 6 7",
		{SockNSM, 346}:   "finish",
		{SockNSM, 338}:   "WRR 1 2 3 4 5 6 7 8",
		{SockNSM, 434}:   "ge1,100,200,300\nge2,1",
		{SockNSM, 430}:   "ge1,100,200,300",
		{SockNSM, 298}:   "50",
		{SockNSM, 73}:    "1 extra",
		{SockAUTHD, 461}: "0",
		{SockAUTHD, 464}: "10.0.0.2 key",
		{SockUM, 397}:    " admin@example",
		{SockUM, 417}:    "rack-1",
		{SockUM, 398}:    "public ro --\nprivate rw full",
		{SockNSM, 440}:   "ge1,1,8\nge2,0,0",
		{SockUM, 182}:    "1",
		{SockNSM, 421}:   "1,1,0,1,0",
		{SockNSM, 90}:    "100,ge1,239.1.1.1 239.1.1.2,\n",
		{SockNSM, 97}:    "100,ge1,",
		{SockNSM, 99}:    "200,ge2,",
	}}
	for _, c := range []struct{ name, want string }{
		{"getCosPriorityInfo", `{"cosPriority":["0","1","2","3","4","5","6","7"]}`},
		{"getDscpQueueInfo", `{"dscpQueue":[],"dscpEn":"0"}`},
		{"getQoSScheduleInfo", `{"qosQueue":["1","2","3","4","5","6","7","8"],"qosMode":"WRR"}`},
		{"getQinqVlanList", `{"list":[{"index":1,"portName":"ge1","startvlan":"100","endvlan":"200","destvlan":"300"},{"index":2,"portName":"ge2","startvlan":"1","endvlan":"200","destvlan":"300"}]}`},
		{"getVlanTransformList", `{"list":[{"index":1,"portName":"ge1","startvlan":"100","endvlan":"200","destvlan":"300"}]}`},
		{"getPortArpAttackInfo", `{"arpReceptRate":"50"}`},
		{"getIgmpSnoopEn", `{"igmpSnoopingEn":"1"}`},
		{"getNetAuthEn", `{"authEn":"0"}`},
		{"getAuthGlobalInfo", `{"authIp":"10.0.0.2","shareKey":"key"}`},
		{"getSnmpBasicInfo", `{"contactInfo":"YWRtaW5AZXhhbXBsZQ==","locationInfo":"cmFjay0x"}`},
		{"getSnmpAccessList", `{"communityList":[{"communityName":"public","accessRule":"ro","mibView":""},{"communityName":"private","accessRule":"rw","mibView":"full"}]}`},
		{"getPortSecurity", `{"list":[{"portNum":1,"portName":"ge1","flapping":"1","limit":"8"},{"portNum":2,"portName":"ge2","flapping":"0","limit":"0"}]}`},
		{"getVerifyCode", `{"isShowverify":true,"telnetEn":true,"sshEn":true,"httpEn":false,"httpsEn":true,"snmpEn":false}`},
		{"getMulGroupList", `{"list":[{"portNum":"ge1","vlanid":"100","groups":"239.1.1.1 239.1.1.2"}]}`},
		{"getMulRouterTab", `{"list":[{"vlanId":"100","port":"ge1"}]}`},
		{"getMulrouterList", `{"list":[{"vlanid":"200","portNum":"ge2"}]}`},
	} {
		if got := string(call(t, fb, "get", c.name, nil, nil)); got != c.want {
			t.Errorf("%s:\ngot  %s\nwant %s", c.name, got, c.want)
		}
	}
	// a QinQ rule with a single field keeps the 0x10 byte the vendor leaves in endvlan
	fb.replies[sockCode{SockNSM, 434}] = "ge1"
	if got := string(call(t, fb, "get", "getQinqVlanList", nil, nil)); got != `{"list":[{"index":1,"portName":"ge1","startvlan":"","endvlan":"\u0010","destvlan":""}]}` {
		t.Errorf("qinq init byte: %s", got)
	}
	// sscanf from every second byte of a short reply: once the source is
	// exhausted the 4-byte buffer keeps its last value (the vendor repeats it).
	fb.replies[sockCode{SockNSM, 346}] = "0 1 2 3"
	if got := string(call(t, fb, "get", "getDscpQueueInfo", nil, nil)); !strings.HasPrefix(got, `{"dscpQueue":["0","1","2","3","3","3",`) || !strings.HasSuffix(got, `"dscpEn":"1"}`) || strings.Count(got, `"3"`) != 61 {
		t.Errorf("dscp: %s", got)
	}
	fb.replies[sockCode{SockNSM, 338}] = "SP"
	if got := string(call(t, fb, "get", "getQoSScheduleInfo", nil, nil)); got != `{"qosQueue":[],"qosMode":"SP"}` {
		t.Errorf("qos SP: %s", got)
	}
	fb.replies[sockCode{SockNSM, 298}] = "error"
	if got := string(call(t, fb, "get", "getPortArpAttackInfo", nil, nil)); got != `{"errCode":"101"}` {
		t.Errorf("arp error: %s", got)
	}
}
