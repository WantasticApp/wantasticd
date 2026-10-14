//go:build linux

package modem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseQuectelServingCellLTE(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseQuectelServingCellInfo([]string{
		`+QENG: "servingcell","NOCONN","LTE","FDD",460,01,1A2B3C4,123,100,1,5,5,1E7F,-97,-8,-68,15,42`,
	}, info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.OperatorMCC != "460" || info.OperatorMNC != "01" {
		t.Fatalf("operator=%s/%s want 460/01", info.OperatorMCC, info.OperatorMNC)
	}
	if info.CellID != 0x1A2B3C4 {
		t.Fatalf("CellID=%x want 1A2B3C4", info.CellID)
	}
	if info.TAC != 0x1E7F {
		t.Fatalf("TAC=%x want 1E7F", info.TAC)
	}
	if info.Signal.RSRP != -97 || info.Signal.RSRQ != -8 || info.Signal.RSSI != -68 || info.Signal.SINR != 15 {
		t.Fatalf("signal=%+v", info.Signal)
	}
}

func TestCGIATResponseMatchesOnlyMicrocomReply(t *testing.T) {
	raw := "Content-type: text/plain\nAT+QENG=\"servingcell\"\n\nAT+QENG=\"servingcell\"\r\n+QENG: \"servingcell\"\r\nOK\r\n"
	if !cgiATResponseMatches(raw, `AT+QENG="servingcell"`) {
		t.Fatal("expected matching CGI microcom reply")
	}

	stale := "Content-type: text/plain\nAT+QENG=\"servingcell\"\n\nAT+QSIMSTAT?\r\n+QSIMSTAT: 0,1\r\nOK\r\n"
	if cgiATResponseMatches(stale, `AT+QENG="servingcell"`) {
		t.Fatal("stale CGI reply must not match the requested command")
	}
}

func TestCleanATCommandOutputDropsStaleATCommandEcho(t *testing.T) {
	lines := cleanATCommandOutput("AT+QSIMSTAT?\n+QSIMSTAT: 0,1\nOK\n", "AT+QENG=\"servingcell\"")
	if len(lines) != 1 || lines[0] != "+QSIMSTAT: 0,1" {
		t.Fatalf("lines=%q", lines)
	}
}

func TestBridgeReadOnlyATCommand(t *testing.T) {
	for _, cmd := range []string{"AT", "ATI", "AT+QCSQ", `AT+QENG="servingcell"`, "AT+CGDCONT?"} {
		if !isBridgeReadOnlyATCommand(cmd) {
			t.Fatalf("%s should be safe to repeat", cmd)
		}
	}
	for _, cmd := range []string{"AT+CMGS=12", "AT+CFUN=1", "AT+CGDCONT=1,\"IP\",\"internet\""} {
		if isBridgeReadOnlyATCommand(cmd) {
			t.Fatalf("%s must not be repeated", cmd)
		}
	}
}

func TestNormalizeATPortCandidatePrefersStableQuectelBridge(t *testing.T) {
	oldExists := atDeviceExists
	t.Cleanup(func() { atDeviceExists = oldExists })
	atDeviceExists = func(path string) bool {
		return path == quectelATBridgePath
	}

	for _, port := range []string{"/dev/at_usb0", "/dev/at_usb1", "/dev/at_mdm0"} {
		if got := normalizeATPortCandidate(port); got != quectelATBridgePath {
			t.Fatalf("normalizeATPortCandidate(%q)=%q want %q", port, got, quectelATBridgePath)
		}
	}
	if got := normalizeATPortCandidate("/dev/ttyUSB2"); got != "/dev/ttyUSB2" {
		t.Fatalf("tty candidate was changed: got %q", got)
	}
}

func TestFindATPortAvoidsContendedQuectelNodesWhenBridgeExists(t *testing.T) {
	oldExists := atDeviceExists
	t.Cleanup(func() { atDeviceExists = oldExists })
	exists := map[string]bool{
		quectelATBridgePath: true,
		"/dev/at_usb0":      true,
		"/dev/at_mdm0":      true,
	}
	atDeviceExists = func(path string) bool {
		return exists[path]
	}

	c := &atController{}
	if got := c.findATPort("/dev/at_usb0"); got != quectelATBridgePath {
		t.Fatalf("findATPort(/dev/at_usb0)=%q want %q", got, quectelATBridgePath)
	}
	if got := c.findATPort("/dev/at_mdm0"); got != quectelATBridgePath {
		t.Fatalf("findATPort(/dev/at_mdm0)=%q want %q", got, quectelATBridgePath)
	}
	if got := c.findATPort("rmnet_data0"); got != quectelATBridgePath {
		t.Fatalf("findATPort(rmnet_data0)=%q want %q", got, quectelATBridgePath)
	}
}

func TestFindATPortKeepsLegacyATNodeWithoutBridge(t *testing.T) {
	oldExists := atDeviceExists
	t.Cleanup(func() { atDeviceExists = oldExists })
	atDeviceExists = func(path string) bool {
		return path == "/dev/at_usb0"
	}

	c := &atController{}
	if got := c.findATPort("cdc-wdm0"); got != "/dev/at_usb0" {
		t.Fatalf("findATPort(cdc-wdm0)=%q want /dev/at_usb0", got)
	}
}

func TestParseQuectelNetworkInfo(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseQuectelNetworkInfo(`+QNWINFO: "FDD LTE","310410","LTE BAND 2",800`, info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.OperatorMCC != "310" || info.OperatorMNC != "410" {
		t.Fatalf("operator=%s/%s want 310/410", info.OperatorMCC, info.OperatorMNC)
	}
	if info.Band != "800" {
		t.Fatalf("Band=%q want 800", info.Band)
	}
}

func TestParseQuectelGPSLocation(t *testing.T) {
	info, ok := parseQuectelGPSLocation(`+QGPSLOC: 120000.0,33.573100,-7.589800,0.8,45.2,3,180.5,12.4,6.7,150726,08`)
	if !ok {
		t.Fatal("parseQuectelGPSLocation returned ok=false")
	}
	if info.Status != "Fix3D" {
		t.Fatalf("Status=%q want Fix3D", info.Status)
	}
	if info.Latitude != 33.573100 || info.Longitude != -7.589800 {
		t.Fatalf("coordinates=(%f,%f)", info.Latitude, info.Longitude)
	}
	if info.HDOP != 0.8 || info.Altitude != 45.2 || info.Course != 180.5 || info.SpeedKPH != 12.4 {
		t.Fatalf("metrics hdop=%f alt=%f course=%f speed=%f", info.HDOP, info.Altitude, info.Course, info.SpeedKPH)
	}
	if info.SatellitesUsed != 8 {
		t.Fatalf("SatellitesUsed=%d want 8", info.SatellitesUsed)
	}
	if got := info.UTC.Format("2006-01-02T15:04:05Z"); got != "2026-07-15T12:00:00Z" {
		t.Fatalf("UTC=%s", got)
	}
}

func TestParseCGCONTRDPPrefersNonIMSContext(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseCGCONTRDP([]string{
		`+CGCONTRDP: 2,6,"ims","36.4.216.1",,"fd00::1","fd00::2"`,
		`+CGCONTRDP: 1,5,"internet","10.110.61.83",,"10.151.151.44","10.151.151.48"`,
	}, info)

	if info.APN != "internet" {
		t.Fatalf("APN=%q want internet", info.APN)
	}
	if info.IPAddress != "10.110.61.83" || !info.Connected || info.IPVersion != 4 {
		t.Fatalf("connection ip=%q connected=%v ipversion=%d", info.IPAddress, info.Connected, info.IPVersion)
	}
	if info.DNS1 != "10.151.151.44" || info.DNS2 != "10.151.151.48" {
		t.Fatalf("dns=%q/%q want 10.151.151.44/10.151.151.48", info.DNS1, info.DNS2)
	}
}

func TestParseQuectelWANIP(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseQuectelWANIP([]string{
		`+QMAP: "WWAN",1,1,"IPV4","10.110.61.83"`,
		`+QMAP: "WWAN",1,1,"IPV6","2001:db8::10"`,
		`+QMAP: "WWAN",0,1,"IPV6","0:0:0:0:0:0:0:0"`,
	}, info)

	if !info.Connected {
		t.Fatal("Connected=false want true")
	}
	if info.IPAddress != "10.110.61.83" || info.IPv6Address != "2001:db8::10" {
		t.Fatalf("addresses=%q/%q", info.IPAddress, info.IPv6Address)
	}
	if info.IPVersion != -1 {
		t.Fatalf("IPVersion=%d want -1 for IPv4v6", info.IPVersion)
	}
}

func TestParseQuectelCarrierAggregation(t *testing.T) {
	rows := parseQuectelCarrierAggregation([]string{
		`+QCAINFO: "PCC",1850,120,-91,-8,16,100,"LTE BAND 3",20`,
		`+QCAINFO: "NR5G",627264,322,-88,-10,21,0,"NR5G BAND 78",100`,
	})

	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	if rows[0].Role != "PCC" || rows[0].RAT != "LTE" || rows[0].Band != "B3" || rows[0].EARFCN != 1850 || rows[0].PCI != 120 {
		t.Fatalf("lte row=%+v", rows[0])
	}
	if rows[1].RAT != "NR" || rows[1].Band != "N78" || rows[1].EARFCN != 627264 || rows[1].SINR != 21 {
		t.Fatalf("nr row=%+v", rows[1])
	}
}

func TestParseQuectelMetricAverages(t *testing.T) {
	sig := SignalQuality{}

	parseQuectelMetricAverages([]string{
		`+QRSRP: -91,-92,-32768,-140,"LTE"`,
		`+QRSRP: -88,-89,-32768,-37625,"NR5G"`,
	}, "QRSRP", &sig.RSRP)
	parseQuectelMetricAverages([]string{
		`+QRSRQ: -8,-9,-32768,-32768,"LTE"`,
	}, "QRSRQ", &sig.RSRQ)
	parseQuectelMetricAverages([]string{
		`+QSINR: 1500,1200,-32768,-32768,"NR5G"`,
	}, "QSINR", &sig.SINR)

	if sig.RSRP != -90 {
		t.Fatalf("RSRP=%d want -90", sig.RSRP)
	}
	if sig.RSRQ != -8 {
		t.Fatalf("RSRQ=%d want -8", sig.RSRQ)
	}
	if sig.SINR != 14 {
		t.Fatalf("SINR=%d want 14", sig.SINR)
	}
}

func TestParseQuectelTemperatureAndTimingAdvance(t *testing.T) {
	temp := parseQuectelTemperature([]string{
		`+QTEMP: "cpuss-0",46`,
		`+QTEMP: "cpuss-1",48`,
		`+QTEMP: "pmic-0",255`,
	})
	if temp != 47 {
		t.Fatalf("temp=%d want 47", temp)
	}

	ta := parseQuectelTimeAdvance([]string{
		`+QNWCFG: "lte_time_advance",1,32`,
	}, "lte_time_advance")
	if ta != 32 {
		t.Fatalf("timing advance=%d want 32", ta)
	}
}

func TestParseQuectelDataCounters(t *testing.T) {
	info := &Info{}
	parseQuectelDataCounters([]string{
		`+QGDCNT: 100,200`,
	}, info)
	if info.TxBytes != 100 || info.RxBytes != 200 {
		t.Fatalf("lte counters tx=%d rx=%d", info.TxBytes, info.RxBytes)
	}

	info = &Info{}
	parseQuectelDataCounters([]string{
		`+QGDNRCNT: 300,400`,
	}, info)
	if info.RxBytes != 300 || info.TxBytes != 400 {
		t.Fatalf("nr counters tx=%d rx=%d", info.TxBytes, info.RxBytes)
	}
}

func TestParseQuectelCarrierAggregationQuecManagerLayout(t *testing.T) {
	rows := parseQuectelCarrierAggregation([]string{
		`+QCAINFO: "PCC",501390,12,"NR5G BAND 41",147,-11,-11,2463`,
		`+QCAINFO: "SCC",393850,3,"NR5G BAND 25",1,354,1,3,378000`,
	})

	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	if rows[0].RAT != "NR" || rows[0].Band != "N41" || rows[0].Bandwidth != "100 MHz" || rows[0].PCI != 147 {
		t.Fatalf("pcc row=%+v", rows[0])
	}
	if rows[0].RSRP != -11 || rows[0].RSRQ != -11 || rows[0].SINR != 25 {
		t.Fatalf("pcc signal=%+v", rows[0])
	}
	if rows[1].Band != "N25" || rows[1].Bandwidth != "20 MHz" || rows[1].PCI != 354 {
		t.Fatalf("scc row=%+v", rows[1])
	}
	if rows[1].SINR != 40 {
		t.Fatalf("scc sinr=%d want 40", rows[1].SINR)
	}
}

func TestParseQuectelNeighborCells(t *testing.T) {
	lte := parseQuectelNeighborCells([]string{
		`+QENG: "neighbourcell intra","LTE",1650,461,-12,-97,-62,-,-,-,-,-,-`,
	})
	nr := parseQuectelNR5GMeasInfo([]string{
		`+QNWCFG: "nr5g_meas_info",627264,322,0,-88,-10`,
	})

	if len(lte) != 1 || lte[0].RAT != "LTE" || lte[0].Relation != "intra" || lte[0].PCI != 461 {
		t.Fatalf("lte=%+v", lte)
	}
	if lte[0].RSRP != -97 || lte[0].RSRQ != -12 {
		t.Fatalf("lte signal=%+v", lte[0])
	}
	if len(nr) != 1 || nr[0].RAT != "NR" || nr[0].Relation != "nr5g" || nr[0].Frequency != 627264 {
		t.Fatalf("nr=%+v", nr)
	}
}

func TestParseFibocomXCESQ(t *testing.T) {
	c := &atController{}
	sig := SignalQuality{}

	c.parseFibocomXCESQ("+XCESQ: 99,99,255,255,30,50", &sig)

	if sig.RSRQ != -4 || sig.RSRP != -90 {
		t.Fatalf("signal=%+v want RSRQ=-4 RSRP=-90", sig)
	}
}

func TestParseJSONSignalUQMI(t *testing.T) {
	info := &Info{}

	parseJSONSignal([]byte(`{"type":"lte","rssi":-61,"rsrq":-8,"rsrp":-91,"snr":16}`), info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.Signal.RSSI != -61 || info.Signal.RSRQ != -8 || info.Signal.RSRP != -91 || info.Signal.SINR != 16 {
		t.Fatalf("signal=%+v", info.Signal)
	}
}

func TestParseDefaultRouteCellularInterface(t *testing.T) {
	routes := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"bridge0\t00E1A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n" +
		"rmnet_data1\t00000000\tAA65A70A\t0003\t0\t0\t0\t00000000\n"
	if got := parseDefaultRouteCellularInterface(routes); got != "rmnet_data1" {
		t.Fatalf("interface=%q want rmnet_data1", got)
	}
}

func TestParseATTextMessages(t *testing.T) {
	messages := parseATTextMessages([]string{
		`+CMGL: 14,"REC UNREAD","665",,"26/07/17,09:04:11+04"`,
		`hello from network`,
	})
	if len(messages) != 1 || messages[0].Index != 14 || messages[0].Number != "665" || messages[0].Body != "hello from network" {
		t.Fatalf("messages=%+v", messages)
	}
	if !validSMSPhoneNumber("+212600000000") || validSMSPhoneNumber("+212;reboot") {
		t.Fatal("SMS phone validation failed")
	}
}

func TestParseATTextMessagesMultilineAndInvalidHeader(t *testing.T) {
	messages := parseATTextMessages([]string{
		`+CMGL: nope,"REC READ","123"`,
		`ignored`,
		`+CMGL: 2,"REC READ","+212700000000",,"26/07/18,10:00:00+04"`,
		`first line`,
		`second line`,
	})
	if len(messages) != 1 || messages[0].Body != "first line\nsecond line" {
		t.Fatalf("messages=%+v", messages)
	}
}

func TestSanitizeOutgoingSMSTextPreservesParagraphs(t *testing.T) {
	input := "  hello world\r\nsecond paragraph with spaces\tand tabs  "
	got := sanitizeOutgoingSMSText(input)
	want := "hello world\nsecond paragraph with spaces\tand tabs"
	if got != want {
		t.Fatalf("sanitizeOutgoingSMSText=%q want %q", got, want)
	}
}

func TestSanitizeOutgoingSMSTextStripsDangerousControls(t *testing.T) {
	input := "AT+QSIMSTAT?\x1atesting\u202e\nok"
	got := sanitizeOutgoingSMSText(input)
	want := "AT+QSIMSTAT?testing\nok"
	if got != want {
		t.Fatalf("sanitizeOutgoingSMSText=%q want %q", got, want)
	}
}

func TestSMSToolSendSupportsOnlySingleTokenFallback(t *testing.T) {
	if !smsToolSendSupportsMessage("hello") {
		t.Fatal("single-token sms_tool fallback should be allowed")
	}
	for _, value := range []string{"hello world", "hello\tworld", "hello\nworld"} {
		if smsToolSendSupportsMessage(value) {
			t.Fatalf("sms_tool fallback should reject %q", value)
		}
	}
}

func TestSMSInboxNormalizationSanitizesAndDecodesMarkedUCS2(t *testing.T) {
	messages := parseATTextMessages([]string{
		`+CMGL: 8,"REC UNREAD","+212700000000",,"26/07/21,09:04:11+04"`,
		`UCS2:00480065006C006C006F`,
	})
	if len(messages) != 1 || messages[0].Body != "Hello" {
		t.Fatalf("messages=%+v", messages)
	}

	payload, err := normalizeSMSInboxJSON(`[{"storage":"SM","index":8,"number":"+212700000000\u0000","body":"UCS2:00480069\u202e"}]`)
	if err != nil {
		t.Fatalf("normalizeSMSInboxJSON: %v", err)
	}
	var normalized []atTextMessage
	if err := json.Unmarshal([]byte(payload), &normalized); err != nil {
		t.Fatalf("unmarshal normalized SMS: %v", err)
	}
	if len(normalized) != 1 || normalized[0].Number != "+212700000000" || normalized[0].Body != "Hi" {
		t.Fatalf("normalized=%+v", normalized)
	}
}

func TestSMSInboxNormalizationDecodesLikelyBareUCS2Body(t *testing.T) {
	const bareUCS2 = "00480069002C002000690074002700730020004100540054002E0020005500730065002000570069002D0046006900200074006F002000680065006C0070002E"
	payload, err := normalizeSMSInboxJSON(`[{"storage":"ME","index":17,"number":"7535","body":"` + bareUCS2 + `"}]`)
	if err != nil {
		t.Fatalf("normalizeSMSInboxJSON: %v", err)
	}
	var normalized []atTextMessage
	if err := json.Unmarshal([]byte(payload), &normalized); err != nil {
		t.Fatalf("unmarshal normalized SMS: %v", err)
	}
	if len(normalized) != 1 || normalized[0].Body != "Hi, it's ATT. Use Wi-Fi to help." {
		t.Fatalf("normalized=%+v", normalized)
	}
}

func TestSMSInboxNormalizationLeavesAmbiguousHexBodyAlone(t *testing.T) {
	payload, err := normalizeSMSInboxJSON(`[{"storage":"ME","index":18,"number":"7535","body":"DEADBEEF12345678"}]`)
	if err != nil {
		t.Fatalf("normalizeSMSInboxJSON: %v", err)
	}
	var normalized []atTextMessage
	if err := json.Unmarshal([]byte(payload), &normalized); err != nil {
		t.Fatalf("unmarshal normalized SMS: %v", err)
	}
	if len(normalized) != 1 || normalized[0].Body != "DEADBEEF12345678" {
		t.Fatalf("normalized=%+v", normalized)
	}
}

func TestClearStaleMicrocomLockRemovesEmptyAndDeadLocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "LCK..ttyOUT2")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	clearStaleMicrocomLock(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty lock was not removed: %v", err)
	}

	if err := os.WriteFile(path, []byte("99999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clearStaleMicrocomLock(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dead lock was not removed: %v", err)
	}
}

func TestRM520CarrierBandAndNSAMode(t *testing.T) {
	carriers := parseQuectelCarrierAggregation([]string{
		`+QCAINFO: "PCC",1650,100,"LTE BAND 3",1,461,-97,-12,-62,9`,
		`+QCAINFO: "SCC",649920,10,"NR5G BAND 78",356`,
	})
	if len(carriers) != 2 || carriers[1].Band != "N78" || carriers[1].RAT != "NR" {
		t.Fatalf("carriers=%+v", carriers)
	}
	if !hasLTEAndNRCarriers(carriers) {
		t.Fatal("LTE+NR carriers were not recognized as NSA")
	}
}

func TestRM520NeighborFiltering(t *testing.T) {
	rows := parseQuectelNeighborCells([]string{
		`+QENG: "neighbourcell intra","LTE",1650,461,-12,-97,-62,-,-,-,-,-,-`,
		`+QENG: "neighbourcell inter","LTE",2850,-,-,-,-,-,30,6,22,14`,
		`+QENG: "neighbourcell","WCDMA",2956,2,12,8,-,-,-,-`,
	})
	if len(rows) != 1 || rows[0].RSRP != -97 || rows[0].RSRQ != -12 {
		t.Fatalf("rows=%+v", rows)
	}
}
