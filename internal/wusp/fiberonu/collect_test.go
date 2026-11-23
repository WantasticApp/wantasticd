package fiberonu

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestCollectONUDisabled(t *testing.T) {
	msg := wusp.NewMessage()
	CollectONU(context.Background(), Options{}, false, msg)

	assertField(t, msg, wusp.WUSPONUPrefix+"Installed", "true")
	assertField(t, msg, wusp.WUSPONUPrefix+"Platform", "onu")
	assertField(t, msg, wusp.WUSPONUPrefix+"Status", "disabled")
}

func TestCollectONUWithProcData(t *testing.T) {
	dir := t.TempDir()
	ponPhyDir := filepath.Join(dir, "pon_phy")
	xponDir := filepath.Join(dir, "xpon")
	os.MkdirAll(ponPhyDir, 0755)
	os.MkdirAll(xponDir, 0755)

	// /proc/xpon/ponInfo with register values
	os.WriteFile(filepath.Join(xponDir, "ponInfo"), []byte(`Mode: GPON
G_ACTIVATION     (0xBFB640BC): 0x5
DBG_RX_GEM_CNT              (0xBFB64300): 0x1a4
DBG_TX_GEM_CNT              (0xBFB64310): 0x82
DBG_RX_CRC_ERR_CNT          (0xBFB64320): 0x0
DBG_GEM_HEC_ONE_ERR_CNT     (0xBFB64330): 0x3
DBG_GEM_HEC_TWO_ERR_CNT     (0xBFB64340): 0x0
DBG_GEM_HEC_UC_ERR_CNT      (0xBFB64350): 0x1
`), 0644)

	// /proc/xpon/data with link status
	os.WriteFile(filepath.Join(xponDir, "data"), []byte(`gpPonSysData->sysLinkStatus: 1
gpPonSysData->sysOnuType: 2
gpPonSysData->sysOltType: 0x0010
gpPhyData->rogue_state: 0
`), 0644)

	// /proc/pon_phy/info with PHY status
	os.WriteFile(filepath.Join(ponPhyDir, "info"), []byte(`PHY Status: sync (0xa)
`), 0644)

	// DDMI scalar files
	os.WriteFile(filepath.Join(ponPhyDir, "Temperature"), []byte("42.5\n"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "VCC"), []byte("3.28\n"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "BiasCurrent"), []byte("11.5\n"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "RSSICurrent"), []byte("-18.3\n"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "BER"), []byte("0.0\n"), 0644)

	// DDMI dump with TX/RX power
	os.WriteFile(filepath.Join(ponPhyDir, "ddmi"), []byte(`Temperature: 42.500 C
VCC: 3.280 V
TX Bias: 11.500 mA
TX Power: 2.100 dBm
RX Power: -18.500 dBm
`), 0644)

	// Fake CGI server for sysinfo
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/getSysteminfo.cgi" {
			w.Write([]byte(`<GPON_SN=HWTC93BB0308><Macaddress=00:18:93:BB:03:08><OUI=001893><Manufacturer=ECNT><ModelName=PTF2164Q><SWVersion=1.0.0><HWVersion=V1.0><PON_MODE=GPON>`))
		}
	}))
	defer srv.Close()

	msg := wusp.NewMessage()
	opts := Options{
		ProcPonPhyDir: ponPhyDir,
		ProcXponDir:   xponDir,
		CGIBaseURL:    srv.URL,
	}
	CollectONU(context.Background(), opts, true, msg)

	// Verify sysinfo fields
	assertField(t, msg, wusp.WUSPONUPrefix+"SerialNumber", "HWTC93BB0308")
	assertField(t, msg, wusp.WUSPONUPrefix+"MacAddress", "00:18:93:BB:03:08")
	assertField(t, msg, wusp.WUSPONUPrefix+"OUI", "001893")
	assertField(t, msg, wusp.WUSPONUPrefix+"Manufacturer", "ECNT")
	assertField(t, msg, wusp.WUSPONUPrefix+"ModelName", "PTF2164Q")
	assertField(t, msg, wusp.WUSPONUPrefix+"FirmwareVersion", "1.0.0")
	assertField(t, msg, wusp.WUSPONUPrefix+"HardwareVersion", "V1.0")
	assertField(t, msg, wusp.WUSPONUPrefix+"Mode", "gpon")

	// Verify ponInfo registers
	assertField(t, msg, wusp.WUSPONUPrefix+"ActivationState", "O5")
	assertField(t, msg, wusp.WUSPONUPrefix+"GemRxCount", "420")
	assertField(t, msg, wusp.WUSPONUPrefix+"GemTxCount", "130")
	assertField(t, msg, wusp.WUSPONUPrefix+"RxCrcErrorCount", "0")
	assertField(t, msg, wusp.WUSPONUPrefix+"GemHecErrorCount", "4")

	// Verify ponData fields
	assertField(t, msg, wusp.WUSPONUPrefix+"LinkStatus", "up")
	assertField(t, msg, wusp.WUSPONUPrefix+"OnuType", "2")
	assertField(t, msg, wusp.WUSPONUPrefix+"RogueState", "false")

	// Verify PHY status
	assertField(t, msg, wusp.WUSPONUPrefix+"PhyStatus", "sync")

	// Verify DDMI
	assertField(t, msg, wusp.WUSPONUPrefix+"Temperature", "42.5")
	assertField(t, msg, wusp.WUSPONUPrefix+"Voltage", "3.28")
	assertField(t, msg, wusp.WUSPONUPrefix+"BiasCurrent", "11.5")
	assertField(t, msg, wusp.WUSPONUPrefix+"TxPower", "2.1")
	assertField(t, msg, wusp.WUSPONUPrefix+"RxPower", "-18.5")

	// Status should be ok
	assertField(t, msg, wusp.WUSPONUPrefix+"Status", "ok")
}

func TestCollectONUProcFailure(t *testing.T) {
	dir := t.TempDir()
	msg := wusp.NewMessage()
	opts := Options{
		ProcPonPhyDir: filepath.Join(dir, "nonexistent_phy"),
		ProcXponDir:   filepath.Join(dir, "nonexistent_xpon"),
		CGIBaseURL:    "http://127.0.0.1:1", // unreachable
	}
	CollectONU(context.Background(), opts, true, msg)

	// All sources failed — status should reflect that
	val, ok := msg.Get(wusp.WUSPONUPrefix + "Status")
	if !ok {
		t.Fatal("Status not set")
	}
	status := wusp.ValueToString(val)
	if status == "ok" {
		t.Fatal("Status should not be ok when all sources fail")
	}
}

func TestCollectONUDDMIError(t *testing.T) {
	dir := t.TempDir()
	ponPhyDir := filepath.Join(dir, "pon_phy")
	os.MkdirAll(ponPhyDir, 0755)

	// DDMI files with I2C errors (OLT down scenario)
	os.WriteFile(filepath.Join(ponPhyDir, "Temperature"), []byte("Error! phy_I2C_read failed"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "VCC"), []byte("Error! phy_I2C_read failed"), 0644)
	os.WriteFile(filepath.Join(ponPhyDir, "ddmi"), []byte("Error! phy_I2C_read failed"), 0644)

	msg := wusp.NewMessage()
	applyDDMI(msg, ponPhyDir)

	// None of the DDMI fields should be set
	for _, leaf := range []string{"Temperature", "Voltage", "TxPower", "RxPower"} {
		if _, ok := msg.Get(wusp.WUSPONUPrefix + leaf); ok {
			t.Errorf("DDMI field %s should not be set on I2C error", leaf)
		}
	}
}

func TestParseSysinfo(t *testing.T) {
	text := `<GPON_SN=HWTC93BB0308><Macaddress=00:18:93:BB:03:08><OUI=001893><Manufacturer=ECNT><ModelName=PTF2164Q><SWVersion=1.0.0><HWVersion=V1.0><PON_MODE=GPON><TelnetStatus=Yes>`
	info := parseSysinfo(text)
	if info["GPON_SN"] != "HWTC93BB0308" {
		t.Fatalf("GPON_SN=%q", info["GPON_SN"])
	}
	if info["Macaddress"] != "00:18:93:BB:03:08" {
		t.Fatalf("Macaddress=%q", info["Macaddress"])
	}
	if info["PON_MODE"] != "GPON" {
		t.Fatalf("PON_MODE=%q", info["PON_MODE"])
	}
	if info["TelnetStatus"] != "Yes" {
		t.Fatalf("TelnetStatus=%q", info["TelnetStatus"])
	}
}

func TestParseDDMIValue(t *testing.T) {
	dump := `Temperature: 42.500 C
VCC: 3.280 V
TX Bias: 11.500 mA
TX Power: 2.100 dBm
RX Power: -18.500 dBm`

	if v, ok := parseDDMIValue(dump, "TX Power"); !ok || v != 2.1 {
		t.Fatalf("TX Power=%f,%v", v, ok)
	}
	if v, ok := parseDDMIValue(dump, "RX Power"); !ok || v != -18.5 {
		t.Fatalf("RX Power=%f,%v", v, ok)
	}
	if _, ok := parseDDMIValue(dump, "Nonexistent"); ok {
		t.Fatal("should not find Nonexistent")
	}
}

func TestApplyPonInfo(t *testing.T) {
	text := `Mode: GPON
G_ACTIVATION     (0xBFB640BC): 0x3
DBG_RX_GEM_CNT              (0xBFB64300): 0xff
DBG_TX_GEM_CNT              (0xBFB64310): 0x10
`
	msg := wusp.NewMessage()
	applyPonInfo(msg, text)
	assertField(t, msg, wusp.WUSPONUPrefix+"Mode", "gpon")
	assertField(t, msg, wusp.WUSPONUPrefix+"ActivationState", "O3")
	assertField(t, msg, wusp.WUSPONUPrefix+"GemRxCount", "255")
	assertField(t, msg, wusp.WUSPONUPrefix+"GemTxCount", "16")
}

func TestApplyPonData(t *testing.T) {
	text := `gpPonSysData->sysLinkStatus: 0
gpPonSysData->sysOnuType: 2
gpPonSysData->sysOltType: 0x0010
gpPhyData->rogue_state: 1
`
	msg := wusp.NewMessage()
	applyPonData(msg, text)
	assertField(t, msg, wusp.WUSPONUPrefix+"LinkStatus", "down")
	assertField(t, msg, wusp.WUSPONUPrefix+"OnuType", "2")
	assertField(t, msg, wusp.WUSPONUPrefix+"RogueState", "true")
}

func TestParsePhyStatus(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"PHY Status: sync (0xa)\n", "sync"},
		{"PHY Status: unplug\n", "unplug"},
		{"no status here", ""},
	}
	for _, tc := range cases {
		got := parsePhyStatus(tc.input)
		if got != tc.want {
			t.Errorf("parsePhyStatus(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestFirstFloat(t *testing.T) {
	if v, ok := firstFloat("42.5\n"); !ok || v != 42.5 {
		t.Fatalf("firstFloat(42.5)=%f,%v", v, ok)
	}
	if _, ok := firstFloat("Error! phy_I2C_read failed"); ok {
		t.Fatal("should reject Error! text")
	}
	if _, ok := firstFloat(""); ok {
		t.Fatal("should reject empty")
	}
}

func assertField(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	val, ok := msg.Get(path)
	if !ok {
		t.Errorf("missing %s", path)
		return
	}
	got := wusp.ValueToString(val)
	if !strings.Contains(got, want) && got != want {
		t.Errorf("%s = %q, want %q", path, got, want)
	}
}
