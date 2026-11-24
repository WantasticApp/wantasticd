package fiberolt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func fakeOLTServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			w.Header().Set("Set-Cookie", "_:USERNAME:_=admin; path=/")
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/goform/getSysStatus":
			json.NewEncoder(w).Encode(SysStatus{
				RunTime:       "3600",
				CPUPercent:    "42%",
				MemoryPercent: "61%",
				Temp1Value:    "55.0",
				Temp2Value:    "48.5",
				Fan1:          "WORK     RPM: 6600",
				SoftwareVer:   "1.1.3.18",
				HardwareVer:   "3.0",
				DeviceName:    "GP8X2G6",
				MAC:           "00:90:4c:06:a4:27",
				SN:            "TESTOLT001",
				Ports: []Port{
					{PortName: "pon1", PortStatus: "1", PortSpeed: "2500", Online: "2", Offline: "1"},
					{PortName: "ge1", PortStatus: "1", PortSpeed: "1000", Online: "0", Offline: "0"},
				},
			})
		case "/goform/getOntListBrife":
			json.NewEncoder(w).Encode(OntList{
				List: []OntEntry{
					{"onuid": "0/1/1", "sn": "HWTC93BB0308", "status": "online", "ponPort": "pon1"},
					{"onuid": "0/1/2", "sn": "HWTC93BB0309", "status": "offline", "ponPort": "pon1"},
				},
			})
		case "/goform/getOntDetail":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]any{
					{"rxpower": "-18.5", "txpower": "2.1"},
				},
			})
		case "/goform/getSystemLogList":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]any{
					{"index": "1", "logTime": "2024-01-01 12:00:00", "logType": "Info", "logTips": "System started"},
				},
			})
		case "/goform/getLineprofileList":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]any{
					{"profileid": "1", "profilename": "default", "onttype": "SFU", "mapping_mode": "vlan", "traffic_mode": "car"},
				},
			})
		case "/goform/getOntListConfig":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]any{
					{"onuid": "0/1/1", "mode": "sn", "info": "HWTC93BB0308", "lineid": "1", "desc": "test-onu"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestCollectOLTDisabled(t *testing.T) {
	msg := wusp.NewMessage()
	srv := fakeOLTServer(t)
	defer srv.Close()
	api := NewClient(srv.URL, "admin", "admin")

	CollectOLT(context.Background(), api, nil, false, msg)

	assertField(t, msg, wusp.WUSPOLTPrefix+"Installed", "true")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Platform", "olt")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Status", "disabled")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Enable", "false")
}

func TestCollectOLTEnabled(t *testing.T) {
	msg := wusp.NewMessage()
	srv := fakeOLTServer(t)
	defer srv.Close()
	api := NewClient(srv.URL, "admin", "admin")

	CollectOLT(context.Background(), api, nil, true, msg)

	assertField(t, msg, wusp.WUSPOLTPrefix+"Status", "ok")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Enable", "true")
	assertField(t, msg, wusp.WUSPOLTPrefix+"CpuPercent", "42")
	assertField(t, msg, wusp.WUSPOLTPrefix+"MemoryPercent", "61")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Temperature", "55")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PonTemperature", "48.5")
	assertField(t, msg, wusp.WUSPOLTPrefix+"FanSpeed", "6600")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Uptime", "3600")

	// Port table
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPortNumberOfEntries", "2")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.1.Name", "pon1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.1.Type", "pon")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.1.Status", "up")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.1.Speed", "2500")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.1.OnlineONUs", "2")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.2.Name", "ge1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"PONPort.2.Type", "ge")

	// ONU table
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONUNumberOfEntries", "2")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.1.Index", "0/1/1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.1.SerialNumber", "HWTC93BB0308")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.1.Status", "online")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.1.PONPort", "pon1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.2.Index", "0/1/2")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ONU.2.Status", "offline")

	// Online counters
	assertField(t, msg, wusp.WUSPOLTPrefix+"TotalONUs", "2")
	assertField(t, msg, wusp.WUSPOLTPrefix+"OnlineONUs", "2")

	// Syslog
	assertField(t, msg, wusp.WUSPOLTPrefix+"SyslogNumberOfEntries", "1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"Syslog.1.Type", "Info")

	// Line profiles
	assertField(t, msg, wusp.WUSPOLTPrefix+"LineProfileNumberOfEntries", "1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"LineProfile.1.Name", "default")

	// Provisioned ONU table
	assertField(t, msg, wusp.WUSPOLTPrefix+"ProvisionedONUNumberOfEntries", "1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ProvisionedONU.1.OnuID", "0/1/1")
	assertField(t, msg, wusp.WUSPOLTPrefix+"ProvisionedONU.1.Mode", "sn")
}

func TestCollectOLTLoginError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"errCode": "badCredentials"})
	}))
	defer srv.Close()

	msg := wusp.NewMessage()
	api := NewClient(srv.URL, "admin", "wrong")
	CollectOLT(context.Background(), api, nil, true, msg)

	assertField(t, msg, wusp.WUSPOLTPrefix+"Status", "login_error")
}

func TestParsers(t *testing.T) {
	if got := ParsePercent("42%"); got != 42 {
		t.Fatalf("ParsePercent(42%%)=%d want 42", got)
	}
	if got := ParsePercent("100"); got != 100 {
		t.Fatalf("ParsePercent(100)=%d want 100", got)
	}
	if got := ParseFanRPM("WORK     RPM: 6600"); got != 6600 {
		t.Fatalf("ParseFanRPM='WORK RPM: 6600'=%d want 6600", got)
	}
	if got := ParseFanRPM("STOP"); got != 0 {
		t.Fatalf("ParseFanRPM(STOP)=%d want 0", got)
	}
	if secs, ok := ParseUpTime("1d22h48m"); !ok || secs != 86400+22*3600+48*60 {
		t.Fatalf("ParseUpTime(1d22h48m)=%d,%v want %d", secs, ok, 86400+22*3600+48*60)
	}
	if secs, ok := ParseUpTime("3600"); !ok || secs != 3600 {
		t.Fatalf("ParseUpTime(3600)=%d,%v", secs, ok)
	}
}

func TestParseONUInfos(t *testing.T) {
	out := `ONU online info:
0/1/1  HWTC-93bb0308  0d0h40m  Normal  working
0/1/2  HWTC-93bb0309  1d22h48m  Normal  working
`
	rows := ParseONUInfos(out)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].ID != "0/1/1" || rows[0].SN != "HWTC-93bb0308" {
		t.Fatalf("row[0]=%+v", rows[0])
	}
	if rows[1].ConfigState != "Normal" || rows[1].MemberState != "working" {
		t.Fatalf("row[1]=%+v", rows[1])
	}
}

func TestParseONUOptical(t *testing.T) {
	out := `Power Feed Voltage(V): 3.280
RX Optical Power(dBm): -18.500 (OLT TX: 9.510)
TX Optical Power(dBm): 2.100
Laser Bias Current(mA): 11.5
Temperature(C): 42.0
Port status is Enable, Linkup`
	opt := ParseONUOptical(out)
	if opt.VoltageV != 3.28 {
		t.Fatalf("VoltageV=%f want 3.28", opt.VoltageV)
	}
	if opt.RxPowerDBm != -18.5 {
		t.Fatalf("RxPowerDBm=%f want -18.5", opt.RxPowerDBm)
	}
	if opt.TxPowerDBm != 2.1 {
		t.Fatalf("TxPowerDBm=%f want 2.1", opt.TxPowerDBm)
	}
	if opt.BiasCurrent != 11.5 {
		t.Fatalf("BiasCurrent=%f want 11.5", opt.BiasCurrent)
	}
	if opt.TempC != 42 {
		t.Fatalf("TempC=%f want 42", opt.TempC)
	}
	if !opt.EthKnown || !opt.EthPortUp {
		t.Fatalf("EthKnown=%v EthPortUp=%v want true,true", opt.EthKnown, opt.EthPortUp)
	}
}

func TestParseTempAlarm(t *testing.T) {
	// The vendor CLI separates the number from the unit/label with spaces:
	// "60 'C (High)    -30 'C (Low)"
	out := "Temperature Alarm: 60 'C (High)    -30 'C (Low)"
	hi, lo, ok := ParseTempAlarm(out)
	if !ok || hi != 60 || lo != -30 {
		t.Fatalf("ParseTempAlarm=%f,%f,%v want 60,-30,true", hi, lo, ok)
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
