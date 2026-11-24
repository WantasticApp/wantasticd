package fiberolt

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordedCall is one request the fake OLT received.
type recordedCall struct {
	Path string
	Body map[string]any
}

// fakeOLT is a scriptable FOS web API: handlers answer per goform path and
// every request (path + decoded JSON body) is recorded, so tests can assert
// both what the agent asked for and what it wrote. Unknown paths answer 404.
// Reusable for every control added to the registry.
type fakeOLT struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	calls []recordedCall
	// violations lists goform paths requested without the session cookie.
	violations []string
	handlers   map[string]func(body map[string]any) any
}

func newFakeOLT(t *testing.T) *fakeOLT {
	t.Helper()
	f := &fakeOLT{t: t, handlers: map[string]func(map[string]any) any{}}
	f.handle("/login/Auth", map[string]any{"errCode": "success"})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if len(body) == 0 && r.Method == http.MethodGet && len(r.URL.Query()) > 0 {
			body = map[string]any{}
			for k := range r.URL.Query() {
				body[k] = r.URL.Query().Get(k)
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{Path: r.URL.Path, Body: body})
		h := f.handlers[r.URL.Path]
		// FOS session rule: a goform request without the session cookie
		// kills the session. The fake enforces it and the test fails.
		if r.URL.Path == "/login/Auth" {
			w.Header().Set("Set-Cookie", "_:USERNAME:_=admin; path=/")
		} else if strings.HasPrefix(r.URL.Path, "/goform/") || strings.HasPrefix(r.URL.Path, "/cgi-bin/") {
			// net/http cannot parse the vendor cookie name (it contains
			// ':'), so check the raw header like the GoAhead server does.
			if !strings.Contains(r.Header.Get("Cookie"), "_:USERNAME:_=admin") {
				f.violations = append(f.violations, r.URL.Path)
				f.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"errCode":"timeout"}`))
				return
			}
		}
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		switch out := h(body).(type) {
		case string:
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(out))
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		}
	}))
	t.Cleanup(func() {
		f.srv.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.violations) > 0 {
			t.Errorf("goform requests sent without the session cookie: %v", f.violations)
		}
	})
	return f
}

// handle answers path with a fixed reply.
func (f *fakeOLT) handle(path string, reply any) {
	f.handleFunc(path, func(map[string]any) any { return reply })
}

// reply returns the current fixed reply of a path (for stateful wrappers).
func (f *fakeOLT) reply(path string) any {
	f.mu.Lock()
	h := f.handlers[path]
	f.mu.Unlock()
	return h(nil)
}

// handleFunc answers path with a computed reply (stateful fakes).
func (f *fakeOLT) handleFunc(path string, h func(body map[string]any) any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[path] = h
}

func (f *fakeOLT) client() *Client { return NewClient(f.srv.URL, "admin", "admin") }

// callsTo returns the recorded requests for one path.
func (f *fakeOLT) callsTo(path string) []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedCall
	for _, c := range f.calls {
		if c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeOLT) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// fakeCLI is a FOS telnet look-alike: Username/Password login, "OLT#"
// prompt, canned outputs per command (unknown commands print nothing).
type fakeCLI struct {
	ln       net.Listener
	mu       sync.Mutex
	outputs  map[string]string
	commands []string
}

func newFakeCLI(t *testing.T, outputs map[string]string) *fakeCLI {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCLI{ln: ln, outputs: outputs}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeCLI) serve(conn net.Conn) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("Welcome\r\nUsername:"))
	if _, err := rd.ReadString('\n'); err != nil {
		return
	}
	_, _ = conn.Write([]byte("Password:"))
	if _, err := rd.ReadString('\n'); err != nil {
		return
	}
	_, _ = conn.Write([]byte("\r\nOLT#"))
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		f.mu.Lock()
		f.commands = append(f.commands, cmd)
		out := f.outputs[cmd]
		f.mu.Unlock()
		_, _ = conn.Write([]byte(cmd + "\r\n" + out + "\r\nOLT#"))
	}
}

func (f *fakeCLI) cli() *CLI { return NewCLI(f.ln.Addr().String(), "admin", "admin") }

// richOLT scripts a fake OLT that exercises every existing collector branch:
// unsorted web ONU rows, a CLI-only ONU, empty port names, partial misc
// data, an empty first DNS server, an invalid route metric.
func richOLT(t *testing.T) *fakeOLT {
	f := newFakeOLT(t)
	f.handle("/goform/getSysStatus", map[string]any{
		"runTime": "3600", "cpuPercent": "42%", "memoryPercent": "61%",
		"temp1value": "55.0", "temp2value": "48.5", "fan1": "WORK     RPM: 6600",
		"deviceName": "GPON-OLT", "deviceLocation": "MA==", "mac": "0090.4C06.A427", "sn": "123456790",
		"softwareVersion": "1.1.3.18(release-000530)", "hardwareVersion": "V4.0",
		"temphi": "60", "templo": "-30", "dnsType": "manual", "preferredDNS": "223.5.5.5", "alternateDNS": "0.0.0.0",
		"ip": "192.168.100.100", "mask": "255.255.255.0", "ipType": "manul", "gateway": "192.168.100.1",
		"inbandip": "192.168.130.179", "inbandmask": "255.255.255.0", "mngvlan": "4000", "mnghost": "",
		"pon_not_start": 0,
		"port": []map[string]any{
			{"portNum": "1", "portName": "pon1", "portStatus": "1", "portSpeed": "2500", "online": "02", "offline": "01"},
			{"portNum": "", "portName": "", "portStatus": "1"},
			{"portNum": "2", "portName": "pon2", "portStatus": "0", "portSpeed": "x", "online": "0", "offline": "0"},
			{"portNum": "9", "portName": "ge1", "portStatus": "1", "portSpeed": "1000", "online": "", "offline": "3"},
			{"portNum": "10", "portName": "ge2", "portStatus": "2", "portSpeed": "1000"},
		},
	})
	f.handle("/goform/getOntListBrife", map[string]any{"list": []map[string]any{
		{"onuid": "0/1/2", "sn": "HWTC-00000002", "status": "online", "updowntime": "1d2h3m", "equipid": "PTF2164Q", "cfgstate": "Normal", "downcause": "-", "desc": "-"},
		{"onuid": "0/1/1", "sn": "HWTC-00000001", "status": "offline", "updowntime": "-", "equipid": "-", "cfgstate": "Normal", "downcause": "dying-gasp", "desc": "-"},
		{"sn": "no-id"},
	}, "ponPortList": []string{"pon1", "all"}})
	f.handle("/goform/getOntListOptical", map[string]any{"list": []map[string]any{
		{"onuid": "0/1/2", "sn": "HWTC-00000002", "vol": "3.30", "txpower": "2.30", "rxpower": "-19.20", "bias": "12.5", "temp": "45.0"},
		{"onuid": "0/1/1", "sn": "HWTC-00000001", "vol": "-", "txpower": "-", "rxpower": "-", "bias": "-", "temp": "-"},
	}})
	f.handle("/goform/getSystemLogList", map[string]any{"list": []map[string]any{
		{"index": "1", "logTime": "2024-01-01 12:00:00", "logType": "Info", "logTips": " System started "},
		{"index": "2", "logTime": "2024-01-01 12:01:00", "logType": "Warning", "logTips": "pon1 los"},
	}})
	f.handle("/goform/getLineprofileList", map[string]any{"list": []map[string]any{
		{"profileid": "1", "profilename": "default", "onttype": "SFU", "mapping_mode": "vlan", "traffic_mode": "car"},
	}})
	f.handle("/goform/getOntListConfig", map[string]any{"list": []map[string]any{
		{"onuid": "0/1/1", "mode": "sn", "info": "HWTC00000001", "lineid": "1", "desc": "first"},
		{"onuid": "0/1/2", "mode": "loid", "info": "LOID2", "lineid": "1", "desc": "second"},
	}})
	f.handle("/goform/getSystemTimeInfo", map[string]any{
		"systemTime": "2026-11-24 13:14:47", "currentTime": "2026-11-24 13:14:47", "timeType": "network",
		"timeZone": "0", "sntppserver": "pool.ntp.org", "sntpsserver": "",
	})
	f.handle("/goform/getAclList", map[string]any{"list": []map[string]any{
		{"aclId": "100", "remark": "mgmt", "type": "ipv4"},
		{"aclId": "7", "remark": "legacy", "type": "ipv4"},
	}})
	f.handle("/goform/getStaticRouteList", map[string]any{"list": []map[string]any{
		{"destIp": "10.0.0.0", "mask": "255.0.0.0", "nextHop": "192.168.100.254"},
		{"destIp": "172.16.0.0", "mask": "255.240.0.0", "nextHop": "192.168.100.253"},
	}})
	f.handle("/goform/getQvlanList", map[string]any{"list": []map[string]any{
		{"vlanId": "1", "remark": "default", "ip": "192.168.1.100", "mask": "255.255.255.0", "ipType": "static", "threeLayersEn": "1"},
		{"vlanId": "4000", "remark": "VLAN4000", "ip": "192.168.130.179", "mask": "255.255.255.0", "ipType": "static", "threeLayersEn": "1"},
		{"vlanId": "300", "remark": "svc", "ip": "", "mask": "", "ipType": "", "threeLayersEn": "0"},
	}})
	f.handle("/goform/getExportStatus", map[string]any{"errCode": "0"})
	return f
}

// richCLIOutputs answers the CLI commands the collector issues for richOLT.
func richCLIOutputs() map[string]string {
	return map[string]string{
		"show ont info online 0/1/1-0/1/64":  "ONT-ID  SN  UpTime  Config  Member\n0/1/2  HWTC-00000002  1d2h3m  Normal  working\n0/1/3  HWTC-00000003  0d0h5m  Normal  working\n",
		"show ont info offline 0/1/1-0/1/64": "0/1/1  HWTC-00000001  -  Normal  offline\n",
		"show ont optical-info 0/1/2":        "Power Feed Voltage(V)   : 3.30\nRX Optical Power(dBm)   : -19.20 (OLT TX: 9.510)\nTX Optical Power(dBm)   : 2.30\nLaser Bias Current(mA)  : 12.5\nTemperature(C)          : 45.0\nPort status is Enable, Linkup\n",
		"show ont optical-info 0/1/3":        "RX Optical Power(dBm)   : -\nTemperature(C)          : 40.0\n",
		"show alarm temperature":             "Temperature Alarm: 60'C (High)    -30'C (Low)\n",
	}
}
