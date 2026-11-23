package fiberolt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestCollectOLTMgmtInterface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
		case "/goform/getLanIpMask":
			json.NewEncoder(w).Encode(map[string]string{
				"ip": "192.168.100.1", "mask": "255.255.255.0",
			})
		case "/goform/getSysMisc":
			json.NewEncoder(w).Encode(map[string]string{
				"gateway": "192.168.100.254", "mac": "AA:BB:CC:DD:EE:FF",
				"status": "up",
			})
		case "/goform/getSystemTimeInfo":
			json.NewEncoder(w).Encode(map[string]string{
				"dnsServer1": "8.8.8.8", "dnsServer2": "8.8.4.4",
				"ntpServer": "pool.ntp.org", "ntpEnable": "1",
			})
		case "/goform/getAclList":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]string{
					{"id": "1", "name": "allow-ssh", "action": "permit", "protocol": "tcp", "dstPort": "22"},
				},
			})
		case "/goform/getStaticRouteList":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]string{
					{"destination": "10.0.0.0", "mask": "255.0.0.0", "gateway": "192.168.100.254", "interface": "eth0", "metric": "10"},
				},
			})
		case "/goform/getServicePort":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]string{
					{"ponPort": "pon1", "onuId": "0/1/1", "gemport": "1", "svlan": "4000", "cvlan": "100", "vlanmode": "tag"},
				},
			})
		case "/goform/getQvlanList":
			json.NewEncoder(w).Encode(map[string]any{
				"list": []map[string]string{
					{"id": "1", "name": "service", "startvlan": "4000", "endvlan": "4000", "vlanEn": "1"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	msg := wusp.NewMessage()
	ctx := context.Background()

	CollectOLTNetwork(ctx, api, msg)

	assertField := func(path, want string) {
		t.Helper()
		v, ok := msg.Get(path)
		if !ok {
			t.Errorf("missing %s", path)
			return
		}
		got := wusp.ValueToString(v)
		if got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}

	assertField(oltNetPrefix+"Mgmt.IPAddress", "192.168.100.1")
	assertField(oltNetPrefix+"Mgmt.SubnetMask", "255.255.255.0")
	assertField(oltNetPrefix+"Mgmt.Gateway", "192.168.100.254")
	assertField(oltNetPrefix+"Mgmt.MACAddress", "AA:BB:CC:DD:EE:FF")
	assertField(oltNetPrefix+"Mgmt.Status", "up")

	assertField(oltNetPrefix+"DNS.Server.1.Address", "8.8.8.8")
	assertField(oltNetPrefix+"DNS.Server.2.Address", "8.8.4.4")
	assertField(oltNetPrefix+"DNS.ServerNumberOfEntries", "2")
	assertField(oltNetPrefix+"NTP.Server", "pool.ntp.org")

	v, ok := msg.Get(oltNetPrefix + "NTP.Enabled")
	if !ok || !v.AsBool() {
		t.Errorf("NTP.Enabled should be true")
	}

	assertField(oltNetPrefix+"ACLNumberOfEntries", "1")
	assertField(oltNetPrefix+"ACL.1.Name", "allow-ssh")
	assertField(oltNetPrefix+"ACL.1.Action", "permit")

	assertField(oltNetPrefix+"RouteNumberOfEntries", "1")
	assertField(oltNetPrefix+"Route.1.Destination", "10.0.0.0")
	assertField(oltNetPrefix+"Route.1.Gateway", "192.168.100.254")

	// Service ports (VLAN4000 mapping)
	assertField(oltNetPrefix+"ServicePortNumberOfEntries", "1")
	assertField(oltNetPrefix+"ServicePort.1.PONPort", "pon1")
	assertField(oltNetPrefix+"ServicePort.1.OnuID", "0/1/1")
	assertField(oltNetPrefix+"ServicePort.1.GEMPort", "1")
	assertField(oltNetPrefix+"ServicePort.1.SVLAN", "4000")
	assertField(oltNetPrefix+"ServicePort.1.CVLAN", "100")
	assertField(oltNetPrefix+"ServicePort.1.VLANMode", "tag")

	// Q-VLANs
	assertField(oltNetPrefix+"QVLANNumberOfEntries", "1")
	assertField(oltNetPrefix+"QVLAN.1.ID", "1")
	assertField(oltNetPrefix+"QVLAN.1.Name", "service")
	assertField(oltNetPrefix+"QVLAN.1.StartVLAN", "4000")
	assertField(oltNetPrefix+"QVLAN.1.EndVLAN", "4000")

	v2, ok2 := msg.Get(oltNetPrefix + "QVLAN.1.Enabled")
	if !ok2 || !v2.AsBool() {
		t.Errorf("QVLAN.1.Enabled should be true")
	}
}

func TestSetOLTNetworkParam(t *testing.T) {
	var lastPath string
	var lastBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/Auth" {
			json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
			return
		}
		lastPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&lastBody)
		json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	ctx := context.Background()

	tests := []struct {
		path      string
		value     string
		wantPath  string
		wantField string
	}{
		{wusp.WUSPOLTPrefix + "Network.Mgmt.IPAddress", "10.0.0.1", "/goform/setQuickCfgNetwork", "ip"},
		{wusp.WUSPOLTPrefix + "Network.DNS.Server.1.Address", "1.1.1.1", "/goform/setSystemTimeInfo", "dnsServer1"},
		{wusp.WUSPOLTPrefix + "Network.NTP.Server", "time.google.com", "/goform/setSystemTimeInfo", "ntpServer"},
	}

	for _, tt := range tests {
		lastPath = ""
		lastBody = nil
		err := SetOLTNetworkParam(ctx, api, tt.path, wusp.String(tt.value))
		if err != nil {
			t.Errorf("SetOLTNetworkParam(%q) = %v", tt.path, err)
			continue
		}
		if lastPath != tt.wantPath {
			t.Errorf("SetOLTNetworkParam(%q): called %q, want %q", tt.path, lastPath, tt.wantPath)
		}
	}
}

func TestOLTNetworkOperateACL(t *testing.T) {
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/Auth" {
			json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
			return
		}
		lastPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	ctx := context.Background()

	input := wusp.NewMessage()
	input.Set("Name", wusp.String("block-telnet"))
	input.Set("Action", wusp.String("deny"))
	input.Set("Protocol", wusp.String("tcp"))
	input.Set("DstPort", wusp.String("23"))

	err := OLTNetworkOperate(ctx, api, wusp.WUSPOLTPrefix+"Network.ACL.Add()", input)
	if err != nil {
		t.Fatalf("ACL.Add: %v", err)
	}
	if lastPath != "/goform/setAclListInfo" {
		t.Errorf("ACL.Add called %q, want /goform/setAclListInfo", lastPath)
	}
}

func TestOLTNetworkOperateServicePort(t *testing.T) {
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/Auth" {
			json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
			return
		}
		lastPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	ctx := context.Background()

	input := wusp.NewMessage()
	input.Set("PONPort", wusp.String("pon1"))
	input.Set("OnuID", wusp.String("0/1/1"))
	input.Set("GEMPort", wusp.String("1"))
	input.Set("SVLAN", wusp.String("4000"))
	input.Set("CVLAN", wusp.String("100"))
	input.Set("VLANMode", wusp.String("tag"))

	err := OLTNetworkOperate(ctx, api, wusp.WUSPOLTPrefix+"Network.ServicePort.Add()", input)
	if err != nil {
		t.Fatalf("ServicePort.Add: %v", err)
	}
	if lastPath != "/goform/setServicePort" {
		t.Errorf("ServicePort.Add called %q, want /goform/setServicePort", lastPath)
	}
}

func TestOLTNetworkOperateQVLAN(t *testing.T) {
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/Auth" {
			json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
			return
		}
		lastPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"errCode": "success"})
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	ctx := context.Background()

	input := wusp.NewMessage()
	input.Set("StartVLAN", wusp.String("4000"))
	input.Set("EndVLAN", wusp.String("4000"))

	err := OLTNetworkOperate(ctx, api, wusp.WUSPOLTPrefix+"Network.QVLAN.Add()", input)
	if err != nil {
		t.Fatalf("QVLAN.Add: %v", err)
	}
	if lastPath != "/goform/setQvlanInfo" {
		t.Errorf("QVLAN.Add called %q, want /goform/setQvlanInfo", lastPath)
	}
}
