package fiberolt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestSetOLTParamEnable(t *testing.T) {
	srv := fakeOLTServer(t)
	defer srv.Close()
	api := NewClient(srv.URL, "admin", "admin")

	var saved bool
	err := SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"Enable", wusp.Bool(false), func(v bool) error {
		saved = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved {
		t.Fatal("expected saved=false")
	}

	err = SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"Enable", wusp.Bool(true), func(v bool) error {
		saved = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !saved {
		t.Fatal("expected saved=true")
	}
}

func TestSetOLTParamUnsupported(t *testing.T) {
	srv := fakeOLTServer(t)
	defer srv.Close()
	api := NewClient(srv.URL, "admin", "admin")

	err := SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"Temperature", wusp.String("99"), nil)
	if err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("expected ErrUSPPathUnsupported, got %v", err)
	}
}

func TestSetOLTParamONUEnable(t *testing.T) {
	var gotAction string
	var gotIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/goform/getOntListBrife":
			json.NewEncoder(w).Encode(OntList{
				List: []OntEntry{
					{"onuid": "0/1/1", "sn": "HWTC93BB0308", "status": "online"},
				},
			})
		case "/goform/setOntListActive":
			gotAction = "active"
			json.NewEncoder(w).Encode(map[string]string{})
		case "/goform/setOntListDeactive":
			gotAction = "deactive"
			json.NewEncoder(w).Encode(map[string]string{})
		default:
			http.NotFound(w, r)
		}
		_ = gotIDs
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")

	// Disable ONU.1 → deactive
	err := SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"ONU.1.Enable", wusp.Bool(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotAction != "deactive" {
		t.Fatalf("expected deactive, got %q", gotAction)
	}

	// Enable ONU.1 → active
	err = SetOLTParam(context.Background(), api, wusp.WUSPOLTPrefix+"ONU.1.Enable", wusp.Bool(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotAction != "active" {
		t.Fatalf("expected active, got %q", gotAction)
	}
}

func TestOLTOperateReboot(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/goform/setSystemReboot":
			called = true
			json.NewEncoder(w).Encode(map[string]string{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	err := OLTOperate(context.Background(), api, wusp.WUSPOLTRebootCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("setSystemReboot was not called")
	}
}

func TestOLTOperateFactoryRestore(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/goform/setSystemRestore":
			called = true
			json.NewEncoder(w).Encode(map[string]string{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	err := OLTOperate(context.Background(), api, wusp.WUSPOLTFactoryRestoreCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("setSystemRestore was not called")
	}
}

func TestOLTOperateONUReboot(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/goform/setOntListReboot":
			gotPath = r.URL.Path
			json.NewEncoder(w).Encode(map[string]string{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	input := wusp.NewMessage()
	input.Set("Index", wusp.String("0/1/1"))
	err := OLTOperate(context.Background(), api, wusp.WUSPOLTONURebootCommand, input)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/goform/setOntListReboot" {
		t.Fatalf("expected setOntListReboot, got %q", gotPath)
	}
}

func TestOLTOperateBackupConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/Auth":
			json.NewEncoder(w).Encode(map[string]string{"errCode": "success"})
		case "/cgi-bin/DownloadCfg/olt_config.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hostname OLT-1\ninterface pon1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api := NewClient(srv.URL, "admin", "admin")
	result := wusp.NewMessage()
	err := OLTOperate(context.Background(), api, wusp.WUSPOLTBackupConfigCommand, result)
	if err != nil {
		t.Fatal(err)
	}
	val, ok := result.Get(wusp.WUSPOLTPrefix + "Config")
	if !ok {
		t.Fatal("Config field not set in result")
	}
	text := wusp.ValueToString(val)
	if text != "hostname OLT-1\ninterface pon1\n" {
		t.Fatalf("unexpected config text: %q", text)
	}
}

func TestOLTOperateUnsupported(t *testing.T) {
	srv := fakeOLTServer(t)
	defer srv.Close()
	api := NewClient(srv.URL, "admin", "admin")
	err := OLTOperate(context.Background(), api, "Device.WUSP_OLT.FakeCommand()", nil)
	if err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("expected ErrUSPPathUnsupported, got %v", err)
	}
}
