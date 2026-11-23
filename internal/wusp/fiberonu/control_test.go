package fiberonu

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestSetONUParamEnable(t *testing.T) {
	var saved bool
	err := SetONUParam(Options{}, wusp.WUSPONUPrefix+"Enable", wusp.Bool(false), func(v bool) error {
		saved = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved {
		t.Fatal("expected saved=false")
	}

	err = SetONUParam(Options{}, wusp.WUSPONUPrefix+"Enable", wusp.Bool(true), func(v bool) error {
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

func TestSetONUParamUnsupported(t *testing.T) {
	err := SetONUParam(Options{}, wusp.WUSPONUPrefix+"Temperature", wusp.String("99"), nil)
	if err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("expected ErrUSPPathUnsupported, got %v", err)
	}
}

func TestSetONUParamEnableNilCallback(t *testing.T) {
	err := SetONUParam(Options{}, wusp.WUSPONUPrefix+"Enable", wusp.Bool(true), nil)
	if err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("expected ErrUSPPathUnsupported with nil callback, got %v", err)
	}
}

func TestONUOperateReboot(t *testing.T) {
	var gotPath string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := Options{CGIBaseURL: srv.URL}
	err := ONUOperate(context.Background(), opts, wusp.WUSPONURebootCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/cgi-bin/mag-reset.asp" {
		t.Fatalf("expected /cgi-bin/mag-reset.asp, got %q", gotPath)
	}
	if gotBody == "" {
		t.Fatal("expected form body")
	}
}

func TestONUOperateFactoryRestore(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := Options{CGIBaseURL: srv.URL}
	err := ONUOperate(context.Background(), opts, wusp.WUSPONUFactoryRestoreCommand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/cgi-bin/mag-reset.asp" {
		t.Fatalf("expected /cgi-bin/mag-reset.asp, got %q", gotPath)
	}
}

func TestONUOperateUnsupported(t *testing.T) {
	opts := Options{CGIBaseURL: "http://127.0.0.1:1"}
	err := ONUOperate(context.Background(), opts, "Device.WUSP_ONU.FakeCommand()", nil)
	if err != wusp.ErrUSPPathUnsupported {
		t.Fatalf("expected ErrUSPPathUnsupported, got %v", err)
	}
}

func TestONUOperateUpgradeNoFileName(t *testing.T) {
	opts := Options{CGIBaseURL: "http://127.0.0.1:1"}
	err := ONUOperate(context.Background(), opts, wusp.WUSPONUUpgradeCommand, nil)
	if err == nil {
		t.Fatal("expected error for missing FileName")
	}
}

func TestOperateInputString(t *testing.T) {
	msg := wusp.NewMessage()
	msg.Set("Device.WUSP_ONU.Upgrade().FileName", wusp.String("firmware.bin"))

	got := OperateInputString(msg, "FileName")
	if got != "firmware.bin" {
		t.Fatalf("OperateInputString=%q want 'firmware.bin'", got)
	}

	got = OperateInputString(msg, "Nonexistent")
	if got != "" {
		t.Fatalf("OperateInputString(Nonexistent)=%q want ''", got)
	}

	got = OperateInputString(nil, "FileName")
	if got != "" {
		t.Fatalf("OperateInputString(nil)=%q want ''", got)
	}
}
