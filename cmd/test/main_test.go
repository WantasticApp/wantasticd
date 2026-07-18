package main

import (
	"errors"
	"testing"

	"wantastic-agent/internal/modem"
	"wantastic-agent/internal/wusp"
)

type fakeController struct {
	action string
	dev    string
	a      string
	b      string
}

func (f *fakeController) Discover() ([]string, error)         { return []string{"/dev/ttyUSB2"}, nil }
func (f *fakeController) GetInfo(string) (*modem.Info, error) { return &modem.Info{}, nil }
func (f *fakeController) GetSignal(string) (*modem.SignalQuality, error) {
	return &modem.SignalQuality{}, nil
}
func (f *fakeController) Connect(dev, apn string) error {
	f.action, f.dev, f.a = "connect", dev, apn
	return nil
}
func (f *fakeController) Disconnect(dev string) error {
	f.action, f.dev = "disconnect", dev
	return nil
}
func (f *fakeController) Close() error                                    { return nil }
func (f *fakeController) SetFunctionality(string, string) error           { return nil }
func (f *fakeController) SetSIMSlot(string, int) error                    { return nil }
func (f *fakeController) SetIMEI(string, string) error                    { return nil }
func (f *fakeController) SetAPNProfile(string, int, string, string) error { return nil }
func (f *fakeController) SetGNSS(dev string, enabled bool) error {
	f.action, f.dev = "gnss-stop", dev
	if enabled {
		f.action = "gnss-start"
	}
	return nil
}
func (f *fakeController) GetGNSS(string) (*modem.GNSSInfo, error) { return &modem.GNSSInfo{}, nil }
func (f *fakeController) SendSMS(dev, phone, text string) error {
	f.action, f.dev, f.a, f.b = "sms-send", dev, phone, text
	return nil
}
func (f *fakeController) ListSMS(string) (string, error) { return "[]", nil }
func (f *fakeController) DeleteSMS(dev, index string) error {
	f.action, f.dev, f.a = "sms-delete", dev, index
	return nil
}

func TestRunActionRoutesExplicitMutations(t *testing.T) {
	f := &fakeController{}
	if err := runAction(f, "/dev/ttyUSB2", "sms-send", "+212600000000", "probe", "", ""); err != nil {
		t.Fatal(err)
	}
	if f.action != "sms-send" || f.dev != "/dev/ttyUSB2" || f.a != "+212600000000" || f.b != "probe" {
		t.Fatalf("unexpected action: %+v", f)
	}
	if err := runAction(f, "/dev/ttyUSB2", "gnss-start", "", "", "", ""); err != nil || f.action != "gnss-start" {
		t.Fatalf("GNSS start: action=%q err=%v", f.action, err)
	}
	if err := runAction(f, "/dev/ttyUSB2", "invalid", "", "", "", ""); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestMessageFieldsAreStableAndInspectable(t *testing.T) {
	msg := wusp.NewMessage()
	msg.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(1))
	msg.Set("Device.Cellular.RoamingEnabled", wusp.Bool(true))
	got := messageFields(msg)
	if len(got) != 2 || got[0].Path != "Device.Cellular.InterfaceNumberOfEntries" || got[1].Path != "Device.Cellular.RoamingEnabled" {
		t.Fatalf("fields not sorted: %+v", got)
	}
}

func TestFakeControllerSatisfiesControlContract(t *testing.T) {
	var ctl modem.Controller = &fakeController{}
	if _, ok := ctl.(modem.ControlController); !ok {
		t.Fatal(errors.New("diagnostic action controller lost control support"))
	}
}
