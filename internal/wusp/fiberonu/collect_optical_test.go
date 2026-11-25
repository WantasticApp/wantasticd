package fiberonu

import (
	"context"
	"errors"
	"testing"

	"wantastic-agent/internal/wusp"
)

func phyExec(vals map[string]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) == 3 && args[0] == "get" && args[1] == "XPON_LinkCfg" && args[2] == "LinkSta" {
			if v, ok := vals["LinkSta"]; ok {
				return []byte(v + "\n"), nil
			}
			return []byte("1\n"), nil
		}
		if len(args) == 3 && args[0] == "get" && args[1] == "Info_PonPhy" {
			if v, ok := vals[args[2]]; ok {
				return []byte(v + "\n"), nil
			}
			return []byte("no attribute information\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
}

func onuFloat(t *testing.T, msg *wusp.Message, name string) (string, bool) {
	t.Helper()
	v, ok := msg.Get(wusp.WUSPONUPrefix + name)
	if !ok {
		return "", false
	}
	return wusp.ValueToString(v), true
}

// Readings from the lab ONU (HWTC93BB0308) through `tcapi get Info_PonPhy`,
// converted like the firmware's sta-network.asp.
func TestApplyPonPhyTcapi(t *testing.T) {
	msg := wusp.NewMessage()
	opts := Options{Exec: phyExec(map[string]string{
		"RxPower": "7190", "TxPower": "17328", "SupplyVoltage": "33150",
		"TxBiasCurrent": "4250", "Temperature": "11776",
	})}
	applyPonPhyTcapi(context.Background(), opts, msg)
	want := map[string]string{
		"RxPower": "-1.4", "TxPower": "2.4", "Voltage": "3.315", "BiasCurrent": "8.5", "Temperature": "46",
	}
	for k, w := range want {
		if got, ok := onuFloat(t, msg, k); !ok || got != w {
			t.Errorf("%s = %q (set %v), want %q", k, got, ok, w)
		}
	}
}

func TestApplyPonPhyTcapiNegativeTemperature(t *testing.T) {
	msg := wusp.NewMessage()
	applyPonPhyTcapi(context.Background(), Options{Exec: phyExec(map[string]string{"Temperature": "64768"})}, msg)
	if got, _ := onuFloat(t, msg, "Temperature"); got != "-3" {
		t.Fatalf("Temperature = %q, want -3", got)
	}
}

// A down link reads 0 or N/A: nothing may be published, so the console shows
// "no reading" instead of an invented level.
func TestApplyPonPhyTcapiNoSignal(t *testing.T) {
	msg := wusp.NewMessage()
	applyPonPhyTcapi(context.Background(), Options{Exec: phyExec(map[string]string{
		"RxPower": "0", "TxPower": "N/A", "SupplyVoltage": "junk",
	})}, msg)
	for _, k := range []string{"RxPower", "TxPower", "Voltage", "BiasCurrent", "Temperature"} {
		if v, ok := onuFloat(t, msg, k); ok {
			t.Errorf("%s set to %q, want unset", k, v)
		}
	}
}

// With the PON link down the module reports noise; no optical power may be
// published (sta-network.asp shows "-" in that state too).
func TestApplyPonPhyTcapiLinkDown(t *testing.T) {
	msg := wusp.NewMessage()
	applyPonPhyTcapi(context.Background(), Options{Exec: phyExec(map[string]string{
		"LinkSta": "0", "RxPower": "1", "TxPower": "17176", "Temperature": "11471",
	})}, msg)
	for _, k := range []string{"RxPower", "TxPower"} {
		if v, ok := onuFloat(t, msg, k); ok {
			t.Errorf("%s = %q with link down, want unset", k, v)
		}
	}
	if got, _ := onuFloat(t, msg, "Temperature"); got != "44.8" {
		t.Errorf("Temperature = %q, want 44.8 (module health still readable)", got)
	}
}

func TestApplyPonPhyTcapiInf(t *testing.T) {
	msg := wusp.NewMessage()
	applyPonPhyTcapi(context.Background(), Options{Exec: phyExec(map[string]string{"RxPower": "Inf", "TxPower": "+Inf"})}, msg)
	for _, k := range []string{"RxPower", "TxPower"} {
		if v, ok := onuFloat(t, msg, k); ok {
			t.Errorf("%s = %q from Inf, want unset", k, v)
		}
	}
}
