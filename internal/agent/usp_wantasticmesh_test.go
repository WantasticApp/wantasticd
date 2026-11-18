package agent

import (
	"context"
	"errors"
	"testing"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms"
)

type wantasticMeshOperateBackend struct {
	easyMeshOperateBackend
	restarts int
	kind     string
	change   platforms.WantasticMeshRadioChange
}

func (b *wantasticMeshOperateBackend) RestartWantasticMesh(context.Context) error {
	b.restarts++
	return nil
}

func (b *wantasticMeshOperateBackend) SetWantasticMeshChannel(_ context.Context, change platforms.WantasticMeshRadioChange) (string, string, error) {
	b.kind, b.change = "channel", change
	return "36", "149", nil
}

func (b *wantasticMeshOperateBackend) SetWantasticMeshTxPower(_ context.Context, change platforms.WantasticMeshRadioChange) (string, string, error) {
	b.kind, b.change = "txpower", change
	return "20", "17", nil
}

func TestUSPRuntimeWantasticMeshOperate(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	backend := &wantasticMeshOperateBackend{}
	runtime.rawBackend = backend
	p := wusp.WUSPWantasticMeshPrefix

	output, err := runtime.handleOperate(context.Background(), "Device.WUSP_WantasticMesh.Restart()", nil, nil)
	if err != nil || backend.restarts != 1 {
		t.Fatalf("restart err=%v restarts=%d", err, backend.restarts)
	}
	if status, _ := output.Get(p + "LastOperationStatus"); status.AsString() != "Success" {
		t.Fatalf("restart status=%v", status)
	}

	input := wusp.NewMessage()
	input.Set(p+"Radio.Interface", wusp.String("ath1"))
	input.Set(p+"Radio.Channel", wusp.Uint(149))
	input.Set(p+"Radio.RevertSeconds", wusp.Uint(120))
	if err := wusp.ValidateMessageFast(input); err != nil {
		t.Fatalf("hub-style inputs do not validate: %v", err)
	}
	output, err = runtime.handleOperate(context.Background(), "Device.WUSP_WantasticMesh.Radio.SetChannel()", input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if backend.kind != "channel" || backend.change != (platforms.WantasticMeshRadioChange{Interface: "ath1", Value: 149, RevertSeconds: 120}) {
		t.Fatalf("channel change=%s %+v", backend.kind, backend.change)
	}
	before, _ := output.Get(p + "Radio.Before")
	after, _ := output.Get(p + "Radio.After")
	if before.AsString() != "36" || after.AsString() != "149" {
		t.Fatalf("before=%v after=%v", before, after)
	}
	if err := wusp.ValidateMessageFast(output); err != nil {
		t.Fatalf("output does not validate: %v", err)
	}

	input = wusp.NewMessage()
	input.Set(p+"Radio.Interface", wusp.String("ath0"))
	input.Set(p+"Radio.Power", wusp.Int(17))
	input.Set(p+"Radio.Probe", wusp.Bool(true))
	if _, err := runtime.handleOperate(context.Background(), "Device.WUSP_WantasticMesh.Radio.SetTxPower()", input, nil); err != nil {
		t.Fatal(err)
	}
	if backend.kind != "txpower" || backend.change != (platforms.WantasticMeshRadioChange{Interface: "ath0", Value: 17, RevertSeconds: 60, Probe: true}) {
		t.Fatalf("txpower change=%s %+v", backend.kind, backend.change)
	}

	// Missing or malformed inputs never reach the backend.
	backend.kind = ""
	for _, tc := range []map[string]wusp.Value{
		{"Radio.Channel": wusp.Uint(36)},
		{"Radio.Interface": wusp.String("ath0")},
		{"Radio.Interface": wusp.String("ath0"), "Radio.Channel": wusp.String("36; reboot")},
		{"Radio.Interface": wusp.String("ath0"), "Radio.Channel": wusp.Uint(36), "Radio.RevertSeconds": wusp.String("soon")},
		{"Radio.Interface": wusp.String("ath0"), "Radio.Channel": wusp.Uint(36), "Radio.Probe": wusp.String("maybe")},
	} {
		input = wusp.NewMessage()
		for leaf, value := range tc {
			input.Set(p+leaf, value)
		}
		if _, err := runtime.handleOperate(context.Background(), "Device.WUSP_WantasticMesh.Radio.SetChannel()", input, nil); err == nil {
			t.Errorf("accepted %+v", tc)
		}
	}
	if backend.kind != "" {
		t.Fatalf("invalid input reached the backend: %+v", backend.change)
	}

	// A backend without WantasticMesh reports the command as unsupported.
	runtime.rawBackend = &easyMeshOperateBackend{}
	if _, err := runtime.handleOperate(context.Background(), "Device.WUSP_WantasticMesh.Restart()", nil, nil); !errors.Is(err, wusp.ErrUSPPathUnsupported) {
		t.Fatalf("unsupported backend err=%v", err)
	}
}
