package agent

import (
	"context"
	"errors"
	"testing"

	"wantastic-agent/internal/wusp"
)

type spectralOperateBackend struct {
	easyMeshOperateBackend
	requests int
	onDone   func()
	err      error
}

func (b *spectralOperateBackend) RequestSpectralCapture(onDone func()) (bool, error) {
	b.requests++
	b.onDone = onDone
	return b.err == nil, b.err
}

func TestUSPRuntimeSpectralCaptureOperate(t *testing.T) {
	const command = "Device.WUSP_SpectralTelemetry.Capture()"
	tests := []struct {
		name       string
		backend    wusp.DataBackend
		wantErr    error
		wantStatus string
	}{
		{"capable backend", &spectralOperateBackend{}, nil, "Capturing"},
		{"backend refuses", &spectralOperateBackend{err: errors.New("spectral capture is not available on this device")}, nil, ""},
		{"backend without spectral", &easyMeshOperateBackend{}, wusp.ErrUSPPathUnsupported, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := newTestUSPRuntime(t)
			runtime.rawBackend = tt.backend
			// Keep the test off the persistent on-disk cache.
			runtime.dataModelCache = nil
			output, err := runtime.handleOperate(context.Background(), command, nil, nil)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err=%v, want %v", err, tt.wantErr)
				}
				return
			}
			spectral, _ := tt.backend.(*spectralOperateBackend)
			if spectral.err != nil {
				if err == nil {
					t.Fatal("backend refusal must surface as an Operate error")
				}
				return
			}
			if err != nil {
				t.Fatalf("handleOperate: %v", err)
			}
			if spectral.requests != 1 || spectral.onDone == nil {
				t.Fatalf("requests=%d onDone set=%t", spectral.requests, spectral.onDone != nil)
			}
			status, ok := output.Get(wusp.WUSPSpectralTelemetryPrefix + "Status")
			if !ok || status.AsString() != tt.wantStatus {
				t.Fatalf("status=%v present=%t", status, ok)
			}
			// The completion callback must be safe without a cache.
			spectral.onDone()
		})
	}
}
