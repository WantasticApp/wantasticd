package platforms

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"wantastic-agent/internal/qcaspectral"
	"wantastic-agent/internal/wusp"
)

func TestAppendSpectralSnapshotFieldsUnsupported(t *testing.T) {
	msg := &wusp.Message{}
	if err := appendSpectralSnapshotFields(msg, spectralSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := msg.Get(wusp.WUSPSpectralTelemetryPrefix + "Status"); v.AsString() != "Unsupported" {
		t.Fatalf("status = %q", v.AsString())
	}
	if len(msg.Fields) != 3 {
		t.Fatalf("unsupported builds must stay minimal, got %d fields", len(msg.Fields))
	}
}

func TestAppendSpectralSnapshotFieldsReady(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x03, 0x7f, 0x01, 0x02, 0x03}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	samples := []qcaspectral.Sample{
		{Frequency: 5180, ChannelWidth: 80, RSSI: -40, NoiseFloor: -96, TimestampMicros: 10, Bins: []byte{10, 20, 30}},
		{Frequency: 5180, ChannelWidth: 80, RSSI: -42, NoiseFloor: -95, TimestampMicros: 20, Bins: []byte{12, 18, 31}},
		{Frequency: 5180, ChannelWidth: 80, RSSI: -44, NoiseFloor: -90, TimestampMicros: 30, Bins: []byte{11, 25, 29}},
	}
	msg := &wusp.Message{}
	msg.Set("Device.WiFi.Radio.2.Name", wusp.String("wifi1"))
	err := appendSpectralSnapshotFields(msg, spectralSnapshot{
		Supported:   true,
		Discovered:  true,
		LastCapture: now,
		Radios: []spectralRadioSnapshot{{
			Radio:       qcaspectral.Radio{Interface: "wifi1", MAC: mac, Caps: qcaspectral.Caps{Spectral: true, Advanced: true}},
			Status:      "Ready",
			Result:      qcaspectral.Result{Layout: qcaspectral.LayoutCMN, Samples: samples, Started: now.Add(-time.Second), Completed: now},
			CollectedAt: now,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("emitted spectral fields violate schema: %v", err)
	}
	p := wusp.WUSPSpectralTelemetryPrefix + "Radio.1."
	expectString(t, msg, wusp.WUSPSpectralTelemetryPrefix+"Status", "Ready")
	expectString(t, msg, p+"RadioReference", "Device.WiFi.Radio.2.")
	expectString(t, msg, p+"SampleLayout", "qca-cmn")
	if v, _ := msg.Get(p + "NoiseFloor"); v.AsInt() != -95 {
		t.Fatalf("median noise floor = %d", v.AsInt())
	}
	if v, _ := msg.Get(p + "BinMax"); !bytes.Equal(v.AsBytes(), []byte{12, 25, 31}) {
		t.Fatalf("BinMax = %v", v.AsBytes())
	}
	if v, _ := msg.Get(p + "BinAverage"); !bytes.Equal(v.AsBytes(), []byte{11, 21, 30}) {
		t.Fatalf("BinAverage = %v", v.AsBytes())
	}
	block, _ := msg.Get(p + "SampleBlock")
	decoded, err := wusp.DecodeSpectralSampleBlock(block.AsBytes())
	if err != nil || len(decoded) != 3 || !bytes.Equal(decoded[2].Bins, samples[2].Bins) {
		t.Fatalf("sample block round trip failed: %v %+v", err, decoded)
	}
}

func expectString(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	if v, ok := msg.Get(path); !ok || v.AsString() != want {
		t.Fatalf("%s = %q, want %q", path, v.AsString(), want)
	}
}

func TestSpectralCoordinatorRunsInBackgroundAndRateLimits(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	release := make(chan struct{})
	captures := 0
	c := &spectralCoordinator{
		supported: true,
		now:       clock,
		discover: func(string) ([]qcaspectral.Radio, error) {
			return []qcaspectral.Radio{{Interface: "wifi0"}}, nil
		},
		capture: func(context.Context, qcaspectral.Radio, qcaspectral.CaptureOptions) (qcaspectral.Result, error) {
			<-release
			mu.Lock()
			captures++
			mu.Unlock()
			return qcaspectral.Result{Samples: []qcaspectral.Sample{{Bins: []byte{1}}}}, nil
		},
	}
	if snap := c.snapshotAndTrigger(""); !snap.Capturing {
		t.Fatal("first read must start a background capture without blocking")
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		snap := c.snapshotAndTrigger("")
		if !snap.Capturing && len(snap.Radios) == 1 {
			if snap.Radios[0].Status != "Ready" {
				t.Fatalf("radio status = %q", snap.Radios[0].Status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("capture did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.snapshotAndTrigger("")
	mu.Lock()
	defer mu.Unlock()
	if captures != 1 {
		t.Fatalf("reads inside the capture interval must not recapture, got %d captures", captures)
	}
}
