package wusp

import (
	"bytes"
	"testing"
)

func TestSpectralSampleBlockRoundTrip(t *testing.T) {
	samples := []SpectralSample{
		{TimestampMicros: 0xfffffff0, RSSI: -60, NoiseFloor: -95, MaxIndex: 12, Bins: []byte{10, 20, 30, 250}},
		{TimestampMicros: 0x00000010, RSSI: -61, NoiseFloor: -96, MaxIndex: 13, Bins: []byte{11, 19, 30, 5}},
		{TimestampMicros: 0x00000200, RSSI: 4, NoiseFloor: -94, MaxIndex: 3, Bins: []byte{11, 19, 31, 255}},
	}
	data, err := EncodeSpectralSampleBlock(samples)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeSpectralSampleBlock(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(samples) {
		t.Fatalf("got %d samples, want %d", len(got), len(samples))
	}
	for i := range samples {
		want, have := samples[i], got[i]
		if want.TimestampMicros != have.TimestampMicros || want.RSSI != have.RSSI || want.NoiseFloor != have.NoiseFloor || want.MaxIndex != have.MaxIndex || !bytes.Equal(want.Bins, have.Bins) {
			t.Fatalf("sample %d mismatch: got %+v want %+v", i, have, want)
		}
	}
}

func TestSpectralSampleBlockRejectsInconsistentBins(t *testing.T) {
	_, err := EncodeSpectralSampleBlock([]SpectralSample{{Bins: []byte{1, 2}}, {Bins: []byte{1}}})
	if err == nil {
		t.Fatal("expected error for mismatched bin counts")
	}
}

func TestSpectralSampleBlockRejectsTruncated(t *testing.T) {
	data, err := EncodeSpectralSampleBlock([]SpectralSample{{Bins: []byte{1, 2, 3}}})
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(data); n++ {
		if _, err := DecodeSpectralSampleBlock(data[:n]); err == nil {
			t.Fatalf("expected error for %d-byte prefix", n)
		}
	}
}

func TestSpectralTelemetryParamsRegistered(t *testing.T) {
	for _, param := range AllWUSPSpectralTelemetryParams {
		if _, ok := RuntimeDevice().GetParam(param.Path); !ok {
			t.Fatalf("%s missing from runtime device model", param.Path)
		}
	}
	if _, ok := LookupBroadbandDataModel("wusp-spectral-telemetry"); !ok {
		t.Fatal("spectral telemetry data model not registered")
	}
}

func TestSpectralBinsSurviveMessageRoundTrip(t *testing.T) {
	bins := []byte{0, 1, 0, 255, 0}
	msg := &Message{}
	msg.Set(WUSPSpectralTelemetryPrefix+"Radio.1.BinMax", Bytes(bins))
	if err := ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	encoded, err := EncodeMessage(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	value, ok := decoded.Get(WUSPSpectralTelemetryPrefix + "Radio.1.BinMax")
	if !ok || !bytes.Equal(value.AsBytes(), bins) {
		t.Fatalf("bins did not survive round trip: %v", value.AsBytes())
	}
	if got := ValueToString(value); got != "000100ff00" {
		t.Fatalf("ValueToString = %q, want hex", got)
	}
}

// Sample blocks arrive from devices: corrupt or truncated input must be
// rejected without panicking or allocating beyond the declared caps.
func FuzzDecodeSpectralSampleBlock(f *testing.F) {
	valid, err := EncodeSpectralSampleBlock([]SpectralSample{
		{TimestampMicros: 10, RSSI: -60, NoiseFloor: -95, MaxIndex: 3, Bins: []byte{1, 2, 3, 4}},
		{TimestampMicros: 20, RSSI: -61, NoiseFloor: -96, MaxIndex: 1, Bins: []byte{4, 3, 2, 1}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{'S', 'B', 1, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0x0f})
	for n := range valid {
		f.Add(valid[:n])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		samples, err := DecodeSpectralSampleBlock(data)
		if err == nil && len(samples) > SpectralMaxSamplesPerBlock {
			t.Fatalf("decoded %d samples", len(samples))
		}
		for _, s := range samples {
			if len(s.Bins) > SpectralMaxBins {
				t.Fatalf("decoded %d bins", len(s.Bins))
			}
		}
	})
}
