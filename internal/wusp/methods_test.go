package wusp

import (
	"sync"
	"testing"
	"time"
)

type methodsBenchmarkFixture struct {
	msg        *Message
	raw        []byte
	compressed []byte
}

var (
	methodsMaxSizeFixtureOnce         sync.Once
	methodsMaxSizeFixtureData         methodsBenchmarkFixture
	methodsMaxSizeFixtureErr          error
	methodsMaxCompressibleFixtureOnce sync.Once
	methodsMaxCompressibleFixtureData methodsBenchmarkFixture
	methodsMaxCompressibleFixtureErr  error
)

func TestBuildFilledMessage(t *testing.T) {
	msg, err := BuildFilledMessage(FillOptions{
		Profile:   FillProfileRealistic,
		DeviceID:  "usp:device:test:safe-methods",
		Timestamp: time.Unix(1_700_000_000, 123456789).UTC(),
	})
	if err != nil {
		t.Fatalf("BuildFilledMessage returned error: %v", err)
	}

	if len(msg.Fields) != len(AllDeviceParams) {
		t.Fatalf("field count=%d want=%d", len(msg.Fields), len(AllDeviceParams))
	}
	if err := ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast returned error: %v", err)
	}
}

func TestSafeEncodeDecodeRoundTrip(t *testing.T) {
	msg, err := BuildFilledMessage(FillOptions{
		Profile:   FillProfileRealistic,
		DeviceID:  "usp:device:test:roundtrip",
		Timestamp: time.Unix(1_700_000_123, 987654321).UTC(),
	})
	if err != nil {
		t.Fatalf("BuildFilledMessage returned error: %v", err)
	}

	raw, err := EncodeMessage(msg)
	if err != nil {
		t.Fatalf("EncodeMessage returned error: %v", err)
	}
	decodedRaw, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage(raw) returned error: %v", err)
	}
	assertMessageEqual(t, msg, decodedRaw)

	compressed, err := EncodeMessageLZ4(msg)
	if err != nil {
		t.Fatalf("EncodeMessageLZ4 returned error: %v", err)
	}
	decodedCompressed, err := DecodeMessage(compressed)
	if err != nil {
		t.Fatalf("DecodeMessage(lz4) returned error: %v", err)
	}
	assertMessageEqual(t, msg, decodedCompressed)
}

func TestFilledValueForConcreteInstancePath(t *testing.T) {
	path := "Device.WireGuard.Peer.1.PublicKey"
	value, err := FilledValueForPath(path, FillProfileRealistic)
	if err != nil {
		t.Fatalf("FilledValueForPath returned error: %v", err)
	}

	msg := &Message{
		DeviceID:  "usp:device:test:instance",
		Timestamp: time.Unix(1_700_000_456, 0).UTC(),
		Fields: []Field{
			{Path: path, Val: value},
		},
	}
	if err := ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast returned error: %v", err)
	}

	frame, err := EncodeMessage(msg)
	if err != nil {
		t.Fatalf("EncodeMessage returned error: %v", err)
	}
	decoded, err := DecodeMessage(frame)
	if err != nil {
		t.Fatalf("DecodeMessage returned error: %v", err)
	}
	assertMessageEqual(t, msg, decoded)
}

func TestValidateMessageFastRejectsInvalidFields(t *testing.T) {
	t.Run("unknown path", func(t *testing.T) {
		msg := &Message{
			Fields: []Field{
				{Path: "Device.Unknown.Param", Val: String("x")},
			},
		}
		if err := ValidateMessageFast(msg); err == nil {
			t.Fatal("ValidateMessageFast returned nil error for unknown path")
		}
	})

	t.Run("wrong tag", func(t *testing.T) {
		msg := &Message{
			Fields: []Field{
				{Path: "Device.DeviceInfo.Manufacturer", Val: Uint(1)},
			},
		}
		if err := ValidateMessageFast(msg); err == nil {
			t.Fatal("ValidateMessageFast returned nil error for wrong tag")
		}
	})

	t.Run("bad constrained value", func(t *testing.T) {
		msg := &Message{
			Fields: []Field{
				{Path: "Device.DeviceInfo.ManufacturerOUI", Val: String("BAD")},
			},
		}
		if err := ValidateMessageFast(msg); err == nil {
			t.Fatal("ValidateMessageFast returned nil error for invalid constrained value")
		}
	})
}

func BenchmarkBuildFilledMessageMaxSize(b *testing.B) {
	opts := FillOptions{
		Profile:   FillProfileRealistic,
		DeviceID:  "usp:device:bench:max-size",
		Timestamp: time.Unix(1_700_000_789, 123456789).UTC(),
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		msg, err := BuildFilledMessage(opts)
		if err != nil {
			b.Fatalf("BuildFilledMessage returned error: %v", err)
		}
		if len(msg.Fields) != len(AllDeviceParams) {
			b.Fatalf("field count=%d want=%d", len(msg.Fields), len(AllDeviceParams))
		}
	}
}

func BenchmarkValidateMessageFastMaxSize(b *testing.B) {
	fixture := mustMethodsMaxSizeFixture(b)

	b.ReportAllocs()
	b.SetBytes(int64(len(fixture.raw)))
	for i := 0; i < b.N; i++ {
		if err := ValidateMessageFast(fixture.msg); err != nil {
			b.Fatalf("ValidateMessageFast returned error: %v", err)
		}
	}
}

func BenchmarkEncodeMessageMaxSize(b *testing.B) {
	fixture := mustMethodsMaxSizeFixture(b)

	benchmarks := []struct {
		name string
		fn   func(*Message) ([]byte, error)
	}{
		{name: "raw", fn: EncodeMessage},
		{name: "lz4", fn: EncodeMessageLZ4},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := bm.fn(fixture.msg)
				if err != nil {
					b.Fatalf("encode returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("encode returned empty frame")
				}
			}
		})
	}
}

func BenchmarkDecodeMessageMaxSize(b *testing.B) {
	fixture := mustMethodsMaxSizeFixture(b)

	benchmarks := []struct {
		name  string
		frame []byte
	}{
		{name: "raw", frame: fixture.raw},
		{name: "lz4", frame: fixture.compressed},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(bm.frame)))
			for i := 0; i < b.N; i++ {
				msg, err := DecodeMessage(bm.frame)
				if err != nil {
					b.Fatalf("DecodeMessage returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkRoundTripMessageMaxSize(b *testing.B) {
	fixture := mustMethodsMaxSizeFixture(b)

	benchmarks := []struct {
		name string
		fn   func(*Message) ([]byte, error)
	}{
		{name: "raw", fn: EncodeMessage},
		{name: "lz4", fn: EncodeMessageLZ4},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := bm.fn(fixture.msg)
				if err != nil {
					b.Fatalf("encode returned error: %v", err)
				}
				msg, err := DecodeMessage(frame)
				if err != nil {
					b.Fatalf("DecodeMessage returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkBuildFilledMessageMaxCompressible(b *testing.B) {
	opts := FillOptions{
		Profile:   FillProfileMaxCompressible,
		DeviceID:  "WUSPWUSPWUSPWUSPWUSPWUSPWUSPWUSP",
		Timestamp: time.Unix(253402300799, 0).UTC(),
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		msg, err := BuildFilledMessage(opts)
		if err != nil {
			b.Fatalf("BuildFilledMessage returned error: %v", err)
		}
		if len(msg.Fields) != len(AllDeviceParams) {
			b.Fatalf("field count=%d want=%d", len(msg.Fields), len(AllDeviceParams))
		}
	}
}

func BenchmarkValidateMessageFastMaxCompressible(b *testing.B) {
	fixture := mustMethodsMaxCompressibleFixture(b)

	b.ReportAllocs()
	b.SetBytes(int64(len(fixture.raw)))
	for i := 0; i < b.N; i++ {
		if err := ValidateMessageFast(fixture.msg); err != nil {
			b.Fatalf("ValidateMessageFast returned error: %v", err)
		}
	}
}

func BenchmarkEncodeMessageMaxCompressible(b *testing.B) {
	fixture := mustMethodsMaxCompressibleFixture(b)

	benchmarks := []struct {
		name string
		fn   func(*Message) ([]byte, error)
	}{
		{name: "raw", fn: EncodeMessage},
		{name: "lz4", fn: EncodeMessageLZ4},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := bm.fn(fixture.msg)
				if err != nil {
					b.Fatalf("encode returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("encode returned empty frame")
				}
			}
		})
	}
}

func BenchmarkDecodeMessageMaxCompressible(b *testing.B) {
	fixture := mustMethodsMaxCompressibleFixture(b)

	benchmarks := []struct {
		name  string
		frame []byte
	}{
		{name: "raw", frame: fixture.raw},
		{name: "lz4", frame: fixture.compressed},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(bm.frame)))
			for i := 0; i < b.N; i++ {
				msg, err := DecodeMessage(bm.frame)
				if err != nil {
					b.Fatalf("DecodeMessage returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkRoundTripMessageMaxCompressible(b *testing.B) {
	fixture := mustMethodsMaxCompressibleFixture(b)

	benchmarks := []struct {
		name string
		fn   func(*Message) ([]byte, error)
	}{
		{name: "raw", fn: EncodeMessage},
		{name: "lz4", fn: EncodeMessageLZ4},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := bm.fn(fixture.msg)
				if err != nil {
					b.Fatalf("encode returned error: %v", err)
				}
				msg, err := DecodeMessage(frame)
				if err != nil {
					b.Fatalf("DecodeMessage returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func mustMethodsMaxSizeFixture(tb testing.TB) methodsBenchmarkFixture {
	tb.Helper()
	methodsMaxSizeFixtureOnce.Do(func() {
		methodsMaxSizeFixtureData, methodsMaxSizeFixtureErr = buildMethodsFixture(
			FillProfileRealistic,
			"usp:device:bench:max-size",
			time.Unix(1_700_000_789, 123456789).UTC(),
		)
	})
	if methodsMaxSizeFixtureErr != nil {
		tb.Fatalf("buildMethodsMaxSizeFixture returned error: %v", methodsMaxSizeFixtureErr)
	}
	return methodsMaxSizeFixtureData
}

func mustMethodsMaxCompressibleFixture(tb testing.TB) methodsBenchmarkFixture {
	tb.Helper()
	methodsMaxCompressibleFixtureOnce.Do(func() {
		methodsMaxCompressibleFixtureData, methodsMaxCompressibleFixtureErr = buildMethodsFixture(
			FillProfileMaxCompressible,
			"WUSPWUSPWUSPWUSPWUSPWUSPWUSPWUSP",
			time.Unix(253402300799, 0).UTC(),
		)
	})
	if methodsMaxCompressibleFixtureErr != nil {
		tb.Fatalf("buildMethodsMaxCompressibleFixture returned error: %v", methodsMaxCompressibleFixtureErr)
	}
	return methodsMaxCompressibleFixtureData
}

func buildMethodsFixture(profile FillProfile, deviceID string, timestamp time.Time) (methodsBenchmarkFixture, error) {
	msg, err := BuildFilledMessage(FillOptions{
		Profile:   profile,
		DeviceID:  deviceID,
		Timestamp: timestamp,
	})
	if err != nil {
		return methodsBenchmarkFixture{}, err
	}

	raw, err := EncodeMessage(msg)
	if err != nil {
		return methodsBenchmarkFixture{}, err
	}

	compressed, err := EncodeMessageLZ4(msg)
	if err != nil {
		return methodsBenchmarkFixture{}, err
	}

	return methodsBenchmarkFixture{
		msg:        msg,
		raw:        raw,
		compressed: compressed,
	}, nil
}
