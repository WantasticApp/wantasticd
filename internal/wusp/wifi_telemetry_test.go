package wusp

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func wifiTestHistory(n int, start time.Time) []WiFiHistorySample {
	out := make([]WiFiHistorySample, n)
	for i := range out {
		values := map[uint8]int64{
			WiFiMetricSignal:     int64(-60 - i%5),
			WiFiMetricTxRate:     866700 - int64(i)*1000,
			WiFiMetricDownlink:   int64(1200 + i*37),
			WiFiMetricLatencyAvg: int64(2400 + (i%3)*150),
		}
		if i%4 == 0 {
			delete(values, WiFiMetricLatencyAvg) // probe round skipped
		}
		out[i] = WiFiHistorySample{Time: start.Add(time.Duration(i) * time.Minute), Values: values}
	}
	return out
}

func TestWiFiHistoryRoundTrip(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	samples := wifiTestHistory(WiFiHistoryDepth, start)
	block, err := EncodeWiFiHistoryBlock(samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(block) > 400 {
		t.Fatalf("30 samples x 4 series should stay compact, got %d bytes", len(block))
	}
	decoded, err := DecodeWiFiHistoryBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, samples) {
		t.Fatalf("round trip mismatch\n got %+v\nwant %+v", decoded[0], samples[0])
	}
}

func TestWiFiHistoryKeepsNewestDepth(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	samples := wifiTestHistory(45, start)
	block, err := EncodeWiFiHistoryBlock(samples)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeWiFiHistoryBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != WiFiHistoryDepth || !decoded[0].Time.Equal(samples[15].Time) {
		t.Fatalf("expected newest %d samples, got %d starting %s", WiFiHistoryDepth, len(decoded), decoded[0].Time)
	}
}

func TestMergeWiFiHistory(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	stored := wifiTestHistory(20, start)
	// Agent restarted: its ring only holds the last 5 minutes, overlapping 2.
	incoming := wifiTestHistory(5, start.Add(18*time.Minute))
	incoming[0].Values[WiFiMetricSignal] = -40
	merged := MergeWiFiHistory(stored, incoming, WiFiHistoryDepth)
	if len(merged) != 23 {
		t.Fatalf("got %d samples", len(merged))
	}
	if merged[18].Values[WiFiMetricSignal] != -40 {
		t.Fatal("incoming sample must win on the same second")
	}
	for i := 1; i < len(merged); i++ {
		if !merged[i].Time.After(merged[i-1].Time) {
			t.Fatal("merged history out of order")
		}
	}
}

func TestDecodeWiFiHistoryHostile(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	block, err := EncodeWiFiHistoryBlock(wifiTestHistory(WiFiHistoryDepth, start))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		mutated := append([]byte(nil), block...)
		for j := 0; j < 1+rng.Intn(4); j++ {
			mutated[rng.Intn(len(mutated))] = byte(rng.Intn(256))
		}
		if rng.Intn(3) == 0 {
			mutated = mutated[:rng.Intn(len(mutated))]
		}
		samples, err := DecodeWiFiHistoryBlock(mutated)
		if err == nil && len(samples) > WiFiHistoryDepth {
			t.Fatal("decoder exceeded depth")
		}
	}
	for _, bad := range [][]byte{
		{'W', 'H', 1, 0, 0},
		{'W', 'H', 1, 0, 31, 0},
		{'W', 'H', 1, 0, 1, 17},
		{'W', 'H', 2, 0},
		{'X', 'H', 1, 0},
		{'W', 'H', 1, 1, 0xff, 0xff, 0xff},
	} {
		if _, err := DecodeWiFiHistoryBlock(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}
