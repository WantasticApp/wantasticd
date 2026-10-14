package iwinfo

import "testing"

func TestParseHostapdStationsPreservesKnownZeroAndCapabilities(t *testing.T) {
	entries := ParseHostapdStations(`02:11:22:33:44:55
flags=[AUTH][ASSOC][AUTHORIZED][HT][VHT][HE]
signal=-57
signal_avg=-60
inactive_msec=0
connected_time=81
rx_bytes64=12345678901
tx_bytes=42
rx_packets=0
tx_packets=9
tx_retries=0
tx_failed=2
rx_bitrate=866.7 MBit/s
tx_bitrate=1200.0 MBit/s`)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if !entry.AuthenticationKnown || !entry.Authenticated || entry.OperatingStandard != "ax" {
		t.Fatalf("unexpected authentication/standard: %+v", entry)
	}
	if !entry.InactiveKnown || entry.Inactive != 0 || !entry.RxPacketsKnown || entry.RxPackets != 0 || !entry.TxRetriesKnown || entry.TxRetries != 0 {
		t.Fatalf("known zero values were lost: %+v", entry)
	}
	if !entry.RxBytesKnown || entry.RxBytes != 12345678901 || !entry.RxRateKnown || entry.RxRate != 866700 {
		t.Fatalf("unexpected counters/rate: %+v", entry)
	}
}

func TestParseHostapdStationsRejectsMulticastAndInvalidMAC(t *testing.T) {
	entries := ParseHostapdStations("01:00:5e:00:00:01\nflags=[AUTH]", "not-a-mac\nflags=[AUTH]")
	if len(entries) != 0 {
		t.Fatalf("got %+v, want no stations", entries)
	}
}

func TestParseHostapdStationsRejectsNonFiniteRates(t *testing.T) {
	entries := ParseHostapdStations("02:11:22:33:44:55\nrx_bitrate=NaN MBit/s\ntx_bitrate=+Inf MBit/s")
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].RxRateKnown || entries[0].TxRateKnown {
		t.Fatalf("non-finite rate was marked measured: %+v", entries[0])
	}
}
