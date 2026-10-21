package qcaspectral

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testMAC = net.HardwareAddr{0x00, 0x03, 0x7f, 0x12, 0x34, 0x56}

// datagram wraps a SAMP payload in an nlmsghdr. skbLen mimics the fixed-size
// driver skb that can exceed nlmsg_len.
func datagram(order binary.ByteOrder, payload []byte, nlPayloadLen, skbLen int) []byte {
	if skbLen < nlmsgHdrLen+len(payload) {
		skbLen = nlmsgHdrLen + len(payload)
	}
	out := make([]byte, skbLen)
	order.PutUint32(out[0:4], uint32(nlmsgHdrLen+nlPayloadLen))
	copy(out[nlmsgHdrLen:], payload)
	return out
}

func legacyPayload(order binary.ByteOrder, bins []byte) []byte {
	p := make([]byte, legacyMessageLength)
	order.PutUint32(p[0:], sampSignature)
	order.PutUint16(p[legacyFreq:], 5180)
	copy(p[legacyMAC:], testMAC)
	order.PutUint16(p[legacyRSSI:], uint16(0xffd8)) // -40
	order.PutUint32(p[legacyTimestamp:], 123456)
	order.PutUint16(p[legacyMaxIndex:], 7)
	order.PutUint16(p[legacyBinCount:], uint16(len(bins)))
	copy(p[legacyBins:], bins)
	order.PutUint16(p[legacyNoiseFloor:], uint16(0xffa1)) // -95
	order.PutUint32(p[legacyChannelWidth:], 1)
	return p
}

func cmnPayload(order binary.ByteOrder, bins, sec80 []byte) []byte {
	p := make([]byte, cmnMaxLength)
	order.PutUint32(p[0:], sampSignature)
	order.PutUint16(p[cmnFreq:], 5500)
	order.PutUint16(p[cmnSeg1:], 5530)
	copy(p[cmnMAC:], testMAC)
	order.PutUint16(p[cmnRSSI:], uint16(0xffce)) // -50
	order.PutUint32(p[cmnTimestamp:], 42)
	order.PutUint16(p[cmnMaxIndex:], 300)
	order.PutUint16(p[cmnBinCount:], uint16(len(bins)))
	order.PutUint16(p[cmnBinCountSec80:], uint16(len(sec80)))
	copy(p[cmnBins:], bins)
	copy(p[cmnBinsSec80:], sec80)
	order.PutUint16(p[cmnNoiseFloor:], uint16(0xff9c)) // -100
	order.PutUint32(p[cmnChannelWidth:], 3)
	return p
}

func optimizedPayload(order binary.ByteOrder, bins []byte) []byte {
	p := make([]byte, optBins+len(bins))
	order.PutUint32(p[0:], sampSignature)
	order.PutUint32(p[4:], 1) // target_reset_count
	order.PutUint32(p[optPri20:], 5955)
	order.PutUint32(p[optCFreq1:], 5985)
	order.PutUint32(p[optBinCount:], uint32(len(bins)))
	order.PutUint32(p[optDet0Timestamp:], 99)
	order.PutUint16(p[optDet0MaxIndex:], 5)
	order.PutUint16(p[optDet0Noise:], uint16(0xffa6)) // -90
	p[optDet0RSSI] = 0xf6                             // -10
	copy(p[optMAC:], testMAC)
	p[optOperatingBW] = 2
	copy(p[optBins:], bins)
	return p
}

func TestParseNetlinkLayouts(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		bins := []byte{1, 2, 3, 4, 200}
		t.Run("legacy", func(t *testing.T) {
			p := legacyPayload(order, bins)
			s, err := ParseNetlink(datagram(order, p, 648, 0), order)
			if err != nil {
				t.Fatal(err)
			}
			if s.Layout != LayoutLegacy || s.Frequency != 5180 || s.RSSI != -40 || s.NoiseFloor != -95 ||
				s.MaxIndex != 7 || s.TimestampMicros != 123456 || s.ChannelWidth != 40 ||
				!bytes.Equal(s.Bins, bins) || !bytes.Equal(s.MAC, testMAC) {
				t.Fatalf("unexpected legacy sample %+v", s)
			}
		})
		t.Run("cmn", func(t *testing.T) {
			sec80 := []byte{9, 8}
			p := cmnPayload(order, bins, sec80)
			// cmn drivers send a fixed 3028-byte skb with nlmsg_len from sizeof.
			s, err := ParseNetlink(datagram(order, p, 1776, 3028), order)
			if err != nil {
				t.Fatal(err)
			}
			if s.Layout != LayoutCMN || s.Frequency != 5500 || s.CenterFrequency1 != 5530 || s.RSSI != -50 ||
				s.NoiseFloor != -100 || s.MaxIndex != 300 || s.ChannelWidth != 160 ||
				!bytes.Equal(s.Bins, append(append([]byte(nil), bins...), sec80...)) {
				t.Fatalf("unexpected cmn sample %+v", s)
			}
		})
		t.Run("cmn-optimized", func(t *testing.T) {
			p := optimizedPayload(order, bins)
			s, err := ParseNetlink(datagram(order, p, 404, 3028), order)
			if err != nil {
				t.Fatal(err)
			}
			if s.Layout != LayoutCMNOptimized || s.Frequency != 5955 || s.CenterFrequency1 != 5985 ||
				s.RSSI != -10 || s.NoiseFloor != -90 || s.MaxIndex != 5 || s.TimestampMicros != 99 ||
				s.ChannelWidth != 80 || !bytes.Equal(s.Bins, bins) || !bytes.Equal(s.MAC, testMAC) {
				t.Fatalf("unexpected optimized sample %+v", s)
			}
		})
	}
}

func TestParseNetlinkRejects(t *testing.T) {
	order := binary.LittleEndian
	if _, err := ParseNetlink(datagram(order, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, 0), order); !errors.Is(err, ErrNotSpectral) {
		t.Fatalf("bad signature: got %v", err)
	}
	// Valid signature and frequency but a payload size matching no known
	// layout must fail closed instead of being parsed with the wrong offsets.
	p := legacyPayload(order, []byte{1})
	if _, err := ParseNetlink(datagram(order, append(p, make([]byte, 400)...), 1047, 0), order); !errors.Is(err, ErrUnknownLayout) {
		t.Fatalf("unknown size: got %v", err)
	}
	p = legacyPayload(order, []byte{1})
	order.PutUint16(p[legacyBinCount:], 600)
	if _, err := ParseNetlink(datagram(order, p, 648, 0), order); !errors.Is(err, ErrUnknownLayout) {
		t.Fatalf("oversized bin count: got %v", err)
	}
	p = optimizedPayload(order, []byte{1, 2})
	order.PutUint32(p[optBinCount:], 50) // beyond the datagram
	if _, err := ParseNetlink(datagram(order, p, 404, 0), order); !errors.Is(err, ErrUnknownLayout) {
		t.Fatalf("truncated optimized bins: got %v", err)
	}
}

func TestDecodeCaps(t *testing.T) {
	if _, ok := decodeCaps([]byte{1, 0, 0, 0}, 29); ok {
		t.Fatal("spectral_cap=0 must be rejected")
	}
	// IS_ACTIVE answering on the wrong base writes a u32 0/1, never a caps set.
	if _, ok := decodeCaps([]byte{1, 0, 0, 0, 0, 0, 0, 0}, 22); ok {
		t.Fatal("IS_ACTIVE-shaped output must be rejected")
	}
	if _, ok := decodeCaps([]byte{1, 1, 7, 1}, 29); ok {
		t.Fatal("non-boolean flags must be rejected")
	}
	caps, ok := decodeCaps([]byte{1, 1, 1, 1}, 22)
	if !ok || !caps.Spectral || !caps.Advanced || caps.IoctlBase != 22 {
		t.Fatalf("valid caps rejected: %+v", caps)
	}
}

type fakeDriver struct {
	caps      map[string]Caps
	active    bool
	scanCalls []bool
	datagrams [][]byte
}

func (d *fakeDriver) Probe(ifname string) (Caps, error) {
	if caps, ok := d.caps[ifname]; ok {
		return caps, nil
	}
	return Caps{}, ErrUnsupported
}
func (d *fakeDriver) IsActive(string, Caps) (bool, error) { return d.active, nil }
func (d *fakeDriver) SetScan(_ string, _ Caps, start bool) error {
	d.scanCalls = append(d.scanCalls, start)
	return nil
}
func (d *fakeDriver) OpenSamples() (sampleSource, error) { return &fakeSource{d: d}, nil }

type fakeSource struct{ d *fakeDriver }

func (s *fakeSource) Recv(int) ([]byte, error) {
	if len(s.d.datagrams) == 0 {
		return nil, nil
	}
	next := s.d.datagrams[0]
	s.d.datagrams = s.d.datagrams[1:]
	return next, nil
}
func (s *fakeSource) Close() error { return nil }

func nativeLegacy(mac net.HardwareAddr, bins []byte) []byte {
	order := binary.NativeEndian
	p := legacyPayload(order, bins)
	copy(p[legacyMAC:], mac)
	return datagram(order, p, 648, 0)
}

func TestCaptureStartsAndStopsOwnedScan(t *testing.T) {
	other := net.HardwareAddr{0x00, 0x03, 0x7f, 0x99, 0x99, 0x99}
	d := &fakeDriver{datagrams: [][]byte{
		nativeLegacy(testMAC, []byte{1, 2, 3}),
		nativeLegacy(other, []byte{9, 9, 9}), // another known radio: ignored
		nativeLegacy(testMAC, []byte{1, 2}),  // bin count changed: dropped
		nativeLegacy(testMAC, []byte{4, 5, 6}),
	}}
	radio := Radio{Interface: "wifi0", MAC: testMAC, Caps: Caps{Spectral: true, IoctlBase: 29}}
	res, err := capture(context.Background(), d, radio, CaptureOptions{
		Window: 50 * time.Millisecond, MaxSamples: 2, KnownMACs: []net.HardwareAddr{testMAC, other},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Passive || len(res.Samples) != 2 || res.Dropped != 1 || res.Layout != LayoutLegacy {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(d.scanCalls) != 2 || !d.scanCalls[0] || d.scanCalls[1] {
		t.Fatalf("scan must be started then stopped, got %v", d.scanCalls)
	}
}

func TestCapturePassiveLeavesForeignScanRunning(t *testing.T) {
	unknown := net.HardwareAddr{0xde, 0xad, 0x00, 0x00, 0x00, 0x01}
	d := &fakeDriver{active: true, datagrams: [][]byte{
		nativeLegacy(unknown, []byte{1}), // unattributable while another owner scans
		nativeLegacy(testMAC, []byte{2}),
	}}
	radio := Radio{Interface: "wifi1", MAC: testMAC, Caps: Caps{Spectral: true, IoctlBase: 22}}
	res, err := capture(context.Background(), d, radio, CaptureOptions{Window: 30 * time.Millisecond, KnownMACs: []net.HardwareAddr{testMAC}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passive || len(res.Samples) != 1 || len(d.scanCalls) != 0 {
		t.Fatalf("passive capture must not touch scan state: %+v calls=%v", res, d.scanCalls)
	}
}

func TestDiscoverRadiosProbesOnlyQCARadioNetdevs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wifi10", "wifi1", "ath0", "wlan0", "wifi2"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, name, "address"), []byte("00:03:7f:12:34:56\n"), 0o644)
	}
	d := &fakeDriver{caps: map[string]Caps{
		"wifi1":  {Spectral: true, IoctlBase: 29},
		"wifi10": {Spectral: true, IoctlBase: 29},
		"ath0":   {Spectral: true, IoctlBase: 29},
	}}
	radios, err := discoverRadios(d, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Every wifiN gets a row; a failed probe keeps its reason instead of
	// silently disappearing.
	if len(radios) != 3 || radios[0].Interface != "wifi1" || radios[1].Interface != "wifi2" || radios[2].Interface != "wifi10" || !bytes.Equal(radios[0].MAC, testMAC) {
		t.Fatalf("unexpected radios %+v", radios)
	}
	if radios[1].Caps.Spectral || radios[1].ProbeError == "" || radios[1].Caps.ControlPath != ControlPathNone {
		t.Fatalf("failed probe must be reported, got %+v", radios[1])
	}
	if _, err := discoverRadios(d, t.TempDir()); !errors.Is(err, ErrNoRadioNetdev) {
		t.Fatalf("empty net class dir: got %v", err)
	}
}

func TestCaptureReportsWhyNothingArrived(t *testing.T) {
	d := &fakeDriver{}
	radio := Radio{Interface: "wifi0", MAC: testMAC, Caps: Caps{Spectral: true, ControlPath: ControlPathVendor}}
	res, err := capture(context.Background(), d, radio, CaptureOptions{Window: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.LastError == "" || res.Completed.IsZero() {
		t.Fatalf("empty capture must explain itself and record completion: %+v", res)
	}
}

func TestCaptureRefusesForeignRelayScan(t *testing.T) {
	d := &fakeDriver{active: true}
	radio := Radio{Interface: "wifi0", MAC: testMAC, Caps: Caps{Spectral: true, ControlPath: ControlPathVendor, DataTransport: TransportRelay}}
	res, err := capture(context.Background(), d, radio, CaptureOptions{Window: 20 * time.Millisecond})
	if err == nil || res.LastError == "" || len(d.scanCalls) != 0 {
		t.Fatalf("passive relay capture must fail with a reason and leave the scan alone: %v %+v", err, res)
	}
}
