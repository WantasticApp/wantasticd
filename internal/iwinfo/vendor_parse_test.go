package iwinfo

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func madwifiRecord(mac net.HardwareAddr, freq uint16, rssi byte, aid uint16, ie []byte) []byte {
	ne := binary.NativeEndian
	size := (madwifiStaInfoFixedLen + len(ie) + 3) &^ 3
	rec := make([]byte, size)
	ne.PutUint16(rec[0:], uint16(size))
	ne.PutUint16(rec[2:], freq)
	ne.PutUint16(rec[6:], 0x0001) // authorized
	rec[9] = rssi
	copy(rec[14:], mac)
	rec[20] = 4                                    // nrates
	copy(rec[21:], []byte{0x82, 0x84, 0x8b, 0x6c}) // 1,2,5.5,54 Mbit/s
	rec[36] = 3                                    // txrate index -> 54M
	ne.PutUint16(rec[38:], uint16(len(ie)))
	ne.PutUint16(rec[40:], 0xc000|aid)
	ne.PutUint16(rec[114:], 7)
	copy(rec[madwifiStaInfoFixedLen:], ie)
	return rec
}

func TestDecodeMadwifiStaInfo(t *testing.T) {
	a, _ := net.ParseMAC("02:11:22:33:44:55")
	b, _ := net.ParseMAC("02:11:22:33:44:66")
	buf := append(madwifiRecord(a, 5180, 40, 1, []byte{0xdd, 3, 1, 2, 3}), madwifiRecord(b, 2437, 20, 2, nil)...)
	entries, err := decodeMadwifiStaInfo(buf, -95, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	if e.MAC.String() != a.String() || e.Signal != -55 || e.TxRate != 54000 || e.AssociationID != 1 || e.Inactive != 7000 || !e.Authenticated {
		t.Fatalf("unexpected entry %+v", e)
	}
	if entries[1].Signal != -75 {
		t.Fatalf("second signal %d", entries[1].Signal)
	}
}

func TestDecodeMadwifiStaInfoRejectsForeignLayout(t *testing.T) {
	a, _ := net.ParseMAC("02:11:22:33:44:55")
	rec := madwifiRecord(a, 5180, 40, 1, nil)
	// A QCA record carries more fixed fields: isi_len no longer matches.
	binary.NativeEndian.PutUint16(rec[0:], 240)
	rec = append(rec, make([]byte, 240-len(rec))...)
	if _, err := decodeMadwifiStaInfo(rec, -95, true); err != ErrVendorLayout {
		t.Fatalf("expected layout error, got %v", err)
	}
	if entries, err := decodeMadwifiStaInfo(nil, -95, true); err != nil || len(entries) != 0 {
		t.Fatalf("empty table should be valid: %v %v", entries, err)
	}
}

func TestParseWlanconfigStationsQSDK(t *testing.T) {
	out := `ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS XCAPS        ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS            VHTCAPS ASSOCTIME    IEs   MODE RXNSS TXNSS                   PSMODE
a4:83:e7:01:02:03    1  149 866M   780M   55       0      56    0      0   65535   EPSs         0          b              0           27                 AWPM             gGRSs 00:12:34 RSN WME IEEE80211_MODE_11AC_VHT80  2 2   0
02:00:00:00:00:ff    2   36 badM   12M    -48
`
	entries := ParseWlanconfigStations(out, -96, true)
	if len(entries) != 2 {
		t.Fatalf("got %d", len(entries))
	}
	e := entries[0]
	if e.TxRate != 866000 || e.RxRate != 780000 || e.Signal != -41 || e.Noise != -96 || e.AssociationID != 1 {
		t.Fatalf("unexpected %+v", e)
	}
	if e.ConnectedTime != 754 || e.OperatingStandard != "ac" || e.RxNSS != 2 || e.TxNSS != 2 || !e.InactiveKnown {
		t.Fatalf("unexpected tail fields %+v", e)
	}
	if entries[1].TxRateKnown || entries[1].Signal != -48 {
		t.Fatalf("second row %+v", entries[1])
	}
}

func TestParseWlanconfigStationsMadwifi(t *testing.T) {
	out := `ADDR               AID CHAN RATE RSSI DBM IDLE  TXSEQ  TXFRAG RXSEQ RXFRAG CAPS ACAPS ERP    STATE     MODE
00:15:6d:aa:bb:cc    1    6  54M   35  -60    0     12      0   3456      0 ESs           0       27   Normal WME
`
	entries := ParseWlanconfigStations(out, -95, false)
	if len(entries) != 1 || entries[0].TxRate != 54000 || entries[0].Signal != -60 || entries[0].NoiseKnown {
		t.Fatalf("unexpected %+v", entries)
	}
}

func TestParseProcNetWirelessNoise(t *testing.T) {
	data := `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
  ath0: 0000   94.  -1.  -95.       0      0      0      0      0        0
  ath1: 0000   0   0   161.       0      0      0      0      0        0
`
	if n, ok := parseProcNetWirelessNoise(data, "ath0"); !ok || n != -95 {
		t.Fatalf("ath0 %d %v", n, ok)
	}
	if n, ok := parseProcNetWirelessNoise(data, "ath1"); !ok || n != -95 {
		t.Fatalf("ath1 %d %v", n, ok)
	}
	if _, ok := parseProcNetWirelessNoise(data, "ath2"); ok {
		t.Fatal("ath2 should be missing")
	}
}

func TestMadwifiNodeStatsLayout(t *testing.T) {
	rxData, rxBytes, txData, txBytes, size := madwifiNodeStatsLayout()
	if rxData != 8 || rxBytes%4 != 0 || txData <= rxBytes || txBytes <= txData || size <= txBytes {
		t.Fatalf("layout %d %d %d %d %d", rxData, rxBytes, txData, txBytes, size)
	}
}

func TestParseHostapdCtrlInterface(t *testing.T) {
	conf := "interface=wlan0\nctrl_interface=/data/vendor/wifi/hostapd/ctrl\n#ctrl_interface=/nope\nctrl_interface=DIR=/var/run/hostapd GROUP=0\nctrl_interface=../etc\n"
	got := parseHostapdCtrlInterface(conf)
	if len(got) != 2 || got[0] != "/data/vendor/wifi/hostapd/ctrl" || got[1] != "/var/run/hostapd" {
		t.Fatalf("unexpected %v", got)
	}
}

func buildChanInfo(header, stride, ieeeOff int, freqs []int, power int8) []byte {
	buf := make([]byte, header+255*stride)
	binary.NativeEndian.PutUint32(buf, uint32(len(freqs)))
	for i, f := range freqs {
		e := buf[header+i*stride:]
		binary.NativeEndian.PutUint16(e, uint16(f))
		e[ieeeOff] = byte(FrequencyChannel(f))
		e[ieeeOff+1] = byte(power)
	}
	return buf
}

func TestDecodeVendorChanInfoLayouts(t *testing.T) {
	sixGHz := []int{5955, 5975, 5995, 6115, 6135, 6415}
	for _, layout := range []struct{ header, stride, ieee int }{
		{4, 8, 4},   // madwifi
		{8, 24, 11}, // qca-wifi with u64 flags + flagext
		{8, 32, 11},
	} {
		w := wiphyFromChannels(decodeVendorChanInfo(buildChanInfo(layout.header, layout.stride, layout.ieee, sixGHz, 24)))
		if len(w.Bands) != 1 || w.Bands[0].Band != "6GHz" || len(w.Bands[0].Channels) != len(sixGHz) {
			t.Fatalf("layout %+v: %+v", layout, w)
		}
		if ch := w.Bands[0].Channels[0]; ch.Channel != 1 || ch.MaxPowerDBM != 24 {
			t.Fatalf("layout %+v first=%+v", layout, ch)
		}
	}
	dual := []int{2412, 2437, 2462, 5180, 5500, 5745}
	w := wiphyFromChannels(decodeVendorChanInfo(buildChanInfo(4, 8, 4, dual, 20)))
	if len(w.Bands) != 2 || w.Bands[0].Band != "2.4GHz" || w.Bands[1].Band != "5GHz" {
		t.Fatalf("dual=%+v", w)
	}
	if decodeVendorChanInfo(make([]byte, 64)) != nil {
		t.Fatal("empty table decoded")
	}
}

// qcaRecord builds a qca-like ieee80211req_sta_info: wider and reordered
// fields, an appended MLO block and trailing IEs, walked by isi_len.
func qcaRecord(mac string, aid uint16, rssi uint8, idle uint16, tx, rx uint32, ies int) []byte {
	const fixed = 168
	n := (fixed + ies + 3) &^ 3
	r := make([]byte, n)
	binary.NativeEndian.PutUint16(r[0:], uint16(n))
	binary.NativeEndian.PutUint16(r[2:], 5180)
	binary.NativeEndian.PutUint32(r[4:], 0x00010003) // flags
	r[11] = rssi
	hw, _ := net.ParseMAC(mac)
	copy(r[16:], hw)
	binary.NativeEndian.PutUint16(r[44:], 0xc000|aid)
	binary.NativeEndian.PutUint32(r[60:], tx)
	binary.NativeEndian.PutUint32(r[64:], rx)
	binary.NativeEndian.PutUint16(r[120:], idle)
	copy(r[150:], hw) // MLD address equal to the link address
	return r
}

const qcaWlanconfig = `ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS XCAPS ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS            VHTCAPS ASSOCTIME    IEs   MODE RXNSS TXNSS PSMODE
aa:bb:cc:00:00:01    3   36   866M   780M   41      30      55    4      0  65535   EPSs  BRP          0       b              0      AWPM     gpsSRs     0       00:12:31 RSN WME IEEE80211_MODE_11AC_VHT80  2 2   0
aa:bb:cc:00:00:02    7   36   390M   433M   27      20      40   12      0  65535   EPSs  BRP          0       b              0      AWPM     gpsSRs     0       01:02:03 RSN WME IEEE80211_MODE_11AC_VHT80  1 1   1
`

func TestCalibratedQCAStaInfo(t *testing.T) {
	noise := -95
	buf := append(qcaRecord("aa:bb:cc:00:00:01", 3, 41, 4, 866700, 780000, 22),
		qcaRecord("aa:bb:cc:00:00:02", 7, 27, 12, 390000, 433300, 40)...)
	if _, err := decodeMadwifiStaInfo(buf, noise, true); err == nil {
		t.Fatal("madwifi decoder accepted a qca layout")
	}
	ref := ParseWlanconfigStations(qcaWlanconfig, noise, true)
	layout, ok := calibrateStaLayout(buf, ref, noise)
	if !ok || layout.macOff != 16 || layout.aidOff != 44 || layout.rssiOff != 11 || layout.txRateOff != 60 || layout.rxRateOff != 64 || layout.idleOff != 120 {
		t.Fatalf("layout=%+v ok=%v", layout, ok)
	}

	// A later poll: values moved, the layout still decodes them.
	later := append(qcaRecord("aa:bb:cc:00:00:02", 7, 30, 1, 433300, 520000, 40),
		qcaRecord("aa:bb:cc:00:00:01", 3, 44, 0, 1200900, 866700, 22)...)
	entries, ok := decodeCalibratedStaInfo(later, layout, noise, true)
	if !ok || len(entries) != 2 {
		t.Fatalf("entries=%+v", entries)
	}
	if e := entries[1]; e.MAC.String() != "aa:bb:cc:00:00:01" || e.AssociationID != 3 || e.Signal != -51 || e.TxRate != 1200900 || e.RxRate != 866700 {
		t.Fatalf("decoded=%+v", e)
	}
}

func TestCalibrationNeedsUnambiguousEvidence(t *testing.T) {
	// One station whose RSSI byte also appears elsewhere: ambiguous, so the
	// caller keeps using wlanconfig rather than guessing.
	rec := qcaRecord("aa:bb:cc:00:00:01", 3, 41, 4, 866700, 780000, 0)
	rec[90] = 41
	ref := ParseWlanconfigStations(strings.Split(qcaWlanconfig, "\n")[0]+"\n"+strings.Split(qcaWlanconfig, "\n")[1]+"\n", -95, true)
	if layout, ok := calibrateStaLayout(rec, ref, -95); ok {
		t.Fatalf("ambiguous evidence calibrated: %+v", layout)
	}
}
