package iwinfo

import (
	"encoding/binary"
	"net"
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
