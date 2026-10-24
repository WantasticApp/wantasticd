package iwinfo

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func putUTF16(dst []byte, s string) {
	for i, u := range utf16.Encode([]rune(s)) {
		binary.LittleEndian.PutUint16(dst[2*i:], u)
	}
}

func TestDecodeWlanStructures(t *testing.T) {
	list := make([]byte, 8+2*wlanInterfaceInfoSize)
	binary.LittleEndian.PutUint32(list, 2)
	putUTF16(list[8+16:], "Intel(R) Wi-Fi 6E AX211 160MHz")
	binary.LittleEndian.PutUint32(list[8+528:], 1)
	putUTF16(list[8+wlanInterfaceInfoSize+16:], "USB Wireless")
	ifaces := decodeWlanInterfaceList(list)
	if len(ifaces) != 2 || ifaces[0].description != "Intel(R) Wi-Fi 6E AX211 160MHz" || ifaces[0].state != 1 || ifaces[1].description != "USB Wireless" {
		t.Fatalf("ifaces=%+v", ifaces)
	}

	attrs := make([]byte, wlanConnectionAttrsSize)
	a := attrs[wlanAssocOffset:]
	binary.LittleEndian.PutUint32(a, 7)
	copy(a[4:], "office5")
	copy(a[40:], []byte{0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03})
	binary.LittleEndian.PutUint32(a[48:], dot11PhyHE)
	binary.LittleEndian.PutUint32(a[56:], 80)
	binary.LittleEndian.PutUint32(a[60:], 1201000)
	info := &InterfaceInfo{}
	applyWlanConnection(attrs, info)
	if info.SSID != "office5" || info.BSSID != "aa:bb:cc:01:02:03" || info.HardwareName != "802.11ax" || info.Signal != -60 || info.Bitrate != 1201000 || info.Quality != 80 {
		t.Fatalf("info=%+v", info)
	}

	capability := make([]byte, 20+4*3)
	binary.LittleEndian.PutUint32(capability[16:], 3)
	for i, phy := range []uint32{dot11PhyERP, dot11PhyVHT, dot11PhyHE} {
		binary.LittleEndian.PutUint32(capability[20+4*i:], phy)
	}
	if m := decodeWlanPhyTypes(capability); m == nil || !m.G || !m.AC || !m.AX || m.N || m.BE {
		t.Fatalf("modes=%+v", m)
	}
	if channelFrequency(36) != 5180 || channelFrequency(6) != 2437 || channelFrequency(14) != 2484 {
		t.Fatal("channel frequency mapping")
	}
}
