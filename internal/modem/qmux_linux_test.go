//go:build linux

package modem

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeQMIModem answers QMUX requests on one end of a SEQPACKET socketpair,
// which keeps message boundaries the way a cdc-wdm node does.
func fakeQMIModem(t *testing.T, fd int, answers map[[2]uint16][]qmuxTLV) {
	t.Helper()
	go func() {
		buf := make([]byte, 4096)
		nextClient := uint8(7)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil || n < 6 {
				return
			}
			frame := buf[:n]
			service, client := frame[4], frame[5]
			sdu := frame[6:]
			ok := []qmuxTLV{{0x02, []byte{0, 0, 0, 0}}}
			var reply []byte
			if service == qmuxServiceCTL {
				message := binary.LittleEndian.Uint16(sdu[2:])
				tlvs := ok
				if message == 0x0022 {
					tlvs = append(tlvs, qmuxTLV{0x01, []byte{decodeQMITLVs(sdu[6:])[0x01][0], nextClient}})
					nextClient++
				}
				body := encodeQMITLVs(tlvs)
				reply = []byte{0x01, sdu[1], 0, 0, 0, 0}
				binary.LittleEndian.PutUint16(reply[2:], message)
				binary.LittleEndian.PutUint16(reply[4:], uint16(len(body)))
				reply = append(reply, body...)
			} else {
				message := binary.LittleEndian.Uint16(sdu[3:])
				tlvs, found := answers[[2]uint16{uint16(service), message}]
				if !found {
					tlvs = []qmuxTLV{{0x02, []byte{1, 0, 0x2f, 0}}} // QMI_ERR_NOT_SUPPORTED
				} else {
					tlvs = append(ok, tlvs...)
				}
				// An unsolicited indication first: the client must skip it.
				indication := []byte{0x04, 0, 0, 0x01, 0x00, 0, 0}
				_, _ = unix.Write(fd, encodeQMUX(service, client, indication))
				body := encodeQMITLVs(tlvs)
				reply = []byte{0x02, sdu[1], sdu[2], 0, 0, 0, 0}
				binary.LittleEndian.PutUint16(reply[3:], message)
				binary.LittleEndian.PutUint16(reply[5:], uint16(len(body)))
				reply = append(reply, body...)
			}
			if _, err := unix.Write(fd, encodeQMUX(service, client, reply)); err != nil {
				return
			}
		}
	}()
}

func TestQMUXQueryFillsInfo(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	le := func(v int16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, uint16(v)); return b }
	i8 := func(v int8) byte { return byte(v) }
	lte := append([]byte{i8(-61), i8(-11)}, append(le(-95), le(135)...)...)
	nr := append(le(-88), le(210)...)
	plmn := append([]byte{0x6c, 0x02, 0x01, 0x00, 4}, "Orng"...) // MCC 620, MNC 1
	ip := make([]byte, 4)
	binary.LittleEndian.PutUint32(ip, 0x0A400102) // 10.64.1.2
	fakeQMIModem(t, pair[1], map[[2]uint16][]qmuxTLV{
		{qmuxServiceDMS, 0x0025}: {{0x11, []byte("861234567890123")}},
		{qmuxServiceDMS, 0x0043}: {{0x01, []byte("604001234567890")}},
		{qmuxServiceNAS, 0x0024}: {{0x01, []byte{1, 1, 1, 2, 2, 8, 12}}, {0x10, []byte{1}}, {0x12, plmn}},
		{qmuxServiceNAS, 0x004F}: {{0x14, lte}, {0x17, nr}},
		{qmuxServiceWDS, 0x0022}: {{0x01, []byte{2}}},
		{qmuxServiceWDS, 0x002D}: {{0x14, []byte("internet")}, {0x1E, ip}},
	})
	saved := openQMUXDevice
	openQMUXDevice = func(string) (*qmuxConn, error) { return &qmuxConn{fd: pair[0]}, nil }
	t.Cleanup(func() { openQMUXDevice = saved })

	info := &Info{Protocol: "sysfs"}
	if !qmuxQuery("/dev/cdc-wdm0", info) {
		t.Fatal("native QMI did not answer")
	}
	if info.IMEI != "861234567890123" || info.IMSI != "604001234567890" || info.ICCID != "" {
		t.Fatalf("identity=%q/%q/%q", info.IMEI, info.IMSI, info.ICCID)
	}
	if info.Status != RegHome || info.Technology != TechNR5GNSA || info.OperatorMCC != "620" || info.OperatorMNC != "01" || info.Operator != "Orng" {
		t.Fatalf("serving=%v %v %s-%s %q", info.Status, info.Technology, info.OperatorMCC, info.OperatorMNC, info.Operator)
	}
	if info.Signal.RSSI != -61 || info.Signal.RSRP != -88 || info.Signal.SINR != 21 || info.Signal.RSRQ != -11 {
		t.Fatalf("signal=%+v", info.Signal)
	}
	if !info.Connected || info.APN != "internet" || info.IPAddress != "10.64.1.2" || info.Protocol != "qmi" {
		t.Fatalf("wds=%v %q %q %q", info.Connected, info.APN, info.IPAddress, info.Protocol)
	}
}
