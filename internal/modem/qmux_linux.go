//go:build linux

package modem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Native QMI (Qualcomm MSM Interface) over a cdc-wdm control node, speaking
// the QMUX framing uqmi and libqmi use. One collection opens the node once
// and reuses a client per service instead of forking uqmi for every query.

const (
	qmuxServiceCTL = 0x00
	qmuxServiceWDS = 0x01
	qmuxServiceDMS = 0x02
	qmuxServiceNAS = 0x03

	qmuxTimeout = 2 * time.Second
)

// Per-node lock: QMI transactions on one cdc-wdm must not interleave between
// collectors.
var qmuxLocks sync.Map

type qmuxConn struct {
	fd     int
	ctlTID uint8
	tid    uint16
}

type qmuxTLV struct {
	kind  uint8
	value []byte
}

// qmuxError is a QMI result TLV failure (QMI_ERR_* code).
type qmuxError uint16

func (e qmuxError) Error() string { return fmt.Sprintf("QMI error 0x%04x", uint16(e)) }

// openQMUXDevice is replaced in tests by an in-memory modem.
var openQMUXDevice = openQMUX

func openQMUX(path string) (*qmuxConn, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	return &qmuxConn{fd: fd}, nil
}

func (c *qmuxConn) close() { _ = unix.Close(c.fd) }

func encodeQMUX(service, client uint8, sdu []byte) []byte {
	frame := make([]byte, 6+len(sdu))
	frame[0] = 0x01
	binary.LittleEndian.PutUint16(frame[1:], uint16(len(frame)-1))
	frame[3] = 0x00 // sent by the control point
	frame[4] = service
	frame[5] = client
	copy(frame[6:], sdu)
	return frame
}

func encodeQMITLVs(tlvs []qmuxTLV) []byte {
	var out []byte
	for _, tlv := range tlvs {
		head := []byte{tlv.kind, 0, 0}
		binary.LittleEndian.PutUint16(head[1:], uint16(len(tlv.value)))
		out = append(out, head...)
		out = append(out, tlv.value...)
	}
	return out
}

func decodeQMITLVs(data []byte) map[uint8][]byte {
	out := map[uint8][]byte{}
	for len(data) >= 3 {
		size := int(binary.LittleEndian.Uint16(data[1:]))
		if len(data) < 3+size {
			break
		}
		out[data[0]] = data[3 : 3+size]
		data = data[3+size:]
	}
	return out
}

// request sends one QMI request and waits for its response, skipping
// indications and replies meant for other transactions.
func (c *qmuxConn) request(service, client uint8, message uint16, tlvs []qmuxTLV) (map[uint8][]byte, error) {
	payload := encodeQMITLVs(tlvs)
	var sdu []byte
	var tid uint16
	if service == qmuxServiceCTL {
		c.ctlTID++
		if c.ctlTID == 0 {
			c.ctlTID = 1
		}
		tid = uint16(c.ctlTID)
		sdu = []byte{0x00, c.ctlTID, 0, 0, 0, 0}
		binary.LittleEndian.PutUint16(sdu[2:], message)
		binary.LittleEndian.PutUint16(sdu[4:], uint16(len(payload)))
	} else {
		c.tid++
		if c.tid == 0 {
			c.tid = 1
		}
		tid = c.tid
		sdu = []byte{0x00, 0, 0, 0, 0, 0, 0}
		binary.LittleEndian.PutUint16(sdu[1:], tid)
		binary.LittleEndian.PutUint16(sdu[3:], message)
		binary.LittleEndian.PutUint16(sdu[5:], uint16(len(payload)))
	}
	if _, err := unix.Write(c.fd, encodeQMUX(service, client, append(sdu, payload...))); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(qmuxTimeout)
	buf := make([]byte, 16<<10)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("QMI request timed out")
		}
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, int(remaining.Milliseconds())+1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		} else if n == 0 {
			continue
		}
		n, err := unix.Read(c.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if tlvs, ok, err := matchQMUXResponse(buf[:n], service, client, message, tid); ok {
			return tlvs, err
		}
	}
}

func matchQMUXResponse(frame []byte, service, client uint8, message, tid uint16) (map[uint8][]byte, bool, error) {
	if len(frame) < 6 || frame[0] != 0x01 || frame[4] != service || (service != qmuxServiceCTL && frame[5] != client) {
		return nil, false, nil
	}
	sdu := frame[6:]
	var flags uint8
	var gotTID, gotMessage uint16
	var body []byte
	if service == qmuxServiceCTL {
		if len(sdu) < 6 {
			return nil, false, nil
		}
		flags, gotTID = sdu[0], uint16(sdu[1])
		gotMessage = binary.LittleEndian.Uint16(sdu[2:])
		body = sdu[6:]
		if flags&0x01 == 0 { // not a response
			return nil, false, nil
		}
	} else {
		if len(sdu) < 7 {
			return nil, false, nil
		}
		flags, gotTID = sdu[0], binary.LittleEndian.Uint16(sdu[1:])
		gotMessage = binary.LittleEndian.Uint16(sdu[3:])
		body = sdu[7:]
		if flags&0x02 == 0 {
			return nil, false, nil
		}
	}
	if gotTID != tid || gotMessage != message {
		return nil, false, nil
	}
	tlvs := decodeQMITLVs(body)
	if result := tlvs[0x02]; len(result) >= 4 && binary.LittleEndian.Uint16(result) != 0 {
		return tlvs, true, qmuxError(binary.LittleEndian.Uint16(result[2:]))
	}
	return tlvs, true, nil
}

func (c *qmuxConn) allocateClient(service uint8) (uint8, error) {
	tlvs, err := c.request(qmuxServiceCTL, 0, 0x0022, []qmuxTLV{{0x01, []byte{service}}})
	if err != nil {
		return 0, err
	}
	if id := tlvs[0x01]; len(id) >= 2 && id[0] == service {
		return id[1], nil
	}
	return 0, errors.New("QMI client allocation returned no id")
}

func (c *qmuxConn) releaseClient(service, client uint8) {
	_, _ = c.request(qmuxServiceCTL, 0, 0x0023, []qmuxTLV{{0x01, []byte{service, client}}})
}

// qmuxQuery fills info from DMS, NAS and WDS. It reports false when the node
// does not speak QMI at all, so the caller can fall back to the uqmi CLI.
func qmuxQuery(path string, info *Info) bool {
	lock, _ := qmuxLocks.LoadOrStore(path, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	if cdcWDMDriver(path) == "cdc_mbim" {
		return false
	}
	conn, err := openQMUXDevice(path)
	if err != nil {
		return false
	}
	defer conn.close()
	answered, silent := false, false
	withClient := func(service uint8, fn func(client uint8)) {
		if silent {
			return
		}
		client, err := conn.allocateClient(service)
		if err != nil {
			// A QMI error is an answer; silence means the node does not
			// speak QMI, so stop instead of waiting out every timeout.
			var qmiErr qmuxError
			silent = !errors.As(err, &qmiErr)
			return
		}
		answered = true
		defer conn.releaseClient(service, client)
		fn(client)
	}
	withClient(qmuxServiceDMS, func(client uint8) {
		if tlvs, err := conn.request(qmuxServiceDMS, client, 0x0025, nil); err == nil && info.IMEI == "" {
			info.IMEI = qmiString(tlvs[0x11])
		}
		if tlvs, err := conn.request(qmuxServiceDMS, client, 0x0043, nil); err == nil && info.IMSI == "" {
			info.IMSI = qmiString(tlvs[0x01])
		}
		if tlvs, err := conn.request(qmuxServiceDMS, client, 0x003C, nil); err == nil && info.ICCID == "" {
			info.ICCID = qmiString(tlvs[0x01])
		}
	})
	withClient(qmuxServiceNAS, func(client uint8) {
		if tlvs, err := conn.request(qmuxServiceNAS, client, 0x0024, nil); err == nil {
			applyQMIServingSystem(tlvs, info)
		}
		if tlvs, err := conn.request(qmuxServiceNAS, client, 0x004F, nil); err == nil {
			applyQMISignalInfo(tlvs, info)
		}
	})
	withClient(qmuxServiceWDS, func(client uint8) {
		if tlvs, err := conn.request(qmuxServiceWDS, client, 0x0022, nil); err == nil {
			if status := tlvs[0x01]; len(status) >= 1 {
				info.Connected = status[0] == 0x02
			}
		}
		// Requested settings: APN, DNS, IP address and gateway.
		mask := make([]byte, 4)
		binary.LittleEndian.PutUint32(mask, 1<<3|1<<4|1<<8|1<<9)
		if tlvs, err := conn.request(qmuxServiceWDS, client, 0x002D, []qmuxTLV{{0x10, mask}}); err == nil {
			applyQMICurrentSettings(tlvs, info)
		}
	})
	if answered && info.Protocol == "sysfs" {
		info.Protocol = "qmi"
	}
	return answered
}

// cdcWDMDriver names the kernel driver behind a cdc-wdm node (qmi_wwan,
// cdc_mbim), or "" when sysfs does not say.
func cdcWDMDriver(path string) string {
	link, err := os.Readlink(filepath.Join("/sys/class/usbmisc", filepath.Base(path), "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

func qmiString(value []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(value), "\x00"))
}

// NAS radio interfaces (QmiNasRadioInterface).
func qmiRadioTech(rats []byte) Technology {
	has := map[byte]bool{}
	for _, rat := range rats {
		has[rat] = true
	}
	switch {
	case has[12] && has[8]:
		return TechNR5GNSA
	case has[12]:
		return TechNR5G
	case has[8]:
		return TechLTE
	case has[5], has[9]:
		return TechUMTS
	case has[4]:
		return TechGSM
	}
	return TechUnknown
}

func applyQMIServingSystem(tlvs map[uint8][]byte, info *Info) {
	if serving := tlvs[0x01]; len(serving) >= 5 {
		status := RegUnknown
		switch serving[0] {
		case 0:
			status = RegNotRegistered
		case 1:
			status = RegHome
		case 2:
			status = RegSearching
		case 3:
			status = RegDenied
		}
		count := int(serving[4])
		if len(serving) >= 5+count {
			info.Technology = firstKnownTech(info.Technology, qmiRadioTech(serving[5:5+count]))
		}
		if roaming := tlvs[0x10]; status == RegHome && len(roaming) >= 1 && roaming[0] == 0 {
			status = RegRoaming
		}
		info.Status = firstKnownReg(info.Status, status)
	}
	if plmn := tlvs[0x12]; len(plmn) >= 5 {
		mcc, mnc := binary.LittleEndian.Uint16(plmn), binary.LittleEndian.Uint16(plmn[2:])
		info.OperatorMCC = firstNonEmpty(info.OperatorMCC, fmt.Sprintf("%03d", mcc))
		info.OperatorMNC = firstNonEmpty(info.OperatorMNC, fmt.Sprintf("%02d", mnc))
		if size := int(plmn[4]); len(plmn) >= 5+size {
			info.Operator = firstNonEmpty(info.Operator, qmiString(plmn[5:5+size]))
		}
	}
}

func applyQMISignalInfo(tlvs map[uint8][]byte, info *Info) {
	le := binary.LittleEndian
	if gsm := tlvs[0x12]; len(gsm) >= 1 {
		info.Signal.RSSI = int(int8(gsm[0]))
	}
	if wcdma := tlvs[0x13]; len(wcdma) >= 3 {
		info.Signal.RSSI = int(int8(wcdma[0]))
		info.Signal.ECIO = -int(int16(le.Uint16(wcdma[1:]))) / 2 // -0.5 dB units
	}
	if lte := tlvs[0x14]; len(lte) >= 6 {
		info.Signal.RSSI = int(int8(lte[0]))
		info.Signal.RSRQ = int(int8(lte[1]))
		info.Signal.RSRP = int(int16(le.Uint16(lte[2:])))
		info.Signal.SINR = int(int16(le.Uint16(lte[4:]))) / 10 // 0.1 dB units
	}
	if nr := tlvs[0x17]; len(nr) >= 4 {
		if rsrp := int(int16(le.Uint16(nr))); rsrp != 0 && rsrp > -32768 {
			info.Signal.RSRP = rsrp
		}
		if snr := int(int16(le.Uint16(nr[2:]))); snr > -32768 {
			info.Signal.SINR = snr / 10
		}
	}
	if nrRSRQ := tlvs[0x18]; len(nrRSRQ) >= 2 {
		if rsrq := int(int16(le.Uint16(nrRSRQ))); rsrq > -32768 {
			info.Signal.RSRQ = rsrq
		}
	}
}

func qmiIPv4(value []byte) string {
	if len(value) < 4 {
		return ""
	}
	v := binary.LittleEndian.Uint32(value)
	if v == 0 {
		return ""
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

func applyQMICurrentSettings(tlvs map[uint8][]byte, info *Info) {
	info.APN = firstNonEmpty(info.APN, qmiString(tlvs[0x14]))
	info.DNS1 = firstNonEmpty(info.DNS1, qmiIPv4(tlvs[0x15]))
	info.DNS2 = firstNonEmpty(info.DNS2, qmiIPv4(tlvs[0x16]))
	info.IPAddress = firstNonEmpty(info.IPAddress, qmiIPv4(tlvs[0x1E]))
	if v6 := tlvs[0x25]; len(v6) >= 16 {
		if ip := net.IP(v6[:16]); !ip.IsUnspecified() {
			info.IPv6Address = firstNonEmpty(info.IPv6Address, ip.String())
		}
	}
	if info.IPAddress != "" || info.IPv6Address != "" {
		info.Connected = true
	}
}
