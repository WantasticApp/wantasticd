//go:build linux

package modem

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Quectel modems in ECM or RNDIS USB mode need the data call bound to their
// USB network device with AT+QNETDEVCTL; AT+CGACT alone activates the PDP
// context but leaves the host link without traffic. Two argument orders
// exist: ASR-chipset modems (EC200T/EC100Y, which reject
// AT+QNETDEVSTATUS=?) take "op,cid,urc" and need the context active first;
// the others take "cid,op,urc" and report readiness via AT+QNETDEVSTATUS.
// (Command semantics per Quectel's AT manuals and QConnectManager.)

type atSender func(cmd string, timeoutSeconds int) ([]string, error)

type quectelNetdevStyle int

const (
	quectelNetdevNone quectelNetdevStyle = iota
	quectelNetdevQualcomm
	quectelNetdevASR
)

// quectelUSBNetMode reads AT+QCFG="usbnet": 0 RmNet/QMI, 1 ECM, 2 MBIM,
// 3 RNDIS; -1 when unknown.
func quectelUSBNetMode(send atSender) int {
	lines, err := send(`AT+QCFG="usbnet"`, 5)
	if err != nil {
		return -1
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "+QCFG:") {
			continue
		}
		fields := strings.Split(strings.TrimPrefix(line, "+QCFG:"), ",")
		if len(fields) >= 2 {
			if mode, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil {
				return mode
			}
		}
	}
	return -1
}

func detectQuectelNetdev(send atSender) quectelNetdevStyle {
	switch quectelUSBNetMode(send) {
	case 0, 2: // QMI and MBIM are dialled over their control channel
		return quectelNetdevNone
	}
	if _, err := send("AT+QNETDEVCTL=?", 5); err != nil {
		return quectelNetdevNone
	}
	if _, err := send("AT+QNETDEVSTATUS=?", 5); err != nil {
		return quectelNetdevASR
	}
	return quectelNetdevQualcomm
}

func pdpContextActive(send atSender, cid int) bool {
	lines, err := send("AT+CGACT?", 10)
	if err != nil {
		return false
	}
	for _, line := range lines {
		fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "+CGACT:")), ",")
		if len(fields) >= 2 && strings.TrimSpace(fields[0]) == strconv.Itoa(cid) {
			return strings.TrimSpace(fields[1]) == "1"
		}
	}
	return false
}

// quectelNetdevConnect brings the data call up on the USB network device
// and, where the modem can say, waits until it carries an address.
func quectelNetdevConnect(send atSender, style quectelNetdevStyle, cid int, wait time.Duration) error {
	switch style {
	case quectelNetdevASR:
		if !pdpContextActive(send, cid) {
			if _, err := send(fmt.Sprintf("AT+CGACT=1,%d", cid), 30); err != nil {
				return err
			}
		}
		_, err := send(fmt.Sprintf("AT+QNETDEVCTL=1,%d,1", cid), 30)
		return err
	case quectelNetdevQualcomm:
		if _, err := send(fmt.Sprintf("AT+QNETDEVCTL=%d,1,1", cid), 30); err != nil {
			return err
		}
		deadline := time.Now().Add(wait)
		for {
			if _, err := send(fmt.Sprintf("AT+QNETDEVSTATUS=%d", cid), 5); err == nil {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("modem did not report the data call up within %s", wait)
			}
			time.Sleep(time.Second)
		}
	}
	return fmt.Errorf("modem has no USB network device control")
}

func quectelNetdevDisconnect(send atSender, style quectelNetdevStyle, cid int) error {
	cmd := fmt.Sprintf("AT+QNETDEVCTL=%d,0,0", cid)
	if style == quectelNetdevASR {
		cmd = fmt.Sprintf("AT+QNETDEVCTL=0,%d,0", cid)
	}
	_, err := send(cmd, 30)
	return err
}
