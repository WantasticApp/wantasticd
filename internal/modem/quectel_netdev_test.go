//go:build linux

package modem

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type scriptedModem struct {
	replies map[string][]string // command → lines; missing → ERROR
	sent    []string
	fails   map[string]int // command → number of ERRORs before OK
}

func (m *scriptedModem) send(cmd string, _ int) ([]string, error) {
	m.sent = append(m.sent, cmd)
	if m.fails[cmd] > 0 {
		m.fails[cmd]--
		return nil, errors.New("ERROR")
	}
	if lines, ok := m.replies[cmd]; ok {
		return lines, nil
	}
	return nil, errors.New("ERROR")
}

func TestQuectelNetdevQualcommStyle(t *testing.T) {
	m := &scriptedModem{
		replies: map[string][]string{
			`AT+QCFG="usbnet"`:    {`+QCFG: "usbnet",1`},
			"AT+QNETDEVCTL=?":     {"+QNETDEVCTL: (0-3),(1-16),(0,1)"},
			"AT+QNETDEVSTATUS=?":  {"+QNETDEVSTATUS: (1-16)"},
			"AT+QNETDEVCTL=1,1,1": {},
			"AT+QNETDEVSTATUS=1":  {"+QNETDEVSTATUS: 0A400102,FFFFFFFC,0A400101,0A400101,08080808"},
			"AT+QNETDEVCTL=1,0,0": {},
		},
		fails: map[string]int{"AT+QNETDEVSTATUS=1": 1},
	}
	style := detectQuectelNetdev(m.send)
	if style != quectelNetdevQualcomm {
		t.Fatalf("style=%v", style)
	}
	if err := quectelNetdevConnect(m.send, style, 1, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := quectelNetdevDisconnect(m.send, style, 1); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.sent, " | "); !strings.Contains(got, "AT+QNETDEVCTL=1,1,1") || !strings.HasSuffix(got, "AT+QNETDEVCTL=1,0,0") {
		t.Fatalf("sent=%s", got)
	}
}

func TestQuectelNetdevASRStyleActivatesContextFirst(t *testing.T) {
	m := &scriptedModem{replies: map[string][]string{
		`AT+QCFG="usbnet"`:    {`+QCFG: "usbnet",3`},
		"AT+QNETDEVCTL=?":     {"+QNETDEVCTL: (0,1),(1-8),(0,1)"},
		"AT+CGACT?":           {"+CGACT: 1,0"},
		"AT+CGACT=1,1":        {},
		"AT+QNETDEVCTL=1,1,1": {},
		"AT+QNETDEVCTL=0,1,0": {},
	}}
	style := detectQuectelNetdev(m.send)
	if style != quectelNetdevASR {
		t.Fatalf("style=%v", style)
	}
	if err := quectelNetdevConnect(m.send, style, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := quectelNetdevDisconnect(m.send, style, 1); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(m.sent, " | ")
	if !strings.Contains(got, "AT+CGACT=1,1 | AT+QNETDEVCTL=1,1,1") || !strings.HasSuffix(got, "AT+QNETDEVCTL=0,1,0") {
		t.Fatalf("sent=%s", got)
	}
}

func TestQuectelNetdevSkipsQMIAndMBIM(t *testing.T) {
	for _, mode := range []string{"0", "2"} {
		m := &scriptedModem{replies: map[string][]string{`AT+QCFG="usbnet"`: {`+QCFG: "usbnet",` + mode}, "AT+QNETDEVCTL=?": {}}}
		if style := detectQuectelNetdev(m.send); style != quectelNetdevNone {
			t.Fatalf("usbnet %s: style=%v", mode, style)
		}
	}
	plain := &scriptedModem{replies: map[string][]string{}}
	if style := detectQuectelNetdev(plain.send); style != quectelNetdevNone {
		t.Fatalf("non-Quectel modem: style=%v", style)
	}
}
