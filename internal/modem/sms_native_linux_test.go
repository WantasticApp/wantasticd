//go:build linux

package modem

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeSMSModem answers AT, CMGF, CMGS (with the "> " prompt and Ctrl-Z
// terminated PDU) and CMGL on the master side of a pty.
type fakeSMSModem struct {
	mu        sync.Mutex
	submitted []string
	inbox     map[string][]string // storage → CMGL lines
	failing   map[string]string   // storage → final error line
	commands  []string
	textMode  bool
}

func (m *fakeSMSModem) serve(master int) {
	buf := make([]byte, 4096)
	var pending strings.Builder
	awaitingPDU := false
	reply := func(text string) { _, _ = unix.Write(master, []byte(text)) }
	for {
		n, err := unix.Read(master, buf)
		if err == unix.EIO {
			// No slave open between two sessions; wait for the next one.
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err != nil || n == 0 {
			return
		}
		pending.Write(buf[:n])
		for {
			data := pending.String()
			if awaitingPDU {
				end := strings.IndexByte(data, 0x1a)
				if end < 0 {
					break
				}
				m.mu.Lock()
				m.submitted = append(m.submitted, strings.TrimSpace(data[:end]))
				m.mu.Unlock()
				pending.Reset()
				pending.WriteString(data[end+1:])
				awaitingPDU = false
				reply("\r\n+CMGS: 42\r\n\r\nOK\r\n")
				continue
			}
			end := strings.IndexByte(data, '\r')
			if end < 0 {
				break
			}
			cmd := strings.TrimSpace(data[:end])
			pending.Reset()
			pending.WriteString(strings.TrimLeft(data[end+1:], "\n"))
			if cmd != "" {
				m.mu.Lock()
				m.commands = append(m.commands, cmd)
				m.mu.Unlock()
			}
			switch {
			case cmd == "":
			case cmd == "AT+CMGF?" && m.textMode:
				reply("\r\n+CMGF: 1\r\n\r\nOK\r\n")
			case strings.HasPrefix(cmd, "AT+CMGS="):
				awaitingPDU = true
				reply("\r\n> ")
			case strings.Contains(cmd, "+CMGL=4"):
				storage := "SM"
				if strings.Contains(cmd, `"ME"`) {
					storage = "ME"
				}
				if failure := m.failing[storage]; failure != "" {
					reply("\r\n" + failure + "\r\n")
					continue
				}
				reply("\r\n" + strings.Join(m.inbox[storage], "\r\n") + "\r\n\r\nOK\r\n")
			default:
				reply("\r\nOK\r\n")
			}
		}
	}
}

func TestNativePDUSendAndList(t *testing.T) {
	master, slave := openPTY(t)
	atLockDir = t.TempDir()
	t.Cleanup(func() { atLockDir = "/var/lock" })
	modem := &fakeSMSModem{inbox: map[string][]string{
		"SM": append([]string{"+CMGL: 2,1,,40"}, deliverPDUs(t, "+212622222222", "Bonjour, coupure prévue ce soir")[0]),
	}}
	go modem.serve(master)

	c := &atController{}
	long := strings.Repeat("Router back online. ", 10) // 200 chars → 2 parts
	if err := c.sendSMSPDU(slave, "+212600000000", long); err != nil {
		t.Fatal(err)
	}
	modem.mu.Lock()
	sent := append([]string(nil), modem.submitted...)
	modem.mu.Unlock()
	if len(sent) != 2 || !strings.HasPrefix(sent[0], "00") {
		t.Fatalf("submitted=%q", sent)
	}

	payload, err := c.listSMSPDU(slave)
	if err != nil {
		t.Fatal(err)
	}
	var inbox []smsInboxMessage
	if err := json.Unmarshal([]byte(payload), &inbox); err != nil || len(inbox) != 1 {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
	if inbox[0].Body != "Bonjour, coupure prévue ce soir" || inbox[0].Storage != "SM" || inbox[0].Index != "2" {
		t.Fatalf("inbox=%+v", inbox[0])
	}
}

func TestNativePDUListRestoresTextModeAndToleratesStorageErrors(t *testing.T) {
	master, slave := openPTY(t)
	atLockDir = t.TempDir()
	t.Cleanup(func() { atLockDir = "/var/lock" })
	long := strings.Repeat("Coverage maintenance tonight. ", 9)
	parts := deliverPDUs(t, "+212655555555", long)
	lines := []string{"+CPMS: 2,50,2,50,2,50"}
	for i, pdu := range parts {
		lines = append(lines, fmt.Sprintf("+CMGL: %d,1,,140", 7+i), pdu)
		if i == 0 {
			lines = append(lines, `+CMTI: "SM",9`)
		}
	}
	modem := &fakeSMSModem{
		textMode: true,
		inbox:    map[string][]string{"SM": lines},
		failing:  map[string]string{"ME": "+CMS ERROR: 302"},
	}
	go modem.serve(master)

	payload, err := (&atController{}).listSMSPDU(slave)
	if err != nil {
		t.Fatal(err)
	}
	var inbox []smsInboxMessage
	if err := json.Unmarshal([]byte(payload), &inbox); err != nil || len(inbox) != 1 {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
	if inbox[0].Body != normalizeSMSBody(long) || inbox[0].Index != "7,8" {
		t.Fatalf("joined=%+v", inbox[0])
	}
	modem.mu.Lock()
	commands := append([]string(nil), modem.commands...)
	modem.mu.Unlock()
	if last := commands[len(commands)-1]; last != "AT+CMGF=1" {
		t.Fatalf("text mode not restored; commands=%q", commands)
	}
}

func TestATPortLockSerializesSessions(t *testing.T) {
	release, err := lockATPort("/dev/ttyTEST0", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockATPort("/dev/ttyTEST0", 50*time.Millisecond); err == nil {
		t.Fatal("second session got the port while the first held it")
	}
	other, err := lockATPort("/dev/ttyTEST1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("another port must not be blocked: %v", err)
	}
	other()
	release()
	release() // idempotent
	again, err := lockATPort("/dev/ttyTEST0", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("port not released: %v", err)
	}
	again()
}

func TestATIdentityCacheFollowsSIMState(t *testing.T) {
	t.Cleanup(invalidateATIdentity)
	port := "/dev/ttyTEST2"
	storeATIdentity(port, &Info{Model: "RM520N-GL", IMEI: "860000000000001", ICCID: "8921200000000000001", SIMStatus: SIMReady})

	info := &Info{SIMStatus: SIMReady}
	if !applyCachedATIdentity(port, info) || info.IMEI != "860000000000001" || info.ICCID == "" {
		t.Fatalf("cached identity not applied: %+v", info)
	}
	if applyCachedATIdentity(port, &Info{SIMStatus: SIMAbsent}) {
		t.Fatal("SIM state change must force a fresh identity read")
	}
	invalidateATIdentity()
	if applyCachedATIdentity(port, &Info{SIMStatus: SIMReady}) {
		t.Fatal("identity survived invalidation")
	}
}

func TestBridgeRetriesOnlyIdempotentSMSCommands(t *testing.T) {
	for cmd, want := range map[string]bool{
		`AT+CMGF=0;+CPMS="SM";+CMGL=4`: true,
		"AT+CMGF=1":                    true,
		"AT+CMGF?":                     true,
		`AT+CMGF=0;+CPMS="SM";+CMGD=3`: false,
		"AT+CMGS=23":                   false,
	} {
		if got := isBridgeReadOnlyATCommand(cmd); got != want {
			t.Errorf("%q: got %v want %v", cmd, got, want)
		}
	}
	if mode := parseCMGFMode([]string{"+CMGF: 1"}); mode != "1" {
		t.Fatalf("mode=%q", mode)
	}
}
