//go:build linux

package modem

import (
	"encoding/json"
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
			switch {
			case cmd == "":
			case strings.HasPrefix(cmd, "AT+CMGS="):
				awaitingPDU = true
				reply("\r\n> ")
			case strings.Contains(cmd, "+CMGL=4"):
				storage := "SM"
				if strings.Contains(cmd, `"ME"`) {
					storage = "ME"
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
