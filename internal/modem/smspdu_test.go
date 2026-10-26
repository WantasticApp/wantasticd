//go:build linux

package modem

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

func TestEncodeSMSSubmitChoosesAlphabetAndSplits(t *testing.T) {
	short, err := encodeSMSSubmit("+212600000000", "Router back online")
	if err != nil || len(short) != 1 || !strings.HasPrefix(short[0].hex, "00") || short[0].length*2+2 != len(short[0].hex) {
		t.Fatalf("short=%+v err=%v", short, err)
	}
	arabic, err := encodeSMSSubmit("+212600000000", "مرحبا بك")
	if err != nil || len(arabic) != 1 {
		t.Fatalf("ucs2=%+v err=%v", arabic, err)
	}
	long, err := encodeSMSSubmit("+212600000000", strings.Repeat("a", 400))
	if err != nil || len(long) != 3 {
		t.Fatalf("400 GSM chars should take 3 concatenated parts, got %d (err=%v)", len(long), err)
	}
}

// deliverPDUs builds what a modem stores for a received message: SMSC field
// (here 7 bytes) followed by SMS-DELIVER TPDUs.
func deliverPDUs(t *testing.T, from, text string) []string {
	t.Helper()
	tmpl := tpdu.TPDU{Direction: tpdu.MT}
	tmpl.SetSmsType(tpdu.SmsDeliver)
	tmpl.OA.SetNumber(from)
	pdus, err := sms.Encode([]byte(text), sms.WithTemplate(tmpl), sms.WithAllCharsets)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := range pdus {
		raw, err := pdus[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, "07912160130300F4"[:16]+strings.ToUpper(hex.EncodeToString(raw)))
	}
	return out
}

func TestParseAndJoinCMGL(t *testing.T) {
	long := strings.Repeat("Signal restored on tower 7. ", 12)
	parts := deliverPDUs(t, "+212611111111", long)
	if len(parts) < 2 {
		t.Fatalf("expected a multi-part message, got %d", len(parts))
	}
	lines := []string{}
	for i, pdu := range parts {
		lines = append(lines, "+CMGL: "+[]string{"3", "4", "5", "6"}[i]+",1,,140", pdu)
	}
	single := deliverPDUs(t, "7535", "Votre forfait expire demain")
	lines = append(lines, "+CMGL: 9,0,,40", single[0])
	lines = append(lines, "+CMGL: 10,1,,12", "ZZ-not-hex")

	messages := joinSMSPDUs("SM", parseCMGLPDUs(lines))
	if len(messages) != 3 {
		t.Fatalf("messages=%+v", messages)
	}
	// An undecodable slot stays listed (so it can be deleted) with an error.
	if bad := messages[1]; bad.Index != "10" || bad.Error == "" || bad.Body != "" {
		t.Fatalf("undecodable=%+v", bad)
	}
	messages = append(messages[:1], messages[2:]...)
	if strings.TrimPrefix(messages[0].Number, "+") != "7535" || messages[0].Index != "9" || messages[0].Status != "REC UNREAD" || messages[0].Body != "Votre forfait expire demain" {
		t.Fatalf("single=%+v", messages[0])
	}
	joined := messages[1]
	if joined.Body != strings.TrimSpace(normalizeSMSBody(long)) && joined.Body != normalizeSMSBody(long) {
		t.Fatalf("joined body=%q", joined.Body)
	}
	if !strings.HasPrefix(joined.Index, "3,4") || joined.Number != "+212611111111" {
		t.Fatalf("joined=%+v", joined)
	}
}

func TestParseSMSDeleteTarget(t *testing.T) {
	if storage, idx, err := parseSMSDeleteTarget("ME:3,4,5"); err != nil || storage != "ME" || len(idx) != 3 {
		t.Fatalf("%s %v %v", storage, idx, err)
	}
	for _, bad := range []string{"XX:1", "SM:0", "SM:a", "SM:"} {
		if _, _, err := parseSMSDeleteTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// submitPDU builds a stored outgoing message the way a modem keeps it after
// AT+CMGW or a sent CMGS: empty SMSC field then an SMS-SUBMIT TPDU.
func storedSubmitPDU(t *testing.T, to, text string) string {
	t.Helper()
	pdus, err := encodeSMSSubmit(to, text)
	if err != nil || len(pdus) != 1 {
		t.Fatalf("encode: %v", err)
	}
	return pdus[0].hex
}

func TestParseCMGLSkipsURCsAndDecodesStoredSubmit(t *testing.T) {
	deliver := deliverPDUs(t, "+212633333333", "Facture disponible")[0]
	lines := []string{
		"+CPMS: 3,50,3,50,3,50",
		"+CMGL: 1,1,,30",
		"+CMTI: \"SM\",4", // URC between header and PDU
		deliver,
		"+QIND: \"csq\",20,99",
		"+CMGL: 2,3,,25",
		storedSubmitPDU(t, "+212644444444", "Reboot scheduled"),
		"+CMGL: 3,0,,30", // PDU line lost: must not swallow the next header
		"+CMGL: 4,0,,30",
		deliver,
	}
	entries := parseCMGLPDUs(lines)
	if len(entries) != 4 {
		t.Fatalf("entries=%d %+v", len(entries), entries)
	}
	messages := joinSMSPDUs("SM", entries)
	byIndex := map[string]smsInboxMessage{}
	for _, msg := range messages {
		byIndex[msg.Index] = msg
	}
	if got := byIndex["1"]; got.Body != "Facture disponible" || got.Number != "+212633333333" || got.Status != "REC READ" {
		t.Fatalf("deliver after URC=%+v", got)
	}
	if got := byIndex["2"]; got.Body != "Reboot scheduled" || got.Number != "+212644444444" || got.Status != "STO SENT" || got.Time != "" {
		t.Fatalf("stored submit=%+v", got)
	}
	if got := byIndex["3"]; got.Error == "" {
		t.Fatalf("missing PDU should be reported, got %+v", got)
	}
	if got := byIndex["4"]; got.Body != "Facture disponible" || got.Status != "REC UNREAD" {
		t.Fatalf("row after a lost PDU=%+v", got)
	}
}

func TestParseCMGLEmptyStorage(t *testing.T) {
	if entries := parseCMGLPDUs([]string{"+CPMS: 0,50,0,50,0,50"}); len(entries) != 0 {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestSortSMSInboxOldestFirst(t *testing.T) {
	messages := []smsInboxMessage{
		{Index: "9", Time: "2026-10-26T10:00:00+01:00"},
		{Index: "2"},
		{Index: "4", Time: "2026-10-25T08:00:00+00:00"},
	}
	sortSMSInbox(messages)
	if messages[0].Index != "2" || messages[1].Index != "4" || messages[2].Index != "9" {
		t.Fatalf("order=%+v", messages)
	}
}
