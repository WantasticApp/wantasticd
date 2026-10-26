//go:build linux

package modem

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

// SMS in PDU mode (AT+CMGF=0), the way sms_tool works: GSM 7-bit or UCS-2
// is chosen per message, long texts are split with concatenation headers,
// and received parts are joined again.

// smsSubmitPDU is one AT+CMGS frame: the hex PDU (with an empty SMSC field,
// so the SIM's service centre is used) and the TPDU length CMGS expects.
type smsSubmitPDU struct {
	hex    string
	length int
}

func encodeSMSSubmit(number, message string) ([]smsSubmitPDU, error) {
	pdus, err := sms.Encode([]byte(message), sms.To(number), sms.WithAllCharsets)
	if err != nil {
		return nil, fmt.Errorf("encode SMS: %w", err)
	}
	out := make([]smsSubmitPDU, 0, len(pdus))
	for i := range pdus {
		raw, err := pdus[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode SMS part %d: %w", i+1, err)
		}
		out = append(out, smsSubmitPDU{hex: "00" + strings.ToUpper(hex.EncodeToString(raw)), length: len(raw)})
	}
	return out, nil
}

// smsInboxMessage is the inbox row shape the console already parses; Index
// lists every storage slot of a joined multi-part message ("3,4,5").
type smsInboxMessage struct {
	Storage string `json:"storage,omitempty"`
	Index   string `json:"index"`
	Status  string `json:"status,omitempty"`
	Number  string `json:"number,omitempty"`
	Time    string `json:"time,omitempty"`
	Body    string `json:"body,omitempty"`
	Error   string `json:"error,omitempty"`
}

type smsPDUEntry struct {
	index  int
	status string
	tpdu   *tpdu.TPDU
	// err is set when the stored PDU could not be decoded. The row is still
	// listed (with its storage index) so it can be deleted from the console
	// instead of silently filling the SIM.
	err error
}

var cmglStatus = map[string]string{"0": "REC UNREAD", "1": "REC READ", "2": "STO UNSENT", "3": "STO SENT"}

// parseCMGLPDUs reads AT+CMGL=4 output in PDU mode: a "+CMGL: idx,stat,,len"
// line followed by the hex PDU (SMSC field included). Unsolicited result
// codes the modem interleaves (+CMTI, +QIND, RDY, ...) are skipped while
// looking for the PDU, so a URC never shifts every later message.
func parseCMGLPDUs(lines []string) []smsPDUEntry {
	var out []smsPDUEntry
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "+CMGL:") {
			continue
		}
		fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "+CMGL:")), ",")
		index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil || index <= 0 {
			continue
		}
		stat := ""
		if len(fields) > 1 {
			stat = strings.TrimSpace(fields[1])
		}
		pduLine := ""
		for j := i + 1; j < len(lines); j++ {
			candidate := strings.TrimSpace(lines[j])
			if strings.HasPrefix(candidate, "+CMGL:") {
				break
			}
			if isHexPDU(candidate) {
				pduLine = candidate
				i = j
				break
			}
		}
		entry := smsPDUEntry{index: index, status: cmglStatus[stat]}
		entry.tpdu, entry.err = decodeStoredPDU(pduLine, stat)
		out = append(out, entry)
	}
	return out
}

func isHexPDU(value string) bool {
	if len(value) < 4 || len(value)%2 != 0 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// decodeStoredPDU strips the SMSC field and unmarshals the TPDU. Stored
// outgoing messages (stat 2/3) are SMS-SUBMIT and must be decoded in the
// mobile-originated direction, or their MTI reads as a SUBMIT-REPORT.
func decodeStoredPDU(pduLine, stat string) (*tpdu.TPDU, error) {
	if pduLine == "" {
		return nil, fmt.Errorf("missing PDU")
	}
	raw, err := hex.DecodeString(pduLine)
	if err != nil {
		return nil, fmt.Errorf("invalid PDU hex: %w", err)
	}
	if len(raw) < 1 || len(raw) < 1+int(raw[0]) {
		return nil, fmt.Errorf("truncated PDU")
	}
	direction := sms.AsMT
	if stat == "2" || stat == "3" {
		direction = sms.AsMO
	}
	pdu, err := sms.Unmarshal(raw[1+int(raw[0]):], direction)
	if err != nil {
		return nil, fmt.Errorf("decode PDU: %w", err)
	}
	return pdu, nil
}

// smsPeerNumber is the sender of a received message or the recipient of a
// stored outgoing one.
func smsPeerNumber(pdu *tpdu.TPDU) string {
	if pdu == nil {
		return ""
	}
	if pdu.SmsType() == tpdu.SmsSubmit {
		return pdu.DA.Number()
	}
	return pdu.OA.Number()
}

// joinSMSPDUs decodes entries into inbox rows, joining concatenated parts
// from the same sender and reference. Incomplete sets are shown per part.
func joinSMSPDUs(storage string, entries []smsPDUEntry) []smsInboxMessage {
	type group struct {
		parts    map[int]smsPDUEntry
		segments int
	}
	groups := map[string]*group{}
	var order []string
	var out []smsInboxMessage
	emit := func(parts []smsPDUEntry) {
		segments := make([]*tpdu.TPDU, len(parts))
		indexes := make([]string, len(parts))
		for i, part := range parts {
			segments[i] = part.tpdu
			indexes[i] = strconv.Itoa(part.index)
		}
		first := parts[0]
		msg := smsInboxMessage{
			Storage: storage,
			Index:   strings.Join(indexes, ","),
			Status:  first.status,
		}
		if first.tpdu == nil {
			msg.Error = first.err.Error()
			out = append(out, msg)
			return
		}
		msg.Number = smsPeerNumber(first.tpdu)
		if body, err := sms.Decode(segments); err == nil {
			msg.Body = normalizeSMSBody(string(body))
		} else {
			msg.Error = "decode text: " + err.Error()
		}
		if first.tpdu.SmsType() == tpdu.SmsDeliver && !first.tpdu.SCTS.IsZero() {
			msg.Time = first.tpdu.SCTS.Format("2006-01-02T15:04:05-07:00")
		}
		out = append(out, msg)
	}
	for _, entry := range entries {
		if entry.tpdu == nil {
			emit([]smsPDUEntry{entry})
			continue
		}
		segments, seqno, mref, ok := entry.tpdu.ConcatInfo()
		if !ok || segments <= 1 {
			emit([]smsPDUEntry{entry})
			continue
		}
		key := fmt.Sprintf("%s|%d|%d|%d", smsPeerNumber(entry.tpdu), entry.tpdu.SmsType(), mref, segments)
		g := groups[key]
		if g == nil {
			g = &group{parts: map[int]smsPDUEntry{}, segments: segments}
			groups[key] = g
			order = append(order, key)
		}
		g.parts[seqno] = entry
	}
	for _, key := range order {
		g := groups[key]
		seqnos := make([]int, 0, len(g.parts))
		for seqno := range g.parts {
			seqnos = append(seqnos, seqno)
		}
		sort.Ints(seqnos)
		parts := make([]smsPDUEntry, 0, len(seqnos))
		for _, seqno := range seqnos {
			parts = append(parts, g.parts[seqno])
		}
		if len(parts) == g.segments {
			emit(parts)
			continue
		}
		for _, part := range parts {
			emit([]smsPDUEntry{part})
		}
	}
	return out
}

// sortSMSInbox orders rows oldest first by service-centre time, keeping the
// storage order for rows without one (stored drafts, undecodable PDUs), so a
// size-capped inbox keeps the newest messages at the end.
func sortSMSInbox(messages []smsInboxMessage) {
	sort.SliceStable(messages, func(i, j int) bool {
		ti, okI := parseSMSInboxTime(messages[i].Time)
		tj, okJ := parseSMSInboxTime(messages[j].Time)
		if okI != okJ {
			return !okI
		}
		return okI && ti.Before(tj)
	})
}

func parseSMSInboxTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05-07:00", value)
	return t, err == nil
}

// parseSMSDeleteTarget accepts "SM:3", "ME:3,4,5" or "7" (SIM storage).
func parseSMSDeleteTarget(value string) (string, []int, error) {
	storage, list := "SM", strings.TrimSpace(value)
	if parts := strings.SplitN(list, ":", 2); len(parts) == 2 {
		storage, list = strings.ToUpper(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
	}
	if storage != "SM" && storage != "ME" {
		return "", nil, fmt.Errorf("SMS storage must be SM or ME")
	}
	var indexes []int
	for _, item := range strings.Split(list, ",") {
		index, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || index <= 0 || index > 9999 {
			return "", nil, fmt.Errorf("SMS index must be a positive integer or storage:index[,index]")
		}
		indexes = append(indexes, index)
	}
	if len(indexes) == 0 || len(indexes) > 32 {
		return "", nil, fmt.Errorf("SMS index list is empty or too long")
	}
	return storage, indexes, nil
}
