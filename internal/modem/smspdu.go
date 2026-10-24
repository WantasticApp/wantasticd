//go:build linux

package modem

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

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
}

type smsPDUEntry struct {
	index  int
	status string
	tpdu   *tpdu.TPDU
}

var cmglStatus = map[string]string{"0": "REC UNREAD", "1": "REC READ", "2": "STO UNSENT", "3": "STO SENT"}

// parseCMGLPDUs reads AT+CMGL=4 output in PDU mode: a "+CMGL: idx,stat,,len"
// line followed by the hex PDU (SMSC field included).
func parseCMGLPDUs(lines []string) []smsPDUEntry {
	var out []smsPDUEntry
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "+CMGL:") || i+1 >= len(lines) {
			continue
		}
		fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "+CMGL:")), ",")
		index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil || index <= 0 {
			continue
		}
		status := ""
		if len(fields) > 1 {
			status = cmglStatus[strings.TrimSpace(fields[1])]
		}
		raw, err := hex.DecodeString(strings.TrimSpace(lines[i+1]))
		i++
		if err != nil || len(raw) < 1 || len(raw) < 1+int(raw[0]) {
			continue
		}
		pdu, err := sms.Unmarshal(raw[1+int(raw[0]):], sms.AsMT)
		if err != nil {
			continue
		}
		out = append(out, smsPDUEntry{index: index, status: status, tpdu: pdu})
	}
	return out
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
		body, err := sms.Decode(segments)
		if err != nil {
			return
		}
		first := parts[0]
		msg := smsInboxMessage{
			Storage: storage,
			Index:   strings.Join(indexes, ","),
			Status:  first.status,
			Number:  first.tpdu.OA.Number(),
			Body:    normalizeSMSBody(string(body)),
		}
		if !first.tpdu.SCTS.IsZero() {
			msg.Time = first.tpdu.SCTS.Format("2006-01-02T15:04:05-07:00")
		}
		out = append(out, msg)
	}
	for _, entry := range entries {
		segments, seqno, mref, ok := entry.tpdu.ConcatInfo()
		if !ok || segments <= 1 {
			emit([]smsPDUEntry{entry})
			continue
		}
		key := fmt.Sprintf("%s|%d|%d", entry.tpdu.OA.Number(), mref, segments)
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
