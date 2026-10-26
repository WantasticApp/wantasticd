//go:build linux && !qmi && !mbim

package modem

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// SMS through ModemManager's Messaging interface (what mmcli --messaging-*
// uses). While ModemManager runs it owns the modem's AT/QMI/MBIM ports and
// keeps its own SMS objects; issuing CMGF/CPMS/CMGL on its port behind its
// back corrupts both sides' replies and makes it re-read storage. Each SMS
// object is read with one Properties.GetAll call, and every call carries a
// deadline so a wedged daemon cannot hang an Operate.

const (
	mmService        = "org.freedesktop.ModemManager1"
	mmMessagingIface = "org.freedesktop.ModemManager1.Modem.Messaging"
	mmSMSIface       = "org.freedesktop.ModemManager1.Sms"
	mmSMSPathPrefix  = "/org/freedesktop/ModemManager1/SMS/"

	mmSMSCallTimeout = 15 * time.Second
	// Sms.Send returns once the network accepted every part.
	mmSMSSendTimeout = 90 * time.Second
)

// mmSystemBus is replaced in tests.
var mmSystemBus = dbus.SystemBus

func modemManagerListSMS(modemPath dbus.ObjectPath) (string, error) {
	conn, err := mmSystemBus()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), mmSMSCallTimeout)
	defer cancel()
	var paths []dbus.ObjectPath
	if err := conn.Object(mmService, modemPath).CallWithContext(ctx, mmMessagingIface+".List", 0).Store(&paths); err != nil {
		return "", fmt.Errorf("ModemManager SMS list: %w", err)
	}
	messages := make([]smsInboxMessage, 0, len(paths))
	for _, path := range paths {
		var props map[string]dbus.Variant
		err := conn.Object(mmService, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, mmSMSIface).Store(&props)
		if err != nil {
			continue // deleted between List and GetAll
		}
		messages = append(messages, modemManagerSMSRow(path, props))
	}
	sortSMSInbox(messages)
	payload, err := json.Marshal(messages)
	return string(payload), err
}

// modemManagerSMSRow maps one org.freedesktop.ModemManager1.Sms object onto
// the inbox row the console parses. Index is the SMS object number, which
// DeleteSMS accepts back; multi-part messages are already joined by
// ModemManager.
func modemManagerSMSRow(path dbus.ObjectPath, props map[string]dbus.Variant) smsInboxMessage {
	str := func(key string) string {
		if v, ok := props[key]; ok {
			if s, ok := v.Value().(string); ok {
				return s
			}
		}
		return ""
	}
	u32 := func(key string) uint32 {
		if v, ok := props[key]; ok {
			if n, ok := v.Value().(uint32); ok {
				return n
			}
		}
		return 0
	}
	msg := smsInboxMessage{
		Storage: modemManagerSMSStorage(u32("Storage")),
		Index:   strings.TrimPrefix(string(path), mmSMSPathPrefix),
		Status:  modemManagerSMSStatus(u32("State")),
		Number:  sanitizeSMSText(str("Number")),
		Body:    normalizeSMSBody(str("Text")),
		Time:    normalizeModemManagerTimestamp(str("Timestamp")),
	}
	if msg.Body == "" {
		if v, ok := props["Data"]; ok {
			if data, ok := v.Value().([]byte); ok && len(data) > 0 {
				msg.Error = fmt.Sprintf("binary message (%d bytes)", len(data))
			}
		}
	}
	return msg
}

// MMSmsState values.
func modemManagerSMSStatus(state uint32) string {
	switch state {
	case 1:
		return "STO UNSENT"
	case 2:
		return "REC PARTIAL" // parts still missing
	case 3:
		return "REC READ"
	case 4:
		return "STO SENDING"
	case 5:
		return "STO SENT"
	default:
		return ""
	}
}

// MMSmsStorage values.
func modemManagerSMSStorage(storage uint32) string {
	switch storage {
	case 1:
		return "SM"
	case 2:
		return "ME"
	case 3:
		return "MT"
	case 4:
		return "SR"
	case 5:
		return "BM"
	case 6:
		return "TA"
	default:
		return ""
	}
}

// normalizeModemManagerTimestamp converts ModemManager's ISO-8601 stamp
// ("2026-10-26T09:15:02+01", with or without minutes in the offset) to the
// layout the native PDU rows use, so both sort and display alike.
func normalizeModemManagerTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05-07", "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.Format("2006-01-02T15:04:05-07:00")
		}
	}
	return sanitizeSMSText(value)
}

// parseModemManagerSMSTarget accepts "all", "7", "7,8" or the storage-prefixed
// form the AT inbox uses ("SM:7"); the storage is ignored because ModemManager
// addresses messages by object, not slot.
func parseModemManagerSMSTarget(value string) (all bool, ids []int, err error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "all") {
		return true, nil, nil
	}
	if _, rest, found := strings.Cut(value, ":"); found {
		value = rest
	}
	for _, item := range strings.Split(value, ",") {
		id, convErr := strconv.Atoi(strings.TrimSpace(item))
		if convErr != nil || id < 0 {
			return false, nil, fmt.Errorf("SMS index must be all or a ModemManager SMS number list")
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(ids) > 32 {
		return false, nil, fmt.Errorf("SMS index list is empty or too long")
	}
	return false, ids, nil
}

func modemManagerDeleteSMS(modemPath dbus.ObjectPath, target string) error {
	all, ids, err := parseModemManagerSMSTarget(target)
	if err != nil {
		return err
	}
	conn, err := mmSystemBus()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), mmSMSCallTimeout)
	defer cancel()
	messaging := conn.Object(mmService, modemPath)
	var paths []dbus.ObjectPath
	if all {
		if err := messaging.CallWithContext(ctx, mmMessagingIface+".List", 0).Store(&paths); err != nil {
			return fmt.Errorf("ModemManager SMS list: %w", err)
		}
	}
	for _, id := range ids {
		paths = append(paths, dbus.ObjectPath(mmSMSPathPrefix+strconv.Itoa(id)))
	}
	for _, path := range paths {
		if err := messaging.CallWithContext(ctx, mmMessagingIface+".Delete", 0, path).Err; err != nil {
			return fmt.Errorf("ModemManager SMS delete %s: %w", strings.TrimPrefix(string(path), mmSMSPathPrefix), err)
		}
	}
	return nil
}

func modemManagerSendSMS(modemPath dbus.ObjectPath, phoneNumber, message string) error {
	phoneNumber, message, err := validateOutgoingSMS(phoneNumber, message)
	if err != nil {
		return err
	}
	conn, err := mmSystemBus()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), mmSMSSendTimeout)
	defer cancel()
	messaging := conn.Object(mmService, modemPath)
	var path dbus.ObjectPath
	props := map[string]dbus.Variant{
		"number": dbus.MakeVariant(phoneNumber),
		"text":   dbus.MakeVariant(message),
	}
	if err := messaging.CallWithContext(ctx, mmMessagingIface+".Create", 0, props).Store(&path); err != nil {
		return fmt.Errorf("ModemManager SMS create: %w", err)
	}
	if err := conn.Object(mmService, path).CallWithContext(ctx, mmSMSIface+".Send", 0).Err; err != nil {
		// Drop the unsent object so it does not linger as a draft. A part
		// may already be on its way; the error says so and is not retried.
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = messaging.CallWithContext(cleanup, mmMessagingIface+".Delete", 0, path).Err
		cleanupCancel()
		return fmt.Errorf("ModemManager SMS send: %w", err)
	}
	return nil
}
