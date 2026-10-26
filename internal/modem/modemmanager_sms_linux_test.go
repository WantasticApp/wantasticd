//go:build linux && !qmi && !mbim

package modem

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestModemManagerSMSRow(t *testing.T) {
	row := modemManagerSMSRow("/org/freedesktop/ModemManager1/SMS/12", map[string]dbus.Variant{
		"Number":    dbus.MakeVariant("+212666666666"),
		"Text":      dbus.MakeVariant("Votre code: 4821"),
		"Timestamp": dbus.MakeVariant("2026-10-26T09:15:02+01"),
		"State":     dbus.MakeVariant(uint32(3)),
		"Storage":   dbus.MakeVariant(uint32(2)),
	})
	if row.Index != "12" || row.Storage != "ME" || row.Status != "REC READ" || row.Number != "+212666666666" ||
		row.Body != "Votre code: 4821" || row.Time != "2026-10-26T09:15:02+01:00" {
		t.Fatalf("row=%+v", row)
	}
	binary := modemManagerSMSRow("/org/freedesktop/ModemManager1/SMS/0", map[string]dbus.Variant{
		"Data": dbus.MakeVariant([]byte{1, 2, 3}),
	})
	if binary.Index != "0" || binary.Error == "" {
		t.Fatalf("binary=%+v", binary)
	}
}

func TestParseModemManagerSMSTarget(t *testing.T) {
	if all, _, err := parseModemManagerSMSTarget("ALL"); err != nil || !all {
		t.Fatalf("all=%v err=%v", all, err)
	}
	if _, ids, err := parseModemManagerSMSTarget("ME:3,4"); err != nil || len(ids) != 2 || ids[0] != 3 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	if _, ids, err := parseModemManagerSMSTarget("0"); err != nil || len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("object 0: ids=%v err=%v", ids, err)
	}
	for _, bad := range []string{"", "x", "SM:", "-1"} {
		if _, _, err := parseModemManagerSMSTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
