package platforms

import (
	"testing"
	"time"

	modemPkg "wantastic-agent/internal/modem"
	"wantastic-agent/internal/wusp"
)

func TestCellularAccessTechnologyTR181Names(t *testing.T) {
	cases := map[modemPkg.Technology]string{
		modemPkg.TechGPRS:    "GPRS",
		modemPkg.TechEDGE:    "EDGE",
		modemPkg.TechUMTS:    "UMTS",
		modemPkg.TechHSPA:    "UMTSHSPA",
		modemPkg.TechLTE:     "LTE",
		modemPkg.TechLTEA:    "LTE",
		modemPkg.TechNR5G:    "NR",
		modemPkg.TechNR5GNSA: "NR",
	}

	for tech, want := range cases {
		if got := cellularAccessTechnology(tech); got != want {
			t.Fatalf("cellularAccessTechnology(%v)=%q want %q", tech, got, want)
		}
	}
}

func TestCellularStatusMapping(t *testing.T) {
	if got := cellularStatus(&modemPkg.Info{Status: modemPkg.RegRoaming}); got != "Up" {
		t.Fatalf("roaming status=%q want Up", got)
	}
	if got := cellularStatus(&modemPkg.Info{Status: modemPkg.RegSearching}); got != "Dormant" {
		t.Fatalf("searching status=%q want Dormant", got)
	}
	if got := cellularStatus(&modemPkg.Info{SIMStatus: modemPkg.SIMAbsent}); got != "NotPresent" {
		t.Fatalf("absent SIM status=%q want NotPresent", got)
	}
}

func TestCellularModemIdentityUsesStableHardwareKeys(t *testing.T) {
	if got := cellularModemIdentity("/dev/ttyUSB2", &modemPkg.Info{IMEI: "123456789012345"}); got != "imei:123456789012345" {
		t.Fatalf("identity=%q", got)
	}
	if got := cellularModemIdentity("/dev/ttyUSB2", &modemPkg.Info{ICCID: "89014103211118510720"}); got != "iccid:89014103211118510720" {
		t.Fatalf("identity=%q", got)
	}
	if got := cellularModemIdentity("wwan0", &modemPkg.Info{}); got != "" {
		t.Fatalf("empty netdev identity=%q want empty", got)
	}
	if got := cellularModemIdentity("wwan0", &modemPkg.Info{RxBytes: 1}); got != "net:wwan0" {
		t.Fatalf("runtime netdev identity=%q", got)
	}
}

func TestCellularPublishSkipsEmptyNetdevRows(t *testing.T) {
	msg := wusp.NewMessage()
	collectCellularSnapshot(msg, []cellularEntry{
		{devicePath: "rmnet_data3", info: &modemPkg.Info{Interface: "rmnet_data3"}},
		{devicePath: "rmnet_data4", info: &modemPkg.Info{Interface: "rmnet_data4"}},
	})

	assertUintField(t, msg, "Device.Cellular.InterfaceNumberOfEntries", 0)
	if _, ok := msg.Get("Device.Cellular.Interface.1.Name"); ok {
		t.Fatal("empty rmnet row was published")
	}
}

func TestCellularPublishSkipsStatsOnlyNetdevRows(t *testing.T) {
	msg := wusp.NewMessage()
	collectCellularSnapshot(msg, []cellularEntry{
		{devicePath: "rmnet_data3", info: &modemPkg.Info{Interface: "rmnet_data3", RxBytes: 1234, TxBytes: 5678}},
	})

	assertUintField(t, msg, "Device.Cellular.InterfaceNumberOfEntries", 0)
	if _, ok := msg.Get("Device.Cellular.Interface.1.Stats.BytesReceived"); ok {
		t.Fatal("stats-only rmnet row was published as a modem")
	}
}

func TestCoalesceCellularEntriesMergesStatsIntoModem(t *testing.T) {
	entries := coalesceCellularEntries([]cellularEntry{
		{devicePath: "rmnet_data0", info: &modemPkg.Info{Interface: "rmnet_data0", RxBytes: 1234, TxBytes: 5678}},
		{devicePath: "/dev/ttyUSB2", info: &modemPkg.Info{Interface: "rmnet_data0", IMEI: "123456789012345", Signal: modemPkg.SignalQuality{RSRP: -91}}},
	})

	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1", len(entries))
	}
	if entries[0].info.RxBytes != 1234 || entries[0].info.TxBytes != 5678 {
		t.Fatalf("stats not merged: %+v", entries[0].info)
	}
}

func TestCellularPublishIncludesIdentityAndStats(t *testing.T) {
	msg := wusp.NewMessage()
	collectedAt := time.Date(2026, 7, 15, 10, 30, 0, 0, time.UTC)
	collectCellularSnapshot(msg, []cellularEntry{
		{
			devicePath: "/org/freedesktop/ModemManager1/Modem/0",
			info: &modemPkg.Info{
				Manufacturer: "Quectel",
				Model:        "RG520N",
				Revision:     "RG520NNAAR01A08M4G",
				IMEI:         "123456789012345",
				IMSI:         "310410123456789",
				ICCID:        "89014103211118510720",
				Interface:    "rmnet_data0",
				Protocol:     "modemmanager",
				Status:       modemPkg.RegHome,
				Technology:   modemPkg.TechLTE,
				Signal: modemPkg.SignalQuality{
					RSRP: -91,
					RSRQ: -8,
					SINR: 16,
				},
				APN:               "internet",
				IPAddress:         "100.64.1.2",
				DNS1:              "1.1.1.1",
				RxBytes:           5678,
				TxBytes:           1234,
				TemperatureC:      48,
				LTETimingAdvance:  12,
				NR5GTimingAdvance: 23,
				SIMStatus:         modemPkg.SIMReady,
				CollectedAt:       collectedAt,
			},
		},
	})

	assertUintField(t, msg, "Device.Cellular.InterfaceNumberOfEntries", 1)
	assertStringField(t, msg, "Device.Cellular.Interface.1.Name", "rmnet_data0")
	assertStringField(t, msg, "Device.Cellular.Interface.1.IMEI", "123456789012345")
	assertUintField(t, msg, "Device.Cellular.Interface.1.Stats.BytesReceived", 5678)
	assertStringField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.Manufacturer", "Quectel")
	assertStringField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.Model", "RG520N")
	assertStringField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.EquipmentIdentifier", "123456789012345")
	assertIntField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.TemperatureC", 48)
	assertIntField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.LTETimingAdvance", 12)
	assertIntField(t, msg, "Device.WUSP_CellularTelemetry.Interface.1.NR5GTimingAdvance", 23)
	assertStringField(t, msg, "Device.WUSP_CellularControl.Interface.1.SupportedOperations", "SetFunctionality,SwitchSIM,SetIMEI,ApplyAPN,StartGNSS,StopGNSS,RefreshGNSS,SendSMS,ListSMS,DeleteSMS")
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast(cellular publish): %v", err)
	}
}

func TestCellularRepresentativeMessageValidates(t *testing.T) {
	msg := wusp.NewMessage()
	prefix := "Device.Cellular.Interface.1."

	msg.Set("Device.Cellular.RoamingEnabled", wusp.Bool(true))
	msg.Set("Device.Cellular.RoamingStatus", wusp.String("Home"))
	msg.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(1))
	msg.Set("Device.Cellular.AccessPointNumberOfEntries", wusp.Uint(1))
	msg.Set(prefix+"Enable", wusp.Bool(true))
	msg.Set(prefix+"Status", wusp.String("Up"))
	msg.Set(prefix+"Alias", wusp.String("cpe-cellular-1"))
	msg.Set(prefix+"Name", wusp.String("wwan0"))
	msg.Set(prefix+"LastChange", wusp.Uint(0))
	msg.Set(prefix+"LowerLayers", wusp.List())
	msg.Set(prefix+"Upstream", wusp.Bool(true))
	msg.Set(prefix+"IMEI", wusp.String("123456789012345"))
	msg.Set(prefix+"SupportedAccessTechnologies", wusp.List(wusp.String("GPRS"), wusp.String("EDGE"), wusp.String("UMTS"), wusp.String("UMTSHSPA"), wusp.String("LTE"), wusp.String("NR")))
	msg.Set(prefix+"PreferredAccessTechnology", wusp.String("Unknown"))
	msg.Set(prefix+"CurrentAccessTechnology", wusp.String("LTE"))
	msg.Set(prefix+"AvailableNetworks", wusp.List(wusp.String("Carrier (310410)")))
	msg.Set(prefix+"NetworkRequested", wusp.String(""))
	msg.Set(prefix+"NetworkInUse", wusp.String("Carrier (310410)"))
	msg.Set(prefix+"RSSI", wusp.Int(-61))
	msg.Set(prefix+"RSRP", wusp.Int(-91))
	msg.Set(prefix+"RSRQ", wusp.Int(-8))
	msg.Set(prefix+"SINR", wusp.Int(16))
	msg.Set(prefix+"Mode", wusp.String("Unknown"))
	msg.Set(prefix+"SIMReferenceList", wusp.List())
	msg.Set(prefix+"Stats.BytesSent", wusp.Uint(1))
	msg.Set(prefix+"Stats.BytesReceived", wusp.Uint(2))
	msg.Set(prefix+"Stats.PacketsSent", wusp.Uint(3))
	msg.Set(prefix+"Stats.PacketsReceived", wusp.Uint(4))
	msg.Set(prefix+"Stats.ErrorsSent", wusp.Uint(0))
	msg.Set(prefix+"Stats.ErrorsReceived", wusp.Uint(0))
	msg.Set(prefix+"Stats.UnicastPacketsSent", wusp.Uint(3))
	msg.Set(prefix+"Stats.DiscardPacketsSent", wusp.Uint(0))
	msg.Set(prefix+"Stats.DiscardPacketsReceived", wusp.Uint(0))
	msg.Set(prefix+"Stats.MulticastPacketsSent", wusp.Uint(0))
	msg.Set(prefix+"Stats.UnicastPacketsReceived", wusp.Uint(4))
	msg.Set(prefix+"Stats.MulticastPacketsReceived", wusp.Uint(0))
	msg.Set(prefix+"Stats.BroadcastPacketsSent", wusp.Uint(0))
	msg.Set(prefix+"Stats.BroadcastPacketsReceived", wusp.Uint(0))
	msg.Set(prefix+"Stats.UnknownProtoPacketsReceived", wusp.Uint(0))
	msg.Set(prefix+"USIM.Status", wusp.String("Valid"))
	msg.Set(prefix+"USIM.IMSI", wusp.String("310410123456789"))
	msg.Set(prefix+"USIM.ICCID", wusp.String("89014103211118510720"))
	msg.Set(prefix+"USIM.PINCheck", wusp.String("Off"))
	msg.Set(prefix+"SMS.StorageNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"SMS.MessageNumberOfEntries", wusp.Uint(0))
	msg.Set("Device.Cellular.AccessPoint.1.Enable", wusp.Bool(true))
	msg.Set("Device.Cellular.AccessPoint.1.Alias", wusp.String("cpe-cellular-apn-1"))
	msg.Set("Device.Cellular.AccessPoint.1.APN", wusp.String("internet"))
	msg.Set("Device.Cellular.AccessPoint.1.Username", wusp.String(""))
	msg.Set("Device.Cellular.AccessPoint.1.Password", wusp.String(""))
	msg.Set("Device.Cellular.AccessPoint.1.Interface", wusp.String(prefix))
	msg.Set("Device.Cellular.AccessPoint.1.IPVersion", wusp.Int(-1))
	msg.Set("Device.Cellular.AccessPoint.1.Type", wusp.List(wusp.String("default")))

	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast() error: %v", err)
	}
}

func TestCellularTelemetryRepresentativeMessageValidates(t *testing.T) {
	msg := wusp.NewMessage()
	prefix := "Device.WUSP_CellularTelemetry.Interface.1."
	msg.Set("Device.WUSP_CellularTelemetry.InterfaceNumberOfEntries", wusp.Uint(1))
	msg.Set(prefix+"Alias", wusp.String("cpe-cellular-telemetry-1"))
	msg.Set(prefix+"InterfaceReference", wusp.String("Device.Cellular.Interface.1."))
	msg.Set(prefix+"ModemPath", wusp.String("/dev/cdc-wdm0"))
	msg.Set(prefix+"Protocol", wusp.String("at"))
	msg.Set(prefix+"NRMode", wusp.String("NonStandalone"))
	msg.Set(prefix+"Manufacturer", wusp.String("Quectel"))
	msg.Set(prefix+"Model", wusp.String("RG520N"))
	msg.Set(prefix+"Revision", wusp.String("RG520NNAAR01A08M4G"))
	msg.Set(prefix+"EquipmentIdentifier", wusp.String("123456789012345"))
	msg.Set(prefix+"SubscriberIdentity", wusp.String("310410123456789"))
	msg.Set(prefix+"SIMIdentifier", wusp.String("89014103211118510720"))
	msg.Set(prefix+"PhoneNumber", wusp.String("+15555550123"))
	msg.Set(prefix+"CollectedAt", wusp.Time(time.Date(2026, 7, 15, 10, 30, 0, 0, time.UTC)))
	msg.Set(prefix+"Band", wusp.String("B3"))
	msg.Set(prefix+"CellID", wusp.Uint(12345))
	msg.Set(prefix+"TAC", wusp.Uint(22))
	msg.Set(prefix+"DNS1", wusp.String("1.1.1.1"))
	msg.Set(prefix+"TemperatureC", wusp.Int(48))
	msg.Set(prefix+"LTETimingAdvance", wusp.Int(12))
	msg.Set(prefix+"NR5GTimingAdvance", wusp.Int(23))
	msg.Set(prefix+"CarrierNumberOfEntries", wusp.Uint(1))
	msg.Set(prefix+"NeighborCellNumberOfEntries", wusp.Uint(1))
	msg.Set(prefix+"Carrier.1.Role", wusp.String("PCC"))
	msg.Set(prefix+"Carrier.1.RAT", wusp.String("LTE"))
	msg.Set(prefix+"Carrier.1.Band", wusp.String("B3"))
	msg.Set(prefix+"Carrier.1.EARFCN", wusp.Uint(1850))
	msg.Set(prefix+"Carrier.1.PCI", wusp.Uint(120))
	msg.Set(prefix+"Carrier.1.Bandwidth", wusp.String("20MHz"))
	msg.Set(prefix+"Carrier.1.RSRP", wusp.Int(-91))
	msg.Set(prefix+"Carrier.1.RSRQ", wusp.Int(-8))
	msg.Set(prefix+"Carrier.1.SINR", wusp.Int(16))
	msg.Set(prefix+"NeighborCell.1.RAT", wusp.String("LTE"))
	msg.Set(prefix+"NeighborCell.1.Relation", wusp.String("intra"))
	msg.Set(prefix+"NeighborCell.1.Frequency", wusp.Uint(1850))
	msg.Set(prefix+"NeighborCell.1.PCI", wusp.Uint(121))
	msg.Set(prefix+"NeighborCell.1.RSRP", wusp.Int(-101))
	msg.Set(prefix+"NeighborCell.1.RSRQ", wusp.Int(-12))

	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast(cellular telemetry) error: %v", err)
	}
}
