package platforms

import (
	"testing"

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
