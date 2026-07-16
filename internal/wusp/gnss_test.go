package wusp

import (
	"testing"
	"time"
)

func TestWUSPGNSSRepresentativeMessageValidates(t *testing.T) {
	msg := NewMessage()
	prefix := "Device.WUSP_GNSS.Receiver.1."

	msg.Set("Device.WUSP_GNSS.ReceiverNumberOfEntries", Uint(1))
	msg.Set(prefix+"Alias", String("cpe-gnss-1"))
	msg.Set(prefix+"LocationReference", String("Device.DeviceInfo.Location.1."))
	msg.Set(prefix+"ModemPath", String("/dev/ttyUSB2"))
	msg.Set(prefix+"Protocol", String("quectel-at"))
	msg.Set(prefix+"Enable", Bool(true))
	msg.Set(prefix+"Status", String("Fix3D"))
	msg.Set(prefix+"Latitude", Float(33.5731))
	msg.Set(prefix+"Longitude", Float(-7.5898))
	msg.Set(prefix+"Altitude", Float(45.2))
	msg.Set(prefix+"SpeedKPH", Float(12.4))
	msg.Set(prefix+"Course", Float(180.5))
	msg.Set(prefix+"HDOP", Float(0.8))
	msg.Set(prefix+"FixQuality", String("3"))
	msg.Set(prefix+"SatellitesUsed", Uint(8))
	msg.Set(prefix+"SatellitesInView", Uint(12))
	msg.Set(prefix+"UTC", Time(time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)))
	msg.Set(prefix+"LastFixTime", Time(time.Date(2026, 7, 15, 12, 0, 1, 0, time.UTC)))
	msg.Set(prefix+"RawLocation", String(`+QGPSLOC: 120000.0,33.573100,-7.589800,0.8,45.2,3,180.5,12.4,6.7,150726,08`))
	msg.Set(prefix+"RawGGA", String("$GPGGA,120000.0,3334.386,N,00735.388,W,1,08,0.8,45.2,M,0,M,,*00"))
	msg.Set(prefix+"RawRMC", String("$GPRMC,120000.0,A,3334.386,N,00735.388,W,6.7,180.5,150726,,,A*00"))

	if err := ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast(GNSS) error: %v", err)
	}
}
