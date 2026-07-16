package platforms

import (
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestGPSLocationMessageValidates(t *testing.T) {
	msg := wusp.NewMessage()
	info := &gpsInfo{
		lat:              33.573100,
		lon:              -7.589800,
		alt:              45.2,
		speed:            12.4,
		course:           180.5,
		hdop:             0.8,
		satellites:       8,
		satellitesInView: 12,
		fix:              "3D",
		status:           "Fix3D",
		fixQuality:       "3",
		protocol:         "quectel-at",
		modemPath:        "/dev/ttyUSB2",
		nmea:             map[string]string{"GGA": "$GPGGA,120000.0,3334.386,N,00735.388,W,1,08,0.8,45.2,M,0,M,,*00"},
		timestamp:        time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
	}

	appendGNSSFields(msg, info)
	msg.Set("Device.DeviceInfo.LocationNumberOfEntries", wusp.Uint(1))
	msg.Set("Device.DeviceInfo.Location.1.Source", wusp.String("GPS"))
	msg.Set("Device.DeviceInfo.Location.1.AcquiredTime", wusp.Time(info.timestamp))
	msg.Set("Device.DeviceInfo.Location.1.DataObject", wusp.String(formatLocationDataObject(info)))

	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast() error: %v", err)
	}
}

func TestFormatLocationDataObjectUsesPIDFLOPoint(t *testing.T) {
	xml := formatLocationDataObject(&gpsInfo{
		lat:       33.573100,
		lon:       -7.589800,
		timestamp: time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
	})

	for _, want := range []string{
		`xmlns="urn:ietf:params:xml:ns:pidf"`,
		`xmlns="urn:ietf:params:xml:ns:pidf:geopriv10"`,
		`<Point xmlns="http://www.opengis.net/gml"`,
		`<pos>33.573100 -7.589800</pos>`,
		`<timestamp>2026-07-04T12:00:00Z</timestamp>`,
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("PIDF-LO XML missing %q in %s", want, xml)
		}
	}
	if len(xml) > 1200 {
		t.Fatalf("PIDF-LO XML length=%d exceeds TR-181 DataObject limit", len(xml))
	}
}

func TestParseGPSStatusSupportsKeyValueFiles(t *testing.T) {
	info := parseGPSStatus(`
lat=33.573100
lon=-7.589800
altitude=45.2m
satellites=8
time=2026-07-04T12:00:00Z
`, time.Time{})

	if info == nil {
		t.Fatal("parseGPSStatus() returned nil")
	}
	if info.lat != 33.573100 || info.lon != -7.589800 || info.alt != 45.2 {
		t.Fatalf("coordinates=(%f,%f,%f), want 33.573100,-7.589800,45.2", info.lat, info.lon, info.alt)
	}
	if info.satellites != 8 {
		t.Fatalf("satellites=%d want 8", info.satellites)
	}
	if got := info.timestamp.Format(time.RFC3339); got != "2026-07-04T12:00:00Z" {
		t.Fatalf("timestamp=%s want 2026-07-04T12:00:00Z", got)
	}
}
