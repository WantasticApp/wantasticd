package platforms

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"

	"github.com/stratoberry/go-gpsd"
)

// collectGPSStatic populates the standard TR-181 Device.DeviceInfo.Location
// object from gpsd or common OpenWrt GPS status files.
func collectGPSStatic(msg *wusp.Message) {
	info := gpsFromGPSD()
	if info == nil {
		info = gpsFromFile()
	}
	if info == nil {
		return
	}

	msg.Set("Device.DeviceInfo.LocationNumberOfEntries", wusp.Uint(1))

	prefix := "Device.DeviceInfo.Location.1."
	msg.Set(prefix+"Source", wusp.String("GPS"))
	if !info.timestamp.IsZero() {
		msg.Set(prefix+"AcquiredTime", wusp.Time(info.timestamp.UTC()))
	}
	msg.Set(prefix+"DataObject", wusp.String(formatLocationDataObject(info)))
}

type gpsInfo struct {
	lat, lon, alt, speed float64
	satellites           int
	fix                  string
	timestamp            time.Time
}

func gpsFromGPSD() *gpsInfo {
	gps, err := gpsd.Dial("localhost:2947")
	if err != nil {
		return nil
	}
	defer gps.Close()

	info := &gpsInfo{fix: "none"}

	gps.AddFilter("TPV", func(r interface{}) {
		tpv, ok := r.(*gpsd.TPVReport)
		if !ok {
			return
		}
		info.lat = tpv.Lat
		info.lon = tpv.Lon
		info.alt = tpv.Alt
		info.speed = tpv.Speed * 3.6 // m/s → km/h
		info.timestamp = tpv.Time
		switch tpv.Mode {
		case 2:
			info.fix = "2D"
		case 3:
			info.fix = "3D"
		}
	})

	gps.AddFilter("SKY", func(r interface{}) {
		sky, ok := r.(*gpsd.SKYReport)
		if !ok {
			return
		}
		for _, sat := range sky.Satellites {
			if sat.Used {
				info.satellites++
			}
		}
	})

	done := gps.Watch()
	time.Sleep(500 * time.Millisecond)
	gps.Close()
	<-done

	if info.lat == 0 && info.lon == 0 {
		return nil
	}
	return info
}

func gpsFromFile() *gpsInfo {
	for _, path := range []string{"/tmp/gps_info.txt", "/tmp/gpsdata", "/var/run/gps_info.txt"} {
		if info := gpsFromStatusFile(path); info != nil {
			return info
		}
	}
	return nil
}

func gpsFromStatusFile(path string) *gpsInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseGPSStatus(string(data), time.Now())
}

func parseGPSStatus(data string, fallbackTime time.Time) *gpsInfo {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "- ", "-"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "latitude=") {
			var lat, lon, alt float64
			if _, err := fmt.Sscanf(line, "latitude=%f, longitude=%f, altitude=%f", &lat, &lon, &alt); err == nil {
				return &gpsInfo{lat: lat, lon: lon, alt: alt, fix: "2D", timestamp: fallbackTime}
			}
		}
		if key, val, ok := strings.Cut(line, "="); ok {
			values[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}

	lat, latOK := parseFloatValue(values, "lat", "latitude")
	lon, lonOK := parseFloatValue(values, "lon", "lng", "longitude")
	if !latOK || !lonOK || (lat == 0 && lon == 0) {
		return nil
	}
	alt, _ := parseFloatValue(values, "alt", "altitude", "height")
	speed, _ := parseFloatValue(values, "speed")
	satellites, _ := parseIntValue(values, "satellites", "sats", "used")
	timestamp := fallbackTime
	if raw := firstValue(values, "time", "timestamp", "acquiredtime"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			timestamp = parsed
		}
	}
	fix := firstValue(values, "fix", "mode", "status")
	if fix == "" {
		fix = "2D"
	}
	return &gpsInfo{
		lat:        lat,
		lon:        lon,
		alt:        alt,
		speed:      speed,
		satellites: satellites,
		fix:        fix,
		timestamp:  timestamp,
	}
}

func parseFloatValue(values map[string]string, keys ...string) (float64, bool) {
	raw := firstValue(values, keys...)
	if raw == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(strings.TrimSuffix(raw, "m"), 64)
	return parsed, err == nil
}

func parseIntValue(values map[string]string, keys ...string) (int, bool) {
	raw := firstValue(values, keys...)
	if raw == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(raw)
	return parsed, err == nil
}

func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if val := strings.TrimSpace(values[key]); val != "" {
			return val
		}
	}
	return ""
}

func formatLocationDataObject(info *gpsInfo) string {
	timestamp := info.timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	altitude := ""
	if info.alt != 0 {
		altitude = fmt.Sprintf(" %.1f", info.alt)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:wantasticd"><tuple id="gps"><status><geopriv xmlns="urn:ietf:params:xml:ns:pidf:geopriv10"><location-info><Point xmlns="http://www.opengis.net/gml" srsName="urn:ogc:def:crs:EPSG::4979"><pos>%.6f %.6f%s</pos></Point></location-info><usage-rules/><method>GPS</method></geopriv></status><timestamp>%s</timestamp></tuple></presence>`,
		info.lat,
		info.lon,
		altitude,
		timestamp.UTC().Format(time.RFC3339),
	)
}
