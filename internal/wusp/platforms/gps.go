package platforms

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"

	"github.com/stratoberry/go-gpsd"
)

var gnssCollectionCache struct {
	sync.RWMutex
	info       *gpsInfo
	last       time.Time
	refreshing bool
}

// collectGPSStatic populates the standard TR-181 Device.DeviceInfo.Location
// object and the Wantastic GNSS extension from gpsd, ModemManager, Quectel AT,
// or common OpenWrt GPS status files.
func collectGPSStatic(msg *wusp.Message) {
	gnssCollectionCache.Lock()
	info := gnssCollectionCache.info
	stale := gnssCollectionCache.last.IsZero() || time.Since(gnssCollectionCache.last) >= 10*time.Second
	if stale && !gnssCollectionCache.refreshing {
		gnssCollectionCache.refreshing = true
		go refreshGPSCollectionCache()
	}
	gnssCollectionCache.Unlock()
	if info == nil {
		return
	}
	appendGPSInfo(msg, info)
}

func refreshGPSCollectionCache() {
	info := collectGPSInfo()
	gnssCollectionCache.Lock()
	gnssCollectionCache.info = info
	gnssCollectionCache.last = time.Now()
	gnssCollectionCache.refreshing = false
	gnssCollectionCache.Unlock()
}

func collectGPSInfo() *gpsInfo {
	info := gpsFromGPSD()
	if info == nil {
		info = gpsFromModemManager()
	}
	if info == nil {
		info = gpsFromQuectelAT()
	}
	if info == nil {
		info = gpsFromFile()
	}
	if info == nil {
		return nil
	}
	return info
}

func appendGPSInfo(msg *wusp.Message, info *gpsInfo) {
	if msg == nil || info == nil {
		return
	}
	appendGNSSFields(msg, info)
	if info.lat == 0 && info.lon == 0 {
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
	lat, lon, alt, speed, course, hdop float64
	satellites, satellitesInView       int
	fix, status, fixQuality            string
	source, modemPath, protocol        string
	rawLocation                        string
	nmea                               map[string]string
	timestamp, utc                     time.Time
}

func gpsFromGPSD() *gpsInfo {
	gps, err := gpsd.Dial("localhost:2947")
	if err != nil {
		return nil
	}
	defer gps.Close()

	info := &gpsInfo{fix: "none", status: "Searching", source: "gpsd", protocol: "gpsd"}

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
	info.status = gnssStatusFromFix(info.fix)
	return info
}

func gpsFromFile() *gpsInfo {
	for _, path := range []string{"/tmp/gps_info.txt", "/tmp/gpsdata", "/var/run/gps_info.txt"} {
		if info := gpsFromStatusFile(path); info != nil {
			info.source = "file"
			info.protocol = "file"
			info.modemPath = path
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
				return &gpsInfo{lat: lat, lon: lon, alt: alt, fix: "2D", status: "Fix2D", timestamp: fallbackTime}
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
		status:     gnssStatusFromFix(fix),
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

func appendGNSSFields(msg *wusp.Message, info *gpsInfo) {
	if msg == nil || info == nil {
		return
	}
	msg.Set("Device.WUSP_GNSS.ReceiverNumberOfEntries", wusp.Uint(1))
	prefix := "Device.WUSP_GNSS.Receiver.1."
	msg.Set(prefix+"Alias", wusp.String("cpe-gnss-1"))
	msg.Set(prefix+"LocationReference", wusp.String("Device.DeviceInfo.Location.1."))
	msg.Set(prefix+"Enable", wusp.Bool(info.status != "Disabled"))
	msg.Set(prefix+"Status", wusp.String(firstNonEmpty(info.status, gnssStatusFromFix(info.fix), "Unknown")))
	msg.Set(prefix+"Protocol", wusp.String(firstNonEmpty(info.protocol, info.source, "unknown")))
	if info.modemPath != "" {
		msg.Set(prefix+"ModemPath", wusp.String(info.modemPath))
	}
	if info.lat != 0 || info.lon != 0 {
		msg.Set(prefix+"Latitude", wusp.Float(info.lat))
		msg.Set(prefix+"Longitude", wusp.Float(info.lon))
	}
	if info.alt != 0 {
		msg.Set(prefix+"Altitude", wusp.Float(info.alt))
	}
	if info.speed != 0 {
		msg.Set(prefix+"SpeedKPH", wusp.Float(info.speed))
	}
	if info.course != 0 {
		msg.Set(prefix+"Course", wusp.Float(info.course))
	}
	if info.hdop != 0 {
		msg.Set(prefix+"HDOP", wusp.Float(info.hdop))
	}
	if info.fixQuality != "" {
		msg.Set(prefix+"FixQuality", wusp.String(info.fixQuality))
	}
	if info.satellites > 0 {
		msg.Set(prefix+"SatellitesUsed", wusp.Uint(uint64(info.satellites)))
	}
	if info.satellitesInView > 0 {
		msg.Set(prefix+"SatellitesInView", wusp.Uint(uint64(info.satellitesInView)))
	}
	if !info.utc.IsZero() {
		msg.Set(prefix+"UTC", wusp.Time(info.utc.UTC()))
	}
	if !info.timestamp.IsZero() {
		msg.Set(prefix+"LastFixTime", wusp.Time(info.timestamp.UTC()))
	}
	if info.rawLocation != "" {
		msg.Set(prefix+"RawLocation", wusp.String(info.rawLocation))
	}
	for _, item := range []struct {
		key  string
		path string
	}{
		{"GGA", "RawGGA"},
		{"RMC", "RawRMC"},
		{"GSA", "RawGSA"},
		{"GSV", "RawGSV"},
	} {
		if raw := strings.TrimSpace(info.nmea[item.key]); raw != "" {
			msg.Set(prefix+item.path, wusp.String(raw))
		}
	}
}

func gnssStatusFromFix(fix string) string {
	switch strings.ToUpper(strings.TrimSpace(fix)) {
	case "3D", "FIX3D":
		return "Fix3D"
	case "2D", "FIX2D":
		return "Fix2D"
	case "NOFIX", "NONE", "NO FIX", "0":
		return "NoFix"
	default:
		return "Unknown"
	}
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
