//go:build linux

package platforms

import (
	"strconv"
	"strings"
	"time"

	modemPkg "wantastic-agent/internal/modem"

	mm "github.com/maltegrosse/go-modemmanager"
)

func gpsFromModemManager() *gpsInfo {
	manager, err := mm.NewModemManager()
	if err != nil {
		return nil
	}
	modems, err := manager.GetModems()
	if err != nil {
		return nil
	}
	for _, modem := range modems {
		location, err := modem.GetLocation()
		if err != nil {
			continue
		}
		current, err := location.GetLocation()
		if err == nil {
			if info := gpsInfoFromModemManagerLocation(current); info != nil {
				return info
			}
		}
		if enableModemManagerGPS(location) {
			time.Sleep(250 * time.Millisecond)
			current, err = location.GetLocation()
			if err == nil {
				if info := gpsInfoFromModemManagerLocation(current); info != nil {
					return info
				}
			}
		}
	}
	return nil
}

func enableModemManagerGPS(location mm.ModemLocation) bool {
	caps, err := location.GetCapabilities()
	if err != nil {
		return false
	}
	sources := make([]mm.MMModemLocationSource, 0, 2)
	if modemManagerLocationHasSource(caps, mm.MmModemLocationSourceGpsRaw) {
		sources = append(sources, mm.MmModemLocationSourceGpsRaw)
	}
	if modemManagerLocationHasSource(caps, mm.MmModemLocationSourceGpsNmea) {
		sources = append(sources, mm.MmModemLocationSourceGpsNmea)
	}
	if len(sources) == 0 {
		return false
	}
	if err := location.Setup(sources, true); err != nil {
		return false
	}
	_ = location.SetGpsRefreshRate(1)
	return true
}

func modemManagerLocationHasSource(sources []mm.MMModemLocationSource, want mm.MMModemLocationSource) bool {
	for _, source := range sources {
		if source == want {
			return true
		}
	}
	return false
}

func gpsInfoFromModemManagerLocation(location mm.CurrentLocation) *gpsInfo {
	raw := location.GpsRaw
	if raw.Latitude != 0 || raw.Longitude != 0 {
		timestamp := raw.UtcTime
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		return &gpsInfo{
			lat:       raw.Latitude,
			lon:       raw.Longitude,
			alt:       raw.Altitude,
			fix:       "3D",
			status:    "Fix3D",
			source:    "modemmanager",
			protocol:  "modemmanager",
			timestamp: timestamp,
			utc:       timestamp,
		}
	}

	cdma := location.CdmaBs
	if cdma.Latitude != 0 || cdma.Longitude != 0 {
		return &gpsInfo{
			lat:       cdma.Latitude,
			lon:       cdma.Longitude,
			fix:       "2D",
			status:    "Fix2D",
			source:    "modemmanager",
			protocol:  "modemmanager",
			timestamp: time.Now(),
		}
	}

	return gpsInfoFromNMEASentences(location.GpsNmea.NmeaSentences)
}

func gpsInfoFromNMEASentences(sentences []string) *gpsInfo {
	var best *gpsInfo
	for _, sentence := range sentences {
		fields := strings.Split(strings.TrimSpace(sentence), ",")
		if len(fields) < 1 {
			continue
		}
		talker := strings.TrimPrefix(fields[0], "$")
		if strings.HasSuffix(talker, "GGA") {
			if info := gpsInfoFromGGA(fields); info != nil {
				best = info
			}
		}
		if strings.HasSuffix(talker, "RMC") {
			if info := gpsInfoFromRMC(fields); info != nil {
				return info
			}
		}
	}
	return best
}

func gpsFromQuectelAT() *gpsInfo {
	ctl := modemPkg.New()
	defer ctl.Close()
	control, ok := ctl.(modemPkg.ControlController)
	if !ok {
		return nil
	}
	devices, err := ctl.Discover()
	if err != nil || len(devices) == 0 {
		return nil
	}
	for _, dev := range devices {
		info, err := control.GetGNSS(dev)
		if err != nil {
			continue
		}
		if info != nil && info.Status == "Disabled" {
			_ = control.SetGNSS(dev, true)
			time.Sleep(350 * time.Millisecond)
			if refreshed, refreshErr := control.GetGNSS(dev); refreshErr == nil && refreshed != nil {
				info = refreshed
			}
		}
		if converted := gpsInfoFromModemGNSS(dev, info); converted != nil {
			return converted
		}
	}
	return nil
}

func gpsInfoFromModemGNSS(devicePath string, info *modemPkg.GNSSInfo) *gpsInfo {
	if info == nil {
		return nil
	}
	out := &gpsInfo{
		lat:              info.Latitude,
		lon:              info.Longitude,
		alt:              info.Altitude,
		speed:            info.SpeedKPH,
		course:           info.Course,
		hdop:             info.HDOP,
		satellites:       info.SatellitesUsed,
		satellitesInView: info.SatellitesInView,
		fix:              info.Status,
		status:           info.Status,
		fixQuality:       info.FixQuality,
		source:           "quectel-at",
		protocol:         firstNonEmpty(info.Protocol, "quectel-at"),
		modemPath:        firstNonEmpty(info.ModemPath, devicePath),
		rawLocation:      info.RawLocation,
		nmea:             info.NMEA,
		timestamp:        info.LastFixTime,
		utc:              info.UTC,
	}
	if out.timestamp.IsZero() && !out.utc.IsZero() {
		out.timestamp = out.utc
	}
	if out.timestamp.IsZero() && (out.lat != 0 || out.lon != 0) {
		out.timestamp = time.Now()
	}
	if out.status == "" {
		out.status = "Unknown"
	}
	if out.status == "Disabled" || out.status == "Searching" || out.lat != 0 || out.lon != 0 {
		return out
	}
	return nil
}

func gpsInfoFromGGA(fields []string) *gpsInfo {
	if len(fields) < 10 || strings.TrimSpace(fields[6]) == "0" {
		return nil
	}
	lat, lon, ok := parseNMEALatLon(fields[2], fields[3], fields[4], fields[5])
	if !ok {
		return nil
	}
	alt, _ := strconv.ParseFloat(strings.TrimSpace(fields[9]), 64)
	sats, _ := strconv.Atoi(strings.TrimSpace(fields[7]))
	return &gpsInfo{
		lat:        lat,
		lon:        lon,
		alt:        alt,
		satellites: sats,
		fix:        "3D",
		status:     "Fix3D",
		source:     "modemmanager",
		protocol:   "modemmanager",
		timestamp:  parseNMEATimestamp(fields[1], ""),
	}
}

func gpsInfoFromRMC(fields []string) *gpsInfo {
	if len(fields) < 10 || strings.TrimSpace(fields[2]) != "A" {
		return nil
	}
	lat, lon, ok := parseNMEALatLon(fields[3], fields[4], fields[5], fields[6])
	if !ok {
		return nil
	}
	speedKnots, _ := strconv.ParseFloat(strings.TrimSpace(fields[7]), 64)
	return &gpsInfo{
		lat:       lat,
		lon:       lon,
		speed:     speedKnots * 1.852,
		fix:       "2D",
		status:    "Fix2D",
		source:    "modemmanager",
		protocol:  "modemmanager",
		timestamp: parseNMEATimestamp(fields[1], fields[9]),
	}
}

func parseNMEALatLon(rawLat, ns, rawLon, ew string) (float64, float64, bool) {
	lat, ok := parseNMEACoordinate(rawLat, ns)
	if !ok {
		return 0, 0, false
	}
	lon, ok := parseNMEACoordinate(rawLon, ew)
	if !ok {
		return 0, 0, false
	}
	return lat, lon, true
}

func parseNMEACoordinate(raw, hemisphere string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	hemisphere = strings.ToUpper(strings.TrimSpace(hemisphere))
	if raw == "" || hemisphere == "" {
		return 0, false
	}
	degreeDigits := 2
	if hemisphere == "E" || hemisphere == "W" {
		degreeDigits = 3
	}
	if len(raw) <= degreeDigits {
		return 0, false
	}
	degrees, err := strconv.ParseFloat(raw[:degreeDigits], 64)
	if err != nil {
		return 0, false
	}
	minutes, err := strconv.ParseFloat(raw[degreeDigits:], 64)
	if err != nil {
		return 0, false
	}
	value := degrees + minutes/60
	if hemisphere == "S" || hemisphere == "W" {
		value = -value
	}
	return value, true
}

func parseNMEATimestamp(rawTime, rawDate string) time.Time {
	now := time.Now().UTC()
	if len(rawTime) < 6 {
		return now
	}
	hour, errH := strconv.Atoi(rawTime[0:2])
	minute, errM := strconv.Atoi(rawTime[2:4])
	secondFloat, errS := strconv.ParseFloat(rawTime[4:], 64)
	if errH != nil || errM != nil || errS != nil {
		return now
	}
	second := int(secondFloat)
	nsec := int((secondFloat - float64(second)) * 1e9)

	year, month, day := now.Date()
	if len(rawDate) == 6 {
		if parsedDay, err := strconv.Atoi(rawDate[0:2]); err == nil {
			day = parsedDay
		}
		if parsedMonth, err := strconv.Atoi(rawDate[2:4]); err == nil {
			month = time.Month(parsedMonth)
		}
		if parsedYear, err := strconv.Atoi(rawDate[4:6]); err == nil {
			if parsedYear >= 70 {
				year = 1900 + parsedYear
			} else {
				year = 2000 + parsedYear
			}
		}
	}
	return time.Date(year, month, day, hour, minute, second, nsec, time.UTC)
}
