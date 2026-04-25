package platforms

import (
	"fmt"
	"os"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"

	"github.com/stratoberry/go-gpsd"
)

// collectGPSStatic populates Device.DeviceInfo.Location.1.* from gpsd or /tmp/gps_info.txt.
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

	// TR-181 Location uses PIDF-LO XML in DataObject, but for simplicity
	// we store coordinates as individual params that the controller can read.
	// The raw lat/lon/alt are stored as vendor extensions under X_WANTASTIC_
	msg.Set(prefix+"X_WANTASTIC_Latitude", wusp.String(fmt.Sprintf("%.6f", info.lat)))
	msg.Set(prefix+"X_WANTASTIC_Longitude", wusp.String(fmt.Sprintf("%.6f", info.lon)))
	if info.alt != 0 {
		msg.Set(prefix+"X_WANTASTIC_Altitude", wusp.String(fmt.Sprintf("%.1f", info.alt)))
	}
	if info.speed > 0 {
		msg.Set(prefix+"X_WANTASTIC_Speed", wusp.String(fmt.Sprintf("%.1f", info.speed)))
	}
	if info.satellites > 0 {
		msg.Set(prefix+"X_WANTASTIC_Satellites", wusp.Uint(uint64(info.satellites)))
	}
	msg.Set(prefix+"X_WANTASTIC_Fix", wusp.String(info.fix))
	if !info.timestamp.IsZero() {
		msg.Set(prefix+"AcquiredTime", wusp.String(info.timestamp.UTC().Format(time.RFC3339)))
	}
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
	data, err := os.ReadFile("/tmp/gps_info.txt")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "latitude=") {
			line = strings.ReplaceAll(line, "- ", "-")
			var lat, lon, alt float64
			if _, err := fmt.Sscanf(line, "latitude=%f, longitude=%f, altitude=%f", &lat, &lon, &alt); err == nil {
				return &gpsInfo{lat: lat, lon: lon, alt: alt, fix: "2D", timestamp: time.Now()}
			}
		}
	}
	return nil
}
