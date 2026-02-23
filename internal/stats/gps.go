package stats

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stratoberry/go-gpsd"
)

// collectGPSStatistics connects to local gpsd or reads /tmp/gps_info.txt
func collectGPSStatistics() *GPSInfo {
	// 1. Try gpsd first
	if info := collectGPSFromGPSD(); info != nil {
		return info
	}

	// 2. Fallback to file
	return collectGPSFromFile()
}

func collectGPSFromGPSD() *GPSInfo {
	// connect to gpsd
	gps, err := gpsd.Dial("localhost:2947")
	if err != nil {
		// Log debug only if needed, otherwise silent fail is typical for optional stats
		return nil
	}
	defer gps.Close()

	// data channels
	tpvFilter := func(r interface{}) {
		// We only need one TPV and one SKY, so we don't need a complex filter here
		// But the library is event-driven.
	}
	_ = tpvFilter // unused

	// We need to capture data from the callbacks
	info := &GPSInfo{
		Fix: "none",
	}

	// Register handlers
	gps.AddFilter("TPV", func(r interface{}) {
		tpv, ok := r.(*gpsd.TPVReport)
		if !ok {
			return
		}
		info.Lat = tpv.Lat
		info.Lon = tpv.Lon
		info.Alt = tpv.Alt
		info.Speed = tpv.Speed * 3.6 // m/s to km/h
		info.Timestamp = tpv.Time

		switch tpv.Mode {
		case 2:
			info.Fix = "2D"
		case 3:
			info.Fix = "3D"
		default:
			info.Fix = "none"
		}
	})

	gps.AddFilter("SKY", func(r interface{}) {
		sky, ok := r.(*gpsd.SKYReport)
		if !ok {
			return
		}
		// Count used satellites
		count := 0
		for _, sat := range sky.Satellites {
			if sat.Used {
				count++
			}
		}
		info.Satellites = count

		// If we have both TPV and SKY (or sufficient time passed), we could signal done
		// But TPV is the critical one for location.
	})

	// Watch starts the stream and returns a done channel
	done := gps.Watch()

	// Wait for a short period to gather data
	time.Sleep(500 * time.Millisecond)

	// Close connection to stop the watch loop
	gps.Close()

	// Wait for watch loop to exit
	<-done

	if info.Lat == 0 && info.Lon == 0 {
		return nil
	}

	return info
}

func collectGPSFromFile() *GPSInfo {
	data, err := os.ReadFile("/tmp/gps_info.txt")
	if err != nil {
		return nil
	}

	info := &GPSInfo{
		Fix: "2D", // Assume fix if file exists and has data
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		// Look for "latitude=42.228963, longitude=- 76.668428, altitude=465.7"
		if strings.HasPrefix(line, "latitude=") {
			// clean up spaces around minus signs if any, e.g. "- 76" -> "-76"
			line = strings.ReplaceAll(line, "- ", "-")

			var lat, lon, alt float64
			// Sscanf is simple enough for this format
			_, err := fmt.Sscanf(line, "latitude=%f, longitude=%f, altitude=%f", &lat, &lon, &alt)
			if err == nil {
				info.Lat = lat
				info.Lon = lon
				info.Alt = alt
				info.Timestamp = time.Now() // File doesn't have clear ISO timestamp in that line, use now
				return info
			}
		}
	}
	return nil
}
