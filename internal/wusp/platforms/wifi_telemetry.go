package platforms

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/diaglog"
	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wifiprobe"
	"wantastic-agent/internal/wusp"
)

// Device.WUSP_WiFiTelemetry: a background sampler that, every
// wifiTelemetryInterval, reads radio counters, channel load, configured
// distance and every associated station (nl80211, hostapd, QCA/MadWifi
// ioctls), measures goodput from counter deltas, probes station latency with
// ICMP and appends one sample to a rolling history of wusp.WiFiHistoryDepth
// entries per radio and per station. A USP Get only reads the last completed
// sample, mirroring the spectral coordinator.

const (
	wifiTelemetryInterval       = 60 * time.Second
	wifiTelemetrySampleDeadline = 20 * time.Second
	wifiTelemetryProbeCount     = 4
	wifiTelemetryProbeInterval  = 200 * time.Millisecond
	wifiTelemetryProbeTimeout   = time.Second
	// Typical AP/CPE EIRP when the driver reports no TX power; only used
	// for the indicative station distance.
	wifiTelemetryDefaultTxPower = 20
	wifiTelemetryMaxDistance    = 100000
)

type wifiTelemetryVAP struct {
	Name      string
	Radio     string
	Driver    string
	Mode      string
	Vendor    bool
	Frequency int
}

type wifiIfaceCounters struct {
	RxBytes, TxBytes, RxPackets, TxPackets   uint64
	RxErrors, TxErrors, RxDropped, TxDropped uint64
	OK                                       bool
}

type wifiLatency struct {
	Known                 bool
	Avg, Min, Max, Jitter time.Duration
	Success, Lost         int
}

type wifiTelemetryStation struct {
	Entry           iwinfo.AssocEntry
	Interface       string
	Radio           string
	IP              netip.Addr
	Downlink        uint32
	Uplink          uint32
	ThroughputKnown bool
	RetriesDelta    uint32
	RetriesKnown    bool
	Distance        int
	Latency         wifiLatency
	CollectedAt     time.Time
}

type wifiTelemetryRadio struct {
	Name            string
	Driver          string
	Frequency       int
	CenterFrequency int
	ChannelWidth    int
	Noise           int
	TxPower         int
	Utilization     int
	UtilKnown       bool
	Distance        int
	DistanceSource  string
	StationCount    int
	Counters        wifiIfaceCounters
	Downlink        uint32
	Uplink          uint32
	ThroughputKnown bool
	Latency         wifiLatency
	Interfaces      []string
	CollectedAt     time.Time
}

type wifiTelemetrySnapshot struct {
	Supported     bool
	Sampled       bool
	Collecting    bool
	LastSample    time.Time
	LastError     string
	LatencyMethod string
	Radios        []wifiTelemetryRadio
	Stations      []wifiTelemetryStation
	RadioHistory  map[string][]wusp.WiFiHistorySample
	StationHist   map[string][]wusp.WiFiHistorySample
}

type wifiCounterState struct {
	Rx, Tx, Retries uint64
	RetriesKnown    bool
	At              time.Time
}

type wifiSurveyState struct {
	Active, Busy uint64
	Frequency    uint32
}

type wifiTelemetryDeps struct {
	netClassDir    string
	listVAPs       func(netClassDir string) []wifiTelemetryVAP
	stations       func(netClassDir string, vap wifiTelemetryVAP) []iwinfo.AssocEntry
	counters       func(netClassDir, ifname string) wifiIfaceCounters
	survey         func(ifname string) ([]iwinfo.SurveyEntry, error)
	radioLink      func(ifname string) (iwinfo.RadioLink, error)
	vendorDistance func(radio string) (int, string, bool)
	noise          func(ifname string) (int, bool)
	frequency      func(ifname string) (int, bool)
	txPower        func(ifname string) (int, bool)
	neighbors      func() map[string]netip.Addr
	probe          func(context.Context, []netip.Addr, wifiprobe.Options) (map[netip.Addr]wifiprobe.Result, error)
}

func defaultWiFiTelemetryDeps() wifiTelemetryDeps {
	return wifiTelemetryDeps{
		listVAPs:       discoverWiFiTelemetryVAPs,
		stations:       collectWiFiTelemetryStations,
		counters:       readWiFiIfaceCounters,
		survey:         iwinfo.GetSurvey,
		radioLink:      iwinfo.NL80211RadioLink,
		vendorDistance: iwinfo.VendorConfiguredDistance,
		noise:          iwinfo.WirelessNoise,
		frequency:      iwinfo.WextFrequency,
		txPower:        iwinfo.WextTxPower,
		neighbors:      readIPv4Neighbors,
		probe:          wifiprobe.Probe,
	}
}

type wifiTelemetryCoordinator struct {
	mu         sync.Mutex
	started    bool
	interval   time.Duration
	now        func() time.Time
	deps       wifiTelemetryDeps
	current    wifiTelemetrySnapshot
	radioHist  map[string][]wusp.WiFiHistorySample
	staHist    map[string][]wusp.WiFiHistorySample
	radioSeen  map[string]time.Time
	staSeen    map[string]time.Time
	prevSta    map[string]wifiCounterState
	prevRadio  map[string]wifiCounterState
	prevSurvey map[string]wifiSurveyState
}

var defaultWiFiTelemetry = newWiFiTelemetryCoordinator(defaultWiFiTelemetryDeps())

func newWiFiTelemetryCoordinator(deps wifiTelemetryDeps) *wifiTelemetryCoordinator {
	return &wifiTelemetryCoordinator{
		interval:   wifiTelemetryInterval,
		now:        time.Now,
		deps:       deps,
		radioHist:  make(map[string][]wusp.WiFiHistorySample),
		staHist:    make(map[string][]wusp.WiFiHistorySample),
		radioSeen:  make(map[string]time.Time),
		staSeen:    make(map[string]time.Time),
		prevSta:    make(map[string]wifiCounterState),
		prevRadio:  make(map[string]wifiCounterState),
		prevSurvey: make(map[string]wifiSurveyState),
	}
}

// snapshotAndStart returns the last completed sample and lazily starts the
// background sampler on first use.
func (c *wifiTelemetryCoordinator) snapshotAndStart(netClassDir string) wifiTelemetrySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		c.started = true
		c.deps.netClassDir = netClassDir
		c.current.Collecting = true
		go c.loop()
	}
	out := c.current
	out.Radios = append([]wifiTelemetryRadio(nil), c.current.Radios...)
	out.Stations = append([]wifiTelemetryStation(nil), c.current.Stations...)
	out.RadioHistory = make(map[string][]wusp.WiFiHistorySample, len(c.radioHist))
	for k, v := range c.radioHist {
		out.RadioHistory[k] = append([]wusp.WiFiHistorySample(nil), v...)
	}
	out.StationHist = make(map[string][]wusp.WiFiHistorySample, len(c.staHist))
	for k, v := range c.staHist {
		out.StationHist[k] = append([]wusp.WiFiHistorySample(nil), v...)
	}
	return out
}

func (c *wifiTelemetryCoordinator) loop() {
	for {
		c.sampleOnce()
		time.Sleep(c.interval)
	}
}

func (c *wifiTelemetryCoordinator) sampleOnce() {
	defer func() {
		if recovered := recover(); recovered != nil {
			diaglog.Printf("[USP] wifi_telemetry panic=%q", fmt.Sprint(recovered))
			c.mu.Lock()
			c.current.Collecting = false
			c.current.LastError = fmt.Sprintf("sampler panic: %v", recovered)
			c.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), wifiTelemetrySampleDeadline)
	defer cancel()
	c.sample(ctx)
}

func (c *wifiTelemetryCoordinator) sample(ctx context.Context) {
	now := c.now().UTC()
	deps := c.deps
	vaps := deps.listVAPs(deps.netClassDir)
	if len(vaps) == 0 {
		c.mu.Lock()
		c.current = wifiTelemetrySnapshot{Supported: c.current.Supported, Sampled: true, LastSample: now, LatencyMethod: wifiprobe.MethodNone}
		c.mu.Unlock()
		return
	}

	radiosByName := make(map[string]*wifiTelemetryRadio)
	var stations []wifiTelemetryStation
	seenMAC := make(map[string]bool)
	for _, vap := range vaps {
		radio := radiosByName[vap.Radio]
		if radio == nil {
			radio = &wifiTelemetryRadio{Name: vap.Radio, Driver: vap.Driver, CollectedAt: now}
			radiosByName[vap.Radio] = radio
		}
		radio.Interfaces = append(radio.Interfaces, vap.Name)
		if radio.Frequency == 0 {
			radio.Frequency = vap.Frequency
		}
		if radio.Frequency == 0 && deps.frequency != nil {
			radio.Frequency, _ = deps.frequency(vap.Name)
		}
		if counters := deps.counters(deps.netClassDir, vap.Name); counters.OK {
			radio.Counters.OK = true
			radio.Counters.RxBytes += counters.RxBytes
			radio.Counters.TxBytes += counters.TxBytes
			radio.Counters.RxPackets += counters.RxPackets
			radio.Counters.TxPackets += counters.TxPackets
			radio.Counters.RxErrors += counters.RxErrors
			radio.Counters.TxErrors += counters.TxErrors
			radio.Counters.RxDropped += counters.RxDropped
			radio.Counters.TxDropped += counters.TxDropped
		}
		for _, entry := range deps.stations(deps.netClassDir, vap) {
			key := strings.ToLower(entry.MAC.String())
			if seenMAC[key] {
				continue
			}
			seenMAC[key] = true
			if entry.Source == "madwifi-ioctl" || strings.Contains(entry.Source, "madwifi") {
				radio.Driver = "madwifi"
			}
			stations = append(stations, wifiTelemetryStation{Entry: entry, Interface: vap.Name, Radio: vap.Radio, CollectedAt: now})
		}
	}

	// Radio physical layer: noise, TX power, channel load, distance.
	for _, radio := range radiosByName {
		ifname := radio.Interfaces[0]
		if link, err := deps.radioLink(ifname); err == nil {
			if link.Frequency > 0 && radio.Frequency == 0 {
				radio.Frequency = link.Frequency
			}
			radio.CenterFrequency, radio.ChannelWidth = link.CenterFrequency, link.ChannelWidth
			if link.TxPowerKnown {
				radio.TxPower = link.TxPowerDBM
			}
			if link.CoverageKnown {
				radio.Distance, radio.DistanceSource = link.CoverageDistance, "coverage-class"
			}
		}
		if radio.TxPower == 0 && deps.txPower != nil {
			radio.TxPower, _ = deps.txPower(ifname)
		}
		if radio.DistanceSource == "" && deps.vendorDistance != nil {
			if d, source, ok := deps.vendorDistance(radio.Name); ok {
				radio.Distance, radio.DistanceSource = d, source
			}
		}
		if radio.DistanceSource == "" {
			radio.DistanceSource = "none"
		}
		if survey, err := deps.survey(ifname); err == nil {
			c.applySurvey(radio, survey)
		}
		if radio.Noise == 0 && deps.noise != nil {
			radio.Noise, _ = deps.noise(ifname)
		}
		// Fall back to what the Device.WiFi collector observed on any of
		// the radio's interfaces (OpenWrt ubus/iwinfo, vendor readers).
		for _, name := range radio.Interfaces {
			seen, ok := observedRadio(name)
			if !ok {
				continue
			}
			if radio.Noise == 0 && seen.Noise < 0 && seen.Noise > -130 {
				radio.Noise = seen.Noise
			}
			if radio.TxPower == 0 && seen.TxPower > 0 && seen.TxPower <= 40 {
				radio.TxPower = seen.TxPower
			}
			if radio.Frequency == 0 && seen.Frequency > 0 {
				radio.Frequency = seen.Frequency
			}
		}
	}

	// Station enrichment: IPs, throughput, distance.
	neighbors := map[string]netip.Addr{}
	if deps.neighbors != nil {
		neighbors = deps.neighbors()
	}
	sort.Slice(stations, func(i, j int) bool {
		si, sj := stations[i].Entry, stations[j].Entry
		if si.SignalKnown != sj.SignalKnown {
			return si.SignalKnown
		}
		return si.Signal > sj.Signal
	})
	if len(stations) > wusp.WiFiTelemetryMaxStations {
		stations = stations[:wusp.WiFiTelemetryMaxStations]
	}
	c.mu.Lock()
	for i := range stations {
		station := &stations[i]
		key := strings.ToLower(station.Entry.MAC.String())
		station.IP = neighbors[key]
		radio := radiosByName[station.Radio]
		radio.StationCount++
		if radio.Noise != 0 && !station.Entry.NoiseKnown {
			station.Entry.Noise, station.Entry.NoiseKnown = int8(radio.Noise), true
		}
		if station.Entry.RxBytesKnown && station.Entry.TxBytesKnown {
			prev, ok := c.prevSta[key]
			cur := wifiCounterState{Rx: station.Entry.RxBytes, Tx: station.Entry.TxBytes, Retries: uint64(station.Entry.TxRetries), RetriesKnown: station.Entry.TxRetriesKnown, At: now}
			if ok {
				if down, up, ok := throughputKbps(prev, cur); ok {
					station.Downlink, station.Uplink, station.ThroughputKnown = down, up, true
				}
				if prev.RetriesKnown && cur.RetriesKnown && cur.Retries >= prev.Retries {
					station.RetriesDelta, station.RetriesKnown = uint32(min(cur.Retries-prev.Retries, math.MaxUint32)), true
				}
			}
			c.prevSta[key] = cur
		}
		station.Distance = estimateStationDistance(radio.TxPower, station.Entry, radio.Frequency)
	}
	for name, radio := range radiosByName {
		if !radio.Counters.OK {
			continue
		}
		cur := wifiCounterState{Rx: radio.Counters.RxBytes, Tx: radio.Counters.TxBytes, At: now}
		if prev, ok := c.prevRadio[name]; ok {
			if down, up, ok := throughputKbps(prev, cur); ok {
				radio.Downlink, radio.Uplink, radio.ThroughputKnown = down, up, true
			}
		}
		c.prevRadio[name] = cur
	}
	c.mu.Unlock()

	// Latency: one ICMP run over every station with a known IPv4 address.
	latencyMethod := wifiprobe.MethodNone
	lastError := ""
	targets := make([]netip.Addr, 0, len(stations))
	for _, station := range stations {
		if station.IP.IsValid() {
			targets = append(targets, station.IP)
		}
	}
	if len(targets) > 0 && deps.probe != nil {
		results, err := deps.probe(ctx, targets, wifiprobe.Options{Count: wifiTelemetryProbeCount, Interval: wifiTelemetryProbeInterval, Timeout: wifiTelemetryProbeTimeout})
		switch {
		case errors.Is(err, wifiprobe.ErrUnavailable):
			lastError = "ICMP sockets unavailable; latency not measured"
		case err != nil:
			lastError = "latency probe: " + err.Error()
		default:
			latencyMethod = wifiprobe.MethodICMP
			for i := range stations {
				if res, ok := results[stations[i].IP]; ok && res.Sent > 0 {
					stations[i].Latency = latencyFromProbe(res)
				}
			}
		}
	} else if len(targets) == 0 {
		latencyMethod = wifiprobe.MethodICMP
	}
	for name, radio := range radiosByName {
		radio.Latency = aggregateRadioLatency(stations, name)
	}

	radios := make([]wifiTelemetryRadio, 0, len(radiosByName))
	for _, radio := range radiosByName {
		sort.Strings(radio.Interfaces)
		radios = append(radios, *radio)
	}
	sort.Slice(radios, func(i, j int) bool { return radios[i].Name < radios[j].Name })
	if len(radios) > wusp.WiFiTelemetryMaxRadios {
		radios = radios[:wusp.WiFiTelemetryMaxRadios]
	}
	sort.SliceStable(stations, func(i, j int) bool {
		if stations[i].Radio != stations[j].Radio {
			return stations[i].Radio < stations[j].Radio
		}
		return stations[i].Entry.MAC.String() < stations[j].Entry.MAC.String()
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, radio := range radios {
		c.radioHist[radio.Name] = appendHistory(c.radioHist[radio.Name], radioHistorySample(radio, now))
		c.radioSeen[radio.Name] = now
	}
	for _, station := range stations {
		key := strings.ToLower(station.Entry.MAC.String())
		c.staHist[key] = appendHistory(c.staHist[key], stationHistorySample(station, now))
		c.staSeen[key] = now
	}
	c.pruneLocked(now)
	c.current = wifiTelemetrySnapshot{
		Supported:     true,
		Sampled:       true,
		LastSample:    now,
		LastError:     lastError,
		LatencyMethod: latencyMethod,
		Radios:        radios,
		Stations:      stations,
	}
	diaglog.Printf("[USP] wifi_telemetry radios=%d stations=%d probed=%d latency=%s error=%q", len(radios), len(stations), len(targets), latencyMethod, lastError)
}

func (c *wifiTelemetryCoordinator) applySurvey(radio *wifiTelemetryRadio, survey []iwinfo.SurveyEntry) {
	var inUse *iwinfo.SurveyEntry
	for i := range survey {
		if survey[i].InUse {
			inUse = &survey[i]
			break
		}
	}
	if inUse == nil {
		return
	}
	if radio.Frequency == 0 {
		radio.Frequency = int(inUse.Frequency)
	}
	if inUse.Noise < 0 {
		radio.Noise = int(inUse.Noise)
	}
	if inUse.ActiveTime == 0 {
		return
	}
	c.mu.Lock()
	prev, ok := c.prevSurvey[radio.Name]
	c.prevSurvey[radio.Name] = wifiSurveyState{Active: inUse.ActiveTime, Busy: inUse.BusyTime, Frequency: inUse.Frequency}
	c.mu.Unlock()
	active, busy := inUse.ActiveTime, inUse.BusyTime
	// Survey counters are cumulative since the channel was entered; use the
	// interval delta when the channel did not change in between.
	if ok && prev.Frequency == inUse.Frequency && active > prev.Active && busy >= prev.Busy {
		active, busy = active-prev.Active, busy-prev.Busy
	}
	if busy > active {
		busy = active
	}
	radio.Utilization = int((busy*100 + active/2) / active)
	radio.UtilKnown = true
}

func (c *wifiTelemetryCoordinator) pruneLocked(now time.Time) {
	horizon := time.Duration(wusp.WiFiHistoryDepth) * c.interval
	for key, seen := range c.staSeen {
		if now.Sub(seen) > horizon {
			delete(c.staSeen, key)
			delete(c.staHist, key)
			delete(c.prevSta, key)
		}
	}
	for key, seen := range c.radioSeen {
		if now.Sub(seen) > horizon {
			delete(c.radioSeen, key)
			delete(c.radioHist, key)
			delete(c.prevRadio, key)
			delete(c.prevSurvey, key)
		}
	}
	// Hard cap: a roaming-heavy site must not grow history without bound.
	if len(c.staHist) > 2*wusp.WiFiTelemetryMaxStations {
		keys := make([]string, 0, len(c.staSeen))
		for key := range c.staSeen {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return c.staSeen[keys[i]].Before(c.staSeen[keys[j]]) })
		for _, key := range keys[:len(keys)-2*wusp.WiFiTelemetryMaxStations] {
			delete(c.staSeen, key)
			delete(c.staHist, key)
			delete(c.prevSta, key)
		}
	}
}

func appendHistory(history []wusp.WiFiHistorySample, sample wusp.WiFiHistorySample) []wusp.WiFiHistorySample {
	history = append(history, sample)
	if len(history) > wusp.WiFiHistoryDepth {
		history = append([]wusp.WiFiHistorySample(nil), history[len(history)-wusp.WiFiHistoryDepth:]...)
	}
	return history
}

func throughputKbps(prev, cur wifiCounterState) (down, up uint32, ok bool) {
	seconds := cur.At.Sub(prev.At).Seconds()
	if seconds < 1 || cur.Tx < prev.Tx || cur.Rx < prev.Rx {
		return 0, 0, false
	}
	kbps := func(delta uint64) uint32 {
		v := float64(delta) * 8 / 1000 / seconds
		if v > math.MaxUint32 {
			return math.MaxUint32
		}
		return uint32(v + 0.5)
	}
	return kbps(cur.Tx - prev.Tx), kbps(cur.Rx - prev.Rx), true
}

// estimateStationDistance inverts the free-space path loss model,
// FSPL(dB) = 20·log10(d_km) + 20·log10(f_MHz) + 32.44, with the path loss
// taken as radio TX power minus the received signal. It is indicative only.
func estimateStationDistance(txPower int, entry iwinfo.AssocEntry, frequency int) int {
	signal := 0
	switch {
	case entry.SignalAvgKnown && entry.SignalAvg < 0:
		signal = int(entry.SignalAvg)
	case entry.SignalKnown && entry.Signal < 0:
		signal = int(entry.Signal)
	}
	if signal == 0 || frequency <= 0 {
		return 0
	}
	if txPower <= 0 {
		txPower = wifiTelemetryDefaultTxPower
	}
	pathLoss := float64(txPower - signal)
	if pathLoss <= 0 {
		return 1
	}
	km := math.Pow(10, (pathLoss-20*math.Log10(float64(frequency))-32.44)/20)
	meters := int(math.Round(km * 1000))
	if meters < 1 {
		return 1
	}
	if meters > wifiTelemetryMaxDistance {
		return wifiTelemetryMaxDistance
	}
	return meters
}

func latencyFromProbe(res wifiprobe.Result) wifiLatency {
	out := wifiLatency{Known: true, Success: res.Received, Lost: res.Lost()}
	if res.Received > 0 {
		out.Avg, out.Min, out.Max, out.Jitter = res.Avg, res.Min, res.Max, res.Jitter
	}
	return out
}

func aggregateRadioLatency(stations []wifiTelemetryStation, radio string) wifiLatency {
	var out wifiLatency
	var avgSum, jitterSum time.Duration
	answered := 0
	for _, station := range stations {
		if station.Radio != radio || !station.Latency.Known {
			continue
		}
		out.Known = true
		out.Success += station.Latency.Success
		out.Lost += station.Latency.Lost
		if station.Latency.Success == 0 {
			continue
		}
		answered++
		avgSum += station.Latency.Avg
		jitterSum += station.Latency.Jitter
		if out.Min == 0 || station.Latency.Min < out.Min {
			out.Min = station.Latency.Min
		}
		if station.Latency.Max > out.Max {
			out.Max = station.Latency.Max
		}
	}
	if answered > 0 {
		out.Avg = avgSum / time.Duration(answered)
		out.Jitter = jitterSum / time.Duration(answered)
	}
	return out
}

func lossPermille(l wifiLatency) int64 {
	total := l.Success + l.Lost
	if total == 0 {
		return 0
	}
	return int64(l.Lost * 1000 / total)
}

func radioHistorySample(radio wifiTelemetryRadio, now time.Time) wusp.WiFiHistorySample {
	values := map[uint8]int64{wusp.WiFiMetricStationCount: int64(radio.StationCount)}
	if radio.Noise != 0 {
		values[wusp.WiFiMetricNoise] = int64(radio.Noise)
	}
	if radio.UtilKnown {
		values[wusp.WiFiMetricChannelUtilization] = int64(radio.Utilization)
	}
	if radio.ThroughputKnown {
		values[wusp.WiFiMetricDownlink] = int64(radio.Downlink)
		values[wusp.WiFiMetricUplink] = int64(radio.Uplink)
	}
	addLatencyValues(values, radio.Latency)
	return wusp.WiFiHistorySample{Time: now, Values: values}
}

func stationHistorySample(station wifiTelemetryStation, now time.Time) wusp.WiFiHistorySample {
	values := map[uint8]int64{}
	e := station.Entry
	if e.SignalKnown && e.Signal != 0 {
		values[wusp.WiFiMetricSignal] = int64(e.Signal)
	}
	if e.NoiseKnown && e.Noise != 0 {
		values[wusp.WiFiMetricNoise] = int64(e.Noise)
	}
	if e.TxRateKnown {
		values[wusp.WiFiMetricTxRate] = int64(e.TxRate)
	}
	if e.RxRateKnown {
		values[wusp.WiFiMetricRxRate] = int64(e.RxRate)
	}
	if e.ExpectedThroughputKnown {
		values[wusp.WiFiMetricExpectedThroughput] = int64(e.ExpectedThroughput)
	}
	if station.ThroughputKnown {
		values[wusp.WiFiMetricDownlink] = int64(station.Downlink)
		values[wusp.WiFiMetricUplink] = int64(station.Uplink)
	}
	if station.RetriesKnown {
		values[wusp.WiFiMetricTxRetries] = int64(station.RetriesDelta)
	}
	if station.Distance > 0 {
		values[wusp.WiFiMetricDistance] = int64(station.Distance)
	}
	addLatencyValues(values, station.Latency)
	return wusp.WiFiHistorySample{Time: now, Values: values}
}

func addLatencyValues(values map[uint8]int64, l wifiLatency) {
	if !l.Known {
		return
	}
	values[wusp.WiFiMetricLatencyLoss] = lossPermille(l)
	if l.Success > 0 {
		values[wusp.WiFiMetricLatencyAvg] = l.Avg.Microseconds()
		values[wusp.WiFiMetricLatencyMax] = l.Max.Microseconds()
		values[wusp.WiFiMetricLatencyJitter] = l.Jitter.Microseconds()
	}
}

// appendWiFiTelemetryFields emits Device.WUSP_WiFiTelemetry from the last
// completed sample and starts the sampler on first use.
func appendWiFiTelemetryFields(msg *wusp.Message, netClassDir string) error {
	return appendWiFiTelemetrySnapshotFields(msg, defaultWiFiTelemetry.snapshotAndStart(netClassDir))
}

func appendWiFiTelemetrySnapshotFields(msg *wusp.Message, snap wifiTelemetrySnapshot) error {
	prefix := wusp.WUSPWiFiTelemetryPrefix
	appendField(msg, prefix+"SampleIntervalSeconds", wusp.Uint(uint64(wifiTelemetryInterval/time.Second)))
	appendField(msg, prefix+"HistoryDepth", wusp.Uint(wusp.WiFiHistoryDepth))
	appendField(msg, prefix+"LastError", wusp.String(truncateSpectralError(snap.LastError)))
	method := snap.LatencyMethod
	if method == "" {
		method = wifiprobe.MethodNone
	}
	appendField(msg, prefix+"LatencyMethod", wusp.String(method))
	if !snap.LastSample.IsZero() {
		appendField(msg, prefix+"LastSampleTime", wusp.Time(snap.LastSample))
	}
	switch {
	case !snap.Sampled:
		appendField(msg, prefix+"Status", wusp.String("Collecting"))
		// Counts are withheld until the first sample so the controller keeps
		// the rows it already has across an agent restart.
		return nil
	case !snap.Supported:
		appendField(msg, prefix+"Status", wusp.String("Unsupported"))
	case len(snap.Radios) == 0 && snap.LastError != "":
		appendField(msg, prefix+"Status", wusp.String("Error"))
	default:
		appendField(msg, prefix+"Status", wusp.String("Ready"))
	}
	appendField(msg, prefix+"RadioNumberOfEntries", wusp.Uint(uint64(len(snap.Radios))))
	appendField(msg, prefix+"StationNumberOfEntries", wusp.Uint(uint64(len(snap.Stations))))

	wifiRadioRefs := wifiRadioReferencesByInterface(msg)
	radioRow := make(map[string]int, len(snap.Radios))
	for i, radio := range snap.Radios {
		path := fmt.Sprintf("%sRadio.%d.", prefix, i+1)
		radioRow[radio.Name] = i + 1
		appendField(msg, path+"Alias", wusp.String("cpe-wifi-"+radio.Name))
		appendField(msg, path+"Interface", wusp.String(radio.Name))
		if ref := wifiRadioRefs[radio.Name]; ref != "" {
			appendField(msg, path+"RadioReference", wusp.String(ref))
		} else {
			for _, ifname := range radio.Interfaces {
				if ref := wifiRadioRefs[ifname]; ref != "" {
					appendField(msg, path+"RadioReference", wusp.String(ref))
					break
				}
			}
		}
		driver := radio.Driver
		if driver == "" {
			driver = "unknown"
		}
		appendField(msg, path+"Driver", wusp.String(driver))
		appendField(msg, path+"OperatingFrequency", wusp.Uint(uint64(max(radio.Frequency, 0))))
		appendField(msg, path+"Channel", wusp.Uint(uint64(max(wifiChannelFromFrequency(radio.Frequency), 0))))
		appendField(msg, path+"ChannelWidth", wusp.Uint(uint64(max(radio.ChannelWidth, 0))))
		appendField(msg, path+"CenterFrequency", wusp.Uint(uint64(max(radio.CenterFrequency, 0))))
		appendField(msg, path+"Noise", wusp.Int(int64(radio.Noise)))
		appendField(msg, path+"TransmitPower", wusp.Int(int64(radio.TxPower)))
		if radio.UtilKnown {
			appendField(msg, path+"ChannelUtilization", wusp.Uint(uint64(radio.Utilization)))
		}
		appendField(msg, path+"ConfiguredDistance", wusp.Uint(uint64(max(radio.Distance, 0))))
		appendField(msg, path+"DistanceSource", wusp.String(radio.DistanceSource))
		appendField(msg, path+"StationCount", wusp.Uint(uint64(radio.StationCount)))
		if radio.Counters.OK {
			appendField(msg, path+"BytesSent", wusp.Uint(radio.Counters.TxBytes))
			appendField(msg, path+"BytesReceived", wusp.Uint(radio.Counters.RxBytes))
			appendField(msg, path+"PacketsSent", wusp.Uint(radio.Counters.TxPackets))
			appendField(msg, path+"PacketsReceived", wusp.Uint(radio.Counters.RxPackets))
			appendField(msg, path+"ErrorsSent", wusp.Uint(radio.Counters.TxErrors))
			appendField(msg, path+"ErrorsReceived", wusp.Uint(radio.Counters.RxErrors))
			appendField(msg, path+"DiscardPacketsSent", wusp.Uint(radio.Counters.TxDropped))
			appendField(msg, path+"DiscardPacketsReceived", wusp.Uint(radio.Counters.RxDropped))
		}
		if radio.ThroughputKnown {
			appendField(msg, path+"DownlinkThroughput", wusp.Uint(uint64(radio.Downlink)))
			appendField(msg, path+"UplinkThroughput", wusp.Uint(uint64(radio.Uplink)))
		}
		appendLatencyFields(msg, path, radio.Latency)
		appendField(msg, path+"CollectedAt", wusp.Time(radio.CollectedAt))
		if err := appendHistoryField(msg, path, snap.RadioHistory[radio.Name]); err != nil {
			return fmt.Errorf("radio %s history: %w", radio.Name, err)
		}
	}

	for i, station := range snap.Stations {
		path := fmt.Sprintf("%sStation.%d.", prefix, i+1)
		e := station.Entry
		key := strings.ToLower(e.MAC.String())
		appendField(msg, path+"Alias", wusp.String("sta-"+strings.ReplaceAll(key, ":", "")))
		appendField(msg, path+"MACAddress", wusp.MAC(e.MAC))
		if station.IP.IsValid() {
			appendField(msg, path+"IPAddress", wusp.String(station.IP.String()))
		}
		appendField(msg, path+"Interface", wusp.String(station.Interface))
		if row := radioRow[station.Radio]; row > 0 {
			appendField(msg, path+"Radio", wusp.String(fmt.Sprintf("%sRadio.%d.", prefix, row)))
		}
		if source := strings.TrimSpace(e.Source); source != "" {
			if len(source) > 64 {
				source = source[:64]
			}
			appendField(msg, path+"Source", wusp.String(source))
		}
		signal, noise := 0, 0
		if e.SignalKnown {
			signal = int(e.Signal)
		}
		if e.NoiseKnown {
			noise = int(e.Noise)
		}
		appendField(msg, path+"SignalStrength", wusp.Int(int64(signal)))
		appendField(msg, path+"Noise", wusp.Int(int64(noise)))
		snr := 0
		if signal < 0 && noise < 0 && signal > noise {
			snr = signal - noise
		}
		appendField(msg, path+"SNR", wusp.Int(int64(snr)))
		appendField(msg, path+"TxRate", wusp.Uint(uint64(e.TxRate)))
		appendField(msg, path+"RxRate", wusp.Uint(uint64(e.RxRate)))
		appendField(msg, path+"ExpectedThroughput", wusp.Uint(uint64(e.ExpectedThroughput)))
		if station.ThroughputKnown {
			appendField(msg, path+"DownlinkThroughput", wusp.Uint(uint64(station.Downlink)))
			appendField(msg, path+"UplinkThroughput", wusp.Uint(uint64(station.Uplink)))
		}
		if e.TxBytesKnown {
			appendField(msg, path+"BytesSent", wusp.Uint(e.TxBytes))
		}
		if e.RxBytesKnown {
			appendField(msg, path+"BytesReceived", wusp.Uint(e.RxBytes))
		}
		if e.TxRetriesKnown {
			appendField(msg, path+"Retransmissions", wusp.Uint(uint64(e.TxRetries)))
		}
		if e.ConnectedTimeKnown {
			appendField(msg, path+"ConnectedTime", wusp.Uint(uint64(e.ConnectedTime)))
		}
		if e.InactiveKnown {
			appendField(msg, path+"InactiveTime", wusp.Uint(uint64(e.Inactive)))
		}
		appendField(msg, path+"EstimatedDistance", wusp.Uint(uint64(station.Distance)))
		if station.Distance > 0 {
			appendField(msg, path+"DistanceMethod", wusp.String("fspl"))
		} else {
			appendField(msg, path+"DistanceMethod", wusp.String("none"))
		}
		appendLatencyFields(msg, path, station.Latency)
		appendField(msg, path+"CollectedAt", wusp.Time(station.CollectedAt))
		if err := appendHistoryField(msg, path, snap.StationHist[key]); err != nil {
			return fmt.Errorf("station %s history: %w", key, err)
		}
	}
	return nil
}

func appendLatencyFields(msg *wusp.Message, path string, l wifiLatency) {
	if !l.Known {
		return
	}
	appendField(msg, path+"LatencyAverage", wusp.Uint(uint64(l.Avg.Microseconds())))
	appendField(msg, path+"LatencyMinimum", wusp.Uint(uint64(l.Min.Microseconds())))
	appendField(msg, path+"LatencyMaximum", wusp.Uint(uint64(l.Max.Microseconds())))
	appendField(msg, path+"LatencyJitter", wusp.Uint(uint64(l.Jitter.Microseconds())))
	appendField(msg, path+"LatencySuccessCount", wusp.Uint(uint64(l.Success)))
	appendField(msg, path+"LatencyLostCount", wusp.Uint(uint64(l.Lost)))
}

func appendHistoryField(msg *wusp.Message, path string, history []wusp.WiFiHistorySample) error {
	if len(history) == 0 {
		return nil
	}
	block, err := wusp.EncodeWiFiHistoryBlock(history)
	if err != nil {
		return err
	}
	appendField(msg, path+"History", wusp.Bytes(block))
	return nil
}

// wifiRadioReferencesByInterface maps Device.WiFi.Radio names and SSID
// interface names to their Device.WiFi.Radio row, from the fields the WiFi
// collector already emitted in this message.
func wifiRadioReferencesByInterface(msg *wusp.Message) map[string]string {
	out := make(map[string]string)
	for name, index := range wifiRadioIndexByName(msg) {
		out[name] = fmt.Sprintf("Device.WiFi.Radio.%d.", index)
	}
	ssidName := make(map[int]string)
	ssidRadio := make(map[int]string)
	for _, field := range msg.Fields {
		var index int
		switch {
		case strings.HasSuffix(field.Path, ".Name"):
			if _, err := fmt.Sscanf(field.Path, "Device.WiFi.SSID.%d.Name", &index); err == nil {
				ssidName[index] = strings.TrimSpace(wusp.ValueToString(field.Val))
			}
		case strings.HasSuffix(field.Path, ".LowerLayers"):
			if _, err := fmt.Sscanf(field.Path, "Device.WiFi.SSID.%d.LowerLayers", &index); err == nil {
				value := strings.TrimSpace(wusp.ValueToString(field.Val))
				value = strings.Trim(strings.SplitN(value, ",", 2)[0], "[]\" ")
				if strings.HasPrefix(value, "Device.WiFi.Radio.") {
					ssidRadio[index] = value
				}
			}
		}
	}
	for index, name := range ssidName {
		if ref := ssidRadio[index]; name != "" && ref != "" {
			if _, exists := out[name]; !exists {
				out[name] = ref
			}
		}
	}
	return out
}

// discoverWiFiTelemetryVAPs lists the WiFi interfaces to sample: nl80211
// interfaces (mac80211, qcacld, cfg80211-mode qca-wifi) plus qca-wifi and
// MadWifi VAPs found through sysfs, which legacy builds hide from nl80211.
func discoverWiFiTelemetryVAPs(netClassDir string) []wifiTelemetryVAP {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	byName := make(map[string]wifiTelemetryVAP)
	if interfaces, err := iwinfo.RuntimeInterfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Mode == "monitor" || iface.Mode == "p2p-device" || strings.TrimSpace(iface.Name) == "" {
				continue
			}
			vap := wifiTelemetryVAP{
				Name:      iface.Name,
				Radio:     fmt.Sprintf("phy%d", iface.PHY),
				Mode:      iface.Mode,
				Frequency: iface.Frequency,
				Driver:    nl80211DriverFamily(netClassDir, iface.Name),
			}
			if vap.Driver == "qcacld" && hasQCARadioNetdevs(netClassDir) {
				// QSDK (qca-wifi) shares the "wlan" module name with qcacld;
				// its wifiN radio netdevs tell them apart.
				vap.Driver = "qca-wifi"
			}
			if parent := iwinfo.VendorRadioParent(netClassDir, iface.Name); parent != "" {
				vap.Radio, vap.Vendor, vap.Driver = parent, true, "qca-wifi"
			} else if isVendorWiFiVAP(netClassDir, iface.Name) {
				// QSDK cfg80211 mode: the VAP has a phy link but is still a
				// qca-wifi VAP whose nl80211 station dump stays empty.
				vap.Vendor, vap.Driver = true, "qca-wifi"
			}
			byName[iface.Name] = vap
		}
	}
	entries, _ := os.ReadDir(netClassDir)
	for _, entry := range entries {
		name := entry.Name()
		if _, exists := byName[name]; exists || strings.HasPrefix(name, "wifi") {
			continue
		}
		if !isVendorWiFiVAP(netClassDir, name) {
			continue
		}
		radio := iwinfo.VendorRadioParent(netClassDir, name)
		if radio == "" {
			radio = name
		}
		byName[name] = wifiTelemetryVAP{Name: name, Radio: radio, Mode: "ap", Vendor: true, Driver: "qca-wifi"}
	}
	out := make([]wifiTelemetryVAP, 0, len(byName))
	for _, vap := range byName {
		if !runtimeInterfaceIsUp(netClassDir, vap.Name) {
			continue
		}
		out = append(out, vap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func runtimeInterfaceIsUp(netClassDir, name string) bool {
	data, err := os.ReadFile(filepath.Join(netClassDir, name, "operstate"))
	if err != nil {
		iface, ifaceErr := net.InterfaceByName(name)
		return ifaceErr == nil && iface.Flags&net.FlagUp != 0
	}
	state := strings.TrimSpace(string(data))
	return state != "down" && state != "notpresent" && state != "lowerlayerdown"
}

func nl80211DriverFamily(netClassDir, ifname string) string {
	target, err := os.Readlink(filepath.Join(netClassDir, ifname, "device", "driver"))
	if err != nil {
		return "mac80211"
	}
	driver := strings.ToLower(filepath.Base(target))
	switch {
	case driver == "wlan" || strings.Contains(driver, "qcacld") || strings.Contains(driver, "cnss") || strings.Contains(driver, "icnss"):
		return "qcacld"
	case strings.Contains(driver, "qca_ol") || strings.Contains(driver, "ath_ol"):
		return "qca-wifi"
	}
	return "mac80211"
}

// collectWiFiTelemetryStations merges every station source available for vap.
func collectWiFiTelemetryStations(netClassDir string, vap wifiTelemetryVAP) []iwinfo.AssocEntry {
	var stations []iwinfo.AssocEntry
	if observed, err := iwinfo.GetHostapdAssocList(vap.Name); err == nil {
		for i := range observed {
			if observed[i].Source == "" {
				observed[i].Source = "hostapd"
			}
		}
		stations = mergeWiFiAssociations(stations, observed)
	}
	if observed, err := iwinfo.GetAssocList(vap.Name); err == nil {
		stations = mergeWiFiAssociations(stations, observed)
	}
	if vap.Vendor {
		if observed, err := vendorAssocList(vap.Name); err == nil {
			stations = mergeWiFiAssociations(stations, observed)
		}
	}
	stations = mergeWiFiAssociations(observedStations(vap.Name), stations)
	return enrichStationsPerMAC(vap.Name, stations)
}

func readWiFiIfaceCounters(netClassDir, ifname string) wifiIfaceCounters {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	base := filepath.Join(netClassDir, ifname, "statistics")
	read := func(name string) (uint64, bool) {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			return 0, false
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		return v, err == nil
	}
	var out wifiIfaceCounters
	var ok bool
	if out.RxBytes, ok = read("rx_bytes"); !ok {
		return wifiIfaceCounters{}
	}
	out.TxBytes, _ = read("tx_bytes")
	out.RxPackets, _ = read("rx_packets")
	out.TxPackets, _ = read("tx_packets")
	out.RxErrors, _ = read("rx_errors")
	out.TxErrors, _ = read("tx_errors")
	out.RxDropped, _ = read("rx_dropped")
	out.TxDropped, _ = read("tx_dropped")
	out.OK = true
	return out
}

// readIPv4Neighbors maps lower-case MAC addresses to IPv4 addresses from the
// kernel ARP table (complete or permanent entries only).
func readIPv4Neighbors() map[string]netip.Addr {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]netip.Addr{}
	}
	defer file.Close()
	return parseProcNetARP(bufio.NewScanner(file))
}

func parseProcNetARP(scanner *bufio.Scanner) map[string]netip.Addr {
	out := make(map[string]netip.Addr)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 && flags&0x4 == 0 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		mac, macErr := net.ParseMAC(fields[3])
		if err != nil || macErr != nil || !ip.Is4() || len(mac) != 6 {
			continue
		}
		out[strings.ToLower(mac.String())] = ip
	}
	return out
}

func hasQCARadioNetdevs(netClassDir string) bool {
	radios, _ := filepath.Glob(filepath.Join(netClassDir, "wifi[0-9]*"))
	return len(radios) > 0
}
