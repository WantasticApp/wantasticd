package platforms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/diaglog"
	"wantastic-agent/internal/qcaspectral"
	"wantastic-agent/internal/wusp"
)

const (
	spectralCaptureInterval   = 5 * time.Minute
	spectralCaptureWindow     = 1500 * time.Millisecond
	spectralCaptureDeadline   = 30 * time.Second
	spectralMaxCaptureSamples = 64
	spectralDiscoveryInterval = 30 * time.Minute
)

type spectralRadioSnapshot struct {
	Radio       qcaspectral.Radio
	Status      string
	Result      qcaspectral.Result
	LastError   string
	CollectedAt time.Time
}

type spectralSnapshot struct {
	Supported  bool
	Capturing  bool
	Discovered bool
	// NoRadioNetdev is true when discovery found no wifiN netdev at all, the
	// only case reported as Unsupported at the model root.
	NoRadioNetdev  bool
	DiscoveryError string
	LastCapture    time.Time
	Radios         []spectralRadioSnapshot
}

// spectralCoordinator runs captures in the background so a USP Get only ever
// reads the last completed result, mirroring wifiScanCoordinator.
type spectralCoordinator struct {
	mu           sync.Mutex
	supported    bool
	running      bool
	nextRun      time.Time
	discoveredAt time.Time
	discoveryErr error
	lastCapture  time.Time
	radios       []spectralRadioSnapshot
	now          func() time.Time
	discover     func(string) ([]qcaspectral.Radio, error)
	capture      func(context.Context, qcaspectral.Radio, qcaspectral.CaptureOptions) (qcaspectral.Result, error)
}

var defaultSpectralCoordinator = &spectralCoordinator{
	supported: qcaspectral.Supported,
	now:       time.Now,
	discover:  qcaspectral.DiscoverRadios,
	capture:   qcaspectral.Capture,
}

func (c *spectralCoordinator) snapshotAndTrigger(netClassDir string) spectralSnapshot {
	if c == nil || !c.supported {
		return spectralSnapshot{}
	}
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running && (c.nextRun.IsZero() || !now.Before(c.nextRun)) {
		c.running = true
		c.nextRun = now.Add(spectralCaptureInterval)
		rediscover := c.discoveredAt.IsZero() || now.Sub(c.discoveredAt) >= spectralDiscoveryInterval
		known := make([]qcaspectral.Radio, 0, len(c.radios))
		for _, radio := range c.radios {
			known = append(known, radio.Radio)
		}
		go c.run(netClassDir, rediscover, known)
	}
	out := spectralSnapshot{Supported: true, Capturing: c.running, Discovered: !c.discoveredAt.IsZero(), LastCapture: c.lastCapture}
	if c.discoveryErr != nil {
		out.DiscoveryError = c.discoveryErr.Error()
		out.NoRadioNetdev = errors.Is(c.discoveryErr, qcaspectral.ErrNoRadioNetdev)
	}
	out.Radios = append(out.Radios, c.radios...)
	return out
}

func (c *spectralCoordinator) run(netClassDir string, rediscover bool, radios []qcaspectral.Radio) {
	ctx, cancel := context.WithTimeout(context.Background(), spectralCaptureDeadline)
	defer cancel()

	if rediscover {
		discovered, err := c.discover(netClassDir)
		c.mu.Lock()
		c.discoveredAt = c.now().UTC()
		c.discoveryErr = err
		c.mu.Unlock()
		if err != nil {
			diaglog.Printf("[USP] spectral_discovery error=%q", err)
		}
		for _, radio := range discovered {
			diaglog.Printf("[USP] spectral_probe interface=%q spectral=%t control_path=%s vendor_target=%q ioctl_base=%d transport=%q error=%q",
				radio.Interface, radio.Caps.Spectral, radio.Caps.ControlPath, radio.Caps.VendorTarget, radio.Caps.IoctlBase, radio.Caps.DataTransport, radio.ProbeError)
		}
		radios = discovered
	}

	macs := make([]net.HardwareAddr, 0, len(radios))
	for _, radio := range radios {
		macs = append(macs, radio.MAC)
	}
	results := make([]spectralRadioSnapshot, 0, len(radios))
	for _, radio := range radios {
		if !radio.Caps.Spectral {
			results = append(results, spectralRadioSnapshot{
				Radio: radio, Status: "Unsupported", LastError: radio.ProbeError, CollectedAt: c.now().UTC(),
				Result: qcaspectral.Result{Layout: qcaspectral.LayoutUnknown},
			})
			continue
		}
		res, err := c.capture(ctx, radio, qcaspectral.CaptureOptions{
			Window:     spectralCaptureWindow,
			MaxSamples: spectralMaxCaptureSamples,
			KnownMACs:  macs,
			Now:        c.now,
		})
		snap := spectralRadioSnapshot{Radio: radio, Result: res, CollectedAt: c.now().UTC()}
		switch {
		case err != nil:
			snap.Status = "Error"
			snap.LastError = err.Error()
		case len(res.Samples) == 0:
			snap.Status = "NoSamples"
			snap.LastError = res.LastError
		default:
			snap.Status = "Ready"
			snap.LastError = res.LastError
		}
		diaglog.Printf("[USP] spectral_capture interface=%q status=%s samples=%d dropped=%d passive=%t layout=%s error=%q",
			radio.Interface, snap.Status, len(res.Samples), res.Dropped, res.Passive, res.Layout, snap.LastError)
		results = append(results, snap)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	c.radios = results
	if len(results) > 0 {
		c.lastCapture = c.now().UTC()
	}
}

// appendSpectralFields emits Device.WUSP_SpectralTelemetry. Non-Linux builds
// and hosts without any QCA radio netdev report Unsupported with no radio
// rows; every probed wifiN otherwise gets a row carrying its probe outcome.
func appendSpectralFields(msg *wusp.Message, netClassDir string) error {
	return appendSpectralSnapshotFields(msg, defaultSpectralCoordinator.snapshotAndTrigger(netClassDir))
}

func appendSpectralSnapshotFields(msg *wusp.Message, snap spectralSnapshot) error {
	prefix := wusp.WUSPSpectralTelemetryPrefix
	if !snap.Supported {
		appendField(msg, prefix+"Status", wusp.String("Unsupported"))
		appendField(msg, prefix+"Implementation", wusp.String("none"))
		appendField(msg, prefix+"RadioNumberOfEntries", wusp.Uint(0))
		return nil
	}
	appendField(msg, prefix+"Implementation", wusp.String("qca.native"))
	// Always emitted so a cleared error replaces the stored one.
	appendField(msg, prefix+"DiscoveryError", wusp.String(truncateSpectralError(snap.DiscoveryError)))
	appendField(msg, prefix+"CaptureIntervalSeconds", wusp.Uint(uint64(spectralCaptureInterval/time.Second)))
	if !snap.LastCapture.IsZero() {
		appendField(msg, prefix+"LastCaptureTime", wusp.Time(snap.LastCapture))
	}
	appendField(msg, prefix+"Status", wusp.String(spectralRootStatus(snap)))
	appendField(msg, prefix+"RadioNumberOfEntries", wusp.Uint(uint64(len(snap.Radios))))

	radioIndexByName := wifiRadioIndexByName(msg)
	for i, radio := range snap.Radios {
		path := fmt.Sprintf("%sRadio.%d.", prefix, i+1)
		res := radio.Result
		appendField(msg, path+"Alias", wusp.String("cpe-spectral-"+radio.Radio.Interface))
		if index, ok := radioIndexByName[radio.Radio.Interface]; ok {
			appendField(msg, path+"RadioReference", wusp.String(fmt.Sprintf("Device.WiFi.Radio.%d.", index)))
		}
		appendField(msg, path+"Interface", wusp.String(radio.Radio.Interface))
		if validRuntimeMAC(radio.Radio.MAC) {
			appendField(msg, path+"MACAddress", wusp.MAC(radio.Radio.MAC))
		}
		appendField(msg, path+"Status", wusp.String(radio.Status))
		controlPath := radio.Radio.Caps.ControlPath
		if controlPath == "" {
			controlPath = qcaspectral.ControlPathNone
		}
		appendField(msg, path+"ControlPath", wusp.String(controlPath))
		transport := radio.Radio.Caps.DataTransport
		if transport != qcaspectral.TransportNetlink && transport != qcaspectral.TransportRelay {
			transport = "unknown"
		}
		appendField(msg, path+"DataTransport", wusp.String(transport))
		appendField(msg, path+"AdvancedSpectral", wusp.Bool(radio.Radio.Caps.Advanced))
		appendField(msg, path+"SampleLayout", wusp.String(string(res.Layout)))
		appendField(msg, path+"Passive", wusp.Bool(res.Passive))
		appendField(msg, path+"SampleCount", wusp.Uint(uint64(len(res.Samples))))
		appendField(msg, path+"DroppedSamples", wusp.Uint(uint64(res.Dropped)))
		if !res.Started.IsZero() && !res.Completed.IsZero() {
			appendField(msg, path+"CaptureDuration", wusp.Uint(uint64(res.Completed.Sub(res.Started)/time.Millisecond)))
		}
		appendField(msg, path+"CollectedAt", wusp.Time(radio.CollectedAt))
		appendField(msg, path+"LastError", wusp.String(truncateSpectralError(radio.LastError)))
		if len(res.Samples) == 0 {
			continue
		}
		summary := summarizeSpectralSamples(res.Samples)
		appendField(msg, path+"OperatingFrequency", wusp.Uint(uint64(summary.frequency)))
		appendField(msg, path+"CenterFrequency1", wusp.Uint(uint64(summary.centerFrequency1)))
		appendField(msg, path+"CenterFrequency2", wusp.Uint(uint64(summary.centerFrequency2)))
		appendField(msg, path+"ChannelWidth", wusp.Uint(uint64(summary.channelWidth)))
		appendField(msg, path+"BinCount", wusp.Uint(uint64(len(summary.binMax))))
		appendField(msg, path+"NoiseFloor", wusp.Int(int64(summary.noiseFloor)))
		appendField(msg, path+"RSSI", wusp.Int(int64(summary.rssi)))
		appendField(msg, path+"BinMax", wusp.Bytes(summary.binMax))
		appendField(msg, path+"BinAverage", wusp.Bytes(summary.binAverage))
		block, err := wusp.EncodeSpectralSampleBlock(summary.recent)
		if err != nil {
			return fmt.Errorf("encode spectral samples for %s: %w", radio.Radio.Interface, err)
		}
		appendField(msg, path+"SampleBlock", wusp.Bytes(block))
	}
	return nil
}

func spectralRootStatus(snap spectralSnapshot) string {
	if snap.Capturing {
		return "Capturing"
	}
	if len(snap.Radios) == 0 {
		switch {
		case snap.NoRadioNetdev:
			return "Unsupported"
		case snap.DiscoveryError != "":
			return "Error"
		default:
			return "Idle"
		}
	}
	status := "Idle"
	for _, radio := range snap.Radios {
		switch radio.Status {
		case "Ready":
			return "Ready"
		case "Error", "Unsupported":
			status = "Error"
		}
	}
	return status
}

// wifiRadioIndexByName maps Device.WiFi.Radio.N.Name values already emitted
// by the WiFi collector, so the spectral row references the same instance
// without re-reading UCI or ubus.
func wifiRadioIndexByName(msg *wusp.Message) map[string]int {
	out := make(map[string]int)
	for _, field := range msg.Fields {
		var index int
		if _, err := fmt.Sscanf(field.Path, "Device.WiFi.Radio.%d.Name", &index); err != nil || !strings.HasSuffix(field.Path, ".Name") {
			continue
		}
		if name := strings.TrimSpace(wusp.ValueToString(field.Val)); name != "" {
			out[name] = index
		}
	}
	return out
}

type spectralSummary struct {
	frequency, centerFrequency1, centerFrequency2, channelWidth uint32
	noiseFloor, rssi                                            int16
	binMax, binAverage                                          []byte
	recent                                                      []wusp.SpectralSample
}

func summarizeSpectralSamples(samples []qcaspectral.Sample) spectralSummary {
	last := samples[len(samples)-1]
	bins := len(samples[0].Bins)
	summary := spectralSummary{
		frequency:        last.Frequency,
		centerFrequency1: last.CenterFrequency1,
		centerFrequency2: last.CenterFrequency2,
		channelWidth:     last.ChannelWidth,
		binMax:           make([]byte, bins),
		binAverage:       make([]byte, bins),
	}
	sums := make([]uint32, bins)
	noise := make([]int, 0, len(samples))
	rssiSum := 0
	for _, sample := range samples {
		for j, b := range sample.Bins {
			sums[j] += uint32(b)
			if b > summary.binMax[j] {
				summary.binMax[j] = b
			}
		}
		noise = append(noise, int(sample.NoiseFloor))
		rssiSum += int(sample.RSSI)
	}
	n := uint32(len(samples))
	for j, sum := range sums {
		summary.binAverage[j] = byte((sum + n/2) / n)
	}
	sort.Ints(noise)
	summary.noiseFloor = int16(noise[len(noise)/2])
	summary.rssi = int16(rssiSum / len(samples))

	start := len(samples) - wusp.SpectralMaxSamplesPerBlock
	if start < 0 {
		start = 0
	}
	for _, sample := range samples[start:] {
		summary.recent = append(summary.recent, wusp.SpectralSample{
			TimestampMicros: sample.TimestampMicros,
			RSSI:            sample.RSSI,
			NoiseFloor:      sample.NoiseFloor,
			MaxIndex:        sample.MaxIndex,
			Bins:            sample.Bins,
		})
	}
	return summary
}

func truncateSpectralError(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}
