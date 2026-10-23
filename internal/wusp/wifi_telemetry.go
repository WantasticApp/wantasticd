package wusp

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const WUSPWiFiTelemetryPrefix = "Device.WUSP_WiFiTelemetry."

// WiFi telemetry bounds shared by the agent sampler and the controller merge.
const (
	// WiFiHistoryDepth is the number of timestamped samples kept per radio
	// and per station, by the agent and again by the controller.
	WiFiHistoryDepth = 30
	// WiFiTelemetryMaxStations caps station rows per device so a busy AP
	// cannot grow one snapshot without bound.
	WiFiTelemetryMaxStations = 128
	WiFiTelemetryMaxRadios   = 16

	wifiHistoryMaxSeries   = 16
	wifiHistoryMaxBlockLen = 4096
	// A decoded block can never exceed this, which bounds inflate output.
	wifiHistoryMaxPlainLen = 2 + wifiHistoryMaxSeries + WiFiHistoryDepth*binary.MaxVarintLen64*(1+wifiHistoryMaxSeries) + wifiHistoryMaxSeries*((WiFiHistoryDepth+7)/8) + 2*binary.MaxVarintLen64
)

// WiFi history metric identifiers. IDs are part of the wire format and must
// never be reused.
const (
	WiFiMetricSignal             uint8 = 1  // dBm
	WiFiMetricNoise              uint8 = 2  // dBm
	WiFiMetricTxRate             uint8 = 3  // kbit/s PHY rate AP→station
	WiFiMetricRxRate             uint8 = 4  // kbit/s PHY rate station→AP
	WiFiMetricDownlink           uint8 = 5  // kbit/s measured goodput AP→station(s)
	WiFiMetricUplink             uint8 = 6  // kbit/s measured goodput station(s)→AP
	WiFiMetricExpectedThroughput uint8 = 7  // kbit/s driver estimate
	WiFiMetricLatencyAvg         uint8 = 8  // µs ICMP round trip
	WiFiMetricLatencyLoss        uint8 = 9  // per mille of probes lost
	WiFiMetricLatencyJitter      uint8 = 10 // µs mean absolute RTT variation
	WiFiMetricStationCount       uint8 = 11 // associated stations
	WiFiMetricChannelUtilization uint8 = 12 // percent busy airtime
	WiFiMetricDistance           uint8 = 13 // metres
	WiFiMetricTxRetries          uint8 = 14 // retries during the interval
	WiFiMetricLatencyMax         uint8 = 15 // µs
)

var WUSPWiFiTelemetryObjects = []Object{
	{Path: WUSPWiFiTelemetryPrefix, SinceVersion: "1.0", Description: "Agent-owned WiFi radio and station telemetry with a rolling history, collected natively (nl80211, QCA/MadWifi driver ioctls, hostapd) plus ICMP latency probes to associated stations."},
	{Path: WUSPWiFiTelemetryPrefix + "Radio.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Counters, channel load, configured link distance, aggregate throughput and latency for one radio."},
	{Path: WUSPWiFiTelemetryPrefix + "Station.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Signal, rates, measured throughput, estimated distance and latency for one associated station."},
}

func wifiTelemetryParam(path string, typ ParamType, description string, limits Limits) Param {
	return Param{Path: WUSPWiFiTelemetryPrefix + path, Type: typ, Access: ReadOnly, SinceVersion: "1.0", Description: description, Limits: limits}
}

var wifiTelemetryLatencyParams = func(object string) []Param {
	return []Param{
		wifiTelemetryParam(object+"LatencyAverage", TypeUnsignedInt, "Mean ICMP echo round trip of the last probe round in microseconds; 0 when no reply was received.", Limits{Min: iptr(0)}),
		wifiTelemetryParam(object+"LatencyMinimum", TypeUnsignedInt, "Minimum ICMP echo round trip of the last probe round in microseconds.", Limits{Min: iptr(0)}),
		wifiTelemetryParam(object+"LatencyMaximum", TypeUnsignedInt, "Maximum ICMP echo round trip of the last probe round in microseconds.", Limits{Min: iptr(0)}),
		wifiTelemetryParam(object+"LatencyJitter", TypeUnsignedInt, "Mean absolute difference between consecutive round trips in microseconds.", Limits{Min: iptr(0)}),
		wifiTelemetryParam(object+"LatencySuccessCount", TypeUnsignedInt, "Echo replies received in the last probe round.", Limits{Min: iptr(0)}),
		wifiTelemetryParam(object+"LatencyLostCount", TypeUnsignedInt, "Echo requests without a reply in the last probe round.", Limits{Min: iptr(0)}),
	}
}

var AllWUSPWiFiTelemetryParams = concat(
	[]Param{
		wifiTelemetryParam("Status", TypeString, "Sampler state. Unsupported means the platform has no WiFi interface the agent can read.", Limits{Enums: []string{"Unsupported", "Idle", "Collecting", "Ready", "Error"}}),
		wifiTelemetryParam("LastError", TypeString, "Last sampler error, empty after a clean sample.", Limits{MaxLength: 256}),
		wifiTelemetryParam("SampleIntervalSeconds", TypeUnsignedInt, "Interval between telemetry samples.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("HistoryDepth", TypeUnsignedInt, "Maximum number of samples carried in each History block.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("LastSampleTime", TypeDateTime, "Time the most recent sample completed.", Limits{}),
		wifiTelemetryParam("LatencyMethod", TypeString, "How station latency is measured: ICMP echo from the agent over the WiFi link, or none when raw ICMP is unavailable.", Limits{Enums: []string{"icmp", "none"}}),
		wifiTelemetryParam("RadioNumberOfEntries", TypeUnsignedInt, "Number of entries in Device.WUSP_WiFiTelemetry.Radio.{i}.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("StationNumberOfEntries", TypeUnsignedInt, "Number of entries in Device.WUSP_WiFiTelemetry.Station.{i}.", Limits{Min: iptr(0)}),

		wifiTelemetryParam("Radio.{i}.Alias", TypeAlias, "Stable alias derived from the radio interface.", Limits{MaxLength: 64}),
		wifiTelemetryParam("Radio.{i}.Interface", TypeString, "Radio netdev (wifiN) or nl80211 phy name.", Limits{MaxLength: 16}),
		wifiTelemetryParam("Radio.{i}.RadioReference", TypePathRef, "Matching Device.WiFi.Radio row when it can be resolved.", Limits{}),
		wifiTelemetryParam("Radio.{i}.Driver", TypeString, "Driver family the samples were read from.", Limits{Enums: []string{"mac80211", "qca-wifi", "madwifi", "qcacld", "unknown"}}),
		wifiTelemetryParam("Radio.{i}.OperatingFrequency", TypeUnsignedInt, "Operating frequency in MHz, 0 when unknown.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.Channel", TypeUnsignedInt, "Operating channel, 0 when unknown.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.ChannelWidth", TypeUnsignedInt, "Operating channel width in MHz, 0 when unknown.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.CenterFrequency", TypeUnsignedInt, "Center frequency of the whole operating channel in MHz (nl80211 center_freq1), 0 when the driver does not report it.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.Noise", TypeInt, "Noise floor in dBm, 0 when unknown.", Limits{}),
		wifiTelemetryParam("Radio.{i}.TransmitPower", TypeInt, "Current transmit power in dBm, 0 when unknown.", Limits{}),
		wifiTelemetryParam("Radio.{i}.ChannelUtilization", TypeUnsignedInt, "Percentage of airtime the channel was busy during the last interval (nl80211 survey).", Limits{Min: iptr(0), Max: iptr(100)}),
		wifiTelemetryParam("Radio.{i}.ConfiguredDistance", TypeUnsignedInt, "One-way link distance in metres the radio ACK/slot timing is configured for; 0 when the driver uses default timing.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.DistanceSource", TypeString, "Where ConfiguredDistance came from: nl80211 coverage class (450 m per class), the driver distance sysctl, or the slot time (300 m per µs above 9 µs).", Limits{Enums: []string{"coverage-class", "driver-distance", "slottime", "none"}}),
		wifiTelemetryParam("Radio.{i}.StationCount", TypeUnsignedInt, "Associated stations across the radio's access points.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.BytesSent", TypeUnsignedLong, "Bytes sent on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.BytesReceived", TypeUnsignedLong, "Bytes received on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.PacketsSent", TypeUnsignedLong, "Packets sent on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.PacketsReceived", TypeUnsignedLong, "Packets received on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.ErrorsSent", TypeUnsignedLong, "Transmit errors on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.ErrorsReceived", TypeUnsignedLong, "Receive errors on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.DiscardPacketsSent", TypeUnsignedLong, "Transmit drops on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.DiscardPacketsReceived", TypeUnsignedLong, "Receive drops on the radio's interfaces.", Limits{}),
		wifiTelemetryParam("Radio.{i}.DownlinkThroughput", TypeUnsignedInt, "Measured transmit goodput over the last interval in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.UplinkThroughput", TypeUnsignedInt, "Measured receive goodput over the last interval in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Radio.{i}.CollectedAt", TypeDateTime, "Time this row was sampled.", Limits{}),
		wifiTelemetryParam("Radio.{i}.History", TypeHexBinary, "Rolling history in the WUSP WiFi history block v1 encoding (see EncodeWiFiHistoryBlock).", Limits{MaxLength: wifiHistoryMaxBlockLen}),
	},
	wifiTelemetryLatencyParams("Radio.{i}."),
	[]Param{
		wifiTelemetryParam("Station.{i}.Alias", TypeAlias, "Stable alias derived from the station MAC address.", Limits{MaxLength: 64}),
		wifiTelemetryParam("Station.{i}.MACAddress", TypeMACAddress, "Station MAC address.", Limits{}),
		wifiTelemetryParam("Station.{i}.IPAddress", TypeString, "IPv4 address learned from the neighbour table, used for latency probes.", Limits{MaxLength: 45}),
		wifiTelemetryParam("Station.{i}.Interface", TypeString, "Access point interface the station is associated with.", Limits{MaxLength: 16}),
		wifiTelemetryParam("Station.{i}.Radio", TypePathRef, "Device.WUSP_WiFiTelemetry.Radio row of the serving radio.", Limits{}),
		wifiTelemetryParam("Station.{i}.Source", TypeString, "Collectors that reported the station, joined with '+'.", Limits{MaxLength: 64}),
		wifiTelemetryParam("Station.{i}.SignalStrength", TypeInt, "Received signal strength in dBm, 0 when unknown.", Limits{}),
		wifiTelemetryParam("Station.{i}.Noise", TypeInt, "Noise floor in dBm used for SNR, 0 when unknown.", Limits{}),
		wifiTelemetryParam("Station.{i}.SNR", TypeInt, "Signal to noise ratio in dB, 0 when unknown.", Limits{}),
		wifiTelemetryParam("Station.{i}.TxRate", TypeUnsignedInt, "Last PHY rate towards the station in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.RxRate", TypeUnsignedInt, "Last PHY rate from the station in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.ExpectedThroughput", TypeUnsignedInt, "Driver rate-control estimate of achievable goodput in kbit/s, 0 when not reported.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.DownlinkThroughput", TypeUnsignedInt, "Measured goodput towards the station over the last interval in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.UplinkThroughput", TypeUnsignedInt, "Measured goodput from the station over the last interval in kbit/s.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.BytesSent", TypeUnsignedLong, "Bytes sent to the station.", Limits{}),
		wifiTelemetryParam("Station.{i}.BytesReceived", TypeUnsignedLong, "Bytes received from the station.", Limits{}),
		wifiTelemetryParam("Station.{i}.Retransmissions", TypeUnsignedInt, "Frame retries towards the station.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.ConnectedTime", TypeUnsignedInt, "Seconds since association.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.InactiveTime", TypeUnsignedInt, "Milliseconds since the station was last active.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.EstimatedDistance", TypeUnsignedInt, "Free-space path loss estimate of the station distance in metres from transmit power, received signal and frequency; 0 when inputs are missing. Indicative only: walls, antenna gain and client power bias it.", Limits{Min: iptr(0)}),
		wifiTelemetryParam("Station.{i}.DistanceMethod", TypeString, "Method used for EstimatedDistance.", Limits{Enums: []string{"fspl", "none"}}),
		wifiTelemetryParam("Station.{i}.CollectedAt", TypeDateTime, "Time this row was sampled.", Limits{}),
		wifiTelemetryParam("Station.{i}.History", TypeHexBinary, "Rolling history in the WUSP WiFi history block v1 encoding (see EncodeWiFiHistoryBlock).", Limits{MaxLength: wifiHistoryMaxBlockLen}),
	},
	wifiTelemetryLatencyParams("Station.{i}."),
)

// WiFiHistorySample is one timestamped telemetry sample keyed by metric ID;
// a metric absent from Values was not measured in that sample.
type WiFiHistorySample struct {
	Time   time.Time
	Values map[uint8]int64
}

// WiFi history block v1:
//
//	[0] 'W' [1] 'H' [2] version=1 [3] flags (bit0: payload is raw DEFLATE)
//	payload:
//	  uvarint sample_count (<= WiFiHistoryDepth), uvarint series_count (<= 16)
//	  series_count metric ids (1 byte each, strictly increasing)
//	  uvarint first unix second, then uvarint deltas to each later sample
//	  per series: presence bitmap (ceil(sample_count/8) bytes, LSB first),
//	  then one zigzag varint per present sample: the delta from the previous
//	  present value of that series (the first is relative to 0)
//
// Neighbouring samples of one metric change slowly, so most deltas encode in
// one byte; DEFLATE is applied only when it makes the block smaller.
const (
	wifiHistoryMagic0   = 'W'
	wifiHistoryMagic1   = 'H'
	wifiHistoryVersion  = 1
	wifiHistoryDeflated = 1 << 0
)

var ErrWiFiHistoryMalformed = errors.New("wusp: malformed WiFi history block")

// EncodeWiFiHistoryBlock encodes up to WiFiHistoryDepth samples, newest last.
// Older samples beyond the depth are dropped.
func EncodeWiFiHistoryBlock(samples []WiFiHistorySample) ([]byte, error) {
	samples = normaliseWiFiHistory(samples, WiFiHistoryDepth)
	if len(samples) == 0 {
		return nil, nil
	}
	seriesSet := make(map[uint8]bool)
	for _, sample := range samples {
		for id := range sample.Values {
			if id != 0 {
				seriesSet[id] = true
			}
		}
	}
	series := make([]uint8, 0, len(seriesSet))
	for id := range seriesSet {
		series = append(series, id)
	}
	sort.Slice(series, func(i, j int) bool { return series[i] < series[j] })
	if len(series) > wifiHistoryMaxSeries {
		return nil, fmt.Errorf("wusp: WiFi history holds at most %d series, got %d", wifiHistoryMaxSeries, len(series))
	}

	plain := make([]byte, 0, 64+len(samples)*len(series)*2)
	plain = binary.AppendUvarint(plain, uint64(len(samples)))
	plain = binary.AppendUvarint(plain, uint64(len(series)))
	plain = append(plain, series...)
	for i, sample := range samples {
		ts := sample.Time.Unix()
		if ts < 0 {
			return nil, fmt.Errorf("wusp: WiFi history timestamp before epoch")
		}
		if i == 0 {
			plain = binary.AppendUvarint(plain, uint64(ts))
			continue
		}
		plain = binary.AppendUvarint(plain, uint64(ts-samples[i-1].Time.Unix()))
	}
	bitmapLen := (len(samples) + 7) / 8
	for _, id := range series {
		bitmap := make([]byte, bitmapLen)
		for i, sample := range samples {
			if _, ok := sample.Values[id]; ok {
				bitmap[i/8] |= 1 << (i % 8)
			}
		}
		plain = append(plain, bitmap...)
		prev := int64(0)
		for _, sample := range samples {
			v, ok := sample.Values[id]
			if !ok {
				continue
			}
			plain = binary.AppendVarint(plain, v-prev)
			prev = v
		}
	}

	out := []byte{wifiHistoryMagic0, wifiHistoryMagic1, wifiHistoryVersion, 0}
	var compressed bytes.Buffer
	if w, err := flate.NewWriter(&compressed, flate.BestCompression); err == nil {
		if _, err := w.Write(plain); err == nil && w.Close() == nil && compressed.Len() < len(plain) {
			out[3] |= wifiHistoryDeflated
			out = append(out, compressed.Bytes()...)
			return checkWiFiHistoryLen(out)
		}
	}
	return checkWiFiHistoryLen(append(out, plain...))
}

func checkWiFiHistoryLen(block []byte) ([]byte, error) {
	if len(block) > wifiHistoryMaxBlockLen {
		return nil, fmt.Errorf("wusp: WiFi history block of %d bytes exceeds %d", len(block), wifiHistoryMaxBlockLen)
	}
	return block, nil
}

// DecodeWiFiHistoryBlock is the inverse of EncodeWiFiHistoryBlock. It is safe
// on hostile input: counts, timestamps and inflated size are all bounded.
func DecodeWiFiHistoryBlock(data []byte) ([]WiFiHistorySample, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 4 || len(data) > wifiHistoryMaxBlockLen || data[0] != wifiHistoryMagic0 || data[1] != wifiHistoryMagic1 {
		return nil, ErrWiFiHistoryMalformed
	}
	if data[2] != wifiHistoryVersion {
		return nil, fmt.Errorf("wusp: unsupported WiFi history version %d", data[2])
	}
	r := data[4:]
	if data[3]&wifiHistoryDeflated != 0 {
		inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(r)), wifiHistoryMaxPlainLen+1))
		if err != nil || len(inflated) > wifiHistoryMaxPlainLen {
			return nil, ErrWiFiHistoryMalformed
		}
		r = inflated
	}
	next := func() (uint64, error) {
		v, n := binary.Uvarint(r)
		if n <= 0 {
			return 0, ErrWiFiHistoryMalformed
		}
		r = r[n:]
		return v, nil
	}
	count, err := next()
	if err != nil {
		return nil, err
	}
	seriesCount, err := next()
	if err != nil {
		return nil, err
	}
	if count == 0 || count > WiFiHistoryDepth || seriesCount > wifiHistoryMaxSeries || uint64(len(r)) < seriesCount {
		return nil, ErrWiFiHistoryMalformed
	}
	series := append([]byte(nil), r[:seriesCount]...)
	r = r[seriesCount:]
	for i, id := range series {
		if id == 0 || (i > 0 && id <= series[i-1]) {
			return nil, ErrWiFiHistoryMalformed
		}
	}
	samples := make([]WiFiHistorySample, count)
	var ts uint64
	for i := range samples {
		v, err := next()
		if err != nil {
			return nil, err
		}
		if i == 0 {
			ts = v
		} else {
			ts += v
		}
		// Reject anything outside 2000-01-01 .. 2200-01-01.
		if ts < 946684800 || ts > 7258118400 {
			return nil, ErrWiFiHistoryMalformed
		}
		samples[i] = WiFiHistorySample{Time: time.Unix(int64(ts), 0).UTC(), Values: make(map[uint8]int64, len(series))}
	}
	bitmapLen := int((count + 7) / 8)
	for _, id := range series {
		if len(r) < bitmapLen {
			return nil, ErrWiFiHistoryMalformed
		}
		bitmap := r[:bitmapLen]
		r = r[bitmapLen:]
		prev := int64(0)
		for i := range samples {
			if bitmap[i/8]&(1<<(i%8)) == 0 {
				continue
			}
			delta, n := binary.Varint(r)
			if n <= 0 {
				return nil, ErrWiFiHistoryMalformed
			}
			r = r[n:]
			prev += delta
			samples[i].Values[id] = prev
		}
	}
	if len(r) != 0 {
		return nil, ErrWiFiHistoryMalformed
	}
	return samples, nil
}

// MergeWiFiHistory unions two histories by sample second (incoming wins),
// keeping the newest depth samples in time order. The controller uses it to
// keep history across agent restarts.
func MergeWiFiHistory(previous, incoming []WiFiHistorySample, depth int) []WiFiHistorySample {
	return normaliseWiFiHistory(append(append([]WiFiHistorySample(nil), previous...), incoming...), depth)
}

func normaliseWiFiHistory(samples []WiFiHistorySample, depth int) []WiFiHistorySample {
	if depth <= 0 {
		depth = WiFiHistoryDepth
	}
	bySecond := make(map[int64]WiFiHistorySample, len(samples))
	for _, sample := range samples {
		if sample.Time.IsZero() || sample.Time.Unix() < 0 {
			continue
		}
		bySecond[sample.Time.Unix()] = sample
	}
	out := make([]WiFiHistorySample, 0, len(bySecond))
	for _, sample := range bySecond {
		out = append(out, sample)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	if len(out) > depth {
		out = out[len(out)-depth:]
	}
	return out
}
