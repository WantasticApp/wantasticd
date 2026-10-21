package wusp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const WUSPSpectralTelemetryPrefix = "Device.WUSP_SpectralTelemetry."

// Bounds shared by the agent collector and the controller decoder. The sample
// block is sized so one radio's block plus its aggregates stays within a few
// fragmented WUSP datagrams after the nested-message LZ4 pass.
const (
	SpectralMaxBins            = 2048
	SpectralMaxSamplesPerBlock = 16
	spectralMaxBlockLength     = 4 + 2*binary.MaxVarintLen64 + SpectralMaxSamplesPerBlock*(4*binary.MaxVarintLen64+SpectralMaxBins)
)

var WUSPSpectralTelemetryObjects = []Object{
	{Path: WUSPSpectralTelemetryPrefix, SinceVersion: "1.0", Description: "Agent-owned RF spectral scan telemetry collected natively from QCA/QSDK radios."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Spectral capture summary and recent FFT samples for one WiFi radio."},
}

var AllWUSPSpectralTelemetryParams = []Param{
	{Path: WUSPSpectralTelemetryPrefix + "Status", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Agent spectral scheduler state. Unsupported means the binary or device has no native QCA spectral support; reading telemetry never blocks on RF capture.", Limits: Limits{Enums: []string{"Unsupported", "Idle", "Capturing", "Ready", "Error"}}},
	{Path: WUSPSpectralTelemetryPrefix + "Implementation", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Native spectral backend used by the agent.", Limits: Limits{Enums: []string{"qca.athdiag-netlink", "none"}}},
	{Path: WUSPSpectralTelemetryPrefix + "CaptureIntervalSeconds", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Minimum interval between agent-owned spectral captures on one radio.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "LastCaptureTime", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Time the most recent spectral capture on any radio completed."},
	{Path: WUSPSpectralTelemetryPrefix + "RadioNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of entries in Device.WUSP_SpectralTelemetry.Radio.{i}.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.Alias", Type: TypeAlias, Access: ReadOnly, SinceVersion: "1.0", Description: "Stable alias for this spectral radio row, derived from the driver radio interface.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.RadioReference", Type: TypePathRef, Access: ReadOnly, SinceVersion: "1.0", Description: "Reference to the matching Device.WiFi.Radio row when the agent can resolve it."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.Interface", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Driver radio netdev used for spectral control, for example wifi0.", Limits: Limits{MaxLength: 16}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.MACAddress", Type: TypeMACAddress, Access: ReadOnly, SinceVersion: "1.0", Description: "Radio MAC address used to attribute driver spectral samples to this radio."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.Status", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Result of the most recent capture on this radio.", Limits: Limits{Enums: []string{"Pending", "Ready", "NoSamples", "Unsupported", "Error"}}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.AdvancedSpectral", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "Driver reports advanced (11ac and later) spectral capability."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.SampleLayout", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Driver sample message layout detected for this radio.", Limits: Limits{Enums: []string{"qca-legacy", "qca-cmn", "qca-cmn-optimized", "unknown"}}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.Passive", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "True when another consumer already had spectral scan active, so the agent only listened and did not start or stop the scan."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.OperatingFrequency", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Primary 20 MHz channel frequency of the captured samples in MHz.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.CenterFrequency1", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Center frequency of the first segment in MHz when the driver reports it, otherwise 0.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.CenterFrequency2", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Center frequency of the second 80 MHz segment in MHz when the driver reports it, otherwise 0.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.ChannelWidth", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Channel width covered by the samples in MHz when the driver reports it, otherwise 0.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.BinCount", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of FFT bins per sample.", Limits: Limits{Min: iptr(0), Max: iptr(SpectralMaxBins)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.NoiseFloor", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Median driver noise floor across captured samples in dBm."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.RSSI", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Mean spectral RSSI across captured samples as reported by the driver."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.SampleCount", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of samples aggregated into BinMax and BinAverage during the last capture.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.DroppedSamples", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Samples attributed to this radio but rejected during the last capture because of an unknown layout or inconsistent bin count.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.CaptureDuration", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Wall-clock duration of the last capture in milliseconds.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.CollectedAt", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Time the last capture on this radio completed."},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.LastError", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Last capture or decode error for this radio, empty when the last capture succeeded.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.BinMax", Type: TypeHexBinary, Access: ReadOnly, SinceVersion: "1.0", Description: "Per-bin maximum of the driver bin power over the last capture, one byte per bin in driver units.", Limits: Limits{MaxLength: SpectralMaxBins}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.BinAverage", Type: TypeHexBinary, Access: ReadOnly, SinceVersion: "1.0", Description: "Per-bin rounded mean of the driver bin power over the last capture, one byte per bin in driver units.", Limits: Limits{MaxLength: SpectralMaxBins}},
	{Path: WUSPSpectralTelemetryPrefix + "Radio.{i}.SampleBlock", Type: TypeHexBinary, Access: ReadOnly, SinceVersion: "1.0", Description: "Most recent raw FFT samples in the WUSP spectral sample block v1 encoding (see EncodeSpectralSampleBlock).", Limits: Limits{MaxLength: spectralMaxBlockLength}},
}

// SpectralSample is one driver FFT report normalised across QCA layouts.
type SpectralSample struct {
	// TimestampMicros is the driver TSF-derived timestamp in microseconds.
	// It wraps at 2^32; the block encoder stores wrap-aware deltas.
	TimestampMicros uint32
	RSSI            int16
	NoiseFloor      int16
	MaxIndex        uint16
	Bins            []byte
}

// Spectral sample block v1:
//
//	[0] 'S' [1] 'B' [2] version=1 [3] flags (bit0: bins delta-coded)
//	uvarint bin_count, uvarint sample_count
//	per sample:
//	  uvarint timestamp (first: absolute; then uint32 wrap-aware delta)
//	  zigzag rssi, zigzag noise_floor, uvarint max_index
//	  bin_count bytes: raw for the first sample; with bit0 set, later samples
//	  carry (bin - previous_bin) mod 256
//
// Adjacent FFT sweeps are highly correlated, so the byte delta turns most bins
// into zeros or small values that the nested-message LZ4 pass compresses well.
// The transform is lossless.
const (
	spectralBlockMagic0  = 'S'
	spectralBlockMagic1  = 'B'
	spectralBlockVersion = 1
	spectralBlockDelta   = 1 << 0
)

var ErrSpectralBlockMalformed = errors.New("wusp: malformed spectral sample block")

// EncodeSpectralSampleBlock encodes samples that share one bin count.
func EncodeSpectralSampleBlock(samples []SpectralSample) ([]byte, error) {
	if len(samples) == 0 {
		return nil, nil
	}
	if len(samples) > SpectralMaxSamplesPerBlock {
		return nil, fmt.Errorf("wusp: spectral block holds at most %d samples, got %d", SpectralMaxSamplesPerBlock, len(samples))
	}
	binCount := len(samples[0].Bins)
	if binCount == 0 || binCount > SpectralMaxBins {
		return nil, fmt.Errorf("wusp: spectral bin count %d out of range", binCount)
	}
	out := make([]byte, 0, 4+len(samples)*(binCount+12))
	out = append(out, spectralBlockMagic0, spectralBlockMagic1, spectralBlockVersion, spectralBlockDelta)
	out = binary.AppendUvarint(out, uint64(binCount))
	out = binary.AppendUvarint(out, uint64(len(samples)))
	for i, sample := range samples {
		if len(sample.Bins) != binCount {
			return nil, fmt.Errorf("wusp: spectral sample %d has %d bins, want %d", i, len(sample.Bins), binCount)
		}
		ts := uint64(sample.TimestampMicros)
		if i > 0 {
			ts = uint64(sample.TimestampMicros - samples[i-1].TimestampMicros)
		}
		out = binary.AppendUvarint(out, ts)
		out = binary.AppendVarint(out, int64(sample.RSSI))
		out = binary.AppendVarint(out, int64(sample.NoiseFloor))
		out = binary.AppendUvarint(out, uint64(sample.MaxIndex))
		if i == 0 {
			out = append(out, sample.Bins...)
			continue
		}
		prev := samples[i-1].Bins
		for j, b := range sample.Bins {
			out = append(out, b-prev[j])
		}
	}
	return out, nil
}

// DecodeSpectralSampleBlock is the inverse of EncodeSpectralSampleBlock.
func DecodeSpectralSampleBlock(data []byte) ([]SpectralSample, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 4 || data[0] != spectralBlockMagic0 || data[1] != spectralBlockMagic1 {
		return nil, ErrSpectralBlockMalformed
	}
	if data[2] != spectralBlockVersion {
		return nil, fmt.Errorf("wusp: unsupported spectral block version %d", data[2])
	}
	delta := data[3]&spectralBlockDelta != 0
	r := data[4:]
	next := func() (uint64, error) {
		v, n := binary.Uvarint(r)
		if n <= 0 {
			return 0, ErrSpectralBlockMalformed
		}
		r = r[n:]
		return v, nil
	}
	nextSigned := func() (int64, error) {
		v, n := binary.Varint(r)
		if n <= 0 {
			return 0, ErrSpectralBlockMalformed
		}
		r = r[n:]
		return v, nil
	}
	binCount, err := next()
	if err != nil {
		return nil, err
	}
	count, err := next()
	if err != nil {
		return nil, err
	}
	if binCount == 0 || binCount > SpectralMaxBins || count > SpectralMaxSamplesPerBlock {
		return nil, ErrSpectralBlockMalformed
	}
	samples := make([]SpectralSample, 0, count)
	for i := uint64(0); i < count; i++ {
		ts, err := next()
		if err != nil {
			return nil, err
		}
		rssi, err := nextSigned()
		if err != nil {
			return nil, err
		}
		nf, err := nextSigned()
		if err != nil {
			return nil, err
		}
		maxIndex, err := next()
		if err != nil {
			return nil, err
		}
		if uint64(len(r)) < binCount || ts > 0xffffffff || maxIndex > 0xffff {
			return nil, ErrSpectralBlockMalformed
		}
		sample := SpectralSample{
			TimestampMicros: uint32(ts),
			RSSI:            int16(rssi),
			NoiseFloor:      int16(nf),
			MaxIndex:        uint16(maxIndex),
			Bins:            append([]byte(nil), r[:binCount]...),
		}
		r = r[binCount:]
		if i > 0 {
			prev := samples[i-1]
			sample.TimestampMicros += prev.TimestampMicros
			if delta {
				for j := range sample.Bins {
					sample.Bins[j] += prev.Bins[j]
				}
			}
		}
		samples = append(samples, sample)
	}
	if len(r) != 0 {
		return nil, ErrSpectralBlockMalformed
	}
	return samples, nil
}
