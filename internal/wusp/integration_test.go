package wusp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fullSchemaFixture struct {
	msg        *Message
	raw        []byte
	compressed []byte
}

type schemaFixtureProfile string

const (
	fixtureProfileRealistic       schemaFixtureProfile = "realistic"
	fixtureProfileMaxCompressible schemaFixtureProfile = "max-compressible"
)

var (
	fullSchemaFixtureOnce      sync.Once
	fullSchemaFixtureData      fullSchemaFixture
	fullSchemaFixtureErr       error
	maxCompressibleFixtureOnce sync.Once
	maxCompressibleFixtureData fullSchemaFixture
	maxCompressibleFixtureErr  error
)

func TestWUSPFullSchemaRoundTrip(t *testing.T) {
	fixture := mustFullSchemaFixture(t)

	t.Run("raw", func(t *testing.T) {
		decoder := NewDecoder(DecodeOptions{})
		decoded, err := decoder.Decode(fixture.raw)
		if err != nil {
			t.Fatalf("Decode(raw) returned error: %v", err)
		}
		assertMessageEqual(t, fixture.msg, decoded)
	})

	t.Run("lz4", func(t *testing.T) {
		decoder := NewDecoder(DecodeOptions{})
		decoded, err := decoder.Decode(fixture.compressed)
		if err != nil {
			t.Fatalf("Decode(lz4) returned error: %v", err)
		}
		assertMessageEqual(t, fixture.msg, decoded)
	})

	t.Logf("full-schema fixture: fields=%d raw=%dB compressed=%dB", len(fixture.msg.Fields), len(fixture.raw), len(fixture.compressed))
}

func TestWUSPMaxCompressibleRoundTrip(t *testing.T) {
	fixture := mustMaxCompressibleFixture(t)

	t.Run("raw", func(t *testing.T) {
		decoder := NewDecoder(DecodeOptions{})
		decoded, err := decoder.Decode(fixture.raw)
		if err != nil {
			t.Fatalf("Decode(raw) returned error: %v", err)
		}
		assertMessageEqual(t, fixture.msg, decoded)
	})

	t.Run("lz4", func(t *testing.T) {
		decoder := NewDecoder(DecodeOptions{})
		decoded, err := decoder.Decode(fixture.compressed)
		if err != nil {
			t.Fatalf("Decode(lz4) returned error: %v", err)
		}
		assertMessageEqual(t, fixture.msg, decoded)
	})

	t.Logf(
		"max-compressible fixture: fields=%d raw=%dB compressed=%dB ratio=%.2f%%",
		len(fixture.msg.Fields),
		len(fixture.raw),
		len(fixture.compressed),
		compressionRatioPercent(fixture.compressed, fixture.raw),
	)
}

func BenchmarkWUSPEncodeFullSchema(b *testing.B) {
	fixture := mustFullSchemaFixture(b)
	benchmarks := []struct {
		name    string
		options EncodeOptions
	}{
		{
			name: "raw",
			options: EncodeOptions{
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
		{
			name: "lz4",
			options: EncodeOptions{
				Compress:         true,
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			encoder := NewEncoder(bm.options)
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := encoder.Encode(fixture.msg)
				if err != nil {
					b.Fatalf("Encode returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("Encode returned an empty frame")
				}
			}
		})
	}
}

func BenchmarkWUSPEncodeMaxCompressible(b *testing.B) {
	fixture := mustMaxCompressibleFixture(b)
	benchmarks := []struct {
		name    string
		options EncodeOptions
	}{
		{
			name: "raw",
			options: EncodeOptions{
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
		{
			name: "lz4",
			options: EncodeOptions{
				Compress:         true,
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			encoder := NewEncoder(bm.options)
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := encoder.Encode(fixture.msg)
				if err != nil {
					b.Fatalf("Encode returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("Encode returned an empty frame")
				}
			}
		})
	}
}

func BenchmarkWUSPDecodeFullSchema(b *testing.B) {
	fixture := mustFullSchemaFixture(b)
	benchmarks := []struct {
		name  string
		frame []byte
	}{
		{name: "raw", frame: fixture.raw},
		{name: "lz4", frame: fixture.compressed},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			decoder := NewDecoder(DecodeOptions{})
			b.ReportAllocs()
			b.SetBytes(int64(len(bm.frame)))
			for i := 0; i < b.N; i++ {
				msg, err := decoder.Decode(bm.frame)
				if err != nil {
					b.Fatalf("Decode returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("decoded field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkWUSPDecodeMaxCompressible(b *testing.B) {
	fixture := mustMaxCompressibleFixture(b)
	benchmarks := []struct {
		name  string
		frame []byte
	}{
		{name: "raw", frame: fixture.raw},
		{name: "lz4", frame: fixture.compressed},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			decoder := NewDecoder(DecodeOptions{})
			b.ReportAllocs()
			b.SetBytes(int64(len(bm.frame)))
			for i := 0; i < b.N; i++ {
				msg, err := decoder.Decode(bm.frame)
				if err != nil {
					b.Fatalf("Decode returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("decoded field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkWUSPRoundTripFullSchema(b *testing.B) {
	fixture := mustFullSchemaFixture(b)
	benchmarks := []struct {
		name    string
		options EncodeOptions
	}{
		{
			name: "raw",
			options: EncodeOptions{
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
		{
			name: "lz4",
			options: EncodeOptions{
				Compress:         true,
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			encoder := NewEncoder(bm.options)
			decoder := NewDecoder(DecodeOptions{})
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := encoder.Encode(fixture.msg)
				if err != nil {
					b.Fatalf("Encode returned error: %v", err)
				}
				msg, err := decoder.Decode(frame)
				if err != nil {
					b.Fatalf("Decode returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("decoded field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func BenchmarkWUSPRoundTripMaxCompressible(b *testing.B) {
	fixture := mustMaxCompressibleFixture(b)
	benchmarks := []struct {
		name    string
		options EncodeOptions
	}{
		{
			name: "raw",
			options: EncodeOptions{
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
		{
			name: "lz4",
			options: EncodeOptions{
				Compress:         true,
				IncludeDeviceID:  true,
				IncludeTimestamp: true,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			encoder := NewEncoder(bm.options)
			decoder := NewDecoder(DecodeOptions{})
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.raw)))
			for i := 0; i < b.N; i++ {
				frame, err := encoder.Encode(fixture.msg)
				if err != nil {
					b.Fatalf("Encode returned error: %v", err)
				}
				msg, err := decoder.Decode(frame)
				if err != nil {
					b.Fatalf("Decode returned error: %v", err)
				}
				if len(msg.Fields) != len(fixture.msg.Fields) {
					b.Fatalf("decoded field count=%d want=%d", len(msg.Fields), len(fixture.msg.Fields))
				}
			}
		})
	}
}

func mustFullSchemaFixture(tb testing.TB) fullSchemaFixture {
	tb.Helper()
	fullSchemaFixtureOnce.Do(func() {
		fullSchemaFixtureData, fullSchemaFixtureErr = buildSchemaFixture(fixtureProfileRealistic)
	})
	if fullSchemaFixtureErr != nil {
		tb.Fatalf("buildFullSchemaFixture returned error: %v", fullSchemaFixtureErr)
	}
	return fullSchemaFixtureData
}

func mustMaxCompressibleFixture(tb testing.TB) fullSchemaFixture {
	tb.Helper()
	maxCompressibleFixtureOnce.Do(func() {
		maxCompressibleFixtureData, maxCompressibleFixtureErr = buildSchemaFixture(fixtureProfileMaxCompressible)
	})
	if maxCompressibleFixtureErr != nil {
		tb.Fatalf("buildMaxCompressibleFixture returned error: %v", maxCompressibleFixtureErr)
	}
	return maxCompressibleFixtureData
}

func buildSchemaFixture(profile schemaFixtureProfile) (fullSchemaFixture, error) {
	msg, err := buildSchemaMessage(profile)
	if err != nil {
		return fullSchemaFixture{}, err
	}

	rawEncoder := NewEncoder(EncodeOptions{
		IncludeDeviceID:  true,
		IncludeTimestamp: true,
	})
	raw, err := rawEncoder.Encode(msg)
	if err != nil {
		return fullSchemaFixture{}, fmt.Errorf("encode raw fixture: %w", err)
	}

	compressedEncoder := NewEncoder(EncodeOptions{
		Compress:         true,
		IncludeDeviceID:  true,
		IncludeTimestamp: true,
	})
	compressed, err := compressedEncoder.Encode(msg)
	if err != nil {
		return fullSchemaFixture{}, fmt.Errorf("encode compressed fixture: %w", err)
	}

	return fullSchemaFixture{
		msg:        msg,
		raw:        raw,
		compressed: compressed,
	}, nil
}

func buildSchemaMessage(profile schemaFixtureProfile) (*Message, error) {
	valueForParam := realisticMaxValue
	deviceID := "usp:device:wantastic:" + patternString("fixture-device-id", 48)
	timestamp := time.Unix(253402300799, 999999999).UTC()

	if profile == fixtureProfileMaxCompressible {
		valueForParam = maxCompressibleValue
		deviceID = strings.Repeat("WUSP", 16)
		timestamp = time.Unix(253402300799, 0).UTC()
	}

	msg := &Message{
		DeviceID:  deviceID,
		Timestamp: timestamp,
		Fields:    make([]Field, 0, len(AllDeviceParams)),
	}

	seen := make(map[string]struct{}, len(AllDeviceParams))
	for i, param := range AllDeviceParams {
		if _, ok := seen[param.Path]; ok {
			return nil, fmt.Errorf("duplicate param path in AllDeviceParams: %s", param.Path)
		}
		seen[param.Path] = struct{}{}

		id, ok := globalRegistry.IDFor(param.Path)
		if !ok || id == 0 {
			return nil, fmt.Errorf("param path missing from registry: %s", param.Path)
		}

		msg.Fields = append(msg.Fields, Field{
			id:   id,
			Path: param.Path,
			Val:  valueForParam(param, i),
		})
	}

	return msg, nil
}

func realisticMaxValue(param Param, index int) Value {
	switch param.Type {
	case TypeBoolean:
		return Bool(true)
	case TypeUnsignedInt:
		return Uint(uint64(maxUnsignedForParam(param, 32)))
	case TypeUnsignedLong, TypeStatsCounter:
		return Uint(maxUnsignedForParam(param, 64))
	case TypeInt:
		return Int(maxSignedForParam(param, 32))
	case TypeLong:
		return Int(maxSignedForParam(param, 64))
	case TypeDecimal:
		return Float(maxDecimalForParam(param))
	case TypeDateTime:
		return Time(time.Unix(253402300799, int64(index%1_000_000_000)).UTC())
	case TypeBase64:
		return Bytes(maxBinaryValueForParam(param, index))
	case TypeHexBinary:
		return Bytes(maxBinaryValueForParam(param, index))
	case TypeIPv4Address:
		return IP4(net.IPv4(255, 255, 255, byte(1+(index%253))))
	case TypeIPv6Address:
		return IP6(net.ParseIP(fmt.Sprintf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:%x", 1+(index%65534))))
	case TypeIPv4Prefix:
		_, n, _ := net.ParseCIDR(fmt.Sprintf("203.%d.%d.0/24", index%255, (index*7)%255))
		return IP4Prefix(n)
	case TypeIPv6Prefix:
		_, n, _ := net.ParseCIDR(fmt.Sprintf("2001:db8:%x:%x::/64", index%65535, (index*11)%65535))
		return IP6Prefix(n)
	case TypeMACAddress:
		return MAC(net.HardwareAddr{0x02, byte(index >> 16), byte(index >> 8), byte(index), 0xaa, 0xbb})
	case TypeList:
		return maxListValueForParam(param, index)
	default:
		return String(maxStringValueForParam(param, index))
	}
}

func maxCompressibleValue(param Param, index int) Value {
	switch param.Type {
	case TypeBoolean:
		return Bool(true)
	case TypeUnsignedInt:
		return Uint(uint64(maxUnsignedForParam(param, 32)))
	case TypeUnsignedLong, TypeStatsCounter:
		return Uint(maxUnsignedForParam(param, 64))
	case TypeInt:
		return Int(maxSignedForParam(param, 32))
	case TypeLong:
		return Int(maxSignedForParam(param, 64))
	case TypeDecimal:
		return Float(maxDecimalForParam(param))
	case TypeDateTime:
		return Time(time.Unix(253402300799, 0).UTC())
	case TypeBase64:
		return Bytes(repeatedBytes(maxBinaryLengthForParam(param), 0x41))
	case TypeHexBinary:
		return Bytes(repeatedBytes(maxBinaryLengthForParam(param), 0x42))
	case TypeIPv4Address:
		return IP4(net.IPv4(255, 255, 255, 255))
	case TypeIPv6Address:
		return IP6(net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	case TypeIPv4Prefix:
		_, n, _ := net.ParseCIDR("255.255.255.0/24")
		return IP4Prefix(n)
	case TypeIPv6Prefix:
		_, n, _ := net.ParseCIDR("ffff:ffff:ffff:ffff::/64")
		return IP6Prefix(n)
	case TypeMACAddress:
		return MAC(net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
	case TypeList:
		return maxCompressibleListValue(param)
	default:
		return String(maxCompressibleStringValue(param, index))
	}
}

func maxUnsignedForParam(param Param, bits int) uint64 {
	if param.Limits.Max != nil {
		return uint64(*param.Limits.Max)
	}
	if bits == 32 {
		return math.MaxUint32
	}
	return math.MaxUint64
}

func maxSignedForParam(param Param, bits int) int64 {
	if param.Limits.Max != nil {
		return *param.Limits.Max
	}
	if bits == 32 {
		return math.MaxInt32
	}
	return math.MaxInt64
}

func maxDecimalForParam(param Param) float64 {
	if param.Limits.MaxF != nil {
		return *param.Limits.MaxF
	}
	if param.Limits.Max != nil {
		return float64(*param.Limits.Max)
	}
	return 999999.999999
}

func maxBinaryValueForParam(param Param, index int) []byte {
	target := maxBinaryLengthForParam(param)
	return patternBytes(param.Path, index, target)
}

func maxBinaryLengthForParam(param Param) int {
	target := 128
	switch {
	case param.Type == TypeHexBinary && param.Limits.MaxLength > 0:
		target = max(1, param.Limits.MaxLength/2)
	case param.Type == TypeBase64 && param.Limits.MaxLength > 0:
		target = max(1, decodedBase64Len(param.Limits.MaxLength))
	case strings.Contains(strings.ToLower(param.Path), "privatekey"),
		strings.Contains(strings.ToLower(param.Path), "publickey"),
		strings.Contains(strings.ToLower(param.Path), "presharedkey"):
		target = 32
	case strings.Contains(strings.ToLower(param.Path), ".instruction"):
		target = 1024
	case strings.Contains(strings.ToLower(param.Path), ".value"):
		target = 256
	}
	return target
}

func maxStringValueForParam(param Param, index int) string {
	if len(param.Limits.Enums) > 0 {
		return longestString(param.Limits.Enums)
	}

	switch {
	case strings.Contains(strings.ToLower(param.Description), "base64-encoded"):
		return base64.StdEncoding.EncodeToString(maxBinaryValueForParam(param, index))
	case param.Type == TypeAlias:
		return fitString("alias-"+sanitizeSeed(param.Path), lengthTarget(param.Limits, 64))
	case param.Type == TypePathRef || strings.Contains(strings.ToLower(param.Description), "pathref"):
		return fitString(samplePathRef(param.Path), lengthTarget(param.Limits, len(samplePathRef(param.Path))))
	case strings.HasSuffix(param.Path, "URL"):
		return fitString(sampleURL(param.Path), lengthTarget(param.Limits, 256))
	case param.Limits.Pattern == `^[0-9A-F]{6}$` || param.Limits.Pattern == `[0-9A-F]{6}`:
		return "ABCDEF"
	case param.Limits.Pattern == `[r\-][w\-][x\-][n\-]`:
		return "rwxn"
	case strings.Contains(param.Limits.Pattern, `^[a-zA-Z0-9\-\.]*$`):
		return fitString("host-"+sanitizeSeed(param.Path), lengthTarget(param.Limits, 96))
	default:
		return fitString(sanitizeSeed(param.Path), lengthTarget(param.Limits, 96))
	}
}

func maxListValueForParam(param Param, index int) Value {
	if len(param.Limits.Enums) > 0 {
		count := len(param.Limits.Enums)
		if param.Limits.MaxItems > 0 && count > param.Limits.MaxItems {
			count = param.Limits.MaxItems
		}
		items := make([]Value, 0, count)
		for _, enum := range param.Limits.Enums[:count] {
			items = append(items, String(enum))
		}
		return List(items...)
	}

	count := param.Limits.MaxItems
	if count == 0 {
		switch {
		case param.Limits.MaxLength >= 65535:
			count = 64
		case param.Limits.MaxLength >= 1024:
			count = 32
		case param.Limits.MaxLength >= 256:
			count = 12
		default:
			count = 4
		}
	}
	if count < 1 {
		count = 1
	}

	items := make([]Value, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, String(listItemValue(param, index, i, count)))
	}
	return List(items...)
}

func maxCompressibleListValue(param Param) Value {
	if len(param.Limits.Enums) > 0 {
		count := len(param.Limits.Enums)
		if param.Limits.MaxItems > 0 && count > param.Limits.MaxItems {
			count = param.Limits.MaxItems
		}
		item := longestString(param.Limits.Enums)
		items := make([]Value, 0, count)
		for i := 0; i < count; i++ {
			items = append(items, String(item))
		}
		return List(items...)
	}

	count := param.Limits.MaxItems
	if count == 0 {
		switch {
		case param.Limits.MaxLength >= 65535:
			count = 64
		case param.Limits.MaxLength >= 1024:
			count = 32
		case param.Limits.MaxLength >= 256:
			count = 12
		default:
			count = 4
		}
	}
	if count < 1 {
		count = 1
	}

	item := compressibleListItemValue(param, count)
	items := make([]Value, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, String(item))
	}
	return List(items...)
}

func listItemValue(param Param, index, itemIndex, itemCount int) string {
	lowerPath := strings.ToLower(param.Path)
	lowerDesc := strings.ToLower(param.Description)

	switch {
	case strings.Contains(lowerPath, "allowedips"):
		pool := []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32", "fd00::/8"}
		return pool[itemIndex%len(pool)]
	case strings.Contains(lowerPath, "prefix"):
		pool := []string{"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/48", "fd00::/64"}
		return pool[itemIndex%len(pool)]
	case strings.Contains(lowerDesc, "pathref"):
		return samplePathRef(param.Path)
	default:
		target := 32
		if param.Limits.MaxLength > 0 {
			target = max(1, (param.Limits.MaxLength-max(0, itemCount-1))/itemCount)
		}
		return fitString(fmt.Sprintf("%s-%03d", sanitizeSeed(param.Path), index+itemIndex), target)
	}
}

func compressibleListItemValue(param Param, itemCount int) string {
	lowerPath := strings.ToLower(param.Path)
	lowerDesc := strings.ToLower(param.Description)

	switch {
	case strings.Contains(lowerPath, "allowedips"):
		return "0.0.0.0/0"
	case strings.Contains(lowerPath, "prefix"):
		return "255.255.255.0/24"
	case strings.Contains(lowerDesc, "pathref"):
		return samplePathRef(param.Path)
	default:
		target := 32
		if param.Limits.MaxLength > 0 {
			target = max(1, (param.Limits.MaxLength-max(0, itemCount-1))/itemCount)
		}
		return strings.Repeat("A", target)
	}
}

func decodedBase64Len(maxChars int) int {
	if maxChars <= 0 {
		return 0
	}
	return (maxChars / 4) * 3
}

func lengthTarget(l Limits, fallback int) int {
	target := fallback
	if l.MaxLength > 0 {
		target = l.MaxLength
	}
	if l.MinLength > 0 && target < l.MinLength {
		target = l.MinLength
	}
	if target < 1 {
		target = 1
	}
	return target
}

func samplePathRef(path string) string {
	switch {
	case strings.Contains(path, "WireGuard"):
		return "Device.WireGuard.Peer.1."
	case strings.Contains(path, "ManagementServer"):
		return "Device.ManagementServer.ManageableDevice.1."
	case strings.Contains(path, "LocalAgent.ControllerTrust.Role"):
		return "Device.LocalAgent.ControllerTrust.Role.1."
	case strings.Contains(path, "LocalAgent.Certificate"):
		return "Device.LocalAgent.Certificate.1."
	default:
		return "Device.IP.Interface.1."
	}
}

func sampleURL(path string) string {
	host := strings.ToLower(strings.ReplaceAll(sanitizeSeed(path), ".", "-"))
	host = strings.Trim(host, "-")
	if host == "" {
		host = "wantastic"
	}
	return "https://" + host + ".example.net/" + sanitizeSeed(path)
}

func maxCompressibleStringValue(param Param, index int) string {
	if len(param.Limits.Enums) > 0 {
		return longestString(param.Limits.Enums)
	}

	switch {
	case strings.Contains(strings.ToLower(param.Description), "base64-encoded"):
		return base64.StdEncoding.EncodeToString(repeatedBytes(maxBinaryLengthForParam(param), 0x41))
	case param.Type == TypeAlias:
		return strings.Repeat("A", lengthTarget(param.Limits, 64))
	case param.Type == TypePathRef || strings.Contains(strings.ToLower(param.Description), "pathref"):
		return samplePathRef(param.Path)
	case strings.HasSuffix(param.Path, "URL"):
		return fitString("https://aaaaaaaa.example.net/aaaaaaaa", lengthTarget(param.Limits, 256))
	case param.Limits.Pattern == `^[0-9A-F]{6}$` || param.Limits.Pattern == `[0-9A-F]{6}`:
		return "AAAAAA"
	case param.Limits.Pattern == `[r\-][w\-][x\-][n\-]`:
		return "rwxn"
	case strings.Contains(param.Limits.Pattern, `^[a-zA-Z0-9\-\.]*$`):
		return strings.Repeat("a", lengthTarget(param.Limits, 96))
	default:
		return strings.Repeat("A", lengthTarget(param.Limits, 96))
	}
}

func sanitizeSeed(seed string) string {
	var b strings.Builder
	b.Grow(len(seed))
	for i := 0; i < len(seed); i++ {
		c := seed[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('x')
		}
	}
	return b.String()
}

func fitString(seed string, length int) string {
	if length <= 0 {
		return ""
	}
	base := seed
	if base == "" {
		base = "wusp"
	}
	if len(base) >= length {
		return base[:length]
	}
	var b strings.Builder
	b.Grow(length)
	for b.Len() < length {
		remaining := length - b.Len()
		if remaining >= len(base) {
			b.WriteString(base)
		} else {
			b.WriteString(base[:remaining])
		}
	}
	return b.String()
}

func patternString(seed string, length int) string {
	return fitString(sanitizeSeed(seed), length)
}

func patternBytes(seed string, index, length int) []byte {
	if length <= 0 {
		return nil
	}
	base := []byte(sanitizeSeed(seed))
	if len(base) == 0 {
		base = []byte("wusp")
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = base[(i+index)%len(base)] ^ byte((i*31+index)%251)
	}
	return out
}

func repeatedBytes(length int, value byte) []byte {
	if length <= 0 {
		return nil
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func longestString(values []string) string {
	longest := ""
	for _, value := range values {
		if len(value) > len(longest) {
			longest = value
		}
	}
	return longest
}

func assertMessageEqual(t *testing.T, want, got *Message) {
	t.Helper()

	if want.DeviceID != got.DeviceID {
		t.Fatalf("DeviceID mismatch: got %q want %q", got.DeviceID, want.DeviceID)
	}
	if want.Timestamp.UnixNano() != got.Timestamp.UnixNano() {
		t.Fatalf("Timestamp mismatch: got %d want %d", got.Timestamp.UnixNano(), want.Timestamp.UnixNano())
	}
	if len(want.Fields) != len(got.Fields) {
		t.Fatalf("field count mismatch: got %d want %d", len(got.Fields), len(want.Fields))
	}

	for i := range want.Fields {
		wf := want.Fields[i]
		gf := got.Fields[i]
		if wf.Path != gf.Path {
			t.Fatalf("field[%d] path mismatch: got %q want %q", i, gf.Path, wf.Path)
		}
		if !valuesEqual(wf.Val, gf.Val) {
			t.Fatalf("field[%d] value mismatch on %s: got=%+v want=%+v", i, wf.Path, gf.Val, wf.Val)
		}
	}
}

func valuesEqual(a, b Value) bool {
	if a.Tag != b.Tag {
		return false
	}

	switch a.Tag {
	case TagNull, TagFalse, TagTrue:
		return true
	case TagUint:
		return a.AsUint() == b.AsUint()
	case TagInt:
		return a.AsInt() == b.AsInt()
	case TagFloat:
		return math.Float64bits(a.AsFloat()) == math.Float64bits(b.AsFloat())
	case TagString:
		return a.AsString() == b.AsString()
	case TagBytes, TagIP4, TagIP6, TagIP4Pfx, TagIP6Pfx, TagMAC:
		return bytes.Equal(a.AsBytes(), b.AsBytes())
	case TagTime:
		return a.AsTime().UnixNano() == b.AsTime().UnixNano()
	case TagList:
		al := a.AsList()
		bl := b.AsList()
		if len(al) != len(bl) {
			return false
		}
		for i := range al {
			if !valuesEqual(al[i], bl[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func compressionRatioPercent(compressed, raw []byte) float64 {
	if len(raw) == 0 {
		return 0
	}
	return (float64(len(compressed)) / float64(len(raw))) * 100
}
