//go:build !iwinfo

package iwinfo

// Stub implementation when libiwinfo is not available.
// All functions safely return "not available" — the agent never crashes.
// To enable native libiwinfo support, build with: go build -tags iwinfo

// Available always returns false when libiwinfo is not linked.
func Available(ifname string) bool { return false }

// InterfaceInfo holds WiFi data (stub: never populated)
type InterfaceInfo struct {
	Name       string
	SSID       string
	BSSID      string
	Mode       int
	Signal     int
	Noise      int
	Bitrate    int
	Channel    int
	Frequency  int
	TxPower    int
	Quality    int
	QualityMax int
}

// GetInfo returns an error when libiwinfo is not available.
func GetInfo(ifname string) (*InterfaceInfo, error) {
	return nil, errNotAvailable
}

// AssocEntry represents a connected station (stub)
type AssocEntry struct {
	MAC           []byte
	Signal        int8
	SignalAvg     int8
	Noise         int8
	Inactive      uint32
	ConnectedTime uint32
	RxPackets     uint32
	TxPackets     uint32
	RxBytes       uint64
	TxBytes       uint64
	TxRetries     uint32
	TxFailed      uint32
	RxRate        uint32
	TxRate        uint32
	RxMCS         int8
	TxMCS         int8
	RxNSS         uint8
	TxNSS         uint8
}

// GetAssocList returns an error when libiwinfo is not available.
func GetAssocList(ifname string) ([]AssocEntry, error) {
	return nil, errNotAvailable
}

// SurveyEntry represents channel survey data (stub)
type SurveyEntry struct {
	ActiveTime uint64
	BusyTime   uint64
	RxTime     uint64
	TxTime     uint64
	Frequency  uint32
	Noise      int8
}

// GetSurvey returns an error when libiwinfo is not available.
func GetSurvey(ifname string) ([]SurveyEntry, error) {
	return nil, errNotAvailable
}

// Close is a no-op when libiwinfo is not available.
func Close() {}

var errNotAvailable = stubError("iwinfo: libiwinfo not available (build with -tags iwinfo)")

type stubError string

func (e stubError) Error() string { return string(e) }
