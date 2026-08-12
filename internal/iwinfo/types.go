// Package iwinfo provides cross-platform WiFi radio monitoring and control.
//
// Platform implementations:
//
//	Linux:   libiwinfo CGo (-tags iwinfo), sysfs/netctl fallback
//	macOS:   CoreWLAN CGo (-tags iwinfo), system_profiler fallback
//	Windows: wlanapi syscall (always native, no CGo needed)
//
// All platforms export the same API. Build with -tags iwinfo to enable
// CGo-accelerated backends where available.
package iwinfo

import "net"

// InterfaceInfo holds WiFi radio state for a single interface.
type InterfaceInfo struct {
	Name         string
	SSID         string
	BSSID        string
	Mode         int // 0=unknown, 1=master/AP, 2=adhoc, 3=client/station
	Signal       int // dBm
	Noise        int // dBm
	Bitrate      int // kbit/s
	Channel      int
	Frequency    int // MHz
	TxPower      int // dBm
	Quality      int
	QualityMax   int
	PHYName      string
	HardwareName string
	Country      string
}

// HWModes describes which 802.11 generations a radio supports.
type HWModes struct {
	A  bool // 802.11a  (5 GHz legacy)
	B  bool // 802.11b  (2.4 GHz legacy)
	G  bool // 802.11g  (2.4 GHz)
	N  bool // 802.11n  (HT)
	AC bool // 802.11ac (VHT)
	AX bool // 802.11ax (HE / WiFi 6)
	BE bool // 802.11be (EHT / WiFi 7)
}

// AssocEntry represents a connected WiFi station (client).
type AssocEntry struct {
	MAC       net.HardwareAddr
	Signal    int8
	SignalAvg int8
	Noise     int8
	// AuthenticationKnown distinguishes a real false authentication state
	// from collectors (such as nl80211 station dumps) which do not expose it.
	AuthenticationKnown bool
	Authenticated       bool
	OperatingStandard   string // a, b, g, n, ac, ax, or be
	Inactive            uint32 // ms since last activity
	ConnectedTime       uint32 // seconds
	RxPackets           uint32
	TxPackets           uint32
	RxBytes             uint64
	TxBytes             uint64
	TxRetries           uint32
	TxFailed            uint32
	RxRate              uint32 // kbit/s
	TxRate              uint32 // kbit/s
	RxMCS               int8
	TxMCS               int8
	RxNSS               uint8
	TxNSS               uint8
}

// SurveyEntry represents channel survey / utilization data.
type SurveyEntry struct {
	InUse      bool   // currently operating channel, when the backend exposes it
	ActiveTime uint64 // total active time (µs)
	BusyTime   uint64 // channel busy time (µs)
	RxTime     uint64 // time spent receiving (µs)
	TxTime     uint64 // time spent transmitting (µs)
	Frequency  uint32 // MHz
	Noise      int8   // dBm
}
