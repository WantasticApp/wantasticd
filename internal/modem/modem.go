// Package modem provides cross-platform cellular modem monitoring and control.
//
// Platform implementations:
//
//	Linux:   libqmi CGo (-tags qmi), libmbim CGo (-tags mbim), AT commands fallback
//	OpenWrt: uqmi CLI + AT commands
//	All:     AT commands over serial/USB (universal fallback)
//
// Maps to TR-181 Device.Cellular.* data model for WUSP integration.
package modem

import "time"

// Info holds cellular modem identification and status.
type Info struct {
	// Identity
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	Revision     string `json:"revision"`
	IMEI         string `json:"imei"`
	IMSI         string `json:"imsi"`
	ICCID        string `json:"iccid"`
	MSISDN       string `json:"msisdn"` // phone number

	// Registration
	Status                RegistrationStatus `json:"status"`
	Operator              string             `json:"operator"`
	OperatorMCC           string             `json:"operator_mcc"`
	OperatorMNC           string             `json:"operator_mnc"`
	Technology            Technology         `json:"technology"`
	SupportedTechnologies []Technology       `json:"supported_technologies"`
	PreferredTechnology   Technology         `json:"preferred_technology"`
	NRMode                string             `json:"nr_mode"` // "Standalone", "NonStandalone", "Unknown"
	Band                  string             `json:"band"`
	CellID                uint32             `json:"cell_id"`
	LAC                   uint16             `json:"lac"` // Location Area Code
	TAC                   uint32             `json:"tac"` // Tracking Area Code (LTE/5G)

	// Signal quality
	Signal SignalQuality `json:"signal"`

	// Data connection
	Connected   bool   `json:"connected"`
	APN         string `json:"apn"`
	IPAddress   string `json:"ip_address"`
	IPv6Address string `json:"ipv6_address"`
	DNS1        string `json:"dns1"`
	DNS2        string `json:"dns2"`
	IPVersion   int    `json:"ip_version"` // 4, 6, -1 (IPv4v6/unknown)

	// Traffic
	TxBytes               uint64 `json:"tx_bytes"`
	RxBytes               uint64 `json:"rx_bytes"`
	TxPackets             uint64 `json:"tx_packets"`
	RxPackets             uint64 `json:"rx_packets"`
	TxErrors              uint64 `json:"tx_errors"`
	RxErrors              uint64 `json:"rx_errors"`
	TxDropped             uint64 `json:"tx_dropped"`
	RxDropped             uint64 `json:"rx_dropped"`
	TxMulticastPackets    uint64 `json:"tx_multicast_packets"`
	RxMulticastPackets    uint64 `json:"rx_multicast_packets"`
	TxBroadcastPackets    uint64 `json:"tx_broadcast_packets"`
	RxBroadcastPackets    uint64 `json:"rx_broadcast_packets"`
	RxUnknownProtoPackets uint64 `json:"rx_unknown_proto_packets"`
	UpstreamMaxBitRate    uint64 `json:"upstream_max_bit_rate"`
	DownstreamMaxBitRate  uint64 `json:"downstream_max_bit_rate"`

	// Quectel extended radio telemetry.
	CarrierAggregation []CarrierInfo  `json:"carrier_aggregation,omitempty"`
	NeighborCells      []NeighborCell `json:"neighbor_cells,omitempty"`
	TemperatureC       int            `json:"temperature_c,omitempty"`
	LTETimingAdvance   int            `json:"lte_timing_advance,omitempty"`
	NR5GTimingAdvance  int            `json:"nr5g_timing_advance,omitempty"`

	// SMS
	SMSStorageLocation string `json:"sms_storage_location"`
	SMSStorageCapacity uint64 `json:"sms_storage_capacity"`
	SMSStorageUsed     uint64 `json:"sms_storage_used"`

	// SIM
	SIMStatus          SIMStatus `json:"sim_status"`
	SIMSlot            int       `json:"sim_slot"`
	ModemFunctionality string    `json:"modem_functionality"`

	// Metadata
	Interface   string    `json:"interface"` // e.g. "wwan0", "/dev/cdc-wdm0"
	Protocol    string    `json:"protocol"`  // "qmi", "mbim", "at"
	CollectedAt time.Time `json:"collected_at"`
}

// CarrierInfo describes one serving/aggregated LTE or NR carrier, typically
// sourced from Quectel AT+QCAINFO.
type CarrierInfo struct {
	Role      string `json:"role"`
	RAT       string `json:"rat"`
	Band      string `json:"band"`
	EARFCN    uint64 `json:"earfcn"`
	PCI       uint64 `json:"pci"`
	Bandwidth string `json:"bandwidth"`
	RSRP      int    `json:"rsrp"`
	RSRQ      int    `json:"rsrq"`
	SINR      int    `json:"sinr"`
	CellID    string `json:"cell_id"`
	TAC       string `json:"tac"`
	Raw       string `json:"raw,omitempty"`
}

// NeighborCell describes one LTE/NR neighbor measurement.
type NeighborCell struct {
	RAT       string `json:"rat"`
	Relation  string `json:"relation"`
	Frequency uint64 `json:"frequency"`
	PCI       uint64 `json:"pci"`
	RSRP      int    `json:"rsrp"`
	RSRQ      int    `json:"rsrq"`
	Raw       string `json:"raw,omitempty"`
}

// SignalQuality holds multi-technology signal measurements.
type SignalQuality struct {
	RSSI int `json:"rssi"` // dBm (-113 to -51 for GSM, wider for LTE)
	RSRP int `json:"rsrp"` // dBm (LTE/5G Reference Signal Received Power)
	RSRQ int `json:"rsrq"` // dB  (LTE/5G Reference Signal Received Quality)
	SINR int `json:"sinr"` // dB  (LTE/5G Signal-to-Interference+Noise Ratio)
	RSCP int `json:"rscp"` // dBm (UMTS Received Signal Code Power)
	ECIO int `json:"ecio"` // dB  (UMTS Ec/Io)
	CSQ  int `json:"csq"`  // 0-31 (legacy GSM signal quality)
	Bars int `json:"bars"` // 0-5 (normalized signal strength)
}

// GNSSInfo holds modem-backed GPS/GNSS state and raw diagnostic payloads.
type GNSSInfo struct {
	Enabled          bool              `json:"enabled"`
	Status           string            `json:"status"`
	Latitude         float64           `json:"latitude"`
	Longitude        float64           `json:"longitude"`
	Altitude         float64           `json:"altitude"`
	SpeedKPH         float64           `json:"speed_kph"`
	Course           float64           `json:"course"`
	HDOP             float64           `json:"hdop"`
	FixQuality       string            `json:"fix_quality"`
	SatellitesUsed   int               `json:"satellites_used"`
	SatellitesInView int               `json:"satellites_in_view"`
	UTC              time.Time         `json:"utc"`
	LastFixTime      time.Time         `json:"last_fix_time"`
	RawLocation      string            `json:"raw_location"`
	NMEA             map[string]string `json:"nmea,omitempty"`
	ModemPath        string            `json:"modem_path"`
	Protocol         string            `json:"protocol"`
}

// Technology represents the radio access technology.
type Technology int

const (
	TechUnknown  Technology = iota
	TechGSM                 // 2G
	TechGPRS                // 2.5G
	TechEDGE                // 2.75G
	TechUMTS                // 3G
	TechHSPA                // 3.5G
	TechHSPAPlus            // 3.75G
	TechLTE                 // 4G
	TechLTEA                // 4G+
	TechNR5G                // 5G NR
	TechNR5GNSA             // 5G NSA (Non-Standalone)
)

func (t Technology) String() string {
	switch t {
	case TechGSM:
		return "GSM"
	case TechGPRS:
		return "GPRS"
	case TechEDGE:
		return "EDGE"
	case TechUMTS:
		return "UMTS"
	case TechHSPA:
		return "HSPA"
	case TechHSPAPlus:
		return "HSPA+"
	case TechLTE:
		return "LTE"
	case TechLTEA:
		return "LTE-A"
	case TechNR5G:
		return "NR5G"
	case TechNR5GNSA:
		return "NR5G-NSA"
	default:
		return "Unknown"
	}
}

// TR-181 generation mapping
func (t Technology) Generation() string {
	switch t {
	case TechGSM, TechGPRS, TechEDGE:
		return "2G"
	case TechUMTS, TechHSPA, TechHSPAPlus:
		return "3G"
	case TechLTE, TechLTEA:
		return "4G"
	case TechNR5G, TechNR5GNSA:
		return "5G"
	default:
		return "Unknown"
	}
}

// RegistrationStatus represents network registration state.
type RegistrationStatus int

const (
	RegNotRegistered RegistrationStatus = iota
	RegHome
	RegSearching
	RegDenied
	RegUnknown
	RegRoaming
)

func (r RegistrationStatus) String() string {
	switch r {
	case RegHome:
		return "Home"
	case RegRoaming:
		return "Roaming"
	case RegSearching:
		return "Searching"
	case RegDenied:
		return "Denied"
	default:
		return "Not Registered"
	}
}

// SIMStatus represents SIM card state.
type SIMStatus int

const (
	SIMAbsent SIMStatus = iota
	SIMReady
	SIMLocked // PIN required
	SIMError
)

func (s SIMStatus) String() string {
	switch s {
	case SIMReady:
		return "Ready"
	case SIMLocked:
		return "PIN Locked"
	case SIMError:
		return "Error"
	default:
		return "Absent"
	}
}

// Controller is the interface for modem operations.
type Controller interface {
	// Discover finds all cellular modems on the system.
	Discover() ([]string, error)

	// GetInfo reads full modem status from the specified device path.
	GetInfo(devicePath string) (*Info, error)

	// GetSignal reads current signal quality.
	GetSignal(devicePath string) (*SignalQuality, error)

	// Connect initiates a data connection with the given APN.
	Connect(devicePath, apn string) error

	// Disconnect tears down the data connection.
	Disconnect(devicePath string) error

	// Close releases resources.
	Close() error
}

// ControlController is implemented by modem backends that can mutate Quectel /
// 3GPP modem state. The WUSP agent calls these through explicit Operate
// commands because several of them can detach the modem or reboot the radio.
type ControlController interface {
	SetFunctionality(devicePath, mode string) error
	SetSIMSlot(devicePath string, slot int) error
	SetIMEI(devicePath, imei string) error
	SetAPNProfile(devicePath string, profile int, pdpType, apn string) error
	SetGNSS(devicePath string, enabled bool) error
	GetGNSS(devicePath string) (*GNSSInfo, error)
	SendSMS(devicePath, phoneNumber, message string) error
	ListSMS(devicePath string) (string, error)
	DeleteSMS(devicePath, index string) error
}

// New returns the best available modem Controller for this platform.
func New() Controller {
	return newController()
}
