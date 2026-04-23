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
	Model       string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	Revision    string `json:"revision"`
	IMEI        string `json:"imei"`
	IMSI        string `json:"imsi"`
	ICCID       string `json:"iccid"`
	MSISDN      string `json:"msisdn"` // phone number

	// Registration
	Status       RegistrationStatus `json:"status"`
	Operator     string             `json:"operator"`
	OperatorMCC  string             `json:"operator_mcc"`
	OperatorMNC  string             `json:"operator_mnc"`
	Technology   Technology         `json:"technology"`
	Band         string             `json:"band"`
	CellID       uint32             `json:"cell_id"`
	LAC          uint16             `json:"lac"` // Location Area Code
	TAC          uint32             `json:"tac"` // Tracking Area Code (LTE/5G)

	// Signal quality
	Signal  SignalQuality `json:"signal"`

	// Data connection
	Connected    bool   `json:"connected"`
	APN          string `json:"apn"`
	IPAddress    string `json:"ip_address"`
	IPv6Address  string `json:"ipv6_address"`
	DNS1         string `json:"dns1"`
	DNS2         string `json:"dns2"`

	// Traffic
	TxBytes      uint64 `json:"tx_bytes"`
	RxBytes      uint64 `json:"rx_bytes"`

	// SIM
	SIMStatus    SIMStatus `json:"sim_status"`
	SIMSlot      int       `json:"sim_slot"`

	// Metadata
	Interface    string    `json:"interface"` // e.g. "wwan0", "/dev/cdc-wdm0"
	Protocol     string    `json:"protocol"`  // "qmi", "mbim", "at"
	CollectedAt  time.Time `json:"collected_at"`
}

// SignalQuality holds multi-technology signal measurements.
type SignalQuality struct {
	RSSI    int `json:"rssi"`     // dBm (-113 to -51 for GSM, wider for LTE)
	RSRP    int `json:"rsrp"`     // dBm (LTE/5G Reference Signal Received Power)
	RSRQ    int `json:"rsrq"`     // dB  (LTE/5G Reference Signal Received Quality)
	SINR    int `json:"sinr"`     // dB  (LTE/5G Signal-to-Interference+Noise Ratio)
	RSCP    int `json:"rscp"`     // dBm (UMTS Received Signal Code Power)
	ECIO    int `json:"ecio"`     // dB  (UMTS Ec/Io)
	CSQ     int `json:"csq"`      // 0-31 (legacy GSM signal quality)
	Bars    int `json:"bars"`     // 0-5 (normalized signal strength)
}

// Technology represents the radio access technology.
type Technology int

const (
	TechUnknown Technology = iota
	TechGSM                // 2G
	TechGPRS               // 2.5G
	TechEDGE               // 2.75G
	TechUMTS               // 3G
	TechHSPA               // 3.5G
	TechHSPAPlus           // 3.75G
	TechLTE                // 4G
	TechLTEA               // 4G+
	TechNR5G               // 5G NR
	TechNR5GNSA            // 5G NSA (Non-Standalone)
)

func (t Technology) String() string {
	switch t {
	case TechGSM:      return "GSM"
	case TechGPRS:     return "GPRS"
	case TechEDGE:     return "EDGE"
	case TechUMTS:     return "UMTS"
	case TechHSPA:     return "HSPA"
	case TechHSPAPlus: return "HSPA+"
	case TechLTE:      return "LTE"
	case TechLTEA:     return "LTE-A"
	case TechNR5G:     return "NR5G"
	case TechNR5GNSA:  return "NR5G-NSA"
	default:           return "Unknown"
	}
}

// TR-181 generation mapping
func (t Technology) Generation() string {
	switch t {
	case TechGSM, TechGPRS, TechEDGE:     return "2G"
	case TechUMTS, TechHSPA, TechHSPAPlus: return "3G"
	case TechLTE, TechLTEA:                return "4G"
	case TechNR5G, TechNR5GNSA:            return "5G"
	default:                                return "Unknown"
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
	case RegHome:     return "Home"
	case RegRoaming:  return "Roaming"
	case RegSearching: return "Searching"
	case RegDenied:   return "Denied"
	default:          return "Not Registered"
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
	case SIMReady:  return "Ready"
	case SIMLocked: return "PIN Locked"
	case SIMError:  return "Error"
	default:        return "Absent"
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

// New returns the best available modem Controller for this platform.
func New() Controller {
	return newController()
}
