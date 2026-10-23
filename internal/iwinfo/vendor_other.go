//go:build !linux

package iwinfo

import (
	"errors"
	"net"
)

var errVendorUnsupported = errors.New("vendor WiFi ioctls are Linux only")

// ErrStationNotFound is returned by NL80211Station for an unknown MAC.
var ErrStationNotFound = errors.New("nl80211 station not found")

// RadioLink describes physical-layer settings of the radio behind ifname.
type RadioLink struct {
	PHY              int
	TxPowerDBM       int
	TxPowerKnown     bool
	CoverageClass    int
	CoverageKnown    bool
	CoverageDistance int
	Frequency        int
	CenterFrequency  int
	ChannelWidth     int
}

func VendorAssocList(string) ([]AssocEntry, error) { return nil, errVendorUnsupported }
func NL80211Stations(string) ([]AssocEntry, error) { return nil, errVendorUnsupported }
func NL80211Station(string, net.HardwareAddr) (AssocEntry, error) {
	return AssocEntry{}, errVendorUnsupported
}
func NL80211RadioLink(string) (RadioLink, error)          { return RadioLink{}, errVendorUnsupported }
func WirelessNoise(string) (int, bool)                    { return 0, false }
func VendorRadioParent(string, string) string             { return "" }
func VendorConfiguredDistance(string) (int, string, bool) { return 0, "", false }

func WextFrequency(string) (int, bool) { return 0, false }
func WextTxPower(string) (int, bool)   { return 0, false }
