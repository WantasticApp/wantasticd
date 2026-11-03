//go:build android

package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
)

// On Android the app reads the phone through Android's own APIs (an app
// cannot read /proc, netlink or nl80211) and hands the reading over with
// SetAndroidSnapshot; the native desktop path turns it into the data model.

var androidSnapshot atomic.Pointer[desktopSnapshot]

var errAndroidReadOnly = errors.New("Android does not let apps change this setting")

type androidProbe struct{}

func newDesktopProbe(CommandRunner) desktopProbe { return androidProbe{} }

func (androidProbe) collect(context.Context) *desktopSnapshot {
	snap := androidSnapshot.Load()
	if snap == nil {
		return nil
	}
	copy := *snap
	return &copy
}

func (androidProbe) setHostname(context.Context, string) error        { return errAndroidReadOnly }
func (androidProbe) setTimeZone(context.Context, string) error        { return errAndroidReadOnly }
func (androidProbe) setTimeEnabled(context.Context, bool) error       { return errAndroidReadOnly }
func (androidProbe) setNTPServers(context.Context, []string) error    { return errAndroidReadOnly }
func (androidProbe) setWiFiRadio(context.Context, string, bool) error { return errAndroidReadOnly }

// androidReading is the app's JSON; zero values mean unknown.
type androidReading struct {
	Manufacturer    string `json:"manufacturer"`
	ModelName       string `json:"model_name"`
	ModelNumber     string `json:"model_number"`
	HardwareVersion string `json:"hardware_version"`
	SoftwareVersion string `json:"software_version"`
	Description     string `json:"description"`
	Hostname        string `json:"hostname"`
	ProcessorModel  string `json:"processor_model"`
	Architecture    string `json:"architecture"`
	MemTotalKiB     uint64 `json:"mem_total_kib"`
	MemFreeKiB      uint64 `json:"mem_free_kib"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	TimeZone        string `json:"time_zone"`
	AutoTime        *bool  `json:"auto_time"`
	WiFi            *struct {
		Connected  bool   `json:"connected"`
		SSID       string `json:"ssid"`
		BSSID      string `json:"bssid"`
		RSSI       *int   `json:"rssi"`
		Channel    int    `json:"channel"`
		Band       string `json:"band"`
		WidthMHz   int    `json:"width_mhz"`
		Standard   string `json:"standard"`
		TxRateKbps uint64 `json:"tx_rate_kbps"`
		RxRateKbps uint64 `json:"rx_rate_kbps"`
		Security   string `json:"security"`
	} `json:"wifi"`
}

// SetAndroidSnapshot stores the app's latest reading of the phone.
func SetAndroidSnapshot(data []byte) error {
	var r androidReading
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	snap := &desktopSnapshot{
		Manufacturer: r.Manufacturer, ModelName: r.ModelName, ModelNumber: r.ModelNumber,
		HardwareVersion: r.HardwareVersion, SoftwareVersion: r.SoftwareVersion, Description: r.Description,
		Hostname: r.Hostname, ComputerName: r.Hostname,
		ProcessorModel: r.ProcessorModel, Architecture: r.Architecture,
		MemTotalKiB: r.MemTotalKiB, MemFreeKiB: r.MemFreeKiB, UptimeSeconds: r.UptimeSeconds,
		TimeZone: r.TimeZone,
	}
	if r.AutoTime != nil {
		snap.Time = timeState{Enabled: *r.AutoTime, Known: true}
	}
	if w := r.WiFi; w != nil {
		wifi := desktopWiFi{
			Interface: "wlan0", PowerOn: true, Connected: w.Connected, SSID: w.SSID,
			Channel: w.Channel, Band: w.Band, WidthMHz: w.WidthMHz, Standard: w.Standard,
			TxRateKbps: w.TxRateKbps, RxRateKbps: w.RxRateKbps, Security: w.Security,
		}
		if mac, err := net.ParseMAC(w.BSSID); err == nil {
			wifi.BSSID = mac
		}
		if w.RSSI != nil {
			wifi.RSSI, wifi.RSSIKnown = *w.RSSI, true
		}
		snap.WiFi = []desktopWiFi{wifi}
	}
	androidSnapshot.Store(snap)
	return nil
}
