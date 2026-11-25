package fiberonu

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// ---- TR-181 Device.WiFi writes ----------------------------------------------
//
// collect_wifi_radios.go publishes Device.WiFi.Radio/SSID/AccessPoint from
// the same tcapi nodes as Network.Radio/SSID, with the same instance
// numbers: Radio.{i} is the i-th present band, SSID.{k} and AccessPoint.{k}
// are Network.SSID.{k}. A TR-181 write is translated onto the vendor change
// set here, so both families validate the same way and produce the same
// tcapi writes and commits.
//
//	Device.WiFi.Radio.{i}.Enable                        Radio.{i}.Enable (APOn)
//	Device.WiFi.Radio.{i}.Channel                       Radio.{i}.Channel
//	Device.WiFi.Radio.{i}.AutoChannelEnable             true: Radio.{i}.Channel 0;
//	                                                    false: pin the operating channel
//	Device.WiFi.Radio.{i}.OperatingChannelBandwidth     Radio.{i}.Bandwidth
//	Device.WiFi.Radio.{i}.TransmitPower                 Radio.{i}.TxPower (percent)
//	Device.WiFi.SSID.{k}.SSID                           SSID.{k}.Name
//	Device.WiFi.SSID.{k}.Enable                         SSID.{k}.Enable (EnableSSID)
//	Device.WiFi.AccessPoint.{k}.Enable                  SSID.{k}.Enable (EnableSSID)
//	Device.WiFi.AccessPoint.{k}.SSIDAdvertisementEnabled  SSID.{k}.Hidden, inverted
//	Device.WiFi.AccessPoint.{k}.MaxAllowedAssociations  SSID.{k}.MaxStations
//	Device.WiFi.AccessPoint.{k}.MaxAssociatedDevices    SSID.{k}.MaxStations
//	Device.WiFi.AccessPoint.{k}.Security.ModeEnabled    SSID.{k}.AuthMode
//	Device.WiFi.AccessPoint.{k}.Security.EncryptionMode SSID.{k}.Encryption
//	Device.WiFi.AccessPoint.{k}.Security.KeyPassphrase  SSID.{k}.Passphrase (write-only)

// tr181SecurityModes maps Security.ModeEnabled to the vendor AuthMode.
var tr181SecurityModes = map[string]string{
	"None":                     "OPEN",
	"WPA-Personal":             "WPAPSK",
	"WPA2-Personal":            "WPA2PSK",
	"WPA-WPA2-Personal":        "WPAPSKWPA2PSK",
	"WPA3-Personal":            "WPA3PSK",
	"WPA3-Personal-Transition": "WPA2PSKWPA3PSK",
}

// authModeTR181 is the reverse, for the collector.
var authModeTR181 = map[string]string{
	"OPEN":           "None",
	"WPAPSK":         "WPA-Personal",
	"WPA2PSK":        "WPA2-Personal",
	"WPAPSKWPA2PSK":  "WPA-WPA2-Personal",
	"WPA3PSK":        "WPA3-Personal",
	"WPA2PSKWPA3PSK": "WPA3-Personal-Transition",
}

// tr181EncryptionMode maps Security.EncryptionMode (a TR-181 list of TKIP
// and AES) to the vendor EncrypType.
func tr181EncryptionMode(text string) (string, bool) {
	tkip, aes := false, false
	for _, part := range strings.FieldsFunc(strings.ToUpper(text), func(r rune) bool { return r == ',' || r == ' ' || r == '-' || r == '+' }) {
		switch part {
		case "TKIP":
			tkip = true
		case "AES":
			aes = true
		case "TKIPAES":
			tkip, aes = true, true
		default:
			return "", false
		}
	}
	switch {
	case tkip && aes:
		return "TKIPAES", true
	case aes:
		return "AES", true
	case tkip:
		return "TKIP", true
	}
	return "", false
}

// encrypTypeTR181 is the reverse, for the collector.
func encrypTypeTR181(enc string) []string {
	switch enc {
	case "AES":
		return []string{"AES"}
	case "TKIP":
		return []string{"TKIP"}
	case "TKIPAES":
		return []string{"TKIP", "AES"}
	}
	return nil
}

// tr181BandwidthToVendor maps OperatingChannelBandwidth onto the vendor
// width names. "Auto" on 2.4 GHz is 20/40 MHz with BSS coexistence, as the
// collector reports it; 40MHz on 5 GHz is the page's 20/40 MHz (VHT_BW 0).
func tr181BandwidthToVendor(b wlanBand, v string) (string, error) {
	switch strings.TrimSpace(v) {
	case "20MHz":
		return "20 MHz", nil
	case "40MHz":
		if b.vht {
			return "20/40 MHz", nil
		}
		return "40 MHz", nil
	case "Auto":
		if !b.vht {
			return "20/40 MHz", nil
		}
	case "80MHz":
		return "80 MHz", nil
	case "160MHz":
		return "160 MHz", nil
	}
	if b.vht {
		return "", fmt.Errorf("bandwidth %q is not offered; choose 20MHz, 40MHz, 80MHz or 160MHz", v)
	}
	return "", fmt.Errorf("bandwidth %q is not offered; choose 20MHz, Auto (20/40 MHz) or 40MHz", v)
}

// vendorBandwidthTR181 is the reverse, for the collector's capability list.
func vendorBandwidthTR181(b wlanBand, v string) string {
	switch v {
	case "20 MHz":
		return "20MHz"
	case "20/40 MHz":
		if b.vht {
			return "40MHz"
		}
		return "Auto"
	case "40 MHz":
		return "40MHz"
	case "80 MHz":
		return "80MHz"
	case "160 MHz":
		return "160MHz"
	}
	return ""
}

// splitWiFiTR181 splits Device.WiFi.<Object>.<i>.<leaf> into its object,
// instance and leaf ("Security.ModeEnabled" for the AccessPoint
// sub-object).
func splitWiFiTR181(path string) (object string, idx int, leaf string, ok bool) {
	rest, found := strings.CutPrefix(path, wifiPrefix)
	if !found {
		return "", 0, "", false
	}
	parts := strings.SplitN(rest, ".", 3)
	if len(parts) != 3 {
		return "", 0, "", false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil || n < 1 || strconv.Itoa(n) != parts[1] {
		return "", 0, "", false
	}
	return parts[0], n, parts[2], true
}

// isWiFiTR181Leaf says whether path is one of the writable Device.WiFi
// leaves above.
func isWiFiTR181Leaf(path string) bool {
	object, _, leaf, ok := splitWiFiTR181(path)
	if !ok {
		return false
	}
	switch object + "." + leaf {
	case "Radio.Enable", "Radio.Channel", "Radio.AutoChannelEnable",
		"Radio.OperatingChannelBandwidth", "Radio.TransmitPower",
		"SSID.SSID", "SSID.Enable",
		"AccessPoint.Enable", "AccessPoint.SSIDAdvertisementEnabled",
		"AccessPoint.MaxAllowedAssociations", "AccessPoint.MaxAssociatedDevices",
		"AccessPoint.Security.ModeEnabled", "AccessPoint.Security.EncryptionMode",
		"AccessPoint.Security.KeyPassphrase":
		return true
	}
	return false
}

// addTR181 records one Device.WiFi leaf onto the change set. The value text
// is not echoed in errors for KeyPassphrase.
func (c *wlanChangeSet) addTR181(path, text string) error {
	object, idx, leaf, ok := splitWiFiTR181(strings.TrimSpace(path))
	if !ok || !isWiFiTR181Leaf(path) {
		return wusp.ErrUSPPathUnsupported
	}
	radio := "Radio." + strconv.Itoa(idx) + "."
	ssid := "SSID." + strconv.Itoa(idx) + "."
	switch object + "." + leaf {
	case "Radio.Enable":
		return c.add(radio+"Enable", text)
	case "Radio.Channel":
		return c.add(radio+"Channel", text)
	case "Radio.AutoChannelEnable":
		v, err := parseBoolValue("AutoChannelEnable", text)
		if err != nil {
			return err
		}
		c.radio(idx).auto = v
		return nil
	case "Radio.OperatingChannelBandwidth":
		v := strings.TrimSpace(text)
		r := c.radio(idx)
		r.bandwidth = &v
		r.bwTR181 = true
		return nil
	case "Radio.TransmitPower":
		v, err := strconv.ParseInt(strings.TrimSpace(text), 10, 16)
		if err != nil || v < 0 {
			return fmt.Errorf("onu wlan: TransmitPower must be a percentage (automatic, -1, is not offered)")
		}
		return c.add(radio+"TxPower", strconv.FormatInt(v, 10))
	case "SSID.SSID":
		return c.add(ssid+"Name", text)
	case "SSID.Enable", "AccessPoint.Enable":
		return c.add(ssid+"Enable", text)
	case "AccessPoint.SSIDAdvertisementEnabled":
		v, err := parseBoolValue("SSIDAdvertisementEnabled", text)
		if err != nil {
			return err
		}
		return c.add(ssid+"Hidden", strconv.FormatBool(!*v))
	case "AccessPoint.MaxAllowedAssociations", "AccessPoint.MaxAssociatedDevices":
		if _, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16); err != nil {
			return fmt.Errorf("onu wlan: %s must be a whole number", leaf)
		}
		return c.add(ssid+"MaxStations", text)
	case "AccessPoint.Security.ModeEnabled":
		auth, ok := tr181SecurityModes[strings.TrimSpace(text)]
		if !ok {
			return fmt.Errorf("onu wlan: Security.ModeEnabled %q is not offered; choose None, WPA-Personal, WPA2-Personal, WPA-WPA2-Personal, WPA3-Personal or WPA3-Personal-Transition", fieldPathForError(strings.TrimSpace(text)))
		}
		return c.add(ssid+"AuthMode", auth)
	case "AccessPoint.Security.EncryptionMode":
		enc, ok := tr181EncryptionMode(text)
		if !ok {
			return fmt.Errorf("onu wlan: Security.EncryptionMode must be AES, TKIP or TKIP,AES")
		}
		return c.add(ssid+"Encryption", enc)
	case "AccessPoint.Security.KeyPassphrase":
		return c.add(ssid+"Passphrase", text)
	}
	return wusp.ErrUSPPathUnsupported
}

// SetWiFiTR181Param applies one Device.WiFi.* write on the MediaTek driver
// as its own change set. Paths it does not handle, and builds without the
// MediaTek driver, return wusp.ErrUSPPathUnsupported.
func SetWiFiTR181Param(ctx context.Context, opts Options, path string, value wusp.Value) error {
	path = strings.TrimSpace(path)
	if !isWiFiTR181Leaf(path) || len(presentBands(opts)) == 0 {
		return wusp.ErrUSPPathUnsupported
	}
	var change wlanChangeSet
	if err := change.addTR181(path, wusp.ValueToString(value)); err != nil {
		return err
	}
	if change.empty() {
		return errors.New("onu wlan: nothing to change")
	}
	return applyWLAN(ctx, opts, &change)
}
