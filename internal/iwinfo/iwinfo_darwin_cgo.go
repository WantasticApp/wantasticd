//go:build darwin && iwinfo

// macOS CGo implementation using CoreWLAN.framework for WiFi control.
// Build: CGO_ENABLED=1 go build -tags iwinfo

package iwinfo

/*
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

struct darwin_wifi_info {
    char ssid[64];
    char bssid[24];
    int  rssi;
    int  noise;
    int  channel;
    int  channel_width;  // 20, 40, 80, 160
    int  tx_rate;        // Mbps
    int  phy_mode;       // 0=unknown, 1=a, 2=b, 3=g, 4=n, 5=ac, 6=ax, 7=be
};

static int c_darwin_wifi_info(const char *ifname, struct darwin_wifi_info *out) {
    @autoreleasepool {
        memset(out, 0, sizeof(*out));
        NSString *name = [NSString stringWithUTF8String:ifname];
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interfaceWithName:name];
        if (!iface) return -1;

        NSString *ssid = [iface ssid];
        if (ssid) strncpy(out->ssid, [ssid UTF8String], sizeof(out->ssid) - 1);

        NSString *bssid = [iface bssid];
        if (bssid) strncpy(out->bssid, [bssid UTF8String], sizeof(out->bssid) - 1);

        out->rssi = (int)[iface rssiValue];
        out->noise = (int)[iface noiseMeasurement];
        out->tx_rate = (int)[iface transmitRate];

        CWChannel *ch = [iface wlanChannel];
        if (ch) {
            out->channel = (int)[ch channelNumber];
            switch ([ch channelWidth]) {
                case kCWChannelWidth20MHz:  out->channel_width = 20;  break;
                case kCWChannelWidth40MHz:  out->channel_width = 40;  break;
                case kCWChannelWidth80MHz:  out->channel_width = 80;  break;
                case kCWChannelWidth160MHz: out->channel_width = 160; break;
                default:                   out->channel_width = 20;   break;
            }
        }

        switch ([iface activePHYMode]) {
            case kCWPHYMode11a:  out->phy_mode = 1; break;
            case kCWPHYMode11b:  out->phy_mode = 2; break;
            case kCWPHYMode11g:  out->phy_mode = 3; break;
            case kCWPHYMode11n:  out->phy_mode = 4; break;
            case kCWPHYMode11ac: out->phy_mode = 5; break;
            case kCWPHYMode11ax: out->phy_mode = 6; break;
            default:             out->phy_mode = 0; break;
        }
        return 0;
    }
}

struct darwin_wifi_caps {
    int ht, vht, he, eht;
    int max_width; // max supported channel width
    int bands[4];  // 0=none, 2=2.4GHz, 5=5GHz, 6=6GHz
    int num_bands;
};

static int c_darwin_wifi_caps(const char *ifname, struct darwin_wifi_caps *out) {
    @autoreleasepool {
        memset(out, 0, sizeof(*out));
        NSString *name = [NSString stringWithUTF8String:ifname];
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interfaceWithName:name];
        if (!iface) return -1;

        NSSet<CWChannel *> *channels = [iface supportedWLANChannels];
        int maxWidth = 20;

        for (CWChannel *ch in channels) {
            int w = 20;
            switch ([ch channelWidth]) {
                case kCWChannelWidth40MHz:  w = 40;  break;
                case kCWChannelWidth80MHz:  w = 80;  break;
                case kCWChannelWidth160MHz: w = 160; break;
                default: break;
            }
            if (w > maxWidth) maxWidth = w;

            // Detect bands from channel numbers
            int num = (int)[ch channelNumber];
            int band = 0;
            if (num >= 1 && num <= 14) band = 2;
            else if (num >= 32 && num <= 177) band = 5;
            else if (num >= 1 && num <= 233) band = 6; // 6GHz channels overlap

            if (band > 0 && out->num_bands < 4) {
                int found = 0;
                for (int i = 0; i < out->num_bands; i++) {
                    if (out->bands[i] == band) { found = 1; break; }
                }
                if (!found) out->bands[out->num_bands++] = band;
            }
        }

        out->max_width = maxWidth;
        // Infer capabilities from supported PHY modes
        NSSet<NSNumber *> *modes = [iface supportedWLANChannels] ? [NSSet set] : nil;
        // Use max width as proxy for capability level
        if (maxWidth >= 20) out->ht = 1;
        if (maxWidth >= 80) out->vht = 1;
        // HE/EHT detection via active PHY mode (best we can do without private API)
        if ([iface activePHYMode] >= kCWPHYMode11ax) out->he = 1;

        return 0;
    }
}
*/
import "C"

import "fmt"

func Available(ifname string) bool {
	var info C.struct_darwin_wifi_info
	cName := C.CString(ifname)
	defer C.free(C.unsafe.Pointer(cName))
	return C.c_darwin_wifi_info(cName, &info) == 0
}

func GetInfo(ifname string) (*InterfaceInfo, error) {
	var info C.struct_darwin_wifi_info
	cName := C.CString(ifname)
	defer C.free(C.unsafe.Pointer(cName))

	if C.c_darwin_wifi_info(cName, &info) != 0 {
		return nil, fmt.Errorf("CoreWLAN: no WiFi interface %s", ifname)
	}

	return &InterfaceInfo{
		Name:    ifname,
		SSID:    C.GoString(&info.ssid[0]),
		BSSID:   C.GoString(&info.bssid[0]),
		Signal:  int(info.rssi),
		Noise:   int(info.noise),
		Channel: int(info.channel),
		Bitrate: int(info.tx_rate) * 1000,
	}, nil
}

func GetHWModeList(ifname string) (*HWModes, error) {
	var caps C.struct_darwin_wifi_caps
	cName := C.CString(ifname)
	defer C.free(C.unsafe.Pointer(cName))

	if C.c_darwin_wifi_caps(cName, &caps) != 0 {
		return nil, fmt.Errorf("CoreWLAN: interface %s not found", ifname)
	}

	hw := &HWModes{N: caps.ht != 0, AC: caps.vht != 0, AX: caps.he != 0}
	for i := 0; i < int(caps.num_bands); i++ {
		switch caps.bands[i] {
		case 2:
			hw.B, hw.G = true, true
		case 5:
			hw.A = true
		}
	}
	return hw, nil
}

func GetHTModeList(ifname string) ([]string, error) {
	var caps C.struct_darwin_wifi_caps
	cName := C.CString(ifname)
	defer C.free(C.unsafe.Pointer(cName))

	if C.c_darwin_wifi_caps(cName, &caps) != 0 {
		return nil, fmt.Errorf("CoreWLAN: interface %s not found", ifname)
	}

	var modes []string
	if caps.ht != 0 {
		modes = append(modes, "HT20", "HT40")
	}
	if caps.vht != 0 {
		modes = append(modes, "VHT20", "VHT40", "VHT80")
		if caps.max_width >= 160 {
			modes = append(modes, "VHT160")
		}
	}
	if caps.he != 0 {
		modes = append(modes, "HE20", "HE40", "HE80")
		if caps.max_width >= 160 {
			modes = append(modes, "HE160")
		}
	}
	return modes, nil
}

func GetHTMode(ifname string) (string, error) {
	var info C.struct_darwin_wifi_info
	cName := C.CString(ifname)
	defer C.free(C.unsafe.Pointer(cName))

	if C.c_darwin_wifi_info(cName, &info) != 0 {
		return "NOHT", nil
	}

	prefix := "HT"
	switch {
	case info.phy_mode == 6:
		prefix = "HE"
	case info.phy_mode == 5:
		prefix = "VHT"
	}
	return fmt.Sprintf("%s%d", prefix, info.channel_width), nil
}

func GetPHYName(ifname string) (string, error) { return ifname, nil }
func GetAssocList(ifname string) ([]AssocEntry, error) { return nil, nil }
func GetSurvey(ifname string) ([]SurveyEntry, error) { return nil, nil }
func Close() {}
