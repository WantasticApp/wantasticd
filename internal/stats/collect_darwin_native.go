//go:build darwin && cgo

package stats

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

// WiFi info struct passed back to Go
typedef struct {
    char     ifname[32];
    char     ssid[128];
    char     bssid[32];
    char     security[64];
    char     phymode[32];
    int      rssi;          // dBm
    int      noise;         // dBm
    double   txrate;        // Mbps
    int      channel;
    int      band;          // 2 = 2.4GHz, 5 = 5GHz, 6 = 6GHz
    int      channel_width; // MHz
    int      active;        // 1 if interface is active
} CWifiInfo;

// Nearby network info struct
typedef struct {
    char    ssid[128];
    char    bssid[32];
    char    security[64];
    char    phymode[32];
    int     rssi;
    int     noise;
    int     channel;
    int     band;
} CWifiNearby;

static int cw_get_wifi_info(CWifiInfo *info) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) return -1;

        CWInterface *iface = [client interface];
        if (!iface) return -1;

        memset(info, 0, sizeof(CWifiInfo));

        // Interface name
        NSString *name = [iface interfaceName];
        if (name) {
            strncpy(info->ifname, [name UTF8String], sizeof(info->ifname) - 1);
        }

        // Check if powered on
        if (![iface powerOn]) {
            info->active = 0;
            return 0;
        }
        info->active = 1;

        // SSID (may be nil if Location Services not granted)
        NSString *ssid = [iface ssid];
        if (ssid) {
            strncpy(info->ssid, [ssid UTF8String], sizeof(info->ssid) - 1);
        }

        // BSSID (may be nil)
        NSString *bssid = [iface bssid];
        if (bssid) {
            strncpy(info->bssid, [bssid UTF8String], sizeof(info->bssid) - 1);
        }

        // RSSI and Noise
        info->rssi  = (int)[iface rssiValue];
        info->noise = (int)[iface noiseMeasurement];

        // Transmit rate (Mbps as double)
        info->txrate = [iface transmitRate];

        // Channel info
        CWChannel *ch = [iface wlanChannel];
        if (ch) {
            info->channel = (int)[ch channelNumber];
            info->channel_width = (int)[ch channelWidth]; // enum: 0=unknown,1=20,2=40,3=80,4=160

            switch ([ch channelBand]) {
                case kCWChannelBand2GHz: info->band = 2; break;
                case kCWChannelBand5GHz: info->band = 5; break;
                case kCWChannelBand6GHz: info->band = 6; break;
                default: info->band = 0; break;
            }
        }

        // Security (WPA2, WPA3, etc.)
        CWSecurity sec = [iface security];
        const char *sec_str = "unknown";
        switch (sec) {
            case kCWSecurityNone:           sec_str = "none"; break;
            case kCWSecurityWEP:            sec_str = "WEP"; break;
            case kCWSecurityWPAPersonal:    sec_str = "WPA Personal"; break;
            case kCWSecurityWPAEnterprise:  sec_str = "WPA Enterprise"; break;
            case kCWSecurityWPA2Personal:   sec_str = "WPA2 Personal"; break;
            case kCWSecurityWPA2Enterprise: sec_str = "WPA2 Enterprise"; break;
            case kCWSecurityWPA3Personal:   sec_str = "WPA3 Personal"; break;
            case kCWSecurityWPA3Enterprise: sec_str = "WPA3 Enterprise"; break;
            case kCWSecurityWPA3Transition: sec_str = "WPA3 Transition"; break;
            default:                        sec_str = "unknown"; break;
        }
        strncpy(info->security, sec_str, sizeof(info->security) - 1);

        // PHY mode (802.11a/b/g/n/ac/ax/be)
        CWPHYMode phy = [iface activePHYMode];
        const char *phy_str = "unknown";
        switch (phy) {
            case kCWPHYMode11a:  phy_str = "802.11a"; break;
            case kCWPHYMode11b:  phy_str = "802.11b"; break;
            case kCWPHYMode11g:  phy_str = "802.11g"; break;
            case kCWPHYMode11n:  phy_str = "802.11n"; break;
            case kCWPHYMode11ac: phy_str = "802.11ac"; break;
            case kCWPHYMode11ax: phy_str = "802.11ax"; break;
            default:             phy_str = "unknown"; break;
        }
        strncpy(info->phymode, phy_str, sizeof(info->phymode) - 1);

        return 0;
    }
}

// Scan for nearby networks (returns count, fills array up to max_count)
static int cw_scan_nearby(CWifiNearby *results, int max_count) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) return 0;

        CWInterface *iface = [client interface];
        if (!iface) return 0;

        // Use cached scan results (non-blocking, no active scan)
        NSSet<CWNetwork *> *networks = [iface cachedScanResults];
        if (!networks) return 0;

        int count = 0;
        for (CWNetwork *net in networks) {
            if (count >= max_count) break;

            memset(&results[count], 0, sizeof(CWifiNearby));

            NSString *ssid = [net ssid];
            if (ssid && [ssid length] > 0) {
                strncpy(results[count].ssid, [ssid UTF8String], sizeof(results[count].ssid) - 1);
            } else {
                continue; // Skip hidden/redacted networks
            }

            NSString *bssid = [net bssid];
            if (bssid) {
                strncpy(results[count].bssid, [bssid UTF8String], sizeof(results[count].bssid) - 1);
            }

            results[count].rssi  = (int)[net rssiValue];
            results[count].noise = (int)[net noiseMeasurement];

            CWChannel *ch = [net wlanChannel];
            if (ch) {
                results[count].channel = (int)[ch channelNumber];
                switch ([ch channelBand]) {
                    case kCWChannelBand2GHz: results[count].band = 2; break;
                    case kCWChannelBand5GHz: results[count].band = 5; break;
                    case kCWChannelBand6GHz: results[count].band = 6; break;
                    default: results[count].band = 0; break;
                }
            }

            count++;
        }

        return count;
    }
}

// Get hardware MAC address
static int cw_get_mac(char *buf, int buflen) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) return -1;
        CWInterface *iface = [client interface];
        if (!iface) return -1;
        NSString *mac = [iface hardwareAddress];
        if (!mac) return -1;
        strncpy(buf, [mac UTF8String], buflen - 1);
        return 0;
    }
}
*/
import "C"

import (
	"log"
	"net"
	"strings"
	"unsafe"
)

// collectWiFiStatisticsNative uses CoreWLAN framework directly — no exec.Command.
// This replaces the system_profiler based approach with native Objective-C calls.
func collectWiFiStatisticsNative() ([]WiFiInterfaceInfo, bool) {
	var cInfo C.CWifiInfo
	if C.cw_get_wifi_info(&cInfo) != 0 {
		return []WiFiInterfaceInfo{}, false
	}

	ifaceName := C.GoString(&cInfo.ifname[0])
	if ifaceName == "" {
		return []WiFiInterfaceInfo{}, false
	}

	info := WiFiInterfaceInfo{
		Name:      ifaceName,
		SSID:      C.GoString(&cInfo.ssid[0]),
		Connected: cInfo.active == 1 && cInfo.rssi != 0,
		Signal:    int(cInfo.rssi),
		Noise:     int(cInfo.noise),
		Bitrate:   int(cInfo.txrate),
		Channel:   int(cInfo.channel),
		Security:  C.GoString(&cInfo.security[0]),
		PHYMode:   C.GoString(&cInfo.phymode[0]),
	}

	// Try Apple80211 fallback for SSID if CoreWLAN returned empty
	// macOS Ventura+ redacts SSID in CoreWLAN without Location Services
	// even for root, but the private framework may bypass this constraint.
	if info.SSID == "" {
		if a8 := processApple80211(ifaceName); a8 != nil && a8.SSID != "" {
			info.SSID = a8.SSID
		}
	}

	// BSSID
	bssid := C.GoString(&cInfo.bssid[0])
	if bssid != "" {
		info.MAC = bssid
	}

	// Hardware MAC
	var macBuf [32]C.char
	if C.cw_get_mac(&macBuf[0], 32) == 0 {
		info.MAC = C.GoString(&macBuf[0])
	}

	// Frequency from band and channel
	switch cInfo.band {
	case 2:
		if info.Channel >= 1 && info.Channel <= 14 {
			info.Frequency = 2407 + info.Channel*5
			if info.Channel == 14 {
				info.Frequency = 2484
			}
		}
	case 5:
		info.Frequency = 5000 + info.Channel*5
	case 6:
		info.Frequency = 5950 + info.Channel*5
	}

	// SNR
	if info.Signal != 0 && info.Noise != 0 {
		info.SNR = info.Signal - info.Noise
	}

	// SSID may be nil on macOS Ventura+ without Location Services
	if info.SSID == "" && info.Connected {
		log.Println("NOTE: SSID unavailable — macOS requires Location Services for SSID access (System Settings > Privacy & Security > Location Services)")
	}

	// Collect nearby networks from cached scan results
	var nearbyBuf [64]C.CWifiNearby
	nearbyCount := int(C.cw_scan_nearby(&nearbyBuf[0], 64))
	for i := 0; i < nearbyCount; i++ {
		n := &nearbyBuf[i]
		ssid := C.GoString(&n.ssid[0])
		if ssid == "" {
			continue
		}
		nearby := NearbyNetwork{
			SSID:     ssid,
			BSSID:    C.GoString(&n.bssid[0]),
			Signal:   int(n.rssi),
			Noise:    int(n.noise),
			Channel:  int(n.channel),
			Security: C.GoString((*C.char)(unsafe.Pointer(&n.security[0]))),
		}
		info.Nearby = append(info.Nearby, nearby)
	}

	// Get interface TX/RX bytes from net package
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ni := range ifaces {
			if strings.EqualFold(ni.Name, ifaceName) {
				info.MAC = ni.HardwareAddr.String()
				break
			}
		}
	}

	return []WiFiInterfaceInfo{info}, info.Connected
}
