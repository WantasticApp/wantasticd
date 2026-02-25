//go:build darwin && cgo

package stats

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>

// WiFi info from Apple80211 framework
typedef struct {
    char     ssid[128];
    char     bssid[32];
    int      rssi;
    int      noise;
    double   txrate;
    int      channel;
    char     security[64];
    int      active;
} Apple80211Info;

static int get_apple80211_info(const char *ifname_c, Apple80211Info *info) {
    void *lib = dlopen("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Apple80211", RTLD_LAZY);
    if (!lib) return -1;

    int (*Apple80211Open)(void **) = dlsym(lib, "Apple80211Open");
    int (*Apple80211BindToInterface)(void *, CFStringRef) = dlsym(lib, "Apple80211BindToInterface");
    int (*Apple80211Close)(void *) = dlsym(lib, "Apple80211Close");
    int (*Apple80211GetInfoCopy)(void *, CFDictionaryRef *) = dlsym(lib, "Apple80211GetInfoCopy");

    if (!Apple80211Open || !Apple80211BindToInterface || !Apple80211Close || !Apple80211GetInfoCopy) {
        return -2;
    }

    void *a8;
    if (Apple80211Open(&a8) != 0) {
        return -3;
    }

    CFStringRef iface = CFStringCreateWithCString(kCFAllocatorDefault, ifname_c, kCFStringEncodingUTF8);
    if (Apple80211BindToInterface(a8, iface) != 0) {
        Apple80211Close(a8);
        CFRelease(iface);
        return -4; // Often fails if not root
    }

    memset(info, 0, sizeof(Apple80211Info));
    info->active = 1;

    CFDictionaryRef dict = NULL;
    if (Apple80211GetInfoCopy(a8, &dict) == 0 && dict != NULL) {
        // SSID
        CFStringRef ssidStr = CFDictionaryGetValue(dict, CFSTR("SSID_STR"));
        if (ssidStr && CFGetTypeID(ssidStr) == CFStringGetTypeID()) {
            CFStringGetCString(ssidStr, info->ssid, sizeof(info->ssid), kCFStringEncodingUTF8);
        }

        // BSSID
        CFStringRef bssidStr = CFDictionaryGetValue(dict, CFSTR("BSSID"));
        if (bssidStr && CFGetTypeID(bssidStr) == CFStringGetTypeID()) {
             CFStringGetCString(bssidStr, info->bssid, sizeof(info->bssid), kCFStringEncodingUTF8);
        }

        // RSSI
        CFNumberRef rssiNum = CFDictionaryGetValue(dict, CFSTR("RSSI"));
        if (rssiNum && CFGetTypeID(rssiNum) == CFNumberGetTypeID()) {
            CFNumberGetValue(rssiNum, kCFNumberIntType, &info->rssi);
        }

        // Noise
        CFNumberRef noiseNum = CFDictionaryGetValue(dict, CFSTR("NOISE"));
        if (noiseNum && CFGetTypeID(noiseNum) == CFNumberGetTypeID()) {
            CFNumberGetValue(noiseNum, kCFNumberIntType, &info->noise);
        }

        // TX Rate
        CFNumberRef rateNum = CFDictionaryGetValue(dict, CFSTR("RATE"));
        if (rateNum && CFGetTypeID(rateNum) == CFNumberGetTypeID()) {
            CFNumberGetValue(rateNum, kCFNumberDoubleType, &info->txrate);
        }

        // Channel
        CFNumberRef chNum = CFDictionaryGetValue(dict, CFSTR("CHANNEL"));
        if (chNum && CFGetTypeID(chNum) == CFNumberGetTypeID()) {
            CFNumberGetValue(chNum, kCFNumberIntType, &info->channel);
        }

        // Auth
        CFStringRef authStr = CFDictionaryGetValue(dict, CFSTR("AUTH_TYPE"));
        if (authStr && CFGetTypeID(authStr) == CFStringGetTypeID()) {
            CFStringGetCString(authStr, info->security, sizeof(info->security), kCFStringEncodingUTF8);
        }

        CFRelease(dict);
    } else {
        info->active = 0;
    }

    Apple80211Close(a8);
    CFRelease(iface);
    return 0;
}
*/
import "C"
import "unsafe"

// processApple80211 queries the private Apple80211 framework directly.
// This requires root privileges (which the agent has) and bypasses
// some of the Location Services restrictions imposed by the high-level CoreWLAN UI framework.
func processApple80211(ifaceName string) *WiFiInterfaceInfo {
	cIfname := C.CString(ifaceName)
	defer C.free(unsafe.Pointer(cIfname))

	var info C.Apple80211Info
	ret := C.get_apple80211_info(cIfname, &info)

	if ret != 0 || info.active == 0 {
		return nil
	}

	w := &WiFiInterfaceInfo{
		Name:      ifaceName,
		SSID:      C.GoString(&info.ssid[0]),
		Connected: info.rssi != 0,
		Signal:    int(info.rssi),
		Noise:     int(info.noise),
		Bitrate:   int(info.txrate),
		Channel:   int(info.channel),
		Security:  C.GoString(&info.security[0]),
	}

	bssid := C.GoString(&info.bssid[0])
	if bssid != "" {
		w.MAC = bssid
	}

	return w
}
