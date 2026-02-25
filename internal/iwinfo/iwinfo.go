//go:build linux && iwinfo

package iwinfo

/*
#cgo LDFLAGS: -liwinfo
#cgo CFLAGS: -I/usr/include

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Forward-declare the iwinfo API we need.
// On OpenWrt/QSDK, linking against -liwinfo provides these symbols.
// The iwinfo_ops struct has function pointers for each backend (nl80211, wext, madwifi).

// Minimal iwinfo.h reproduction for CGo (avoids needing the header installed at build time)
#define IWINFO_ESSID_MAX_SIZE 32
#define IWINFO_BUFSIZE        24 * 1024

struct iwinfo_rate_entry {
    uint32_t rate;
    int8_t   mcs;
    uint8_t  is_40mhz:1;
    uint8_t  is_short_gi:1;
    uint8_t  is_ht:1;
    uint8_t  is_vht:1;
    uint8_t  is_he:1;
    uint8_t  is_eht:1;
    uint8_t  he_gi;
    uint8_t  he_dcm;
    uint8_t  mhz;
    uint8_t  nss;
    uint8_t  mhz_hi;
    uint8_t  eht_gi;
};

struct iwinfo_assoclist_entry {
    uint8_t  mac[6];
    int8_t   signal;
    int8_t   signal_avg;
    int8_t   noise;
    uint32_t inactive;
    uint32_t connected_time;
    uint32_t rx_packets;
    uint32_t tx_packets;
    uint64_t rx_drop_misc;
    struct iwinfo_rate_entry rx_rate;
    struct iwinfo_rate_entry tx_rate;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint64_t t_offset;
    uint8_t  is_authorized:1;
    uint8_t  is_authenticated:1;
    uint8_t  is_preamble_short:1;
    uint8_t  is_wme:1;
    uint8_t  is_mfp:1;
    uint8_t  is_tdls:1;
    uint32_t thr;
    uint16_t llid;
    uint16_t plid;
    char     plink_state[16];
    char     local_ps[16];
    char     peer_ps[16];
    char     nonpeer_ps[16];
};

struct iwinfo_survey_entry {
    uint64_t active_time;
    uint64_t busy_time;
    uint64_t busy_time_ext;
    uint64_t rxtime;
    uint64_t txtime;
    uint32_t mhz;
    uint8_t  noise;
};

struct iwinfo_ops {
    const char *name;
    int (*probe)(const char *);
    int (*mode)(const char *, int *);
    int (*channel)(const char *, int *);
    int (*center_chan1)(const char *, int *);
    int (*center_chan2)(const char *, int *);
    int (*frequency)(const char *, int *);
    int (*frequency_offset)(const char *, int *);
    int (*txpower)(const char *, int *);
    int (*txpower_offset)(const char *, int *);
    int (*bitrate)(const char *, int *);
    int (*signal)(const char *, int *);
    int (*noise)(const char *, int *);
    int (*quality)(const char *, int *);
    int (*quality_max)(const char *, int *);
    int (*mbssid_support)(const char *, int *);
    int (*hwmodelist)(const char *, int *);
    int (*htmodelist)(const char *, int *);
    int (*htmode)(const char *, int *);
    int (*ssid)(const char *, char *);
    int (*bssid)(const char *, char *);
    int (*country)(const char *, char *);
    int (*hardware_id)(const char *, char *);
    int (*hardware_name)(const char *, char *);
    int (*encryption)(const char *, char *);
    int (*phyname)(const char *, char *);
    int (*assoclist)(const char *, char *, int *);
    int (*txpwrlist)(const char *, char *, int *);
    int (*scanlist)(const char *, char *, int *);
    int (*freqlist)(const char *, char *, int *);
    int (*countrylist)(const char *, char *, int *);
    int (*survey)(const char *, char *, int *);
    int (*lookup_phy)(const char *, char *);
    int (*phy_path)(const char *, const char **);
    void (*close)(void);
};

// These are the actual symbols exported by libiwinfo.so
extern const struct iwinfo_ops * iwinfo_backend(const char *ifname);
extern void iwinfo_finish(void);

// Safe C wrappers that handle NULL checks to prevent Go panics

static int c_iwinfo_signal(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->signal) return -256; // sentinel: not available
    int val = 0;
    if (ops->signal(ifname, &val) != 0) return -256;
    return val;
}

static int c_iwinfo_noise(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->noise) return -256;
    int val = 0;
    if (ops->noise(ifname, &val) != 0) return -256;
    return val;
}

static int c_iwinfo_bitrate(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->bitrate) return -1;
    int val = 0;
    if (ops->bitrate(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_channel(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->channel) return -1;
    int val = 0;
    if (ops->channel(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_frequency(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->frequency) return -1;
    int val = 0;
    if (ops->frequency(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_txpower(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->txpower) return -1;
    int val = 0;
    if (ops->txpower(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_quality(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->quality) return -1;
    int val = 0;
    if (ops->quality(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_quality_max(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->quality_max) return -1;
    int val = 0;
    if (ops->quality_max(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_mode(const char *ifname) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->mode) return -1;
    int val = 0;
    if (ops->mode(ifname, &val) != 0) return -1;
    return val;
}

static int c_iwinfo_ssid(const char *ifname, char *buf, int buflen) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->ssid) return -1;
    memset(buf, 0, buflen);
    return ops->ssid(ifname, buf);
}

static int c_iwinfo_bssid(const char *ifname, char *buf, int buflen) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->bssid) return -1;
    memset(buf, 0, buflen);
    return ops->bssid(ifname, buf);
}

// Assoclist: returns number of entries, fills buf with iwinfo_assoclist_entry structs
static int c_iwinfo_assoclist(const char *ifname, char *buf, int *len) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->assoclist) return -1;
    *len = IWINFO_BUFSIZE;
    if (ops->assoclist(ifname, buf, len) != 0) return -1;
    return *len / sizeof(struct iwinfo_assoclist_entry);
}

// Survey: returns number of entries
static int c_iwinfo_survey(const char *ifname, char *buf, int *len) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->survey) return -1;
    *len = IWINFO_BUFSIZE;
    if (ops->survey(ifname, buf, len) != 0) return -1;
    return *len / sizeof(struct iwinfo_survey_entry);
}

static void c_iwinfo_finish() {
    iwinfo_finish();
}
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

// Available returns true if libiwinfo is linked and the backend can probe the interface.
func Available(ifname string) bool {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))
	return C.iwinfo_backend(cName) != nil
}

// InterfaceInfo holds all collected WiFi data for an interface
type InterfaceInfo struct {
	Name       string
	SSID       string
	BSSID      string
	Mode       int // 0=unknown, 1=master, 2=adhoc, 3=client, ...
	Signal     int // dBm
	Noise      int // dBm
	Bitrate    int // kbit/s (divide by 1000 for Mbps)
	Channel    int
	Frequency  int // MHz
	TxPower    int // dBm
	Quality    int
	QualityMax int
}

// GetInfo gets comprehensive WiFi info for an interface via libiwinfo
func GetInfo(ifname string) (*InterfaceInfo, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	if C.iwinfo_backend(cName) == nil {
		return nil, fmt.Errorf("iwinfo: no backend for %s", ifname)
	}

	info := &InterfaceInfo{Name: ifname}

	sig := int(C.c_iwinfo_signal(cName))
	if sig != -256 {
		info.Signal = sig
	}

	noise := int(C.c_iwinfo_noise(cName))
	if noise != -256 {
		info.Noise = noise
	}

	br := int(C.c_iwinfo_bitrate(cName))
	if br >= 0 {
		info.Bitrate = br
	}

	ch := int(C.c_iwinfo_channel(cName))
	if ch >= 0 {
		info.Channel = ch
	}

	freq := int(C.c_iwinfo_frequency(cName))
	if freq >= 0 {
		info.Frequency = freq
	}

	txp := int(C.c_iwinfo_txpower(cName))
	if txp >= 0 {
		info.TxPower = txp
	}

	qual := int(C.c_iwinfo_quality(cName))
	if qual >= 0 {
		info.Quality = qual
	}

	qualMax := int(C.c_iwinfo_quality_max(cName))
	if qualMax >= 0 {
		info.QualityMax = qualMax
	}

	mode := int(C.c_iwinfo_mode(cName))
	if mode >= 0 {
		info.Mode = mode
	}

	// SSID
	var ssidBuf [64]C.char
	if C.c_iwinfo_ssid(cName, &ssidBuf[0], 64) == 0 {
		info.SSID = C.GoString(&ssidBuf[0])
	}

	// BSSID
	var bssidBuf [64]C.char
	if C.c_iwinfo_bssid(cName, &bssidBuf[0], 64) == 0 {
		info.BSSID = C.GoString(&bssidBuf[0])
	}

	return info, nil
}

// AssocEntry represents a connected station (client)
type AssocEntry struct {
	MAC           net.HardwareAddr
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
	RxRate        uint32 // kbit/s
	TxRate        uint32 // kbit/s
	RxMCS         int8
	TxMCS         int8
	RxNSS         uint8
	TxNSS         uint8
}

// GetAssocList returns the list of associated stations for an AP interface
func GetAssocList(ifname string) ([]AssocEntry, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	buf := C.malloc(C.IWINFO_BUFSIZE)
	if buf == nil {
		return nil, fmt.Errorf("iwinfo: malloc failed")
	}
	defer C.free(buf)

	var length C.int
	count := int(C.c_iwinfo_assoclist(cName, (*C.char)(buf), &length))
	if count < 0 {
		return nil, fmt.Errorf("iwinfo: assoclist failed for %s", ifname)
	}

	entries := make([]AssocEntry, 0, count)
	entrySize := C.sizeof_struct_iwinfo_assoclist_entry

	for i := 0; i < count; i++ {
		ptr := (*C.struct_iwinfo_assoclist_entry)(
			unsafe.Pointer(uintptr(buf) + uintptr(i)*uintptr(entrySize)),
		)

		mac := make(net.HardwareAddr, 6)
		for j := 0; j < 6; j++ {
			mac[j] = byte(ptr.mac[j])
		}

		entries = append(entries, AssocEntry{
			MAC:           mac,
			Signal:        int8(ptr.signal),
			SignalAvg:     int8(ptr.signal_avg),
			Noise:         int8(ptr.noise),
			Inactive:      uint32(ptr.inactive),
			ConnectedTime: uint32(ptr.connected_time),
			RxPackets:     uint32(ptr.rx_packets),
			TxPackets:     uint32(ptr.tx_packets),
			RxBytes:       uint64(ptr.rx_bytes),
			TxBytes:       uint64(ptr.tx_bytes),
			TxRetries:     uint32(ptr.tx_retries),
			TxFailed:      uint32(ptr.tx_failed),
			RxRate:        uint32(ptr.rx_rate.rate),
			TxRate:        uint32(ptr.tx_rate.rate),
			RxMCS:         int8(ptr.rx_rate.mcs),
			TxMCS:         int8(ptr.tx_rate.mcs),
			RxNSS:         uint8(ptr.rx_rate.nss),
			TxNSS:         uint8(ptr.tx_rate.nss),
		})
	}

	return entries, nil
}

// SurveyEntry represents channel survey data
type SurveyEntry struct {
	ActiveTime uint64
	BusyTime   uint64
	RxTime     uint64
	TxTime     uint64
	Frequency  uint32 // MHz
	Noise      int8   // dBm
}

// GetSurvey returns channel survey results for an interface
func GetSurvey(ifname string) ([]SurveyEntry, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	buf := C.malloc(C.IWINFO_BUFSIZE)
	if buf == nil {
		return nil, fmt.Errorf("iwinfo: malloc failed")
	}
	defer C.free(buf)

	var length C.int
	count := int(C.c_iwinfo_survey(cName, (*C.char)(buf), &length))
	if count < 0 {
		return nil, fmt.Errorf("iwinfo: survey failed for %s", ifname)
	}

	entries := make([]SurveyEntry, 0, count)
	entrySize := C.sizeof_struct_iwinfo_survey_entry

	for i := 0; i < count; i++ {
		ptr := (*C.struct_iwinfo_survey_entry)(
			unsafe.Pointer(uintptr(buf) + uintptr(i)*uintptr(entrySize)),
		)

		entries = append(entries, SurveyEntry{
			ActiveTime: uint64(ptr.active_time),
			BusyTime:   uint64(ptr.busy_time),
			RxTime:     uint64(ptr.rxtime),
			TxTime:     uint64(ptr.txtime),
			Frequency:  uint32(ptr.mhz),
			Noise:      int8(ptr.noise),
		})
	}

	return entries, nil
}

// Close releases libiwinfo resources. Call when done.
func Close() {
	C.c_iwinfo_finish()
}
