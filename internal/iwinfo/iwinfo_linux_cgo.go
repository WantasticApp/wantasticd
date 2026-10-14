//go:build linux && iwinfo

// Linux CGo implementation via libiwinfo (OpenWrt).
// Build: CGO_ENABLED=1 go build -tags iwinfo

package iwinfo

/*
#cgo LDFLAGS: -liwinfo
#cgo CFLAGS: -I/usr/include

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ── Minimal iwinfo.h reproduction for CGo ───────────────────────────────────
// Avoids needing the header installed at build time. These structs and constants
// match the libiwinfo ABI on OpenWrt 21.02+ / QSDK.

#define IWINFO_ESSID_MAX_SIZE 32
#define IWINFO_BUFSIZE        24 * 1024

// HW mode bitmask (from iwinfo_hwmodelist)
#define IWINFO_80211_A  (1 << 0)
#define IWINFO_80211_B  (1 << 1)
#define IWINFO_80211_G  (1 << 2)
#define IWINFO_80211_N  (1 << 3)
#define IWINFO_80211_AC (1 << 4)
#define IWINFO_80211_AD (1 << 5)
#define IWINFO_80211_AX (1 << 6)
#define IWINFO_80211_BE (1 << 7)

// HT mode bitmask (from iwinfo_htmodelist)
#define IWINFO_HTMODE_HT20     (1 << 0)
#define IWINFO_HTMODE_HT40     (1 << 1)
#define IWINFO_HTMODE_VHT20    (1 << 2)
#define IWINFO_HTMODE_VHT40    (1 << 3)
#define IWINFO_HTMODE_VHT80    (1 << 4)
#define IWINFO_HTMODE_VHT80_80 (1 << 5)
#define IWINFO_HTMODE_VHT160   (1 << 6)
#define IWINFO_HTMODE_NOHT     (1 << 7)
#define IWINFO_HTMODE_HE20     (1 << 8)
#define IWINFO_HTMODE_HE40     (1 << 9)
#define IWINFO_HTMODE_HE80     (1 << 10)
#define IWINFO_HTMODE_HE80_80  (1 << 11)
#define IWINFO_HTMODE_HE160    (1 << 12)
#define IWINFO_HTMODE_EHT20    (1 << 13)
#define IWINFO_HTMODE_EHT40    (1 << 14)
#define IWINFO_HTMODE_EHT80    (1 << 15)
#define IWINFO_HTMODE_EHT160   (1 << 16)
#define IWINFO_HTMODE_EHT320   (1 << 17)

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

extern const struct iwinfo_ops * iwinfo_backend(const char *ifname);
extern void iwinfo_finish(void);

// ── Safe C wrappers ─────────────────────────────────────────────────────────

static int c_iwinfo_int(const char *ifname, int idx) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops) return -256;
    int val = 0;
    int (*fn)(const char *, int *) = NULL;
    switch (idx) {
        case 0:  fn = ops->signal;       break;
        case 1:  fn = ops->noise;        break;
        case 2:  fn = ops->bitrate;      break;
        case 3:  fn = ops->channel;      break;
        case 4:  fn = ops->frequency;    break;
        case 5:  fn = ops->txpower;      break;
        case 6:  fn = ops->quality;      break;
        case 7:  fn = ops->quality_max;  break;
        case 8:  fn = ops->mode;         break;
        case 9:  fn = ops->hwmodelist;   break;
        case 10: fn = ops->htmodelist;   break;
        case 11: fn = ops->htmode;       break;
    }
    if (!fn) return -256;
    if (fn(ifname, &val) != 0) return -256;
    return val;
}

static int c_iwinfo_str(const char *ifname, int idx, char *buf, int buflen) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops) return -1;
    memset(buf, 0, buflen);
    int (*fn)(const char *, char *) = NULL;
    switch (idx) {
        case 0: fn = ops->ssid;          break;
        case 1: fn = ops->bssid;         break;
        case 2: fn = ops->country;       break;
        case 3: fn = ops->hardware_name; break;
        case 4: fn = ops->phyname;       break;
    }
    if (!fn) return -1;
    return fn(ifname, buf);
}

static int c_iwinfo_assoclist(const char *ifname, char *buf, int *len) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->assoclist) return -1;
    *len = IWINFO_BUFSIZE;
    if (ops->assoclist(ifname, buf, len) != 0) return -1;
    return *len / sizeof(struct iwinfo_assoclist_entry);
}

static int c_iwinfo_assoc_authenticated(struct iwinfo_assoclist_entry *entry) {
    return entry->is_authenticated && entry->is_authorized;
}

static int c_iwinfo_rate_standard(struct iwinfo_rate_entry *rx, struct iwinfo_rate_entry *tx) {
    if (rx->is_eht || tx->is_eht) return 4;
    if (rx->is_he  || tx->is_he)  return 3;
    if (rx->is_vht || tx->is_vht) return 2;
    if (rx->is_ht  || tx->is_ht)  return 1;
    return 0;
}

static int c_iwinfo_survey(const char *ifname, char *buf, int *len) {
    const struct iwinfo_ops *ops = iwinfo_backend(ifname);
    if (!ops || !ops->survey) return -1;
    *len = IWINFO_BUFSIZE;
    if (ops->survey(ifname, buf, len) != 0) return -1;
    return *len / sizeof(struct iwinfo_survey_entry);
}

static void c_iwinfo_finish() { iwinfo_finish(); }
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

// ── Availability ────────────────────────────────────────────────────────────

func Available(ifname string) bool {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))
	return C.iwinfo_backend(cName) != nil
}

// ── Interface info ──────────────────────────────────────────────────────────

func GetInfo(ifname string) (*InterfaceInfo, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	if C.iwinfo_backend(cName) == nil {
		return nil, fmt.Errorf("iwinfo: no backend for %s", ifname)
	}

	info := &InterfaceInfo{Name: ifname}

	// Integer fields
	if v := int(C.c_iwinfo_int(cName, 0)); v != -256 {
		info.Signal = v
	}
	if v := int(C.c_iwinfo_int(cName, 1)); v != -256 {
		info.Noise = v
	}
	if v := int(C.c_iwinfo_int(cName, 2)); v != -256 {
		info.Bitrate = v
	}
	if v := int(C.c_iwinfo_int(cName, 3)); v != -256 {
		info.Channel = v
	}
	if v := int(C.c_iwinfo_int(cName, 4)); v != -256 {
		info.Frequency = v
	}
	if v := int(C.c_iwinfo_int(cName, 5)); v != -256 {
		info.TxPower = v
	}
	if v := int(C.c_iwinfo_int(cName, 6)); v != -256 {
		info.Quality = v
	}
	if v := int(C.c_iwinfo_int(cName, 7)); v != -256 {
		info.QualityMax = v
	}
	if v := int(C.c_iwinfo_int(cName, 8)); v != -256 {
		info.Mode = v
	}

	// String fields
	var buf [256]C.char
	if C.c_iwinfo_str(cName, 0, &buf[0], 256) == 0 {
		info.SSID = C.GoString(&buf[0])
	}
	if C.c_iwinfo_str(cName, 1, &buf[0], 256) == 0 {
		info.BSSID = C.GoString(&buf[0])
	}
	if C.c_iwinfo_str(cName, 2, &buf[0], 256) == 0 {
		info.Country = C.GoString(&buf[0])
	}
	if C.c_iwinfo_str(cName, 3, &buf[0], 256) == 0 {
		info.HardwareName = C.GoString(&buf[0])
	}
	if C.c_iwinfo_str(cName, 4, &buf[0], 256) == 0 {
		info.PHYName = C.GoString(&buf[0])
	}

	return info, nil
}

// ── HW Mode List (802.11 a/b/g/n/ac/ax/be) ─────────────────────────────────

func GetHWModeList(ifname string) (*HWModes, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	bitmask := int(C.c_iwinfo_int(cName, 9))
	if bitmask == -256 {
		return nil, fmt.Errorf("iwinfo: hwmodelist not available for %s", ifname)
	}
	return &HWModes{
		A:  bitmask&C.IWINFO_80211_A != 0,
		B:  bitmask&C.IWINFO_80211_B != 0,
		G:  bitmask&C.IWINFO_80211_G != 0,
		N:  bitmask&C.IWINFO_80211_N != 0,
		AC: bitmask&C.IWINFO_80211_AC != 0,
		AX: bitmask&C.IWINFO_80211_AX != 0,
		BE: bitmask&C.IWINFO_80211_BE != 0,
	}, nil
}

// ── HT Mode List (supported channel widths) ─────────────────────────────────

func GetHTModeList(ifname string) ([]string, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	bitmask := int(C.c_iwinfo_int(cName, 10))
	if bitmask == -256 {
		return nil, fmt.Errorf("iwinfo: htmodelist not available for %s", ifname)
	}

	type entry struct {
		bit  int
		name string
	}
	all := []entry{
		{C.IWINFO_HTMODE_HT20, "HT20"},
		{C.IWINFO_HTMODE_HT40, "HT40"},
		{C.IWINFO_HTMODE_VHT20, "VHT20"},
		{C.IWINFO_HTMODE_VHT40, "VHT40"},
		{C.IWINFO_HTMODE_VHT80, "VHT80"},
		{C.IWINFO_HTMODE_VHT80_80, "VHT80+80"},
		{C.IWINFO_HTMODE_VHT160, "VHT160"},
		{C.IWINFO_HTMODE_HE20, "HE20"},
		{C.IWINFO_HTMODE_HE40, "HE40"},
		{C.IWINFO_HTMODE_HE80, "HE80"},
		{C.IWINFO_HTMODE_HE80_80, "HE80+80"},
		{C.IWINFO_HTMODE_HE160, "HE160"},
		{C.IWINFO_HTMODE_EHT20, "EHT20"},
		{C.IWINFO_HTMODE_EHT40, "EHT40"},
		{C.IWINFO_HTMODE_EHT80, "EHT80"},
		{C.IWINFO_HTMODE_EHT160, "EHT160"},
		{C.IWINFO_HTMODE_EHT320, "EHT320"},
	}

	var modes []string
	for _, e := range all {
		if bitmask&e.bit != 0 {
			modes = append(modes, e.name)
		}
	}
	return modes, nil
}

// ── Current HT Mode ─────────────────────────────────────────────────────────

func GetHTMode(ifname string) (string, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	bitmask := int(C.c_iwinfo_int(cName, 11))
	if bitmask == -256 {
		return "", fmt.Errorf("iwinfo: htmode not available for %s", ifname)
	}

	// htmode returns a single-bit bitmask indicating the current mode
	names := map[int]string{
		C.IWINFO_HTMODE_HT20:     "HT20",
		C.IWINFO_HTMODE_HT40:     "HT40",
		C.IWINFO_HTMODE_VHT20:    "VHT20",
		C.IWINFO_HTMODE_VHT40:    "VHT40",
		C.IWINFO_HTMODE_VHT80:    "VHT80",
		C.IWINFO_HTMODE_VHT80_80: "VHT80+80",
		C.IWINFO_HTMODE_VHT160:   "VHT160",
		C.IWINFO_HTMODE_HE20:     "HE20",
		C.IWINFO_HTMODE_HE40:     "HE40",
		C.IWINFO_HTMODE_HE80:     "HE80",
		C.IWINFO_HTMODE_HE80_80:  "HE80+80",
		C.IWINFO_HTMODE_HE160:    "HE160",
		C.IWINFO_HTMODE_EHT20:    "EHT20",
		C.IWINFO_HTMODE_EHT40:    "EHT40",
		C.IWINFO_HTMODE_EHT80:    "EHT80",
		C.IWINFO_HTMODE_EHT160:   "EHT160",
		C.IWINFO_HTMODE_EHT320:   "EHT320",
		C.IWINFO_HTMODE_NOHT:     "NOHT",
	}
	for bit, name := range names {
		if bitmask&bit != 0 {
			return name, nil
		}
	}
	return "NOHT", nil
}

// ── PHY Name ────────────────────────────────────────────────────────────────

func GetPHYName(ifname string) (string, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))
	var buf [64]C.char
	if C.c_iwinfo_str(cName, 4, &buf[0], 64) != 0 {
		return "", fmt.Errorf("iwinfo: phyname not available for %s", ifname)
	}
	return C.GoString(&buf[0]), nil
}

// ── Associated Stations ─────────────────────────────────────────────────────

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
			MAC:                 mac,
			Signal:              int8(ptr.signal),
			SignalAvg:           int8(ptr.signal_avg),
			Noise:               int8(ptr.noise),
			AuthenticationKnown: true,
			Authenticated:       C.c_iwinfo_assoc_authenticated(ptr) != 0,
			OperatingStandard:   cgoRateOperatingStandard(&ptr.rx_rate, &ptr.tx_rate),
			Inactive:            uint32(ptr.inactive),
			ConnectedTime:       uint32(ptr.connected_time),
			RxPackets:           uint32(ptr.rx_packets),
			TxPackets:           uint32(ptr.tx_packets),
			RxBytes:             uint64(ptr.rx_bytes),
			TxBytes:             uint64(ptr.tx_bytes),
			TxRetries:           uint32(ptr.tx_retries),
			TxFailed:            uint32(ptr.tx_failed),
			RxRate:              uint32(ptr.rx_rate.rate),
			TxRate:              uint32(ptr.tx_rate.rate),
			RxMCS:               int8(ptr.rx_rate.mcs),
			TxMCS:               int8(ptr.tx_rate.mcs),
			RxNSS:               uint8(ptr.rx_rate.nss),
			TxNSS:               uint8(ptr.tx_rate.nss),
			SignalKnown:         true,
			SignalAvgKnown:      true,
			NoiseKnown:          true,
			InactiveKnown:       true,
			ConnectedTimeKnown:  true,
			RxPacketsKnown:      true,
			TxPacketsKnown:      true,
			RxBytesKnown:        true,
			TxBytesKnown:        true,
			TxRetriesKnown:      true,
			TxFailedKnown:       true,
			RxRateKnown:         true,
			TxRateKnown:         true,
		})
	}
	return entries, nil
}

func cgoRateOperatingStandard(rx, tx *C.struct_iwinfo_rate_entry) string {
	switch C.c_iwinfo_rate_standard(rx, tx) {
	case 4:
		return "be"
	case 3:
		return "ax"
	case 2:
		return "ac"
	case 1:
		return "n"
	default:
		return ""
	}
}

// ── Channel Survey ──────────────────────────────────────────────────────────

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

// Close releases libiwinfo resources.
func Close() {
	C.c_iwinfo_finish()
}
