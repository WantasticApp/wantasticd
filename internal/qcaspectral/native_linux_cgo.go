//go:build linux && cgo && qsdk

// Native QCA spectral control for QSDK/qca-wifi radios.
// Build: CGO_ENABLED=1 go build -tags qsdk
//
// No QSDK headers are needed at build time: the ath_diag ioctl ABI and the
// SAMP message layouts are reproduced below, matching spectraltool from
// qca-wifi 10.2 and the cmn_dev spectral dispatcher. Nothing is linked beyond
// libc; the driver is reached through ioctl and netlink only.

package qcaspectral

/*
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sockios.h>

#define WQ_NETLINK_ATHEROS 17
#define WQ_SIOCGATHPHYERR  (SIOCDEVPRIVATE + 5)
#define WQ_ATH_DIAG_DYN    0x8000

// Spectral sub-command offsets from DFS_LAST_IOCTL (spectral_ioctl.h).
#define WQ_ACTIVATE_SCAN        6
#define WQ_STOP_SCAN            7
#define WQ_IS_ACTIVE            9
#define WQ_GET_CAPABILITY_INFO 16

// struct ath_diag from if_athioctl.h: natural alignment, pointer-sized
// buffers, so it is compiled for the target ABI rather than hand-packed.
struct wq_ath_diag {
	char         ad_name[IFNAMSIZ];
	uint16_t     ad_id;
	uint16_t     ad_in_size;
	void        *ad_in_data;
	void        *ad_out_data;
	unsigned int ad_out_size;
};

static int wq_diag(const char *ifname, uint16_t id, void *in, uint16_t in_size, void *out, unsigned int out_size) {
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -errno;
	struct wq_ath_diag atd;
	struct ifreq ifr;
	memset(&atd, 0, sizeof(atd));
	memset(&ifr, 0, sizeof(ifr));
	strncpy(atd.ad_name, ifname, IFNAMSIZ - 1);
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	atd.ad_id = id;
	atd.ad_in_data = in;
	atd.ad_in_size = in_size;
	atd.ad_out_data = out;
	atd.ad_out_size = out_size;
	ifr.ifr_data = (char *)&atd;
	int rc = ioctl(s, WQ_SIOCGATHPHYERR, &ifr);
	int err = errno;
	close(s);
	return rc < 0 ? -err : 0;
}

// The capability struct begins with four u8 flags in every release; newer
// cmn_dev appends hw_gen and detector counts. 128 bytes covers all of them.
static int wq_caps(const char *ifname, int base, uint8_t out[128]) {
	memset(out, 0, 128);
	return wq_diag(ifname, (uint16_t)(base + WQ_GET_CAPABILITY_INFO) | WQ_ATH_DIAG_DYN, NULL, 0, out, 128);
}

static int wq_is_active(const char *ifname, int base, uint32_t *active) {
	*active = 0;
	return wq_diag(ifname, (uint16_t)(base + WQ_IS_ACTIVE) | WQ_ATH_DIAG_DYN, NULL, 0, active, sizeof(*active));
}

static int wq_scan(const char *ifname, int base, int start) {
	uint32_t unused = 0;
	int op = start ? WQ_ACTIVATE_SCAN : WQ_STOP_SCAN;
	return wq_diag(ifname, (uint16_t)(base + op) | WQ_ATH_DIAG_DYN, &unused, sizeof(unused), NULL, 0);
}

static int wq_nl_open(void) {
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, WQ_NETLINK_ATHEROS);
	if (fd < 0)
		return -errno;
	int rcvbuf = 512 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0; // kernel-assigned; getpid() collides with other sockets
	addr.nl_groups = 1;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}
	return fd;
}

// Returns bytes read, 0 on timeout, or -errno.
static int wq_nl_recv(int fd, void *buf, int len, int timeout_ms) {
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc < 0)
		return errno == EINTR ? 0 : -errno;
	if (rc == 0)
		return 0;
	ssize_t n = recv(fd, buf, (size_t)len, MSG_DONTWAIT);
	if (n < 0)
		return (errno == EAGAIN || errno == EINTR) ? 0 : -errno;
	return (int)n;
}

// Layout reproductions used only to verify the Go parser offsets.
#define WQ_PACKED __attribute__((packed))
struct wq_interf_rsp { uint8_t type; uint16_t min_freq; uint16_t max_freq; } WQ_PACKED;
struct wq_interf_src_rsp { uint16_t count; struct wq_interf_rsp interf[10]; } WQ_PACKED;
struct wq_classifier { int mode_20_40; int dc_index; int dc_in_mhz; int upper_mhz; int lower_mhz; } WQ_PACKED;

struct wq_legacy_samp_data {
	int16_t data_len; int16_t rssi; int8_t combined_rssi; int8_t upper_rssi; int8_t lower_rssi;
	int8_t chain_ctl_rssi[3]; int8_t chain_ext_rssi[3]; uint8_t max_scale; int16_t bwinfo;
	int32_t tstamp; int16_t max_index; int16_t max_mag; uint8_t max_exp; int32_t last_tstamp;
	int16_t upper_max_index; int16_t lower_max_index; uint8_t nb_upper; uint8_t nb_lower;
	struct wq_classifier classifier; uint16_t bin_pwr_count; uint8_t bin_pwr[512];
	struct wq_interf_src_rsp interf_list; int16_t noise_floor; uint32_t ch_width;
} WQ_PACKED;
struct wq_legacy_msg {
	uint32_t signature; uint16_t freq; uint16_t freq_loading; uint16_t dcs_enabled; int int_type;
	uint8_t macaddr[6]; struct wq_legacy_samp_data samp_data;
} WQ_PACKED;

struct wq_cmn_samp_data {
	int16_t data_len; int16_t data_len_sec80; int16_t rssi; int16_t rssi_sec80;
	int8_t combined_rssi; int8_t upper_rssi; int8_t lower_rssi; int8_t chain_ctl_rssi[3];
	int8_t chain_ext_rssi[3]; uint8_t max_scale; int16_t bwinfo; int32_t tstamp;
	int16_t max_index; int16_t max_index_sec80; int16_t max_mag; int16_t max_mag_sec80;
	uint8_t max_exp; int32_t last_tstamp; int16_t upper_max_index; int16_t lower_max_index;
	uint8_t nb_upper; uint8_t nb_lower; struct wq_classifier classifier; uint16_t bin_pwr_count;
	uint8_t lb_edge_extrabins; uint8_t rb_edge_extrabins; uint16_t bin_pwr_count_sec80;
	uint8_t bin_pwr[1024]; uint8_t bin_pwr_sec80[520]; struct wq_interf_src_rsp interf_list;
	int16_t noise_floor; int16_t noise_floor_sec80; uint32_t ch_width;
	uint8_t agc_total_gain; uint8_t agc_total_gain_sec80; uint8_t gainchange; uint8_t gainchange_sec80;
	int spectral_mode; uint8_t pri80ind; uint8_t pri80ind_sec80; uint32_t last_raw_timestamp;
	uint32_t timestamp_war_offset; uint32_t raw_timestamp; uint32_t raw_timestamp_sec80;
	uint32_t reset_delay; uint32_t target_reset_count; uint32_t agile_ch_width;
	uint16_t bin_pwr_count_5mhz; uint8_t bin_pwr_5mhz[32];
} WQ_PACKED;
struct wq_cmn_msg {
	uint32_t signature; uint16_t freq; uint16_t seg1; uint16_t seg2; uint16_t agile1; uint16_t agile2;
	uint16_t freq_loading; uint16_t dcs_enabled; int int_type; uint8_t macaddr[6];
	struct wq_cmn_samp_data samp_data;
} WQ_PACKED;

struct wq_edge_bins { uint16_t num_bins; uint16_t start_bin_idx; } WQ_PACKED;
struct wq_detector_info {
	uint32_t start_frequency; uint32_t end_frequency; uint32_t timestamp; uint32_t last_tstamp;
	uint32_t last_raw_timestamp; uint32_t timestamp_war_offset; uint32_t raw_timestamp; uint32_t reset_delay;
	struct wq_edge_bins left_edge_bins; struct wq_edge_bins right_edge_bins;
	uint16_t start_bin_idx; uint16_t end_bin_idx; uint16_t max_index; uint16_t max_magnitude;
	int16_t noise_floor; int8_t rssi; uint8_t agc_total_gain; uint8_t gainchange; uint8_t pri80ind;
	uint8_t is_sec80; uint8_t blanking_status;
} WQ_PACKED;
struct wq_span_info { struct wq_detector_info detector_info[2]; uint8_t num_detectors; uint8_t pad[3]; } WQ_PACKED;
struct wq_opt_msg {
	uint32_t signature; uint32_t target_reset_count; uint32_t pri20_freq; uint32_t cfreq1; uint32_t cfreq2;
	uint32_t sscan_cfreq1; uint32_t sscan_cfreq2; uint32_t bin_pwr_count; struct wq_span_info spans[3];
	int8_t lower_rssi; int8_t upper_rssi; int8_t chain_ctl_rssi[3]; int8_t chain_ext_rssi[3];
	uint8_t macaddr[6]; uint8_t spectral_mode; uint8_t operating_bw; uint8_t sscan_bw; uint8_t fft_width;
	uint8_t dcs_enabled; uint8_t int_type; uint8_t num_freq_spans; uint8_t bin_pwr[];
} WQ_PACKED;

#define WQ_OFF(t, f, v) _Static_assert(offsetof(struct t, f) == (v), #t "." #f)
WQ_OFF(wq_legacy_msg, macaddr, 14);
WQ_OFF(wq_legacy_msg, samp_data.rssi, 22);
WQ_OFF(wq_legacy_msg, samp_data.tstamp, 36);
WQ_OFF(wq_legacy_msg, samp_data.max_index, 40);
WQ_OFF(wq_legacy_msg, samp_data.bin_pwr_count, 75);
WQ_OFF(wq_legacy_msg, samp_data.bin_pwr, 77);
WQ_OFF(wq_legacy_msg, samp_data.noise_floor, 641);
WQ_OFF(wq_legacy_msg, samp_data.ch_width, 643);
_Static_assert(sizeof(struct wq_legacy_msg) == 647, "legacy size");
WQ_OFF(wq_cmn_msg, macaddr, 22);
WQ_OFF(wq_cmn_msg, samp_data.rssi, 32);
WQ_OFF(wq_cmn_msg, samp_data.tstamp, 48);
WQ_OFF(wq_cmn_msg, samp_data.max_index, 52);
WQ_OFF(wq_cmn_msg, samp_data.bin_pwr_count, 91);
WQ_OFF(wq_cmn_msg, samp_data.bin_pwr_count_sec80, 95);
WQ_OFF(wq_cmn_msg, samp_data.bin_pwr, 97);
WQ_OFF(wq_cmn_msg, samp_data.bin_pwr_sec80, 1121);
WQ_OFF(wq_cmn_msg, samp_data.noise_floor, 1693);
WQ_OFF(wq_cmn_msg, samp_data.ch_width, 1697);
WQ_OFF(wq_cmn_msg, samp_data.agc_total_gain, 1701);
_Static_assert(sizeof(struct wq_cmn_msg) == 1773, "cmn size");
WQ_OFF(wq_opt_msg, bin_pwr_count, 28);
WQ_OFF(wq_opt_msg, spans[0].detector_info[0].timestamp, 40);
WQ_OFF(wq_opt_msg, spans[0].detector_info[0].max_index, 76);
WQ_OFF(wq_opt_msg, spans[0].detector_info[0].noise_floor, 80);
WQ_OFF(wq_opt_msg, spans[0].detector_info[0].rssi, 82);
WQ_OFF(wq_opt_msg, macaddr, 388);
WQ_OFF(wq_opt_msg, operating_bw, 395);
WQ_OFF(wq_opt_msg, bin_pwr, 401);
_Static_assert(sizeof(struct wq_detector_info) % 4 == 0, "detector size");
_Static_assert(sizeof(struct wq_span_info) % 4 == 0, "span size");
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Supported reports whether this binary carries the native QCA backend.
const Supported = true

// Spectral ioctl IDs are offsets from DFS_LAST_IOCTL, which moved from 22
// (qca-wifi 10.2) to 29 (cmn_dev). Probing the newer base first is safe: on a
// legacy driver 29+16 is an undefined spectral command, and 22+16 on a cmn
// driver is the read-only IS_ACTIVE, which fails capability validation.
var dfsLastIoctlCandidates = []int{29, 22}

type nativeDriver struct{}

func newDriver() driver { return nativeDriver{} }

func (nativeDriver) Probe(ifname string) (Caps, error) {
	cname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cname))
	var lastErr error = ErrUnsupported
	for _, base := range dfsLastIoctlCandidates {
		var out [128]C.uint8_t
		if rc := C.wq_caps(cname, C.int(base), &out[0]); rc < 0 {
			lastErr = fmt.Errorf("spectral caps ioctl on %s: %w", ifname, syscall.Errno(-rc))
			continue
		}
		raw := C.GoBytes(unsafe.Pointer(&out[0]), 128)
		if caps, ok := decodeCaps(raw, base); ok {
			return caps, nil
		}
	}
	return Caps{}, lastErr
}

func (nativeDriver) IsActive(ifname string, base int) (bool, error) {
	cname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cname))
	var active C.uint32_t
	if rc := C.wq_is_active(cname, C.int(base), &active); rc < 0 {
		return false, fmt.Errorf("spectral is_active on %s: %w", ifname, syscall.Errno(-rc))
	}
	return active != 0, nil
}

func (nativeDriver) SetScan(ifname string, base int, start bool) error {
	cname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cname))
	flag := C.int(0)
	if start {
		flag = 1
	}
	if rc := C.wq_scan(cname, C.int(base), flag); rc < 0 {
		return fmt.Errorf("spectral scan control on %s: %w", ifname, syscall.Errno(-rc))
	}
	return nil
}

func (nativeDriver) OpenSamples() (sampleSource, error) {
	fd := C.wq_nl_open()
	if fd < 0 {
		return nil, fmt.Errorf("open NETLINK_ATHEROS: %w", syscall.Errno(-fd))
	}
	return &netlinkSource{fd: fd, buf: make([]byte, 8192)}, nil
}

type netlinkSource struct {
	fd  C.int
	buf []byte
}

func (s *netlinkSource) Recv(timeoutMillis int) ([]byte, error) {
	n := C.wq_nl_recv(s.fd, unsafe.Pointer(&s.buf[0]), C.int(len(s.buf)), C.int(timeoutMillis))
	if n < 0 {
		return nil, fmt.Errorf("recv NETLINK_ATHEROS: %w", syscall.Errno(-n))
	}
	return s.buf[:n], nil
}

func (s *netlinkSource) Close() error {
	C.close(s.fd)
	return nil
}
