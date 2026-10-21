/*
 * Packed SAMP message layouts reproduced from qca-wifi 10.2 spectral_data.h
 * and cmn_dev spectral_ioctl.h. layout_test.go compiles this file when a C
 * compiler is available; each _Static_assert pins an offset parse.go reads.
 */
#include <stddef.h>
#include <stdint.h>
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
