//go:build linux && netctl
// +build linux,netctl

// CGo-accelerated Linux controller. Uses libnl-genl-3 for nl80211 WiFi.
// Build: CGO_ENABLED=1 go build -tags netctl
// Requires: libnl-3-dev libnl-genl-3-dev (or libnl-tiny on OpenWrt)
//
// Falls back to sysfs for WiFi if nl80211 query fails.
// Routes, links, addresses use the same pure-Go netlink as the non-CGo build.

package netctl

/*
#cgo LDFLAGS: -lnl-3 -lnl-genl-3
#cgo CFLAGS: -I/usr/include/libnl3

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <stdlib.h>
#include <string.h>

struct wifi_caps {
    int ht, vht, he, eht;
    int ht40, vht160, vht80p80;
    int max_tx_streams, max_rx_streams;
    int num_bands;
    int bands[4];
};

static int wiphy_cb(struct nl_msg *msg, void *arg) {
    struct wifi_caps *caps = (struct wifi_caps *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_BANDS]) {
        struct nlattr *band;
        int rem;
        nla_for_each_nested(band, tb[NL80211_ATTR_WIPHY_BANDS], rem) {
            struct nlattr *bt[NL80211_BAND_ATTR_MAX + 1];
            nla_parse(bt, NL80211_BAND_ATTR_MAX, nla_data(band), nla_len(band), NULL);

            if (bt[NL80211_BAND_ATTR_HT_CAPA]) {
                uint16_t c = nla_get_u16(bt[NL80211_BAND_ATTR_HT_CAPA]);
                caps->ht = 1;
                if (c & 0x0002) caps->ht40 = 1;
                int rx = (c >> 8) & 0x03;
                if (rx > caps->max_rx_streams) caps->max_rx_streams = rx;
            }
            if (bt[NL80211_BAND_ATTR_VHT_CAPA]) {
                uint32_t c = nla_get_u32(bt[NL80211_BAND_ATTR_VHT_CAPA]);
                caps->vht = 1;
                int cw = (c >> 2) & 0x03;
                if (cw >= 1) caps->vht160 = 1;
                if (cw >= 2) caps->vht80p80 = 1;
            }
            if (bt[NL80211_BAND_ATTR_IFTYPE_DATA]) caps->he = 1;

            if (bt[NL80211_BAND_ATTR_FREQS]) {
                struct nlattr *f; int fr;
                nla_for_each_nested(f, bt[NL80211_BAND_ATTR_FREQS], fr) {
                    struct nlattr *ft[NL80211_FREQUENCY_ATTR_MAX + 1];
                    nla_parse(ft, NL80211_FREQUENCY_ATTR_MAX, nla_data(f), nla_len(f), NULL);
                    if (ft[NL80211_FREQUENCY_ATTR_FREQ] && !ft[NL80211_FREQUENCY_ATTR_DISABLED]) {
                        if (caps->num_bands < 4)
                            caps->bands[caps->num_bands++] = nla_get_u32(ft[NL80211_FREQUENCY_ATTR_FREQ]);
                        break;
                    }
                }
            }
        }
    }
    return NL_SKIP;
}

static int c_get_wifi_caps(int phy_idx, struct wifi_caps *caps) {
    memset(caps, 0, sizeof(*caps));
    struct nl_sock *sk = nl_socket_alloc();
    if (!sk) return -1;
    if (genl_connect(sk) < 0) { nl_socket_free(sk); return -2; }
    int id = genl_ctrl_resolve(sk, "nl80211");
    if (id < 0) { nl_socket_free(sk); return -3; }
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) { nl_socket_free(sk); return -4; }
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, wiphy_cb, caps);
    int err = nl_send_auto(sk, msg);
    if (err >= 0) nl_recvmsgs_default(sk);
    nlmsg_free(msg);
    nl_socket_free(sk);
    return (err >= 0) ? 0 : err;
}
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
)

// cgoController enhances linuxController with nl80211 WiFi via libnl-genl CGo.
type cgoController struct{ linuxController }

func newController() Controller { return &cgoController{} }

func (c *cgoController) WiFiGetCapabilities(ifname string) (*WiFiCapabilities, error) {
	// Read phy index from sysfs
	data, err := os.ReadFile("/sys/class/net/" + ifname + "/phy80211/index")
	if err != nil {
		return c.linuxController.WiFiGetCapabilities(ifname)
	}
	var phyIdx int
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &phyIdx)

	var cc C.struct_wifi_caps
	if C.c_get_wifi_caps(C.int(phyIdx), &cc) != 0 {
		return c.linuxController.WiFiGetCapabilities(ifname) // fallback
	}

	caps := &WiFiCapabilities{
		HT: cc.ht != 0, VHT: cc.vht != 0, HE: cc.he != 0,
		MaxTxStreams: int(cc.max_tx_streams),
		MaxRxStreams: int(cc.max_rx_streams),
	}
	if d, err := os.ReadFile("/sys/class/net/" + ifname + "/phy80211/name"); err == nil {
		caps.PHYName = strings.TrimSpace(string(d))
	}

	if caps.HT {
		caps.SupportedHTModes = append(caps.SupportedHTModes, "HT20")
		if cc.ht40 != 0 {
			caps.SupportedHTModes = append(caps.SupportedHTModes, "HT40")
		}
	}
	if caps.VHT {
		caps.SupportedHTModes = append(caps.SupportedHTModes, "VHT20", "VHT40", "VHT80")
		if cc.vht160 != 0 {
			caps.SupportedHTModes = append(caps.SupportedHTModes, "VHT160")
		}
	}
	if caps.HE {
		caps.SupportedHTModes = append(caps.SupportedHTModes, "HE20", "HE40", "HE80")
		if cc.vht160 != 0 {
			caps.SupportedHTModes = append(caps.SupportedHTModes, "HE160")
		}
	}
	for i := 0; i < int(cc.num_bands); i++ {
		f := int(cc.bands[i])
		switch {
		case f >= 5925:
			caps.Bands = append(caps.Bands, "6GHz")
		case f >= 4900:
			caps.Bands = append(caps.Bands, "5GHz")
		case f >= 2400:
			caps.Bands = append(caps.Bands, "2.4GHz")
		}
	}
	if len(caps.SupportedHTModes) == 0 {
		return nil, fmt.Errorf("no capabilities from nl80211 for %s", ifname)
	}
	return caps, nil
}

var _ Controller = (*cgoController)(nil)
