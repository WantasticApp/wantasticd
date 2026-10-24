//go:build linux

package iwinfo

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// qca-wifi in cfg80211 mode serves wlanconfig's "list sta" through an
// nl80211 vendor command instead of the private ioctl: vendor OUI 0x001374,
// subcommand SET_WIFI_CONFIGURATION (74) carrying generic command 214
// (LIST_STA). The reply's GENERIC_DATA attribute holds the same packed
// ieee80211req_sta_info records. IDs: hostap/qca-wifi qca-vendor.h (ISC)
// and RDK-B hal-qcawifi wifi_hal.c (Apache-2.0).
const (
	qcaVendorOUI                    = 0x001374
	qcaSubcmdSetWifiConfiguration   = 74
	qcaGenericCommandListStations   = 214
	qcaAttrConfigGenericCommand     = 17
	qcaAttrConfigGenericData        = 19
	qcaAttrConfigGenericLength      = 20
	qcaAttrConfigGenericFlags       = 21
	qcaListStationsReplyBufferBytes = 5500 // LIST_STATION_CFG_ALLOC_SIZE in the RDK HAL
)

// QCAVendorStationRecords returns the raw station record blocks of an AP
// VAP, one per reply fragment.
func QCAVendorStationRecords(ifname string) ([][]byte, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	c, err := dialNL80211()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msgs, err := c.execute(unix.NL80211_CMD_VENDOR, 0, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(iface.Index))
		ae.Uint32(unix.NL80211_ATTR_VENDOR_ID, qcaVendorOUI)
		ae.Uint32(unix.NL80211_ATTR_VENDOR_SUBCMD, qcaSubcmdSetWifiConfiguration)
		ae.Nested(unix.NL80211_ATTR_VENDOR_DATA, func(nae *netlink.AttributeEncoder) error {
			nae.Uint32(qcaAttrConfigGenericCommand, qcaGenericCommandListStations)
			nae.Bytes(qcaAttrConfigGenericData, make([]byte, qcaListStationsReplyBufferBytes))
			nae.Uint32(qcaAttrConfigGenericLength, qcaListStationsReplyBufferBytes)
			nae.Uint32(qcaAttrConfigGenericFlags, 0)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("qca vendor list sta on %s: %w", ifname, err)
	}
	return qcaGenericDataBlocks(msgs), nil
}

// qcaGenericDataBlocks extracts GENERIC_DATA from each vendor reply.
func qcaGenericDataBlocks(msgs []genetlink.Message) [][]byte {
	var out [][]byte
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			continue
		}
		for ad.Next() {
			if ad.Type() != unix.NL80211_ATTR_VENDOR_DATA {
				continue
			}
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				var data []byte
				length := -1
				for nad.Next() {
					switch nad.Type() {
					case qcaAttrConfigGenericData:
						data = nad.Bytes()
					case qcaAttrConfigGenericLength:
						length = int(nad.Uint32())
					}
				}
				if length >= 0 && length < len(data) {
					data = data[:length]
				}
				if len(data) > 0 {
					out = append(out, data)
				}
				return nil
			})
		}
	}
	return out
}

// joinStationBlocks concatenates fragments that each end on a record
// boundary, so the usual isi_len walk covers every station.
func joinStationBlocks(blocks [][]byte) []byte {
	var out []byte
	for _, block := range blocks {
		end := 0
		for end+2 <= len(block) {
			n := int(binary.NativeEndian.Uint16(block[end:]))
			if n == 0 || end+n > len(block) {
				break
			}
			end += n
		}
		out = append(out, block[:end]...)
	}
	return out
}
