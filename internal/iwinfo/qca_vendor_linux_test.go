//go:build linux

package iwinfo

import (
	"testing"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestQCAGenericDataBlocksAndJoin(t *testing.T) {
	recA := qcaRecord("aa:bb:cc:00:00:01", 3, 41, 4, 866700, 780000, 22)
	recB := qcaRecord("aa:bb:cc:00:00:02", 7, 27, 12, 390000, 433300, 40)
	reply := func(records []byte, pad int) genetlink.Message {
		ae := netlink.NewAttributeEncoder()
		ae.Nested(unix.NL80211_ATTR_VENDOR_DATA, func(nae *netlink.AttributeEncoder) error {
			nae.Bytes(qcaAttrConfigGenericData, append(append([]byte(nil), records...), make([]byte, pad)...))
			nae.Uint32(qcaAttrConfigGenericLength, uint32(len(records)+pad))
			return nil
		})
		data, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return genetlink.Message{Data: data}
	}
	blocks := qcaGenericDataBlocks([]genetlink.Message{reply(recA, 64), reply(recB, 0)})
	if len(blocks) != 2 {
		t.Fatalf("blocks=%d", len(blocks))
	}
	joined := joinStationBlocks(blocks)
	if len(joined) != len(recA)+len(recB) || len(splitStaRecords(joined)) != 2 {
		t.Fatalf("joined %d bytes, %d records", len(joined), len(splitStaRecords(joined)))
	}
}
