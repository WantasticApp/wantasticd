package linkdiscovery

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mdlayher/lldp"
)

func TestParseLLDPPayloadWithMEDAndPadding(t *testing.T) {
	frame := &lldp.Frame{
		ChassisID: &lldp.ChassisID{Subtype: lldp.ChassisIDSubtypeMACAddress, ID: []byte{0x02, 0, 0, 0, 0, 1}},
		PortID:    &lldp.PortID{Subtype: lldp.PortIDSubtypeInterfaceName, ID: []byte("ath2")},
		TTL:       120 * time.Second,
		Optional: []*lldp.TLV{
			{Type: lldp.TLVTypeSystemName, Length: 3, Value: []byte("T2\x00")},
			{Type: lldp.TLVTypePortDescription, Length: 13, Value: []byte("mesh-backhaul")},
			{Type: lldp.TLVTypeManagementAddress, Length: 12, Value: []byte{5, 1, 192, 168, 200, 2, 2, 0, 0, 0, 7, 0}},
			{Type: lldp.TLVTypeOrganizationSpecific, Length: 6, Value: []byte{0x00, 0x12, 0xbb, 1, 0x01, 0x02}},
		},
	}
	payload, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, make([]byte, 32)...)
	receivedAt := time.Unix(1700000000, 0).UTC()
	neighbor, err := ParseLLDPPayload("eth5", net.HardwareAddr{2, 0, 0, 0, 0, 1}, payload, receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if neighbor.ChassisID != "02:00:00:00:00:01" || neighbor.PortID != "ath2" {
		t.Fatalf("unexpected identity: %+v", neighbor)
	}
	if neighbor.SystemName != "T2" || neighbor.PortDescription != "mesh-backhaul" {
		t.Fatalf("unexpected text TLVs: %+v", neighbor)
	}
	if len(neighbor.ManagementAddresses) != 1 || neighbor.ManagementAddresses[0].String() != "192.168.200.2" {
		t.Fatalf("unexpected management address: %+v", neighbor.ManagementAddresses)
	}
	if len(neighbor.Organizations) != 1 || !neighbor.Organizations[0].LLDPMED || neighbor.Organizations[0].OUI != "0012bb" {
		t.Fatalf("LLDP-MED not retained: %+v", neighbor.Organizations)
	}
}

func TestParseMNDPPayload(t *testing.T) {
	packet := make([]byte, 4)
	binary.LittleEndian.PutUint32(packet, 42)
	appendPart := func(partType uint16, value []byte) {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], partType)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(value)))
		packet = append(packet, header...)
		packet = append(packet, value...)
	}
	appendPart(1, []byte{0x02, 0, 0, 0, 0, 2})
	appendPart(5, []byte("T2"))
	appendPart(8, []byte("MikroTik"))
	appendPart(16, []byte("wlan1"))
	appendPart(17, []byte{192, 168, 200, 2})

	neighbor, err := ParseMNDPPayload("br-lan", net.IPv4(192, 168, 200, 2), packet, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if neighbor.MAC.String() != "02:00:00:00:00:02" || neighbor.Identity != "T2" || neighbor.RemoteInterface != "wlan1" {
		t.Fatalf("unexpected MNDP neighbor: %+v", neighbor)
	}
	if len(neighbor.IPv4) != 1 || neighbor.IPv4[0].String() != "192.168.200.2" {
		t.Fatalf("unexpected MNDP IPv4: %+v", neighbor.IPv4)
	}
}
