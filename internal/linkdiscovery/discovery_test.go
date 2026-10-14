package linkdiscovery

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
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

func TestDiscoveryParsersDoNotPanicOnMalformedTraffic(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 2000; index++ {
		payload := make([]byte, random.Intn(2048))
		if _, err := random.Read(payload); err != nil {
			t.Fatal(err)
		}
		_, _ = ParseLLDPPayload("eth0", nil, payload, time.Now())
		_, _ = ParseMNDPPayload("eth0", nil, payload, time.Now())
	}
}

func TestDiscoveryParsersRejectOversizedTraffic(t *testing.T) {
	if _, err := ParseLLDPPayload("eth0", nil, make([]byte, maxLLDPPayloadBytes+1), time.Now()); err == nil {
		t.Fatal("oversized LLDPDU was accepted")
	}
	if _, err := ParseMNDPPayload("eth0", nil, make([]byte, maxMNDPPayloadBytes+1), time.Now()); err == nil {
		t.Fatal("oversized MNDP packet was accepted")
	}
}

func TestZeroValueMonitorBoundsUntrustedNeighborCaches(t *testing.T) {
	monitor := &Monitor{}
	now := time.Now()
	for index := 0; index < maxLLDPNeighbors+100; index++ {
		monitor.observeLLDP(LLDPNeighbor{
			LocalInterface: "eth0",
			ChassisID:      fmt.Sprintf("chassis-%d", index),
			PortID:         "port",
			TTL:            time.Minute,
			LastUpdate:     now.Add(time.Duration(index) * time.Nanosecond),
		})
	}
	for index := 0; index < maxMNDPNeighbors+100; index++ {
		monitor.observeMNDP(MNDPNeighbor{
			MAC:        net.HardwareAddr{0x02, 0, 0, byte(index >> 16), byte(index >> 8), byte(index)},
			LastUpdate: now.Add(time.Duration(index) * time.Nanosecond),
		})
	}

	monitor.mu.Lock()
	lldpCount, mndpCount := len(monitor.lldp), len(monitor.mndp)
	monitor.mu.Unlock()
	if lldpCount != maxLLDPNeighbors {
		t.Fatalf("LLDP cache has %d entries, want cap %d", lldpCount, maxLLDPNeighbors)
	}
	if mndpCount != maxMNDPNeighbors {
		t.Fatalf("MNDP cache has %d entries, want cap %d", mndpCount, maxMNDPNeighbors)
	}
}

func TestSafelyRunListenerContainsPanic(t *testing.T) {
	stopped := false
	safelyRunListener("test", func() { stopped = true }, func() { panic("malformed packet") })
	if !stopped {
		t.Fatal("listener was not marked stopped after panic")
	}
}

func TestMonitorConcurrentObserveAndSnapshot(t *testing.T) {
	monitor := NewMonitor()
	now := time.Now()
	monitor.markLLDPStarted(now.Add(-time.Minute))
	monitor.markMNDPStarted(now.Add(-2 * time.Minute))

	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 500; index++ {
				identity := worker*500 + index
				monitor.observeLLDP(LLDPNeighbor{
					LocalInterface: "eth0",
					ChassisID:      fmt.Sprintf("chassis-%d", identity),
					PortID:         "port",
					TTL:            time.Minute,
					LastUpdate:     now,
				})
				monitor.observeMNDP(MNDPNeighbor{
					MAC:        net.HardwareAddr{0x02, byte(worker), 0, byte(index >> 16), byte(index >> 8), byte(index)},
					LastUpdate: now,
				})
			}
		}()
	}
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 500; index++ {
				_ = monitor.Snapshot(now)
			}
		}()
	}
	workers.Wait()

	snapshot := monitor.Snapshot(now)
	if len(snapshot.LLDP) > maxLLDPNeighbors || len(snapshot.MNDP) > maxMNDPNeighbors {
		t.Fatalf("concurrent cache exceeded limits: LLDP=%d MNDP=%d", len(snapshot.LLDP), len(snapshot.MNDP))
	}
}
