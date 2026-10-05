package platforms

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEasyMeshConsoleClientRunsAllowlistedCommand(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	commandReceived := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		if _, writeErr := connection.Write([]byte{
			telnetIAC, telnetWILL, 1,
		}); writeErr != nil {
			serverDone <- writeErr
			return
		}
		if _, writeErr := io.WriteString(connection, "EasyMesh console\r\n@ "); writeErr != nil {
			serverDone <- writeErr
			return
		}

		decoder := telnetDecoder{}
		var command bytes.Buffer
		buffer := make([]byte, 256)
		for !strings.Contains(command.String(), "\n") {
			count, readErr := connection.Read(buffer)
			if readErr != nil {
				serverDone <- readErr
				return
			}
			plain, _ := decoder.Decode(buffer[:count])
			_, _ = command.Write(plain)
		}
		commandReceived <- strings.TrimSpace(command.String())
		_, writeErr := io.WriteString(
			connection,
			"ToptReq:ON;Compiled on Oct 5 2023\r\n@ ",
		)
		serverDone <- writeErr
	}()

	client := &easyMeshConsoleClient{
		address: listener.Addr().String(),
		timeout: time.Second,
	}
	output, err := client.Run(t.Context(), easyMeshConsoleEnableTopologyRequests)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if output != "ToptReq:ON;Compiled on Oct 5 2023" {
		t.Fatalf("output=%q", output)
	}
	if command := <-commandReceived; command != "td test on" {
		t.Fatalf("command=%q", command)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("console server: %v", err)
	}
}

func TestEasyMeshConsoleClientRejectsUnknownCommandBeforeDial(t *testing.T) {
	client := &easyMeshConsoleClient{
		address: "127.0.0.1:1",
		timeout: time.Second,
	}
	_, err := client.Run(t.Context(), easyMeshConsoleCommand(255))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("Run error=%v", err)
	}
}

func TestEasyMeshConsoleClientHonorsContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer connection.Close()
			<-serverDone
		}
	}()

	client := &easyMeshConsoleClient{
		address: listener.Addr().String(),
		timeout: time.Second,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Run(ctx, easyMeshConsoleEnableTopologyRequests)
	close(serverDone)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("Run error=%v", err)
	}
}

func TestTelnetDecoderRejectsNegotiationAndKeepsText(t *testing.T) {
	decoder := telnetDecoder{}
	plain, reply := decoder.Decode([]byte{
		'A',
		telnetIAC, telnetWILL, 1,
		'B',
		telnetIAC, telnetDO, 3,
		'C',
		telnetIAC, telnetSB, 31, 0, 80, telnetIAC, telnetSE,
		'D',
	})
	if string(plain) != "ABCD" {
		t.Fatalf("plain=%q", plain)
	}
	wantReply := []byte{
		telnetIAC, telnetDONT, 1,
		telnetIAC, telnetWONT, 3,
	}
	if !bytes.Equal(reply, wantReply) {
		t.Fatalf("reply=%v want %v", reply, wantReply)
	}
}

func TestSetEasyMeshTopologyRequestGateRequiresConfirmation(t *testing.T) {
	backend := &OpenWrtBackend{
		easyMeshConsole: easyMeshConsoleFunc(func(
			context.Context,
			easyMeshConsoleCommand,
		) (string, error) {
			return "command accepted", nil
		}),
	}
	err := backend.setEasyMeshTopologyRequestGate(
		t.Context(),
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "ToptReq:ON") {
		t.Fatalf("setEasyMeshTopologyRequestGate error=%v", err)
	}
}

func TestParseEasyMeshConsoleStatusBuildsRelayTopology(t *testing.T) {
	const output = `Topology Discovery Service module status:
Mode of operation: Relaying MAP-Agent device
Map-Agent Version : 2
        QCA IEEE 1905.1 device: E0:5D:54:4B:E5:DC, IPv4 address: 192.168.200.141
           Package Version: easymesh-12.2.1
        Country Code: US           Upstream Device: 00:03:7F:BA:DB:AD
        Local interfaces:
        Interface name   Medium Type  MAC Address        Contention   Role   PHY Capabilities   Network Information
        ath2     (R=0)   WLAN6G       E2:5D:54:4B:E5:E2  117          AP     20MHz,4,EHT,13,13  br-lan (V=0)
                              SSID: mesh-backhaul,  ESSID: 0
                              Map BSS Type : 0x40, Role: |BH|
        ath21    (R=0)   WLAN6G       E0:5D:54:4B:E5:E2  117          STA                       br-lan (V=0)
                              BSSID: 02:03:7F:12:54:54
        eth1             ETHER        DA:AF:62:22:96:D2  255                                    br-lan (V=0)
        Legacy Devices:
-- DB (2 entries):
        #1: QCA IEEE 1905.1 device: E0:5D:54:4B:E6:CF, IPv4 address: 192.168.200.227 **MAP Agent**
           Relation: Distant Neighbor
           Upstream Device: 00:03:7F:BA:DB:AD
           Stream direction from self: Peer; Number of hops to the device: 0
        #2: QCA IEEE 1905.1 device: 00:03:7F:BA:DB:AD, IPv4 address: 192.168.200.1 **MAP Controller** **MAP Agent**
           Relation: Direct Neighbor
           Upstream Device: None
           Stream direction from self: Upstream; Number of hops to the device: 1`

	snapshot, ok := parseEasyMeshConsoleStatus(output, "G1TK7EY00023A")
	if !ok {
		t.Fatal("parseEasyMeshConsoleStatus rejected valid td s1 output")
	}
	if snapshot.Role != "Agent" || snapshot.LocalMAC != "E0:5D:54:4B:E5:DC" {
		t.Fatalf("role=%q localMAC=%q", snapshot.Role, snapshot.LocalMAC)
	}
	if snapshot.UpstreamMAC != "00:03:7F:BA:DB:AD" {
		t.Fatalf("upstream=%q", snapshot.UpstreamMAC)
	}
	if snapshot.PackageVersion != "easymesh-12.2.1" || snapshot.CountryCode != "US" {
		t.Fatalf("package=%q country=%q", snapshot.PackageVersion, snapshot.CountryCode)
	}
	if len(snapshot.Interfaces) != 3 {
		t.Fatalf("interfaces=%d", len(snapshot.Interfaces))
	}
	if snapshot.Interfaces[0].SSID != "mesh-backhaul" || snapshot.Interfaces[0].BSSRole != "BH" {
		t.Fatalf("first interface=%+v", snapshot.Interfaces[0])
	}

	roots := attachMeshParentHints(normalizedMeshRoots(snapshot.Topology))
	nodes := flattenMeshForest(roots)
	if len(nodes) != 3 {
		t.Fatalf("nodes=%d", len(nodes))
	}
	if len(roots) != 1 || roots[0].mac != "00:03:7F:BA:DB:AD" {
		t.Fatalf("root=%+v", roots)
	}
	if len(roots[0].children) != 2 {
		t.Fatalf("root children=%d", len(roots[0].children))
	}
}

func TestEasyMeshConsoleActionAllowlist(t *testing.T) {
	tests := []struct {
		action string
		text   string
	}{
		{action: "RefreshTopology", text: "td s1"},
		{action: "DiscoverNeighbors", text: "td discovery"},
		{action: "AnnounceTopology", text: "td notify"},
		{action: "RefreshRadioCapabilities", text: "td radiocap"},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			command, ok := easyMeshConsoleActionCommand(test.action)
			if !ok {
				t.Fatalf("action %q not allowlisted", test.action)
			}
			text, err := command.text()
			if err != nil || text != test.text {
				t.Fatalf("text=%q err=%v", text, err)
			}
		})
	}
	if _, ok := easyMeshConsoleActionCommand("FlushDatabase"); ok {
		t.Fatal("destructive EasyMesh console action was allowlisted")
	}
}
