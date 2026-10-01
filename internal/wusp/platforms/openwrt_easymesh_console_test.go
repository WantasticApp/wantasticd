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
