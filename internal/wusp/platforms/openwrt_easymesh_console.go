package platforms

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	easyMeshConsoleAddress   = "127.0.0.1:7777"
	easyMeshConsoleTimeout   = 4 * time.Second
	easyMeshConsoleMaxOutput = 128 << 10
)

type easyMeshConsoleCommand uint8

const (
	easyMeshConsoleEnableTopologyRequests easyMeshConsoleCommand = iota + 1
	easyMeshConsoleDisableTopologyRequests
)

func (command easyMeshConsoleCommand) text() (string, error) {
	switch command {
	case easyMeshConsoleEnableTopologyRequests:
		return "td test on", nil
	case easyMeshConsoleDisableTopologyRequests:
		return "td test off", nil
	default:
		return "", fmt.Errorf("unsupported EasyMesh console command %d", command)
	}
}

type easyMeshConsole interface {
	Run(context.Context, easyMeshConsoleCommand) (string, error)
}

type easyMeshConsoleFunc func(context.Context, easyMeshConsoleCommand) (string, error)

func (run easyMeshConsoleFunc) Run(ctx context.Context, command easyMeshConsoleCommand) (string, error) {
	return run(ctx, command)
}

type easyMeshConsoleClient struct {
	address string
	timeout time.Duration
	dialer  net.Dialer
}

func newEasyMeshConsoleClient() *easyMeshConsoleClient {
	return &easyMeshConsoleClient{
		address: easyMeshConsoleAddress,
		timeout: easyMeshConsoleTimeout,
	}
}

func (client *easyMeshConsoleClient) Run(
	ctx context.Context,
	command easyMeshConsoleCommand,
) (string, error) {
	if client == nil {
		return "", fmt.Errorf("EasyMesh console is unavailable")
	}
	commandText, err := command.text()
	if err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := client.timeout
	if timeout <= 0 {
		timeout = easyMeshConsoleTimeout
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := client.dialer.DialContext(commandCtx, "tcp", client.address)
	if err != nil {
		return "", fmt.Errorf("connect to local EasyMesh console: %w", err)
	}
	defer connection.Close()
	if deadline, ok := commandCtx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return "", fmt.Errorf("set EasyMesh console deadline: %w", err)
		}
	}

	decoder := telnetDecoder{}
	if _, err := readEasyMeshConsolePrompt(commandCtx, connection, &decoder); err != nil {
		return "", fmt.Errorf("read EasyMesh console greeting: %w", err)
	}
	if _, err := io.WriteString(connection, commandText+"\n"); err != nil {
		return "", fmt.Errorf("send EasyMesh console command: %w", err)
	}
	response, err := readEasyMeshConsolePrompt(commandCtx, connection, &decoder)
	if err != nil {
		return "", fmt.Errorf("read EasyMesh console response: %w", err)
	}
	return trimEasyMeshConsolePrompt(response), nil
}

func readEasyMeshConsolePrompt(
	ctx context.Context,
	connection net.Conn,
	decoder *telnetDecoder,
) (string, error) {
	buffer := make([]byte, 4096)
	var output bytes.Buffer
	for {
		count, err := connection.Read(buffer)
		if count > 0 {
			plain, reply := decoder.Decode(buffer[:count])
			if len(reply) > 0 {
				if _, writeErr := connection.Write(reply); writeErr != nil {
					return "", fmt.Errorf("reply to Telnet negotiation: %w", writeErr)
				}
			}
			if output.Len()+len(plain) > easyMeshConsoleMaxOutput {
				return "", fmt.Errorf("response exceeds %d bytes", easyMeshConsoleMaxOutput)
			}
			_, _ = output.Write(plain)
			if hasEasyMeshConsolePrompt(output.String()) {
				return output.String(), nil
			}
		}
		if err == nil {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if deadline, hasDeadline := ctx.Deadline(); hasDeadline && !time.Now().Before(deadline) {
				return "", context.DeadlineExceeded
			}
			return "", fmt.Errorf("timed out waiting for prompt")
		}
		return "", err
	}
}

func hasEasyMeshConsolePrompt(output string) bool {
	trimmed := strings.TrimRight(output, " \t\r\n")
	lineStart := strings.LastIndexByte(trimmed, '\n') + 1
	return strings.TrimSpace(trimmed[lineStart:]) == "@"
}

func trimEasyMeshConsolePrompt(output string) string {
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	trimmed := strings.TrimRight(normalized, " \t\r\n")
	lineStart := strings.LastIndexByte(trimmed, '\n') + 1
	if strings.TrimSpace(trimmed[lineStart:]) == "@" {
		trimmed = trimmed[:lineStart]
	}
	return strings.TrimSpace(trimmed)
}

const (
	telnetSE   = 240
	telnetSB   = 250
	telnetWILL = 251
	telnetWONT = 252
	telnetDO   = 253
	telnetDONT = 254
	telnetIAC  = 255
)

type telnetDecoder struct {
	state byte
	verb  byte
}

const (
	telnetStateData byte = iota
	telnetStateCommand
	telnetStateOption
	telnetStateSubnegotiation
	telnetStateSubnegotiationCommand
)

func (decoder *telnetDecoder) Decode(input []byte) ([]byte, []byte) {
	plain := make([]byte, 0, len(input))
	reply := make([]byte, 0, 6)
	for _, value := range input {
		switch decoder.state {
		case telnetStateData:
			if value == telnetIAC {
				decoder.state = telnetStateCommand
				continue
			}
			plain = append(plain, value)
		case telnetStateCommand:
			switch value {
			case telnetIAC:
				plain = append(plain, value)
				decoder.state = telnetStateData
			case telnetWILL, telnetWONT, telnetDO, telnetDONT:
				decoder.verb = value
				decoder.state = telnetStateOption
			case telnetSB:
				decoder.state = telnetStateSubnegotiation
			default:
				decoder.state = telnetStateData
			}
		case telnetStateOption:
			switch decoder.verb {
			case telnetWILL:
				reply = append(reply, telnetIAC, telnetDONT, value)
			case telnetDO:
				reply = append(reply, telnetIAC, telnetWONT, value)
			}
			decoder.state = telnetStateData
		case telnetStateSubnegotiation:
			if value == telnetIAC {
				decoder.state = telnetStateSubnegotiationCommand
			}
		case telnetStateSubnegotiationCommand:
			if value == telnetSE {
				decoder.state = telnetStateData
			} else {
				decoder.state = telnetStateSubnegotiation
			}
		}
	}
	return plain, reply
}
