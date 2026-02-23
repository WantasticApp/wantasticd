//go:build linux

package stats

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ubus wire protocol constants
const (
	ubusSocketPath = "/var/run/ubus/ubus.sock"

	// ubus message types
	ubusMsgHello  = 0
	ubusMsgStatus = 1
	ubusMsgData   = 2
	ubusMsgPing   = 3
	ubusMsgLookup = 4
	ubusMsgInvoke = 6
)

// ubusCall performs a ubus call via the Unix domain socket.
// This is the pure-Go equivalent of `ubus call <object> <method>`.
// Falls back to trying the legacy /var/run/ubus.sock path if the standard path fails.
func ubusCall(object, method string, timeout time.Duration) ([]byte, error) {
	// Try standard socket paths - prioritize /var/run/ubus.sock as seen on user device
	socketPaths := []string{
		"/var/run/ubus.sock",
		"/var/run/ubus/ubus.sock",
	}

	var conn net.Conn
	var err error
	for _, path := range socketPaths {
		conn, err = net.DialTimeout("unix", path, timeout)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ubus: connect failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// The ubus Unix socket protocol is a simple binary framing protocol.
	// However, many OpenWrt systems also expose ubus via a JSON-RPC HTTP interface
	// or via the `libubus` C API. The Unix socket uses a custom binary protocol
	// that is complex to implement correctly in pure Go.
	//
	// Instead, we use a simpler approach: we check if the `uhttpd` JSON-RPC
	// interface is available (localhost:80/ubus), which is standard on OpenWrt.
	conn.Close()

	return ubusCallHTTP(object, method, timeout)
}

// ubusCallHTTP performs a ubus call via the uhttpd JSON-RPC interface.
// This is the standard OpenWrt ubus HTTP interface exposed by uhttpd.
func ubusCallHTTP(object, method string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", timeout)
	if err != nil {
		return nil, fmt.Errorf("ubus http: connect failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Build JSON-RPC request
	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "call",
		"params":  []any{"00000000000000000000000000000000", object, method, map[string]any{}},
	}
	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, err
	}

	// Write HTTP request manually (avoid importing net/http for minimal binary size)
	httpReq := fmt.Sprintf("POST /ubus HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 64*1024)
	var response []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	// Find JSON body (after \r\n\r\n)
	bodyStart := -1
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}
	if bodyStart < 0 || bodyStart >= len(response) {
		return nil, fmt.Errorf("ubus http: no response body")
	}

	// Parse JSON-RPC response
	var rpcResp struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response[bodyStart:], &rpcResp); err != nil {
		return nil, fmt.Errorf("ubus http: parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("ubus http: error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	// Result is [status_code, data_object]
	if len(rpcResp.Result) < 2 {
		return nil, fmt.Errorf("ubus http: unexpected result length %d", len(rpcResp.Result))
	}

	return rpcResp.Result[1], nil
}

// ubusAvailable checks if ubus is accessible (either via socket or HTTP)
func ubusAvailable() bool {
	// Check socket
	for _, path := range []string{ubusSocketPath, "/var/run/ubus.sock"} {
		if conn, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
			conn.Close()
			return true
		}
	}
	// Check HTTP
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 500*time.Millisecond); err == nil {
		conn.Close()
		return true
	}
	return false
}

// Suppress unused import warning for binary package
var _ = binary.LittleEndian
