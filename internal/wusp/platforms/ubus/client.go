package ubus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	goubus "github.com/honeybbq/goubus"
	goubuserr "github.com/honeybbq/goubus/errdefs"
	goubustransport "github.com/honeybbq/goubus/transport"
)

const (
	DefaultURL          = "http://127.0.0.1/ubus"
	AnonymousSessionID  = "00000000000000000000000000000000"
	defaultContentType  = "application/json"
	defaultReloadConfig = "reload_config"
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type Options struct {
	URL               string
	SessionID         string
	HTTPDoer          Doer
	DisableNative     bool
	NativeSocketPaths []string
}

type Client struct {
	url               string
	sessionID         string
	httpDoer          Doer
	disableNative     bool
	nativeSocketPaths []string
}

var defaultNativeSocketPaths = []string{
	"/var/run/ubus/ubus.sock",
	"/run/ubus/ubus.sock",
	"/tmp/run/ubus/ubus.sock",
}

type Error struct {
	Object string
	Method string
	Code   int
	Err    string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Err) != "" {
		return fmt.Sprintf("ubus %s.%s failed: code=%d err=%s", e.Object, e.Method, e.Code, e.Err)
	}
	return fmt.Sprintf("ubus %s.%s failed: code=%d", e.Object, e.Method, e.Code)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result []json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewClient(opts Options) *Client {
	client := &Client{
		url:               strings.TrimSpace(opts.URL),
		sessionID:         strings.TrimSpace(opts.SessionID),
		httpDoer:          opts.HTTPDoer,
		disableNative:     opts.DisableNative,
		nativeSocketPaths: append([]string(nil), opts.NativeSocketPaths...),
	}
	if client.url == "" {
		client.url = DefaultURL
	}
	if client.sessionID == "" {
		client.sessionID = AnonymousSessionID
	}
	if client.httpDoer == nil {
		client.httpDoer = http.DefaultClient
	}
	if len(client.nativeSocketPaths) == 0 {
		client.nativeSocketPaths = append([]string(nil), defaultNativeSocketPaths...)
	}
	return client
}

func (c *Client) Call(ctx context.Context, object, method string, params map[string]any, timeout time.Duration) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// On-device collection must not depend on rpcd HTTP ACLs or a ubus CLI
	// binary. Prefer ubusd's native Unix socket and retain JSON-RPC only as a
	// compatibility fallback for remote/test clients.
	var nativeErr error
	if !c.disableNative && isLocalUbusURL(c.url) {
		if data, err, attempted := c.callNative(ctx, object, method, params, timeout); err == nil {
			return data, nil
		} else {
			nativeErr = err
			// Once ubusd's local socket was reached, its result is authoritative.
			// Do not repeat failed/unsupported calls through anonymous HTTP rpcd;
			// that path adds seconds to every station refresh and is commonly ACL
			// denied on stock OpenWrt.
			if attempted {
				return nil, err
			}
		}
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "call",
		Params:  []any{c.sessionID, object, method, cloneMap(params)},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", defaultContentType)

	resp, err := c.httpDoer.Do(req)
	if err != nil {
		if nativeErr != nil {
			return nil, fmt.Errorf("native ubus: %v; HTTP ubus %s.%s: %w", nativeErr, object, method, err)
		}
		return nil, fmt.Errorf("ubus %s.%s: %w", object, method, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ubus %s.%s: read body: %w", object, method, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ubus %s.%s: http status %s", object, method, resp.Status)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(payload, &rpcResp); err != nil {
		return nil, fmt.Errorf("ubus %s.%s: decode: %w", object, method, err)
	}
	if rpcResp.Error != nil {
		return nil, &Error{
			Object: object,
			Method: method,
			Code:   rpcResp.Error.Code,
			Err:    rpcResp.Error.Message,
		}
	}
	if len(rpcResp.Result) == 0 {
		return nil, nil
	}

	var status int
	if err := json.Unmarshal(rpcResp.Result[0], &status); err != nil {
		return nil, fmt.Errorf("ubus %s.%s: decode status: %w", object, method, err)
	}
	if status != 0 {
		return nil, &Error{
			Object: object,
			Method: method,
			Code:   status,
		}
	}
	if len(rpcResp.Result) < 2 {
		return nil, nil
	}
	return append([]byte(nil), rpcResp.Result[1]...), nil
}

func (c *Client) callNative(ctx context.Context, object, method string, params map[string]any, timeout time.Duration) ([]byte, error, bool) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var lastErr error
	attempted := false
	for _, socketPath := range c.nativeSocketPaths {
		socketPath = strings.TrimSpace(socketPath)
		if socketPath == "" {
			continue
		}
		info, err := os.Stat(socketPath)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		attempted = true
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		type nativeResult struct {
			data []byte
			err  error
		}
		resultCh := make(chan nativeResult, 1)
		go func() {
			socketClient, err := goubustransport.NewSocketClient(socketPath)
			if err != nil {
				resultCh <- nativeResult{err: err}
				return
			}
			client := goubus.NewClient(socketClient)
			defer client.Close()
			result, err := client.Caller().Call(object, method, cloneMap(params))
			if err != nil {
				resultCh <- nativeResult{err: err}
				return
			}
			var payload map[string]any
			err = result.Unmarshal(&payload)
			if errors.Is(err, goubuserr.ErrNoData) {
				err = nil
				payload = map[string]any{}
			}
			if err != nil {
				resultCh <- nativeResult{err: err}
				return
			}
			data, err := json.Marshal(payload)
			resultCh <- nativeResult{data: data, err: err}
		}()
		select {
		case result := <-resultCh:
			cancel()
			if result.err == nil {
				return result.data, nil, true
			}
			lastErr = result.err
		case <-callCtx.Done():
			lastErr = callCtx.Err()
			cancel()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no local ubus socket")
	}
	return nil, lastErr, attempted
}

func isLocalUbusURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (c *Client) CallJSON(ctx context.Context, object, method string, params map[string]any, timeout time.Duration, out any) error {
	data, err := c.Call(ctx, object, method, params, timeout)
	if err != nil {
		return err
	}
	if len(data) == 0 || out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) UCISet(ctx context.Context, config, section string, values map[string]any, timeout time.Duration) error {
	_, err := c.Call(ctx, "uci", "set", map[string]any{
		"config":  config,
		"section": section,
		"values":  cloneMap(values),
	}, timeout)
	return err
}

func (c *Client) UCIDelete(ctx context.Context, config, section, option string, timeout time.Duration) error {
	params := map[string]any{
		"config":  config,
		"section": section,
	}
	if strings.TrimSpace(option) != "" {
		params["option"] = option
	}
	_, err := c.Call(ctx, "uci", "delete", params, timeout)
	return err
}

func (c *Client) UCIAdd(ctx context.Context, config, sectionType, name string, values map[string]any, timeout time.Duration) (string, error) {
	data, err := c.Call(ctx, "uci", "add", map[string]any{
		"config": config,
		"type":   sectionType,
		"name":   strings.TrimSpace(name),
		"values": cloneMap(values),
	}, timeout)
	if err != nil {
		return "", err
	}
	var resp struct {
		Section string `json:"section"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Section), nil
}

func (c *Client) UCICommit(ctx context.Context, config string, timeout time.Duration) error {
	_, err := c.Call(ctx, "uci", "commit", map[string]any{"config": config}, timeout)
	return err
}

func (c *Client) UCIApply(ctx context.Context, rollback bool, timeout time.Duration) error {
	_, err := c.Call(ctx, "uci", "apply", map[string]any{"rollback": rollback}, timeout)
	return err
}

func (c *Client) UCIReloadConfig(ctx context.Context, timeout time.Duration) error {
	_, err := c.Call(ctx, "uci", defaultReloadConfig, map[string]any{}, timeout)
	return err
}

func cloneMap[T any](src map[string]T) map[string]T {
	if len(src) == 0 {
		return map[string]T{}
	}
	dst := make(map[string]T, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
