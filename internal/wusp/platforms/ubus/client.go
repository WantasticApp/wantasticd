package ubus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	URL       string
	SessionID string
	HTTPDoer  Doer
}

type Client struct {
	url       string
	sessionID string
	httpDoer  Doer
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
		url:       strings.TrimSpace(opts.URL),
		sessionID: strings.TrimSpace(opts.SessionID),
		httpDoer:  opts.HTTPDoer,
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
