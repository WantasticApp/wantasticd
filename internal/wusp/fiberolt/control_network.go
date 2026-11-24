package fiberolt

import (
	"context"
	"fmt"
	"strings"

	"wantastic-agent/internal/wusp"
)

// SetOLTNetworkParam handles Device.WUSP_OLT.Network.* setters through the
// binding tables.
func SetOLTNetworkParam(ctx context.Context, api *Client, path string, value wusp.Value) error {
	if !strings.HasPrefix(path, wusp.WUSPOLTPrefix+"Network.") {
		return wusp.ErrUSPPathUnsupported
	}
	return Set(ctx, &Env{API: api}, path, value)
}

// OLTNetworkOperate runs Device.WUSP_OLT.Network.* Operate commands; output
// fields are written into input.
func OLTNetworkOperate(ctx context.Context, api *Client, cmd string, input *wusp.Message) error {
	if !strings.HasPrefix(cmd, wusp.WUSPOLTPrefix+"Network.") {
		return wusp.ErrUSPPathUnsupported
	}
	return OLTOperate(ctx, api, cmd, input)
}

// ---- Client helpers for network settings ----------------------------------

// SetLanIP sets the management LAN IP/mask via goform/setQuickCfgNetwork.
func (c *Client) SetLanIP(ctx context.Context, field, value string) error {
	if err := c.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return c.post(ctx, "/goform/setQuickCfgNetwork", map[string]any{field: value}, nil)
}

// SetSystemTime sets DNS/NTP fields via goform/setSystemTimeInfo.
func (c *Client) SetSystemTime(ctx context.Context, field, value string) error {
	if err := c.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return c.post(ctx, "/goform/setSystemTimeInfo", map[string]any{field: value}, nil)
}
