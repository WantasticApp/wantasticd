package fiberonu

import "context"

// Identity returns the ONU's vendor identity from the loopback
// getSysteminfo.cgi (GPON_SN, Macaddress, ModelName, Manufacturer, ...).
// It is read-only and returns nil when the cgi is unreachable.
func Identity(ctx context.Context, opts Options) map[string]string {
	return fetchSysinfo(ctx, opts.cgiBase())
}
