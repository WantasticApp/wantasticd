//go:build !linux

package platforms

import "wantastic-agent/internal/wusp"

// appendSystemResources is Linux-only for now (routers and servers).
func appendSystemResources(*wusp.Message) {}
