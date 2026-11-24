package fiberolt

import (
	"context"
	"strings"

	"wantastic-agent/internal/wusp"
)

const oltNetPrefix = wusp.WUSPOLTPrefix + "Network."

// CollectOLTNetwork fills only Device.WUSP_OLT.Network.* (management
// interface, DNS, NTP, ACL, routes, service ports, Q-VLANs) from the
// binding tables. The caller must already be logged in.
func CollectOLTNetwork(ctx context.Context, api *Client, msg *wusp.Message) {
	buildIndex()
	c := newCycle(ctx, envFor(api, nil))
	emitBindings(c, msg, func(rel string) bool { return strings.HasPrefix(rel, "Network.") })
}
