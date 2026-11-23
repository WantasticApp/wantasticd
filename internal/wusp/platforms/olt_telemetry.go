package platforms

import (
	"context"
	"net"
	"strings"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/fiberolt"
)

// oltClient returns the vendor API client for OLT backends, creating it on
// first use. Proxy deployments set OLTAPIURL/credentials in the backend
// options; otherwise the loopback device API with the vendor default login
// is used (agent running on the OLT itself).
func (b *hostBackend) oltClient() *fiberolt.Client {
	if b.oltAPI == nil {
		b.oltAPI = fiberolt.NewClient(b.oltAPIURL, b.oltAPIUser, b.oltAPIPassword)
	}
	return b.oltAPI
}

// oltEnabled reports whether OLT collection/control is on. Defaults to
// enabled once the OLT platform is detected.
func (b *hostBackend) oltEnabled() bool {
	state, err := b.readState()
	if err != nil {
		return true
	}
	return state.OLTEnabled == nil || *state.OLTEnabled
}

// collectOLTStatic fills Device.WUSP_OLT.* through the shared fiberolt
// collector. Every source failure degrades to Status/StatusDetail; it never
// fails the whole collect.
func (b *hostBackend) collectOLTStatic(ctx context.Context, msg *wusp.Message) {
	fiberolt.CollectOLT(ctx, b.oltClient(), b.oltCLI(), b.oltEnabled(), msg)
}

// oltCLI returns a FOS command-line client: the OLT's own management port
// (proxy deployments) or loopback when the agent runs on the OLT.
func (b *hostBackend) oltCLI() *fiberolt.CLI {
	host := "127.0.0.1:23"
	if u := strings.TrimSpace(b.oltAPIURL); u != "" {
		if h := cliHostFromURL(u); h != "" {
			host = net.JoinHostPort(h, "23")
		}
	}
	return fiberolt.NewCLI(host, b.oltAPIUser, b.oltAPIPassword)
}

// cliHostFromURL extracts the host part of an http(s) base URL.
func cliHostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/:"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}
