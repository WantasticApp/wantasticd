// Package firewall keeps the host firewall open for wantasticd: inbound UDP
// to the agent (direct peer-to-peer paths) and inbound traffic addressed to
// this device's overlay IPs (peers pinging or reaching services over the
// tunnel). Only Windows needs it; elsewhere the functions do nothing.
package firewall

// Rule display names; Remove deletes both.
const (
	AppRuleName     = "Wantastic (wantasticd)"
	OverlayRuleName = "Wantastic overlay network"
)
