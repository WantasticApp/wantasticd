// Package firewall keeps the host firewall open for wantasticd: inbound UDP
// to the agent (direct peer-to-peer paths) and inbound traffic addressed to
// this device's overlay IPs (peers pinging or reaching services over the
// tunnel). Only Windows needs it; elsewhere the functions do nothing.
package firewall

// Rule IDs (Windows Firewall "Name") and display names. The app rule ID is
// the one older installers created, so it is replaced rather than doubled.
const (
	AppRuleID       = "Wantastic-wantasticd"
	AppRuleName     = "Wantastic (wantasticd)"
	OverlayRuleID   = "Wantastic-overlay"
	OverlayRuleName = "Wantastic overlay network"
)
