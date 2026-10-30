package wusp

const WUSPExitNodePrefix = "Device.WUSP_ExitNode."

// WUSPExitNodeMaxCandidates bounds the Candidate table.
const WUSPExitNodeMaxCandidates = 64

var WUSPExitNodeObjects = []Object{
	{Path: WUSPExitNodePrefix, SinceVersion: "1.0", Description: "Exit-node control: share this device's internet with peers, or send this device's internet traffic through a peer that shares it."},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Peers this device can use as its exit node."},
}

var AllWUSPExitNodeParams = []Param{
	{Path: WUSPExitNodePrefix + "Supported", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "True when this device can share its internet as an exit node."},
	{Path: WUSPExitNodePrefix + "UnsupportedReason", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Why sharing is unavailable, empty when supported.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPExitNodePrefix + "ClientSupported", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "True when this device can send its internet traffic through another peer."},
	{Path: WUSPExitNodePrefix + "Offer", Type: TypeBoolean, Access: ReadWrite, SinceVersion: "1.0", Description: "Share this device's internet with peers that choose it as their exit node."},
	{Path: WUSPExitNodePrefix + "OfferBackend", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "NAT backend used while sharing.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPExitNodePrefix + "OfferError", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Why sharing could not be enabled, empty otherwise.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPExitNodePrefix + "ActiveUsers", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Peers that sent internet traffic through this device recently.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPExitNodePrefix + "Use", Type: TypeString, Access: ReadWrite, SinceVersion: "1.0", Description: "VPN IPv4 address of the peer this device sends its internet traffic through. Setting an empty string restores normal routing.", Limits: Limits{MaxLength: 45}},
	{Path: WUSPExitNodePrefix + "UseState", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "State of the exit node in use.", Limits: Limits{Enums: []string{"off", "pending", "active", "standby"}}},
	{Path: WUSPExitNodePrefix + "UseHostname", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Hostname of the exit node in use.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPExitNodePrefix + "UsePath", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Path to the exit node in use.", Limits: Limits{Enums: []string{"direct", "relay", "offline"}}},
	{Path: WUSPExitNodePrefix + "UseReason", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Why the exit node in use is not active, empty otherwise.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPExitNodePrefix + "CandidateNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of entries in Device.WUSP_ExitNode.Candidate.{i}.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.IP", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "VPN IPv4 address of the peer.", Limits: Limits{MaxLength: 45}},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.Hostname", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Hostname of the peer.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.Offers", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Whether the peer shares its internet.", Limits: Limits{Enums: []string{"yes", "no", "unknown"}}},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.Online", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "Whether the peer was seen recently."},
	{Path: WUSPExitNodePrefix + "Candidate.{i}.Path", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Path to the peer.", Limits: Limits{Enums: []string{"direct", "relay"}}},
}
