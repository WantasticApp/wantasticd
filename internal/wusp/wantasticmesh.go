package wusp

// WantasticMesh (wmeshd): the Wantastic mesh control plane on QCA routers.
// The agent reads wmeshd's UCI section and the status file it writes
// (/tmp/wmesh-status.json, schema 1) and never talks to its control protocol
// or touches its keys. Writable parameters map one to one onto UCI options;
// wmeshd's procd service restarts itself when its config is committed.

const WUSPWantasticMeshPrefix = "Device.WUSP_WantasticMesh."

// Bounds for the tables, matching wmeshd's own limits with headroom.
const (
	WUSPWantasticMeshMaxNodes     = 64
	WUSPWantasticMeshMaxRadios    = 8
	WUSPWantasticMeshMaxLinks     = 32
	WUSPWantasticMeshMaxDistances = 128
	WUSPWantasticMeshMaxPlanRows  = 64
	WUSPWantasticMeshMaxSurveys   = 16
)

var WUSPWantasticMeshObjects = []Object{
	{Path: WUSPWantasticMeshPrefix, SinceVersion: "1.0", Description: "WantasticMesh (wmeshd) state and settings on this device."},
	{Path: WUSPWantasticMeshPrefix + "Backhaul.", SinceVersion: "1.0", Description: "The wireless backhaul wmeshd manages on this device."},
	{Path: WUSPWantasticMeshPrefix + "Node.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Mesh nodes known to this device: every node on a root, only itself on a leaf."},
	{Path: WUSPWantasticMeshPrefix + "Node.{i}.Radio.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Radios the node reported."},
	{Path: WUSPWantasticMeshPrefix + "Node.{i}.Link.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Directional links the node measured towards a peer radio."},
	{Path: WUSPWantasticMeshPrefix + "Survey.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Channel survey of this node's radios: noise floor and how busy the channel is."},
	{Path: WUSPWantasticMeshPrefix + "Distance.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Great-circle distance between two nodes that both have a GPS fix."},
	{Path: WUSPWantasticMeshPrefix + "PlanChannel.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Channel moves the root's coordination engine proposes."},
	{Path: WUSPWantasticMeshPrefix + "PlanHeal.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "Recovery actions the root's self-heal engine proposes."},
}

func wmeshParam(leaf string, typ ParamType, access Access, description string, limits Limits) Param {
	return Param{Path: WUSPWantasticMeshPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPWantasticMeshParams = []Param{
	wmeshParam("Installed", TypeBoolean, ReadOnly, "True when wmeshd is installed on this device.", Limits{}),
	wmeshParam("Enable", TypeBoolean, ReadWrite, "Run WantasticMesh on this device.", Limits{}),
	wmeshParam("Status", TypeString, ReadOnly, "State of the mesh service.", Limits{Enums: []string{"not_installed", "disabled", "stopped", "starting", "running", "misconfigured"}}),
	wmeshParam("StatusDetail", TypeString, ReadOnly, "What is missing when the service is misconfigured, empty otherwise.", Limits{MaxLength: 256}),
	wmeshParam("StatusAge", TypeUnsignedInt, ReadOnly, "Seconds since wmeshd last wrote its status.", Limits{Min: iptr(0)}),
	wmeshParam("Uptime", TypeUnsignedInt, ReadOnly, "Seconds the mesh service has been running.", Limits{Min: iptr(0)}),
	wmeshParam("Role", TypeString, ReadWrite, "root runs the controller and sees every node; relay is a leaf that reports to it.", Limits{Enums: []string{"root", "relay"}}),
	wmeshParam("NetworkID", TypeString, ReadWrite, "Mesh network id, 16 hex characters. Every node of one mesh uses the same value.", Limits{Pattern: "^([0-9a-fA-F]{16})?$", MaxLength: 16}),
	wmeshParam("NodeID", TypeString, ReadOnly, "This node's id, 32 hex characters.", Limits{MaxLength: 32}),
	wmeshParam("ControllerID", TypeString, ReadWrite, "Node id of the root this leaf reports to, 32 hex characters.", Limits{Pattern: "^([0-9a-fA-F]{32})?$", MaxLength: 32}),
	wmeshParam("ControllerAddress", TypeString, ReadWrite, "Optional IPv4 address of the root, for routed backhauls where multicast discovery cannot reach.", Limits{MaxLength: 45}),
	wmeshParam("ControllerAlive", TypeBoolean, ReadOnly, "True when this leaf's root answers. Always true on the root.", Limits{}),
	wmeshParam("Port", TypeUnsignedInt, ReadWrite, "UDP port of the mesh control protocol.", Limits{Min: iptr(1), Max: iptr(65535)}),
	wmeshParam("GPS", TypeBoolean, ReadWrite, "Report this node's GPS position to the root.", Limits{}),
	wmeshParam("KeyPresent", TypeBoolean, ReadOnly, "True when the node's control key file exists. The key itself is never reported.", Limits{}),
	wmeshParam("AgentsConfigured", TypeUnsignedInt, ReadOnly, "Leaves in the root's keystore.", Limits{Min: iptr(0)}),
	wmeshParam("Transport", TypeString, ReadOnly, "How the mesh control protocol travels between nodes (l2 = Ethernet frames on the backhaul).", Limits{MaxLength: 16}),
	wmeshParam("TransportInterfaces", TypeUnsignedInt, ReadOnly, "Interfaces the control protocol listens on.", Limits{Min: iptr(0)}),
	wmeshParam("MeshConnected", TypeBoolean, ReadOnly, "True when every node the root knows is reachable through the reported links. Root only.", Limits{}),
	wmeshParam("ActiveNodes", TypeUnsignedInt, ReadOnly, "Nodes answering the root. Root only.", Limits{Min: iptr(0)}),
	wmeshParam("StaleNodes", TypeUnsignedInt, ReadOnly, "Nodes that went silent. Root only.", Limits{Min: iptr(0)}),
	wmeshParam("BackhaulLinks", TypeUnsignedInt, ReadOnly, "Backhaul links the root knows. Root only.", Limits{Min: iptr(0)}),
	wmeshParam("MLORadios", TypeUnsignedInt, ReadOnly, "Radios taking part in a multi-link device across the mesh. Root only.", Limits{Min: iptr(0)}),
	wmeshParam("ChannelConflicts", TypeUnsignedInt, ReadOnly, "Pairs of fronthaul radios on the same channel. Root only.", Limits{Min: iptr(0)}),
	wmeshParam("ExchangeSuccess", TypeDecimal, ReadOnly, "Share of control exchanges that completed, in percent.", Limits{MinF: fptr(0), MaxF: fptr(100)}),
	wmeshParam("AuthFailures", TypeUnsignedInt, ReadOnly, "Control frames that failed authentication since the service started.", Limits{Min: iptr(0)}),
	wmeshParam("DecodeErrors", TypeUnsignedInt, ReadOnly, "Control frames that could not be decoded since the service started.", Limits{Min: iptr(0)}),

	wmeshParam("Backhaul.SSID", TypeString, ReadWrite, "SSID of the wireless backhaul wmeshd joins. Empty leaves the backhaul to the firmware.", Limits{MaxLength: 32}),
	wmeshParam("Backhaul.Radio", TypeString, ReadWrite, "Radio (phy) that carries the backhaul.", Limits{MaxLength: 16}),
	wmeshParam("Backhaul.Interface", TypeString, ReadWrite, "Name of the runtime station interface wmeshd creates.", Limits{MaxLength: 15}),
	wmeshParam("Backhaul.BSSID", TypeString, ReadWrite, "Optional BSSID lock for the backhaul.", Limits{Pattern: "^(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})?$", MaxLength: 17}),
	wmeshParam("Backhaul.Frequency", TypeUnsignedInt, ReadWrite, "Optional frequency lock in MHz, 0 for any.", Limits{Min: iptr(0), Max: iptr(7125)}),
	wmeshParam("Backhaul.FourAddress", TypeBoolean, ReadWrite, "Use 4-address (WDS) frames on the backhaul.", Limits{}),
	wmeshParam("Backhaul.MLOSSID", TypeString, ReadWrite, "SSID of a multi-link (802.11be) backhaul: one association over several radios, preferred over the single link, which stays the fallback. Empty disables it.", Limits{MaxLength: 32}),
	wmeshParam("Backhaul.MLORadios", TypeString, ReadWrite, "Radios of the multi-link backhaul, comma separated.", Limits{MaxLength: 64}),
	wmeshParam("Backhaul.MLOFrequencies", TypeString, ReadWrite, "Optional frequency per multi-link radio in MHz, comma separated.", Limits{MaxLength: 64}),
	wmeshParam("Backhaul.Managed", TypeBoolean, ReadOnly, "True when wmeshd manages a backhaul station on this node.", Limits{}),
	wmeshParam("Backhaul.Up", TypeBoolean, ReadOnly, "True when the managed backhaul is associated.", Limits{}),

	wmeshParam("NodeNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_WantasticMesh.Node.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.ID", TypeString, ReadOnly, "Node id, 32 hex characters.", Limits{MaxLength: 32}),
	wmeshParam("Node.{i}.Self", TypeBoolean, ReadOnly, "True for this device's own row.", Limits{}),
	wmeshParam("Node.{i}.Stale", TypeBoolean, ReadOnly, "True when the node has gone silent.", Limits{}),
	wmeshParam("Node.{i}.TelemetryStale", TypeBoolean, ReadOnly, "True when the node is alive but its radios, links and position are old.", Limits{}),
	wmeshParam("Node.{i}.Age", TypeUnsignedInt, ReadOnly, "Seconds since the node last proved it was alive.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Reports", TypeUnsignedInt, ReadOnly, "Reports the root accepted from the node.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.ReportAge", TypeUnsignedInt, ReadOnly, "Seconds since the node's newest accepted report.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.HasFix", TypeBoolean, ReadOnly, "True when the node reports a valid GPS fix.", Limits{}),
	wmeshParam("Node.{i}.Latitude", TypeDecimal, ReadOnly, "Latitude in decimal degrees. Absent without a fix.", Limits{MinF: fptr(-90), MaxF: fptr(90)}),
	wmeshParam("Node.{i}.Longitude", TypeDecimal, ReadOnly, "Longitude in decimal degrees. Absent without a fix.", Limits{MinF: fptr(-180), MaxF: fptr(180)}),
	wmeshParam("Node.{i}.Altitude", TypeInt, ReadOnly, "Altitude in metres. Absent without a fix.", Limits{}),
	wmeshParam("Node.{i}.RTT", TypeUnsignedInt, ReadOnly, "Round-trip time of the root's last exchange with the node in microseconds. Absent when not measured.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.RadioNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Node.{i}.Radio.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.LinkNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Node.{i}.Link.{i}.", Limits{Min: iptr(0)}),

	wmeshParam("Node.{i}.Radio.{i}.Index", TypeUnsignedInt, ReadOnly, "The node's own radio index.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Radio.{i}.Band", TypeString, ReadOnly, "Operating band.", Limits{Enums: []string{"", "2.4GHz", "5GHz", "6GHz"}}),
	wmeshParam("Node.{i}.Radio.{i}.Channel", TypeUnsignedInt, ReadOnly, "Operating channel.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Radio.{i}.Width", TypeUnsignedInt, ReadOnly, "Channel width in MHz.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Radio.{i}.TxPower", TypeInt, ReadOnly, "Transmit power in dBm.", Limits{}),
	wmeshParam("Node.{i}.Radio.{i}.Utilization", TypeUnsignedInt, ReadOnly, "Channel utilization as wmeshd reports it, 0-255.", Limits{Min: iptr(0), Max: iptr(255)}),
	wmeshParam("Node.{i}.Radio.{i}.Backhaul", TypeBoolean, ReadOnly, "True when the radio carries a backhaul link.", Limits{}),
	wmeshParam("Node.{i}.Radio.{i}.MLO", TypeBoolean, ReadOnly, "True when the radio is part of a multi-link device.", Limits{}),
	wmeshParam("Node.{i}.Radio.{i}.MLDLink", TypeUnsignedInt, ReadOnly, "Link id inside the multi-link device. Absent without MLO.", Limits{Min: iptr(0)}),

	wmeshParam("Node.{i}.Link.{i}.PeerMAC", TypeMACAddress, ReadOnly, "MAC of the peer radio.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.Radio", TypeUnsignedInt, ReadOnly, "The node's radio index the link was measured on.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.SignalStrength", TypeInt, ReadOnly, "Received signal in dBm.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.Age", TypeUnsignedInt, ReadOnly, "Milliseconds since the measurement.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.Confidence", TypeUnsignedInt, ReadOnly, "Confidence in the measurement, 0-100.", Limits{Min: iptr(0), Max: iptr(255)}),
	wmeshParam("Node.{i}.Link.{i}.Backhaul", TypeBoolean, ReadOnly, "True when the link carries mesh backhaul traffic.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.Bidirectional", TypeBoolean, ReadOnly, "True when the link is confirmed usable in both directions.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.MLO", TypeBoolean, ReadOnly, "True when the link is part of a multi-link association.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.Approximate", TypeBoolean, ReadOnly, "True when the link was inferred from observation, not verified.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.HasTelemetry", TypeBoolean, ReadOnly, "True when this node's driver counters for the link follow. Only a node's own links carry them.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.TxRate", TypeUnsignedInt, ReadOnly, "Transmit PHY rate in kbit/s.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.RxRate", TypeUnsignedInt, ReadOnly, "Receive PHY rate in kbit/s.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.BytesSent", TypeUnsignedLong, ReadOnly, "Bytes sent on the link.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.BytesReceived", TypeUnsignedLong, ReadOnly, "Bytes received on the link.", Limits{}),
	wmeshParam("Node.{i}.Link.{i}.Retransmissions", TypeUnsignedInt, ReadOnly, "Frames retried.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.Failed", TypeUnsignedInt, ReadOnly, "Frames that failed after every retry.", Limits{Min: iptr(0)}),
	wmeshParam("Node.{i}.Link.{i}.InactiveTime", TypeUnsignedInt, ReadOnly, "Milliseconds since the link last carried a frame.", Limits{Min: iptr(0)}),

	wmeshParam("SurveyNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_WantasticMesh.Survey.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("Survey.{i}.Frequency", TypeUnsignedInt, ReadOnly, "Surveyed frequency in MHz.", Limits{Min: iptr(0)}),
	wmeshParam("Survey.{i}.Noise", TypeInt, ReadOnly, "Noise floor in dBm.", Limits{}),
	wmeshParam("Survey.{i}.Utilization", TypeDecimal, ReadOnly, "Share of time the channel was busy, in percent.", Limits{MinF: fptr(0), MaxF: fptr(100)}),

	wmeshParam("DistanceNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_WantasticMesh.Distance.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("Distance.{i}.A", TypeString, ReadOnly, "Node id of one end.", Limits{MaxLength: 32}),
	wmeshParam("Distance.{i}.B", TypeString, ReadOnly, "Node id of the other end.", Limits{MaxLength: 32}),
	wmeshParam("Distance.{i}.Meters", TypeDecimal, ReadOnly, "Distance in metres from both nodes' GPS fixes.", Limits{MinF: fptr(0)}),

	wmeshParam("PlanChannelNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_WantasticMesh.PlanChannel.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("PlanChannel.{i}.Node", TypeString, ReadOnly, "Node the move is for.", Limits{MaxLength: 32}),
	wmeshParam("PlanChannel.{i}.Radio", TypeUnsignedInt, ReadOnly, "The node's radio index.", Limits{Min: iptr(0)}),
	wmeshParam("PlanChannel.{i}.Band", TypeString, ReadOnly, "Band of the radio.", Limits{Enums: []string{"", "2.4GHz", "5GHz", "6GHz"}}),
	wmeshParam("PlanChannel.{i}.From", TypeUnsignedInt, ReadOnly, "Current channel.", Limits{Min: iptr(0)}),
	wmeshParam("PlanChannel.{i}.To", TypeUnsignedInt, ReadOnly, "Proposed channel.", Limits{Min: iptr(0)}),

	wmeshParam("PlanHealNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_WantasticMesh.PlanHeal.{i}.", Limits{Min: iptr(0)}),
	wmeshParam("PlanHeal.{i}.Node", TypeString, ReadOnly, "Node the action is for.", Limits{MaxLength: 32}),
	wmeshParam("PlanHeal.{i}.Kind", TypeString, ReadOnly, "Kind of recovery action.", Limits{MaxLength: 32}),
	wmeshParam("PlanHeal.{i}.Reason", TypeString, ReadOnly, "Why the action is proposed.", Limits{MaxLength: 256}),
}
