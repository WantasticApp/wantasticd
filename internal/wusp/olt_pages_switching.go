package wusp

// Web-UI pages of the Switching menu, part 1 (see olt_spec.go): port
// config, mirroring, link aggregation, rate limit, statistics, optical,
// 802.1Q VLAN interfaces, VLAN port member, QinQ, VLAN transform, MAC
// table / aging, static MAC and loop detection.
//
// Namespaces: Switching.Port.*, Switching.VLAN.*, Switching.MAC.*,
// Switching.Loop.*.

var (
	swUplinkPorts = []string{"ge1", "ge2", "ge3", "ge4", "ge5", "ge6", "xge1", "xge2"}
	swPONPorts    = []string{"pon1", "pon2", "pon3", "pon4", "pon5", "pon6", "pon7", "pon8"}
)

func swRange(min, max int64) (*int64, *int64) { return OLTRange(min, max) }

// swField sets Min/Max on a field (keeps the page literals compact).
func swField(f OLTField, min, max int64) OLTField {
	f.Min, f.Max = swRange(min, max)
	return f
}

// Port Config row edit. Speed, duplex and admin status are sent as "-1"
// (the UI's "No change") unless that column is the one being written: the
// getter reports the operational speed / status (portStatus "2" = enabled
// but link down), which the setter does not accept back.
var swPortBasicEdit = &OLTWrite{
	Path:     "/goform/setPortBasicInfo",
	Body:     []string{"desc", "portSpeed", "portStatus", "portIsolate", "portbridge", "jumboFrame", "portDuplex"},
	Extra:    map[string]any{"portSpeed": "-1", "portDuplex": "-1", "portStatus": "-1"},
	Port:     "name",
	PortName: true,
	Guard:    "portStatus",
}

// oltLAGTable is the link aggregation table; Add()/Delete() reuse its
// writes. Editing members is not exposed: the vendor edit body wants
// originData = the row and the group number alone, while the getter
// reports "poN".
var oltLAGTable = OLTTable{
	Object: "Switching.Port.LAG",
	Get:    OLTCall{Path: "/goform/getPortAggregatorList"},
	Key:    []string{"groupIndex"},
	Label:  "Aggregation groups",
	Help:   "Link aggregation groups. Add/Delete only: the edit form needs the group number and groupType, which the getter reports as \"poN\" and type.",
	Columns: []OLTField{
		{Leaf: "GroupIndex", Vendor: "groupIndex", Required: true, Label: "Group ID",
			Help: "Reads \"poN\"; on Add give the number only (1-32)."},
		{Leaf: "Mode", Vendor: "type", SetKey: "groupType", Required: true,
			Enum: []string{"static", "dynamic"}, EnumLabels: []string{"Static", "Dynamic (LACP)"}, Label: "Aggregation mode"},
		{Leaf: "Algorithm", Vendor: "algorithm", Required: true,
			Enum: []string{"dst-mac", "src-mac", "src-dst-mac", "dst-ip", "src-ip", "src-dst-ip"}, Label: "Load-balance algorithm"},
		{Leaf: "MemberPorts", Vendor: "port", Codec: "list", Required: true, Label: "Member ports",
			Help: "Comma-separated port names."},
	},
	Add:    &OLTWrite{Path: "/goform/setPortAggregatorRule", Body: []string{"groupIndex", "groupType", "algorithm", "port"}, Extra: map[string]any{"action": "add"}},
	Delete: &OLTWrite{Path: "/goform/delPortAggregatorList"},
}

var oltPagesSwitching = []OLTPage{
	// ---- Port ---------------------------------------------------------------
	{
		Route: "/switch/port/basic", Title: "Port > Port Config",
		Tables: []OLTTable{{
			Object: "Switching.Port.Config",
			Get:    OLTCall{Path: "/goform/getPortBasicList"},
			Key:    []string{"portName"},
			Label:  "Port list",
			Help:   "Per-port basic settings (getPortBasicList / setPortBasicInfo, row edit port=[portName]).",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "PortNum", Vendor: "portNum", Codec: "uint", Label: "Port number"},
				{Leaf: "Description", Vendor: "desc", Write: true, MaxLength: 32, Label: "Description",
					Help: "Port description (max 32). The getter shows \"--\" when empty."},
				{Leaf: "Status", Vendor: "portStatus", Write: true, Effect: OLTEffectDisruptive,
					Enum: []string{"1", "0"}, EnumLabels: []string{"Enable", "Disable"}, Label: "Port status",
					Help: "Reads 0 disabled, 1 link up, 2 enabled/link down; write 1 enable or 0 shut down. Shutting down a link-up uplink is refused (the agent may reach the OLT through it).",
					Set: &OLTWrite{Path: swPortBasicEdit.Path, Body: swPortBasicEdit.Body, Extra: swPortBasicEdit.Extra,
						Port: "name", PortName: true, Guard: "portStatus", NoVerify: true}},
				{Leaf: "Speed", Vendor: "portSpeed", Write: true, Effect: OLTEffectDisruptive, Units: "Mbps",
					Enum: []string{"100", "1000", "10000"}, EnumLabels: []string{"100M full duplex", "1000M full duplex", "10G full duplex"},
					Label: "Rate/Mode",
					Help:  "Reads the current speed in Mbps (\"--\" when down). Write forces a fixed full-duplex speed (portDuplex 1); auto-negotiation and half duplex are not exposed.",
					Set: &OLTWrite{Path: swPortBasicEdit.Path, Body: swPortBasicEdit.Body,
						Extra: map[string]any{"portDuplex": "1", "portStatus": "-1"},
						Port:  "name", PortName: true, Guard: "portStatus", NoVerify: true}},
				{Leaf: "Duplex", Vendor: "portDuplex", Enum: []string{"0", "1", "2"}, EnumLabels: []string{"Half", "Full", "Auto"}, Label: "Duplex"},
				{Leaf: "NegotiationMode", Vendor: "negotiationMode", Label: "Negotiation mode"},
				{Leaf: "Isolation", Vendor: "portIsolate", Codec: "bool01", Write: true, Label: "Port isolation"},
				{Leaf: "ONTP2P", Vendor: "portbridge", Codec: "bool01", Write: true, Label: "ONT P2P",
					Help: "PON ports: allow ONT-to-ONT forwarding (portbridge)."},
				swField(OLTField{Leaf: "JumboFrame", Vendor: "jumboFrame", Codec: "uint", Write: true, Units: "bytes", Label: "Jumbo frame",
					Help: "Max frame size 1522-10240, must be even."}, 1522, 10240),
				{Leaf: "InFlow", Vendor: "inletFlow", Codec: "decimal", Label: "Ingress flow"},
				{Leaf: "OutFlow", Vendor: "outletFlow", Codec: "decimal", Label: "Egress flow"},
			},
			Edit: swPortBasicEdit,
		}},
	},
	{
		Route: "/switch/port/mirror", Title: "Port Mirroring",
		Tables: []OLTTable{{
			Object: "Switching.Port.Mirror",
			Get:    OLTCall{Path: "/goform/getPortMirrorList"},
			Key:    []string{"destPort"},
			Label:  "Mirror groups",
			Help:   "Local mirroring groups (source ports -> destination port). The destination identifies the group; delete and re-add to change it.",
			Columns: []OLTField{
				{Leaf: "DestinationPort", Vendor: "destPort", Enum: swUplinkPorts, Required: true, Label: "Destination port"},
				{Leaf: "SourcePorts", Vendor: "srcPort", Codec: "list", Write: true, Required: true, Label: "Source ports",
					Help: "Comma-separated port names (pon1..pon8, ge1..ge6, xge1..xge2)."},
				{Leaf: "Direction", Vendor: "direction", Write: true, Required: true,
					Enum: []string{"receive", "transmit", "both"}, EnumLabels: []string{"Receive", "Transmit", "Both"}, Label: "Direction"},
				{Leaf: "Type", Vendor: "mirrorType", Label: "Mirroring group type"},
			},
			Edit:   &OLTWrite{Path: "/goform/setPortMirrorInfo", Body: []string{"srcPort", "direction", "destPort"}, Extra: map[string]any{"action": "edit"}, Origin: "row"},
			Add:    &OLTWrite{Path: "/goform/setPortMirrorInfo", Body: []string{"srcPort", "direction", "destPort"}, Extra: map[string]any{"action": "add"}},
			Delete: &OLTWrite{Path: "/goform/delPortMirrorList"},
		}},
	},
	{
		Route: "/switch/port/linkaggregation", Title: "Port Aggregation",
		Tables: []OLTTable{oltLAGTable},
		Actions: []OLTAction{
			{
				Command: "Switching.Port.LAG.Add()", Label: "Add aggregation group", Effect: OLTEffectDisruptive,
				Help:  "setPortAggregatorRule {groupIndex, groupType, algorithm, port:[...], action:add} - the Add dialog. Member ports are uplink ge/xge ports; the vendor rejects a group number already used with the same type.",
				Write: *oltLAGTable.Add,
				Inputs: []OLTField{
					{Leaf: "GroupIndex", Vendor: "groupIndex", Required: true, Min: i64(1), Max: i64(32), Label: "Group number (1-32)"},
					{Leaf: "Mode", Vendor: "groupType", Required: true, Enum: []string{"static", "dynamic"}, EnumLabels: []string{"Static", "Dynamic (LACP)"}, Label: "Aggregation mode"},
					{Leaf: "Algorithm", Vendor: "algorithm", Required: true, Enum: []string{"dst-mac", "src-mac", "src-dst-mac", "dst-ip", "src-ip", "src-dst-ip"}, Label: "Load-balance algorithm"},
					{Leaf: "MemberPorts", Vendor: "port", Codec: "list", Required: true, Label: "Member ports (comma-separated, e.g. ge5,ge6)"},
				},
			},
			{
				Command: "Switching.Port.LAG.Delete()", Label: "Delete aggregation group", Effect: OLTEffectDisruptive,
				Help:  "delPortAggregatorList {list:[group row]} for the group named by Index (the getter's groupIndex, e.g. po1).",
				Write: OLTWrite{Path: "/goform/delPortAggregatorList"},
				Rows:  &oltLAGTable,
			},
		},
	},
	{
		Route: "/switch/port/speed", Title: "Port Rate Limit",
		Tables: []OLTTable{{
			Object: "Switching.Port.RateLimit",
			Get:    OLTCall{Path: "/goform/getPortSpeedList"},
			Key:    []string{"portName"},
			Label:  "Port rate limits",
			Help:   "Per-port egress rate limit and broadcast/multicast/unknown-unicast storm control.",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				swField(OLTField{Leaf: "EgressRate", Vendor: "exitRate", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Units: "Mbps",
					Label: "Egress rate", Help: "0 = no limit; pon 1-2500, ge 1-1000, xge 1-10000 Mbps."}, 0, 10000),
				swField(OLTField{Leaf: "BroadcastLimit", Vendor: "broadcastPacket", Codec: "uint", Write: true, Units: "pps",
					Label: "Broadcast packets", Help: "Storm control, 0 = disabled, 1-1000 pps."}, 0, 1000),
				swField(OLTField{Leaf: "MulticastLimit", Vendor: "multicastPacket", Codec: "uint", Write: true, Units: "pps",
					Label: "Multicast packets", Help: "Storm control, 0 = disabled, 1-1000 pps."}, 0, 1000),
				swField(OLTField{Leaf: "UnknownUnicastLimit", Vendor: "unknownPacket", Codec: "uint", Write: true, Units: "pps",
					Label: "Unknown unicast packets", Help: "Storm control, 0 = disabled, 1-1000 pps."}, 0, 1000),
			},
			Edit: &OLTWrite{Path: "/goform/setPortSpeedInfo",
				Body:  []string{"exitRate", "broadcastPacket", "multicastPacket", "unknownPacket", "speedLimit"},
				Extra: map[string]any{"action": "edit"}, Origin: "row", Port: "name"},
		}},
	},
	{
		Route: "/switch/port/statistics", Title: "Packet Statistics",
		Tables: []OLTTable{{
			Object: "Switching.Port.Statistics",
			Get:    OLTCall{Path: "/goform/getPackageStatisticsList"},
			Key:    []string{"portName"},
			Label:  "Packet statistics",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "TxPackets", Vendor: "sendPacket", Codec: "uint", Type: TypeUnsignedLong, Label: "Transmitted packets"},
				{Leaf: "TxBytes", Vendor: "sendBit", Codec: "uint", Type: TypeUnsignedLong, Units: "bytes", Label: "Transmitted bytes"},
				{Leaf: "RxPackets", Vendor: "receivePacket", Codec: "uint", Type: TypeUnsignedLong, Label: "Received packets"},
				{Leaf: "RxBytes", Vendor: "receiveBit", Codec: "uint", Type: TypeUnsignedLong, Units: "bytes", Label: "Received bytes"},
				{Leaf: "RxBroadcast", Vendor: "receiveBroadcastNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Received broadcast packets"},
				{Leaf: "RxUnicast", Vendor: "receiveUnicastNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Received unicast packets"},
				{Leaf: "RxErrors", Vendor: "receiveErrorNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Received error packets"},
				{Leaf: "RxDiscards", Vendor: "receiveDropNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Received discard packets"},
				{Leaf: "TxBroadcast", Vendor: "sendBroadcastNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Transmitted broadcast packets"},
				{Leaf: "TxUnicast", Vendor: "sendUnicastNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Transmitted unicast packets"},
				{Leaf: "TxErrors", Vendor: "sendErrorNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Transmitted error packets"},
				{Leaf: "TxDiscards", Vendor: "sendDropNum", Codec: "uint", Type: TypeUnsignedLong, Label: "Transmitted discard packets"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.Port.ClearStatistics()",
			Label:   "Clear packet statistics", Effect: OLTEffectDestructive,
			Help:  "clearPackageStatistics {action:\"clear\"}: resets the counters of all ports.",
			Write: OLTWrite{Path: "/goform/clearPackageStatistics", Extra: map[string]any{"action": "clear"}},
		}},
	},
	{
		Route: "/switch/port/optical", Title: "Optical",
		Tables: []OLTTable{{
			Object: "Switching.Port.Optical",
			Get:    OLTCall{Path: "/goform/getPortOptical"},
			Key:    []string{"portName"},
			Label:  "Optical modules",
			Help:   "SFP/DDM readings of the optical ports.",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "Temperature", Vendor: "temperature", Codec: "decimal", Units: "C", Label: "Temperature"},
				{Leaf: "SupplyVoltage", Vendor: "supVol", Codec: "decimal", Units: "V", Label: "Supply voltage"},
				{Leaf: "TxBiasCurrent", Vendor: "txBiasCur", Codec: "decimal", Units: "mA", Label: "TX bias current"},
				{Leaf: "TxPower", Vendor: "txPower", Codec: "decimal", Units: "dBm", Label: "TX power"},
				{Leaf: "RxPower", Vendor: "rxPower", Codec: "decimal", Units: "dBm", Label: "RX power"},
				{Leaf: "VendorName", Vendor: "name", Label: "Vendor name"},
				{Leaf: "OUI", Vendor: "oui", Label: "Vendor OUI"},
				{Leaf: "ProductName", Vendor: "productname", Label: "Product name"},
				{Leaf: "Connector", Vendor: "connector", Label: "Connector"},
				{Leaf: "Wavelength", Vendor: "wavelen", Label: "Wavelength"},
				{Leaf: "Version", Vendor: "version", Label: "Version"},
				{Leaf: "SerialNumber", Vendor: "sn", Label: "Serial number"},
				{Leaf: "Date", Vendor: "date", Label: "Manufacture date"},
			},
		}},
	},

	// ---- VLAN ---------------------------------------------------------------
	{
		// VLAN create/delete and the ID/name columns live in Network.QVLAN
		// (olt.go); this table adds the L3 interface columns and the edit.
		Route: "/switch/vlan/qvlan", Title: "VLAN > 802.1Q VLAN",
		Tables: []OLTTable{{
			Object: "Switching.VLAN.List",
			Get:    OLTCall{Path: "/goform/getQvlanList"},
			Key:    []string{"vlanId"},
			Label:  "VLAN list",
			Help:   "802.1Q VLANs with their L3 virtual interface (setQvlanInfo action edit). Create/delete with Network.QVLAN.Add()/Delete().",
			Columns: []OLTField{
				{Leaf: "VLANID", Vendor: "vlanId", Codec: "uint", Label: "VLAN ID"},
				{Leaf: "Description", Vendor: "remark", SetKey: "vlanRemark", Write: true, MaxLength: 32, Label: "VLAN description"},
				{Leaf: "L3Interface", Vendor: "threeLayersEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "L3 virtual interface"},
				{Leaf: "IPAddress", Vendor: "ip", SetKey: "staticIp", Write: true, Effect: OLTEffectDisruptive, MaxLength: 15, Label: "IPv4 address"},
				{Leaf: "SubnetMask", Vendor: "mask", Write: true, Effect: OLTEffectDisruptive, MaxLength: 15, Label: "Subnet mask"},
				{Leaf: "IPType", Vendor: "ipType", Write: true, Enum: []string{"static", "dhcp"}, EnumLabels: []string{"Static", "DHCP"}, Label: "Address type"},
			},
			Edit: &OLTWrite{Path: "/goform/setQvlanInfo",
				Body:  []string{"vlanId", "vlanRemark=remark", "threeLayersEn", "ipType", "staticIp=ip", "mask"},
				Extra: map[string]any{"action": "edit"}, Origin: "row", Guard: "vlanL3"},
		}},
	},
	{
		Route: "/switch/vlan/member", Title: "VLAN > Port Member",
		Tables: []OLTTable{{
			Object: "Switching.VLAN.PortMember",
			Get:    OLTCall{Path: "/goform/getPortMemberList"},
			Key:    []string{"portName"},
			Label:  "Port members",
			Help:   "Per-port VLAN mode, PVID and tagged/untagged VLAN lists. Removing the agent's VLAN from a link-up uplink is refused.",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "LinkType", Vendor: "linkType", Write: true, Effect: OLTEffectDisruptive,
					Enum: []string{"access", "trunk", "hybrid"}, EnumLabels: []string{"Access", "Trunk", "Hybrid"}, Label: "Link type"},
				swField(OLTField{Leaf: "PVID", Vendor: "pvid", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "PVID"}, 1, 4094),
				{Leaf: "Tagged", Vendor: "tagged", Write: true, Effect: OLTEffectDisruptive, MaxLength: 256, Label: "Tagged VLANs",
					Help: "VLAN list, e.g. 3,5,10-13 (trunk/hybrid); \"--\" = none."},
				{Leaf: "Untagged", Vendor: "untagged", Write: true, Effect: OLTEffectDisruptive, MaxLength: 256, Label: "Untagged VLANs",
					Help: "VLAN list (hybrid); \"--\" = none."},
			},
			Edit: &OLTWrite{Path: "/goform/setPortMemberInfo",
				Body:  []string{"linkType", "pvid", "untagged", "tagged"},
				Extra: map[string]any{"action": "edit"}, Origin: "row", Port: "name", Guard: "vlanMember"},
		}},
	},
	{
		Route: "/switch/vlan/qinqport", Title: "VLAN > QINQ Port Config",
		Tables: []OLTTable{{
			Object: "Switching.VLAN.QinQPort",
			Get:    OLTCall{Path: "/goform/getQinqPortList"},
			Key:    []string{"portName"},
			Label:  "QinQ ports",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "Mode", Vendor: "qinqStatus", SetKey: "qinqenable", Write: true, Effect: OLTEffectDisruptive,
					Enum: []string{"0", "1", "2"}, EnumLabels: []string{"Disable", "provider-port", "customer-edge-port"}, Label: "QinQ"},
			},
			Edit: &OLTWrite{Path: "/goform/setQinqPortInfo", Port: "name"},
		}},
	},
	{
		Route: "/switch/vlan/qinqlist", Title: "VLAN > QINQ",
		Tables: []OLTTable{{
			Object: "Switching.VLAN.QinQ",
			Get:    OLTCall{Path: "/goform/getQinqVlanList"},
			Key:    []string{"index"},
			Label:  "QinQ rules",
			Help:   "Selective QinQ: C-VLAN StartVLAN on the source ports gets outer S-VLAN DestVLAN. Add/delete only.",
			Columns: []OLTField{
				{Leaf: "Index", Vendor: "index", Label: "Index"},
				{Leaf: "Port", Vendor: "portName", SetKey: "port", Codec: "list", Required: true, Label: "Source ports",
					Help: "Comma-separated port names."},
				swField(OLTField{Leaf: "StartVLAN", Vendor: "startvlan", Required: true, Label: "Source VLAN"}, 1, 4094),
				swField(OLTField{Leaf: "EndVLAN", Vendor: "endvlan", Required: true, Label: "End VLAN",
					Help: "Must equal StartVLAN (the UI forces endvlan = startvlan)."}, 1, 4094),
				swField(OLTField{Leaf: "DestVLAN", Vendor: "destvlan", Required: true, Label: "Outer VLAN"}, 1, 4094),
			},
			Add:    &OLTWrite{Path: "/goform/setQinqVlanInfo", Body: []string{"port", "startvlan", "endvlan", "destvlan"}, Extra: map[string]any{"action": "add"}},
			Delete: &OLTWrite{Path: "/goform/delQinqVlanInfo"},
		}},
	},
	{
		Route: "/switch/vlan/vlantransform", Title: "VLAN > Vlan Transform",
		Tables: []OLTTable{{
			Object: "Switching.VLAN.Transform",
			Get:    OLTCall{Path: "/goform/getVlanTransformList"},
			Key:    []string{"index"},
			Label:  "VLAN transform rules",
			Help:   "1:1 VLAN translation: StartVLAN on the source ports becomes DestVLAN. Add/delete only.",
			Columns: []OLTField{
				{Leaf: "Index", Vendor: "index", Label: "Index"},
				{Leaf: "Port", Vendor: "portName", SetKey: "port", Codec: "list", Required: true, Label: "Source ports",
					Help: "Comma-separated port names."},
				swField(OLTField{Leaf: "StartVLAN", Vendor: "startvlan", Required: true, Label: "Source VLAN"}, 1, 4094),
				swField(OLTField{Leaf: "EndVLAN", Vendor: "endvlan", Required: true, Label: "End VLAN",
					Help: "Must equal StartVLAN (the UI forces endvlan = startvlan)."}, 1, 4094),
				swField(OLTField{Leaf: "DestVLAN", Vendor: "destvlan", Required: true, Label: "Translated VLAN"}, 1, 4094),
			},
			Add:    &OLTWrite{Path: "/goform/setVlanTransformInfo", Body: []string{"port", "startvlan", "endvlan", "destvlan"}, Extra: map[string]any{"action": "add"}},
			Delete: &OLTWrite{Path: "/goform/delVlanTransformInfo"},
		}},
	},

	// ---- MAC ----------------------------------------------------------------
	{
		Route: "/switch/macConfig/macAddrTab", Title: "MAC Settings > MAC Address Table",
		Forms: []OLTForm{{
			Object: "Switching.MAC",
			Get:    OLTCall{Path: "/goform/getMacAddrList"},
			Fields: []OLTField{
				swField(OLTField{Leaf: "AgingTime", Vendor: "macagingtime", Codec: "uint", Write: true, Units: "s", Label: "MAC aging time",
					Help: "0 = no aging, else 10-1000000 seconds.",
					Set:  &OLTWrite{Path: "/goform/setMacAgingCfg"}}, 0, 1000000),
			},
		}},
		Tables: []OLTTable{{
			Object: "Switching.MAC.Address",
			Get:    OLTCall{Path: "/goform/getMacAddrList"},
			Key:    []string{"mac", "vlan", "port"},
			Label:  "MAC address table",
			Help:   "Learned/static/local MAC entries; Delete removes one entry.",
			Columns: []OLTField{
				{Leaf: "MACAddress", Vendor: "mac", Label: "MAC address"},
				{Leaf: "Type", Vendor: "type", Enum: []string{"dynamic", "static", "local"}, Label: "Type"},
				{Leaf: "VLAN", Vendor: "vlan", Label: "VLAN"},
				{Leaf: "Port", Vendor: "port", Label: "Port"},
			},
			Delete: &OLTWrite{Path: "/goform/delMacAddrList"},
		}},
	},
	{
		Route: "/switch/macConfig/staticMac", Title: "MAC Settings > Static MAC Address",
		Tables: []OLTTable{{
			Object: "Switching.MAC.Static",
			Get:    OLTCall{Path: "/goform/getStaticMacList"},
			Key:    []string{"vlanId", "mac"},
			Label:  "Static MAC list",
			Help:   "Static MAC entries (VLAN + MAC -> port). VLAN and MAC identify the entry; delete and re-add to change them.",
			Columns: []OLTField{
				swField(OLTField{Leaf: "VLANID", Vendor: "vlanId", Required: true, Label: "VLAN ID"}, 1, 4094),
				{Leaf: "MACAddress", Vendor: "mac", Required: true, MaxLength: 14, Label: "MAC address", Help: "Format xxxx-xxxx-xxxx."},
				{Leaf: "Port", Vendor: "port", Write: true, Required: true, MaxLength: 16, Label: "Port", Help: "One port name, e.g. ge1."},
			},
			Edit:   &OLTWrite{Path: "/goform/setStaticMacInfo", Body: []string{"port", "vlanId", "mac"}, Extra: map[string]any{"action": "edit"}, Origin: "row"},
			Add:    &OLTWrite{Path: "/goform/setStaticMacInfo", Body: []string{"port", "vlanId", "mac"}, Extra: map[string]any{"action": "add"}},
			Delete: &OLTWrite{Path: "/goform/delStaticMacRule"},
		}},
	},

	// ---- Loop detection -----------------------------------------------------
	{
		Route: "/switch/loopDetection/globalLoopDetection", Title: "Loop Detection > Global",
		Tables: []OLTTable{{
			Object: "Switching.Loop.Port",
			Get:    OLTCall{Path: "/goform/getGlobalLoopDetection"},
			Key:    []string{"portName"},
			Label:  "Loop detection ports",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "Enable", Vendor: "loopDetectEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "Loop detection"},
				{Leaf: "VLANs", Vendor: "loopVid", Write: true, MaxLength: 256, Label: "Loop VLAN ID",
					Help: "VLAN list, e.g. 10,20 or 10-13. The getter separates entries with '/' and shows \"--\" for none."},
				swField(OLTField{Leaf: "TxInterval", Vendor: "txIntervalTime", Codec: "uint", Write: true, Units: "s", Label: "Tx-interval time"}, 10, 300),
				swField(OLTField{Leaf: "ResumeTime", Vendor: "resumeTime", Codec: "uint", Write: true, Units: "s", Label: "Resume time"}, 180, 600),
			},
			Edit: &OLTWrite{Path: "/goform/setGlobalLoopDetection",
				Body: []string{"loopDetectEn", "loopVid", "txIntervalTime", "resumeTime"}, Port: "name", PortName: true},
		}},
	},
	{
		Route: "/switch/loopDetection/ponLoopDetection", Title: "Loop Detection > PON Loop Detection",
		Forms: []OLTForm{{
			Object: "Switching.Loop.PON",
			Get:    OLTCall{Path: "/goform/getPonLoopDetectionList"},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "loopDetectEn", Codec: "bool01", Label: "PON loop detection enabled"},
			},
		}},
		Tables: []OLTTable{{
			Object: "Switching.Loop.LoopedONT",
			Get:    OLTCall{Path: "/goform/getPonLoopDetectionList"},
			Key:    []string{"ontId"},
			Label:  "Looped ONTs",
			Help:   "ONTs blocked by loop detection; RecoverONT() un-blocks one.",
			Columns: []OLTField{
				{Leaf: "ONTID", Vendor: "ontId", Label: "ONT ID"},
				{Leaf: "SerialNumber", Vendor: "ontSn", Label: "Serial number"},
				{Leaf: "UpRemainingTime", Vendor: "upRemainingTime", Label: "Up remaining time"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.Loop.RecoverONT()",
			Label:   "Recover looped ONT", Effect: OLTEffectDisruptive,
			Help:  "setForcePonLoopDetection {ontId, port}: force-unblock an ONT. Port is the PON of the ONT ID (0/<n>/x -> pon<n>).",
			Write: OLTWrite{Path: "/goform/setForcePonLoopDetection", Body: []string{"ontId", "port"}},
			Inputs: []OLTField{
				{Leaf: "ONTID", Vendor: "ontId", Required: true, MaxLength: 16, Label: "ONT ID (frame/pon/ont)"},
				{Leaf: "Port", Vendor: "port", Required: true, Enum: swPONPorts, Label: "PON port"},
			},
		}},
	},
	{
		Route: "/switch/loopDetection/uplinkLoopDetection", Title: "Loop Detection > Uplink Loop Detection",
		Tables: []OLTTable{{
			Object: "Switching.Loop.Uplink",
			Get:    OLTCall{Path: "/goform/getUplinkLoopDetectionList"},
			Key:    []string{"portname"},
			Label:  "Uplink loop status",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portname", Label: "Port"},
				{Leaf: "Looped", Vendor: "isloop", Codec: "bool01", Label: "Loop detected"},
				{Leaf: "PortState", Vendor: "portState", Label: "Port state"},
				{Leaf: "UpRemainingTime", Vendor: "upRemainingTime", Label: "Up remaining time"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.Loop.RecoverUplink()",
			Label:   "Recover looped uplink port", Effect: OLTEffectDisruptive,
			Help:  "setForceUplinkLoopDetection {port}: force-unblock an uplink port.",
			Write: OLTWrite{Path: "/goform/setForceUplinkLoopDetection", Body: []string{"port"}},
			Inputs: []OLTField{
				{Leaf: "Port", Vendor: "port", Required: true, MaxLength: 16, Label: "Uplink port"},
			},
		}},
	},
}
