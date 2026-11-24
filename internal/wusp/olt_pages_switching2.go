package wusp

import "strconv"

// Web-UI pages of the Switching menu, part 2: DHCP snooping, spanning
// tree, IGMP (see olt_spec.go).
//
// Not modelled (UI-unreachable or not expressible as specs):
//   - goform/clearDhcpClientList and goform/setFastLeaveInfo: handlers
//     exist, but no UI button posts them.
//   - goform/cleargetIGSStatistics: no UI button and no backend handler.
//   - The multi-port "Edit" dialogs of /switch/snoop/dhcpSnoop and
//     /switch/tree/port (action "add" / port list): every port is editable
//     through its own table row, which posts the same setter.
//   - /switch/lldp/global (hidden menu): outside this file's namespaces.
var oltPagesSwitching2 = []OLTPage{
	{
		Route: "/switch/snoop/dhcpSnoop", Title: "DHCP Snooping > dhcpSnoop",
		Forms: []OLTForm{{
			Object: "Switching.DHCPSnoop",
			Get:    OLTCall{Path: "/goform/getDhcpSnoopList"},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "dhcpSnoopEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "DHCP Snooping",
					Help: "Global DHCP snooping switch. Mutually exclusive with DHCP Relay and DHCP Server.",
					Set:  &OLTWrite{Path: "/goform/setDhcpSnoopEn", Body: []string{}}},
				{Leaf: "VLANList", Vendor: "vlanList", Write: true, Label: "VLAN",
					Help: "VLANs (1-4094) on which DHCP snooping is enabled, e.g. 3,5,7,1000.",
					Set:  &OLTWrite{Path: "/goform/setDhcpSnoopVlanEn", Body: []string{}}},
				{Leaf: "RelayEnable", Vendor: "dhcpRelayEn", Codec: "bool01", Label: "DHCP Relay enabled"},
				{Leaf: "ServerEnable", Vendor: "dhcpServerEn", Codec: "bool01", Label: "DHCP Server enabled"},
			},
		}},
		Tables: []OLTTable{{
			Object: "Switching.DHCPSnoop.Port",
			Get:    OLTCall{Path: "/goform/getDhcpSnoopList"},
			Key:    []string{"portNum"},
			Label:  "Port Option 82",
			Help:   "Per-port trust and DHCP Option 82 configuration.",
			Edit: &OLTWrite{Path: "/goform/setDhcpSnoopInfo", Body: dhcpSnoopPortBody,
				Extra: map[string]any{"action": "edit"}, Origin: "row", Port: "num"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portNum", Label: "Port"},
				{Leaf: "PortType", Vendor: "portType", Write: true, Effect: OLTEffectDisruptive, Label: "Port Property",
					Enum: []string{"trust", "nontrust"}, EnumLabels: []string{"Trusted Port", "Untrusted Port"},
					Help: "Untrusted ports drop DHCP server replies."},
				{Leaf: "Option82Enable", Vendor: "optionStatusEn", Codec: "bool01", Write: true, Label: "Option 82 Status"},
				{Leaf: "Option82Policy", Vendor: "optionPloyType", Write: true, Label: "Option 82 Policy",
					Enum: []string{"replace", "keep", "drop"}, EnumLabels: []string{"Replace", "Keep", "Discard"}},
				{Leaf: "Option82Format", Vendor: "optionFormat", Write: true, Label: "Option 82 Format",
					Enum: []string{"0", "1"}, EnumLabels: []string{"ascii", "hex"}},
				{Leaf: "Option82Delimiter", Vendor: "optionDelimiter", Write: true, Label: "Option 82 Delimiter",
					Enum: []string{"0", "1", "2", "3"}, EnumLabels: []string{"space", "colon", "dot", "slash"}},
				{Leaf: "CircuitIDType", Vendor: "circuitidType", Write: true, Label: "CircuitId Type",
					Enum: []string{"0", "1", "2"}, EnumLabels: []string{"Disable", "User Define", "System Information"}},
				{Leaf: "CircuitID", Vendor: "circuitiddef", Write: true, MaxLength: 64, Label: "CircuitId",
					Help: "User-defined circuit ID (1-64 chars); required when CircuitIDType is 1."},
				{Leaf: "CircuitIDSystemName", Vendor: "circuitsysname", Codec: "bool", Write: true, Label: "CircuitId: System Name"},
				{Leaf: "CircuitIDSystemMAC", Vendor: "circuitsysmac", Codec: "bool", Write: true, Label: "CircuitId: System Mac"},
				{Leaf: "CircuitIDVLANID", Vendor: "circuitvlanid", Codec: "bool", Write: true, Label: "CircuitId: VlanId"},
				{Leaf: "CircuitIDPortName", Vendor: "circuitportname", Codec: "bool", Write: true, Label: "CircuitId: PortName"},
				{Leaf: "CircuitIDONTID", Vendor: "circuitontid", Codec: "bool", Write: true, Label: "CircuitId: OntId"},
				{Leaf: "CircuitIDONTMAC", Vendor: "circuitontmac", Codec: "bool", Write: true, Label: "CircuitId: Ont Mac"},
				{Leaf: "CircuitIDONTSN", Vendor: "circuitontsn", Codec: "bool", Write: true, Label: "CircuitId: Ont SN"},
				{Leaf: "CircuitIDONTModel", Vendor: "circuitontmodel", Codec: "bool", Write: true, Label: "CircuitId: Ont Model"},
				{Leaf: "RemoteIDType", Vendor: "remoteidType", Write: true, Label: "Remoteid Type",
					Enum: []string{"0", "1", "2"}, EnumLabels: []string{"Disable", "User Define", "System Information"}},
				{Leaf: "RemoteID", Vendor: "remoteiddef", Write: true, MaxLength: 64, Label: "RemoteId",
					Help: "User-defined remote ID (1-64 chars); required when RemoteIDType is 1."},
				{Leaf: "RemoteIDSystemName", Vendor: "remotesysname", Codec: "bool", Write: true, Label: "RemoteId: System Name"},
				{Leaf: "RemoteIDSystemMAC", Vendor: "remotesysmac", Codec: "bool", Write: true, Label: "RemoteId: System Mac"},
				{Leaf: "RemoteIDVLANID", Vendor: "remotevlanid", Codec: "bool", Write: true, Label: "RemoteId: VlanId"},
				{Leaf: "RemoteIDPortName", Vendor: "remoteportname", Codec: "bool", Write: true, Label: "RemoteId: PortName"},
				{Leaf: "RemoteIDONTID", Vendor: "remoteontid", Codec: "bool", Write: true, Label: "RemoteId: OntId"},
				{Leaf: "RemoteIDONTMAC", Vendor: "remoteontmac", Codec: "bool", Write: true, Label: "RemoteId: Ont Mac"},
				{Leaf: "RemoteIDONTSN", Vendor: "remoteontsn", Codec: "bool", Write: true, Label: "RemoteId: Ont SN"},
				{Leaf: "RemoteIDONTModel", Vendor: "remoteontmodel", Codec: "bool", Write: true, Label: "RemoteId: Ont Model"},
			},
		}},
	},
	{
		Route: "/switch/snoop/dhcpClientList", Title: "DHCP Snooping > dhcpClientList",
		Tables: []OLTTable{{
			Object: "Switching.DHCPSnoop.Client",
			Get:    OLTCall{Path: "/goform/getDhcpClientList"},
			Key:    []string{"macaddr", "vlan"},
			Label:  "DHCP client (binding) list",
			Help:   "DHCP snooping bindings. Delete removes the binding (destructive).",
			Delete: &OLTWrite{Path: "/goform/delDhcpClientList"},
			Columns: []OLTField{
				{Leaf: "Index", Vendor: "index", Label: "Index"},
				{Leaf: "IPAddress", Vendor: "ipaddr", Label: "IP address"},
				{Leaf: "MACAddress", Vendor: "macaddr", Label: "Mac Address"},
				{Leaf: "Interface", Vendor: "interface", Label: "Interface"},
				{Leaf: "VLAN", Vendor: "vlan", Label: "Vlan"},
				{Leaf: "Expire", Vendor: "expire", Label: "Expire"},
				{Leaf: "RemainingTime", Vendor: "remaintime", Label: "Remain time"},
			},
		}},
	},
	{
		Route: "/switch/tree/global", Title: "Spanning Tree > Global",
		Forms: []OLTForm{{
			Object: "Switching.STP",
			Get:    OLTCall{Path: "/goform/getSpanningTreeInfo"},
			Set: &OLTWrite{Path: "/goform/setSpanningTreeInfo",
				Body: []string{"treeVersion", "agingTime", "helloTime", "forwardDelay", "maxHopCount", "bridgePriority", "domain", "correctionLevel"}},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "treeStatusEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "Status",
					Set: &OLTWrite{Path: "/goform/setSpanningTreeInfo", Body: []string{}}},
				{Leaf: "Mode", Vendor: "treeVersion", Write: true, Effect: OLTEffectDisruptive, Label: "Spanning Tree Mode",
					Enum: []string{"STP", "RSTP", "MSTP"}, EnumLabels: []string{"STP", "RSTP", "MSTP"}},
				{Leaf: "MaxAge", Vendor: "agingTime", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "Maximum Aging Time", Units: "s",
					Min: i64(6), Max: i64(40), Help: "Max aging >= 2x(Hello+1) and <= 2x(Forward delay-1)."},
				{Leaf: "HelloTime", Vendor: "helloTime", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "Hello Time", Units: "s",
					Min: i64(1), Max: i64(10)},
				{Leaf: "ForwardDelay", Vendor: "forwardDelay", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "Forwarding Delay", Units: "s",
					Min: i64(4), Max: i64(30)},
				{Leaf: "MaxHops", Vendor: "maxHopCount", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "Maximum Hops",
					Min: i64(6), Max: i64(40)},
				{Leaf: "BridgePriority", Vendor: "bridgePriority", Write: true, Effect: OLTEffectDisruptive, Label: "Bridge Priority",
					Enum: stpBridgePriorities, EnumLabels: stpBridgePriorities},
				{Leaf: "RegionName", Vendor: "domain", Write: true, Effect: OLTEffectDisruptive, Label: "Region Name", MaxLength: 32,
					Help: "MSTP region name (MSTP mode only)."},
				{Leaf: "Revision", Vendor: "correctionLevel", Codec: "uint", Write: true, Effect: OLTEffectDisruptive, Label: "Revision",
					Min: i64(0), Max: i64(65535), Help: "MSTP revision level (MSTP mode only)."},
				{Leaf: "Digest", Vendor: "summary", Label: "Digest", Help: "MSTP configuration digest."},
				{Leaf: "BridgeID", Vendor: "bridgeId", Label: "Bridge ID"},
				{Leaf: "RootBridgeID", Vendor: "rootBridgeId", Label: "Root Bridge ID"},
				{Leaf: "RegionRootID", Vendor: "rootDomainId", Label: "Region Root ID"},
				{Leaf: "RootPort", Vendor: "rootPort", Label: "Root Port"},
				{Leaf: "RootPathCost", Vendor: "rootPathCost", Label: "Root Path Cost"},
				{Leaf: "InternalRootPathCost", Vendor: "inRootPathCost", Label: "Internal Root Path Cost"},
				{Leaf: "TopologyStatus", Vendor: "topoStatus", Label: "Topology Status"},
				{Leaf: "TopologyChangeTime", Vendor: "topoChangeTime", Label: "Last Changed Time"},
			},
		}},
		Tables: []OLTTable{{
			Object: "Switching.STP.MSTI",
			Get:    OLTCall{Path: "/goform/getMstpInstanceList"},
			Key:    []string{"instanceId"},
			Label:  "MSTP Instance",
			Help:   "MSTP instances (MSTP mode). Instance 0 is the CIST: the web UI offers no edit or delete for it. Change a VLAN mapping with Switching.STP.EditMSTI().",
			Add:    &OLTWrite{Path: "/goform/setMstpInstanceInfo", Body: []string{"instanceId", "vlanList", "bridgePriority"}, Extra: map[string]any{"action": "add"}},
			// Priority-only edit: the UI's VLAN deltas are empty.
			Edit: &OLTWrite{Path: "/goform/setMstpInstanceInfo", Body: []string{"instanceId", "vlanList", "bridgePriority"},
				Extra: map[string]any{"action": "edit", "addList": []any{}, "delList": []any{}}, Origin: "row"},
			Delete:       &OLTWrite{Path: "/goform/delMstpInstanceList"},
			DeleteEffect: OLTEffectDisruptive,
			Columns: []OLTField{
				{Leaf: "InstanceID", Vendor: "instanceId", Codec: "uint", Required: true, Min: i64(1), Max: i64(4094), Label: "Instance ID"},
				{Leaf: "VLANList", Vendor: "vlanList", Required: true, Label: "VLAN Mapping List", Help: "e.g. 3,5,7 or 10-13."},
				{Leaf: "BridgePriority", Vendor: "bridgePriority", Write: true, Required: true, Effect: OLTEffectDisruptive, Label: "Bridge Priority",
					Enum: stpBridgePriorities, EnumLabels: stpBridgePriorities},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.STP.EditMSTI()",
			Label:   "Edit MSTP instance", Effect: OLTEffectDisruptive,
			Help: "setMstpInstanceInfo action edit. The UI posts the new VLAN list plus addList/delList, the individual VLAN IDs added and removed " +
				"(ranges expanded). originData (the old row) is not sent by this command.",
			Write: OLTWrite{Path: "/goform/setMstpInstanceInfo", Body: []string{"instanceId", "vlanList", "bridgePriority", "addList", "delList"},
				Extra: map[string]any{"action": "edit"}},
			Inputs: []OLTField{
				{Leaf: "InstanceID", Vendor: "instanceId", Codec: "uint", Required: true, Min: i64(1), Max: i64(4094), Label: "Instance ID"},
				{Leaf: "VLANList", Vendor: "vlanList", Required: true, Label: "New VLAN mapping list"},
				{Leaf: "BridgePriority", Vendor: "bridgePriority", Required: true, Enum: stpBridgePriorities, Label: "Bridge Priority"},
				{Leaf: "AddList", Vendor: "addList", Codec: "list", Label: "VLAN IDs added (comma-separated, no ranges)"},
				{Leaf: "DelList", Vendor: "delList", Codec: "list", Label: "VLAN IDs removed (comma-separated, no ranges)"},
			},
		}},
	},
	{
		Route: "/switch/tree/port", Title: "Spanning Tree > Port Configuration",
		Tables: []OLTTable{{
			Object: "Switching.STP.Port",
			Get:    OLTCall{Path: "/goform/getPortTreeList"},
			Key:    []string{"portName"},
			Label:  "STP port list",
			Edit:   &OLTWrite{Path: "/goform/setPortTreeInfo", Body: []string{}, Port: "name"},
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "PortNum", Vendor: "portNum", Label: "Port index"},
				{Leaf: "STPEnable", Vendor: "stpEn", Codec: "bool01", Label: "STP Status"},
				{Leaf: "EdgePort", Vendor: "edgePort", Codec: "bool01", Label: "Edge Port"},
				{Leaf: "P2P", Vendor: "p2pPort", Write: true, Effect: OLTEffectDisruptive, Label: "P2P Port",
					Enum: []string{"0", "1", "2"}, EnumLabels: []string{"Disable", "Enable", "Auto"},
					Help: "Not settable on LAG member ports."},
			},
		}},
	},
	{
		Route: "/switch/tree/statistics", Title: "Spanning Tree > Port Statistics",
		Tables: []OLTTable{{
			Object: "Switching.STP.PortStats",
			Get:    OLTCall{Path: "/goform/getPortTreeStatisticsList"},
			Key:    []string{"portName"},
			Label:  "STP port statistics",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "TxMSTP", Vendor: "sendMstp", Codec: "uint", Label: "Transmit MSTP"},
				{Leaf: "TxRSTP", Vendor: "sendRstp", Codec: "uint", Label: "Transmit RSTP"},
				{Leaf: "TxSTP", Vendor: "sendStp", Codec: "uint", Label: "Transmit STP"},
				{Leaf: "TxTCN", Vendor: "sendTcn", Codec: "uint", Label: "Transmit TCN"},
				{Leaf: "RxMSTP", Vendor: "receiveMstp", Codec: "uint", Label: "Receive MSTP"},
				{Leaf: "RxRSTP", Vendor: "receiveRstp", Codec: "uint", Label: "Receive RSTP"},
				{Leaf: "RxSTP", Vendor: "receiveStp", Codec: "uint", Label: "Receive STP"},
				{Leaf: "RxTCN", Vendor: "dropTcn", Codec: "uint", Label: "Receive TCN"},
				{Leaf: "DiscardUnknown", Vendor: "dropUnknown", Codec: "uint", Label: "Discard Unknown"},
				{Leaf: "DiscardIllegal", Vendor: "dropIllegal", Codec: "uint", Label: "Discard Illegal"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.STP.ClearPortStats()",
			Label:   "Clear STP port statistics", Effect: OLTEffectDestructive,
			Write: OLTWrite{Path: "/goform/clearPortTreeStatistics", Extra: map[string]any{"action": "clear"}},
		}},
	},
	{
		Route: "/switch/tree/instance", Title: "Spanning Tree > Instance Info",
		Forms: []OLTForm{{
			Object: "Switching.STP.InstanceInfo",
			Get:    OLTCall{Path: "/goform/getPortTreeStatusList", Params: map[string]string{"instanceId": "0"}},
			Fields: []OLTField{
				{Leaf: "InstanceIDs", Vendor: "instanceList", Codec: "list", Label: "Instance IDs"},
			},
		}},
		Tables: []OLTTable{{
			// The getter takes the instance as a query parameter; the
			// table shows instance 0 (CIST).
			Object: "Switching.STP.CISTPort",
			Get:    OLTCall{Path: "/goform/getPortTreeStatusList", Params: map[string]string{"instanceId": "0"}},
			Key:    []string{"portName"},
			Label:  "Instance 0 (CIST) port status",
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "PortNum", Vendor: "portNum", Label: "Port index"},
				{Leaf: "Role", Vendor: "portRole", Label: "Port Role", Help: "0 Disabled, 1 Root, 2 Designated, 3 Alternate, 4 Backup, 5 Master."},
				{Leaf: "State", Vendor: "portStatus", Label: "Port Status", Help: "0 Disabled, 1 Listening, 2 Learning, 3 Forwarding, 4 Blocking."},
				{Leaf: "RegionRootID", Vendor: "domainRoot", Label: "Region Root ID"},
				{Leaf: "DesignatedBridge", Vendor: "bridgeId", Label: "Designated Bridge"},
				{Leaf: "DesignatedPort", Vendor: "port", Label: "Designated Port"},
				{Leaf: "Priority", Vendor: "priority", Label: "Priority"},
				{Leaf: "PathCost", Vendor: "portPathCost", Label: "Path Cost", Help: "0 = default."},
			},
		}},
		Actions: []OLTAction{{
			Command: "Switching.STP.SetInstancePort()",
			Label:   "Set port priority / path cost in an instance", Effect: OLTEffectDisruptive,
			Help:  "setPortTreeStatusInfo as the multi-port Edit dialog posts it (action add, srcPort = port names).",
			Write: OLTWrite{Path: "/goform/setPortTreeStatusInfo", Body: []string{"srcPort", "instanceId", "priority", "portPathCost"}, Extra: map[string]any{"action": "add"}},
			Inputs: []OLTField{
				{Leaf: "Ports", Vendor: "srcPort", Codec: "list", Required: true, Label: "Port names (comma-separated, e.g. ge1,xge1)"},
				{Leaf: "InstanceID", Vendor: "instanceId", Codec: "uint", Required: true, Min: i64(0), Max: i64(4094), Label: "Instance ID"},
				{Leaf: "Priority", Vendor: "priority", Required: true, Enum: stpPortPriorities, Label: "Priority"},
				{Leaf: "PathCost", Vendor: "portPathCost", Type: TypeUnsignedInt, Required: true, Min: i64(0), Max: i64(200000000), Label: "Path Cost (0 = default)"},
			},
		}},
	},
	{
		Route: "/switch/igmp/global", Title: "IGMP Snooping > Global",
		Forms: []OLTForm{{
			Object: "Switching.IGMP",
			Get:    OLTCall{Path: "/goform/getIgmpSnoopEn"},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "igmpSnoopingEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "IGMP Snooping",
					Set: &OLTWrite{Path: "/goform/setIgmpSnoopEn", Body: []string{}}},
			},
		}},
		Tables: []OLTTable{
			{
				Object: "Switching.IGMP.VLAN",
				Get:    OLTCall{Path: "/goform/getIgmpVlanInfo"},
				List:   "vlanList",
				Key:    []string{"vlanId"},
				Label:  "IGMP per-VLAN settings",
				Help:   "Change with Switching.IGMP.SetVLAN() (the setter keys the VLAN as mulVlanId).",
				Columns: []OLTField{
					{Leaf: "VLANID", Vendor: "vlanId", Label: "VLAN ID"},
					{Leaf: "Enable", Vendor: "vlanEn", Codec: "bool01", Label: "VLAN"},
					{Leaf: "MulticastVLANEnable", Vendor: "mulVlanEn", Codec: "bool01", Label: "Multicast VLAN Status"},
					{Leaf: "Version", Vendor: "igmpVersion", Label: "Protocol Version"},
					{Leaf: "FastLeave", Vendor: "fastleave", Codec: "bool01", Label: "Fast Leave"},
					{Leaf: "ReportSuppression", Vendor: "reportsup", Codec: "bool01", Label: "Report Suppression"},
					{Leaf: "MaxResponseTime", Vendor: "maxResponseTime", Codec: "uint", Units: "s", Label: "Max Query Response Time"},
					{Leaf: "Querier", Vendor: "query", Codec: "bool01", Label: "Querier"},
					{Leaf: "QuerierSourceIP", Vendor: "sourceip", Label: "Querier Source IP"},
				},
			},
			{
				Object: "Switching.IGMP.Group",
				Get:    OLTCall{Path: "/goform/getMulGroupList"},
				Key:    []string{"portNum", "vlanid"},
				Label:  "Multicast Group",
				Columns: []OLTField{
					{Leaf: "Port", Vendor: "portNum", Label: "Port"},
					{Leaf: "VLANID", Vendor: "vlanid", Label: "VlanId"},
					{Leaf: "Groups", Vendor: "groups", Label: "Groups", Help: "Semicolon-separated group addresses."},
				},
			},
			{
				Object: "Switching.IGMP.DynamicRouter",
				Get:    OLTCall{Path: "/goform/getMulrouterList"},
				Key:    []string{"vlanid", "portNum"},
				Label:  "Multicast Routing Port (dynamic)",
				Columns: []OLTField{
					{Leaf: "VLANID", Vendor: "vlanid", Label: "Vlan Id"},
					{Leaf: "Port", Vendor: "portNum", Label: "Port"},
				},
			},
			{
				Object:       "Switching.IGMP.StaticRouter",
				Get:          OLTCall{Path: "/goform/getMulRouterTab"},
				Key:          []string{"vlanId", "port"},
				Label:        "Multicast routing table (static)",
				Help:         "Static multicast router ports. Delete posts the row without the UI's client-side index.",
				Add:          &OLTWrite{Path: "/goform/setMulRouterTab", Body: []string{"port", "vlanId"}, Extra: map[string]any{"action": "add"}},
				Delete:       &OLTWrite{Path: "/goform/delMulRouterTab"},
				DeleteEffect: OLTEffectConfig,
				Columns: []OLTField{
					{Leaf: "VLANID", Vendor: "vlanId", Codec: "uint", Required: true, Min: i64(1), Max: i64(4094), Label: "Vlan Id"},
					{Leaf: "Port", Vendor: "port", Required: true, Label: "Port", Help: "Port name, e.g. ge1 or xge1 (PON ports are not offered)."},
				},
			},
			{
				Object: "Switching.IGMP.Stats",
				Get:    OLTCall{Path: "/goform/getIGSStatistics"},
				Key:    []string{"portName", "vlan"},
				Label:  "IGMP Statistics",
				Columns: []OLTField{
					{Leaf: "Port", Vendor: "portName", Label: "Port"},
					{Leaf: "VLAN", Vendor: "vlan", Label: "vlan"},
					{Leaf: "TxQueryGeneral", Vendor: "txQuerygeneral", Codec: "uint", Label: "Transmit Query general"},
					{Leaf: "TxQueryGroup", Vendor: "txQuerygroup", Codec: "uint", Label: "Transmit Query group"},
					{Leaf: "TxReportV1", Vendor: "txReportV1", Codec: "uint", Label: "Transmit Report V1"},
					{Leaf: "TxReportV2", Vendor: "txReportV2", Codec: "uint", Label: "Transmit Report V2"},
					{Leaf: "TxReportV3", Vendor: "txReportV3", Codec: "uint", Label: "Transmit Report V3"},
					{Leaf: "TxLeaveV2", Vendor: "txLeaveV2", Codec: "uint", Label: "Transmit Leave V2"},
					{Leaf: "TxOther", Vendor: "txOther", Codec: "uint", Label: "Transmit Other"},
					{Leaf: "RxQueryGeneral", Vendor: "rxQuerygeneral", Codec: "uint", Label: "Receive Query general"},
					{Leaf: "RxQueryGroup", Vendor: "rxQuerygroup", Codec: "uint", Label: "Receive Query group"},
					{Leaf: "RxReportV1", Vendor: "rxReportV1", Codec: "uint", Label: "Receive Report V1"},
					{Leaf: "RxReportV2", Vendor: "rxReportV2", Codec: "uint", Label: "Receive Report V2"},
					{Leaf: "RxReportV3", Vendor: "rxReportV3", Codec: "uint", Label: "Receive Report V3"},
					{Leaf: "RxLeaveV2", Vendor: "rxLeaveV2", Codec: "uint", Label: "Receive Leave V2"},
					{Leaf: "RxOther", Vendor: "rxOther", Codec: "uint", Label: "Receive Other"},
				},
			},
		},
		Actions: []OLTAction{{
			Command: "Switching.IGMP.SetVLAN()",
			Label:   "Set IGMP VLAN settings", Effect: OLTEffectDisruptive,
			Help: "setIgmpVlanInfo (Global tab Confirm): all nine fields are posted, so every input is required; read the current values " +
				"from Switching.IGMP.VLAN.{i}.",
			Write: OLTWrite{Path: "/goform/setIgmpVlanInfo",
				Body: []string{"mulVlanId", "vlanEn", "mulVlanEn", "igmpVersion", "fastleave", "reportsup", "maxResponseTime", "query", "sourceip"}},
			Inputs: []OLTField{
				{Leaf: "VLANID", Vendor: "mulVlanId", Codec: "uint", Required: true, Min: i64(1), Max: i64(4094), Label: "VLAN ID"},
				{Leaf: "Enable", Vendor: "vlanEn", Codec: "bool01", Required: true, Label: "VLAN"},
				{Leaf: "MulticastVLANEnable", Vendor: "mulVlanEn", Codec: "bool01", Required: true, Label: "Multicast VLAN Status"},
				{Leaf: "Version", Vendor: "igmpVersion", Required: true, Enum: []string{"v1", "v2", "v3"}, EnumLabels: []string{"v1", "v2", "v3"}, Label: "Protocol Version"},
				{Leaf: "FastLeave", Vendor: "fastleave", Codec: "bool01", Required: true, Label: "Fast Leave"},
				{Leaf: "ReportSuppression", Vendor: "reportsup", Codec: "bool01", Required: true, Label: "Report Suppression"},
				{Leaf: "MaxResponseTime", Vendor: "maxResponseTime", Type: TypeUnsignedInt, Required: true, Min: i64(1), Max: i64(25), Units: "s", Label: "Max Query Response Time"},
				{Leaf: "Querier", Vendor: "query", Codec: "bool01", Required: true, Label: "Querier"},
				{Leaf: "QuerierSourceIP", Vendor: "sourceip", Required: true, Label: "Querier Source IP"},
			},
		}},
	},
}

// dhcpSnoopPortBody is every field of the DHCP snooping port dialog.
var dhcpSnoopPortBody = []string{
	"portType", "optionStatusEn", "optionPloyType", "optionFormat", "optionDelimiter",
	"circuitidType", "circuitiddef", "circuitsysname", "circuitsysmac", "circuitvlanid", "circuitportname",
	"circuitontid", "circuitontmac", "circuitontsn", "circuitontmodel",
	"remoteidType", "remoteiddef", "remotesysname", "remotesysmac", "remotevlanid", "remoteportname",
	"remoteontid", "remoteontmac", "remoteontsn", "remoteontmodel",
}

// stpBridgePriorities: 0-61440 in steps of 4096.
var stpBridgePriorities = oltSteps(0, 61440, 4096)

// stpPortPriorities: 0-240 in steps of 16.
var stpPortPriorities = oltSteps(0, 240, 16)

func oltSteps(from, to, step int) []string {
	var out []string
	for v := from; v <= to; v += step {
		out = append(out, strconv.Itoa(v))
	}
	return out
}
