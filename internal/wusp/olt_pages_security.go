package wusp

// Web-UI pages of the Network Security menu plus the API-only security
// features whose goform handlers exist in firmware 1.1.3.18 (see
// olt_spec.go). The IP ACL list itself (getAclList / setAclListInfo /
// delAclList) is the hand-written Network.ACL table; its rules live here.
//
// Tables whose USP Add would need body keys that are not row columns
// (rule add, ACL binding) are added through an OLTAction instead.

var oltPagesSecurity = []OLTPage{
	{
		Route: "/network/acl/ipacl", Title: "IP ACL", Group: "Security", Section: "ACL",
		Tables: []OLTTable{{
			Object: "Security.ACL.IPRule",
			Label:  "IP ACL rules",
			Help:   "Rules of every IPv4 ACL (getIpAclList, all ACLs). ACL IDs themselves are Device.WUSP_OLT.Network.ACL.{i}.",
			Get:    OLTCall{Path: "/goform/getIpAclList"},
			Key:    []string{"aclId", "priority"},
			Columns: []OLTField{
				{Leaf: "ACLID", Vendor: "aclId", Label: "ACL ID"},
				{Leaf: "Priority", Vendor: "priority", Label: "Priority"},
				{Leaf: "Protocol", Vendor: "protocol", Label: "Protocol", Help: "IP protocol number (1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 255 any)."},
				{Leaf: "SourceType", Vendor: "srcIpType", Label: "Source IP", Enum: []string{"all", "one"}, EnumLabels: []string{"Any", "Specified"}},
				{Leaf: "SourceIP", Vendor: "srcIp", Label: "Source IP address"},
				{Leaf: "SourceMask", Vendor: "srcMask", Label: "Source wildcard mask"},
				{Leaf: "DestType", Vendor: "destIpType", Label: "Destination IP", Enum: []string{"all", "one"}, EnumLabels: []string{"Any", "Specified"}},
				{Leaf: "DestIP", Vendor: "destIp", Label: "Destination IP address"},
				{Leaf: "DestMask", Vendor: "destMask", Label: "Destination wildcard mask"},
				{Leaf: "SourcePort", Vendor: "srcPort", Label: "Source port", Help: "\"-\" = all."},
				{Leaf: "DestPort", Vendor: "destPort", Label: "Destination port", Help: "\"-\" = all."},
				{Leaf: "Action", Vendor: "actionEn", Label: "ACL mode", Enum: []string{"permit", "forbit"}, EnumLabels: []string{"Permit", "Forbid"}},
			},
			Delete: &OLTWrite{Path: "/goform/delIpAclList"},
		}},
		Actions: []OLTAction{{
			Command: "Security.ACL.AddIPRule()",
			Label:   "Add IP ACL rule", Effect: OLTEffectDisruptive,
			Help: "setIpAclInfo action add. A rule bound to a port (Security.ACL.Binding) filters traffic at once; a forbid rule on the management path can cut the agent off.",
			Write: OLTWrite{Path: "/goform/setIpAclInfo",
				Body:  []string{"aclId", "priority", "protocol", "srcIpType", "srcIp", "srcMask", "destIpType", "destIp", "destMask", "srcPort", "destPort", "actionEn"},
				Extra: map[string]any{"action": "add"}},
			Inputs: []OLTField{
				{Leaf: "ACLID", Vendor: "aclId", Required: true, Label: "ACL ID (100-199, must exist)"},
				{Leaf: "Priority", Vendor: "priority", Label: "Priority (1-127; the web UI sends it empty)"},
				{Leaf: "Protocol", Vendor: "protocol", Required: true, Label: "IP protocol 0-255 (1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 255 any)"},
				{Leaf: "SourceType", Vendor: "srcIpType", Required: true, Enum: []string{"all", "one"}, Label: "Source: all | one"},
				{Leaf: "SourceIP", Vendor: "srcIp", Label: "Source IP (SourceType one)"},
				{Leaf: "SourceMask", Vendor: "srcMask", Label: "Source wildcard mask"},
				{Leaf: "DestType", Vendor: "destIpType", Required: true, Enum: []string{"all", "one"}, Label: "Destination: all | one"},
				{Leaf: "DestIP", Vendor: "destIp", Label: "Destination IP (DestType one)"},
				{Leaf: "DestMask", Vendor: "destMask", Label: "Destination wildcard mask"},
				{Leaf: "SourcePort", Vendor: "srcPort", Label: "Source port 1-65535"},
				{Leaf: "DestPort", Vendor: "destPort", Label: "Destination port 1-65535"},
				{Leaf: "Action", Vendor: "actionEn", Required: true, Enum: []string{"permit", "forbit"}, Label: "permit | forbit (sic)"},
			},
		}},
	},
	{
		Route: "/network/acl/appacl", Title: "Apply ACL", Group: "Security", Section: "ACL",
		Tables: []OLTTable{{
			Object: "Security.ACL.Binding",
			Label:  "Applied ACLs",
			Help:   "ACLs bound to ports (ingress). Change a binding by deleting it and binding again.",
			Get:    OLTCall{Path: "/goform/getAppAclList"},
			Key:    []string{"port", "aclId"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "port", Label: "Applied port"},
				{Leaf: "ACLID", Vendor: "aclId", Label: "ACL ID"},
				{Leaf: "Type", Vendor: "aclType", Label: "ACL type"},
				{Leaf: "Direction", Vendor: "filterDirection", Label: "Filter direction"},
			},
			Delete: &OLTWrite{Path: "/goform/delAppAclList"},
		}},
		Actions: []OLTAction{{
			Command: "Security.ACL.Bind()",
			Label:   "Bind IP ACL to ports", Effect: OLTEffectDisruptive,
			Help: "setAppAclInfo action add (ingress, IPv4 ACL). ACLID and IPv4ACL must carry the same ACL ID (the UI sends aclId = ipv4Acl). Filtering starts at once: binding a forbid ACL to the uplink can cut the agent off.",
			Write: OLTWrite{Path: "/goform/setAppAclInfo",
				Body:  []string{"port", "aclId", "ipv4Acl"},
				Extra: map[string]any{"filterDirection": "in", "aclType": "ipv4Acl", "ipv6Acl": "", "macAcl": "", "action": "add"}},
			Inputs: []OLTField{
				{Leaf: "Ports", Vendor: "port", Codec: "list", Required: true, Label: "Port names, comma-separated (pon1,ge1,xge1)"},
				{Leaf: "ACLID", Vendor: "aclId", Required: true, Label: "ACL ID (100-199)"},
				{Leaf: "IPv4ACL", Vendor: "ipv4Acl", Required: true, Label: "Same ACL ID again (ipv4Acl)"},
			},
		}},
	},
	{
		Route: "/network/security/portsecurity", Title: "MAC Security > Port MAC Security", Group: "Security", Section: "PortSecurity",
		Tables: []OLTTable{{
			Object: "Security.PortSecurity.Port",
			Label:  "Port MAC security",
			Get:    OLTCall{Path: "/goform/getPortSecurity"},
			Key:    []string{"portName"},
			Columns: []OLTField{
				{Leaf: "Name", Vendor: "portName", Label: "Port"},
				{Leaf: "Number", Vendor: "portNum", Label: "Port index"},
				{Leaf: "Flapping", Vendor: "flapping", Write: true, Effect: OLTEffectDisruptive, Label: "MAC flapping detection",
					Enum: []string{"1", "0"}, EnumLabels: []string{"Enable", "Disable"}},
				{Leaf: "Limit", Vendor: "limit", Write: true, Effect: OLTEffectDisruptive, Label: "MAC learning limit",
					Help: "0 = no limit, 1-1024 = max learned MACs. A low limit on the uplink can stop the agent's traffic."},
			},
			Edit: &OLTWrite{Path: "/goform/setPortSecurity", Body: []string{"flapping", "limit"},
				Extra: map[string]any{"action": "edit"}, Origin: "row", Port: "name"},
		}},
		Actions: []OLTAction{{
			Command: "Security.PortSecurity.Apply()",
			Label:   "Set MAC security on ports", Effect: OLTEffectDisruptive,
			Help:  "setPortSecurity multi-port edit (action add). Flapping/Limit -1 leaves the value unchanged.",
			Write: OLTWrite{Path: "/goform/setPortSecurity", Body: []string{"port", "flapping", "limit"}, Extra: map[string]any{"action": "add"}},
			Inputs: []OLTField{
				{Leaf: "Ports", Vendor: "port", Codec: "list", Required: true, Label: "Port names, comma-separated"},
				{Leaf: "Flapping", Vendor: "flapping", Required: true, Enum: []string{"-1", "1", "0"}, Label: "-1 unchanged, 1 enable, 0 disable"},
				{Leaf: "Limit", Vendor: "limit", Required: true, Label: "-1 unchanged, 0 no limit, 1-1024"},
			},
		}},
	},
	{
		Route: "/network/security/macflapping", Title: "MAC Security > ONT MAC Flapping", Group: "Security", Section: "MACFlapping",
		Tables: []OLTTable{{
			Object: "Security.MACFlapping.Port",
			Label:  "ONT MAC flapping",
			Get:    OLTCall{Path: "/goform/getOntMacFlappingConfig"},
			Key:    []string{"portnum"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portnum", Label: "PON port"},
				{Leaf: "Enable", Vendor: "enable", Codec: "bool01", Write: true, Label: "MAC address flapping detection"},
			},
			Edit: &OLTWrite{Path: "/goform/setOntMacFlappingConfig", Body: []string{"portnum", "enable"},
				Extra: map[string]any{"action": "edit"}, Origin: "empty"},
		}},
		Actions: []OLTAction{
			{
				Command: "Security.MACFlapping.EnableAll()", Label: "Enable on all PON ports", Effect: OLTEffectConfig,
				Write: OLTWrite{Path: "/goform/setOntMacFlappingConfig", Extra: map[string]any{"portnum": "all", "enable": "1"}},
			},
			{
				Command: "Security.MACFlapping.DisableAll()", Label: "Disable on all PON ports", Effect: OLTEffectConfig,
				Write: OLTWrite{Path: "/goform/setOntMacFlappingConfig", Extra: map[string]any{"portnum": "all", "enable": "0"}},
			},
		},
	},

	// ---- API-only features (orphan web-UI chunks, handlers present) ----

	{
		Route: "(orphan) antiArpAttack.js", Title: "Anti ARP attack", Group: "Security", Section: "AntiARP",
		Forms: []OLTForm{{
			Object: "Security.AntiARP",
			Get:    OLTCall{Path: "/goform/getPortArpAttackInfo"},
			Set:    &OLTWrite{Path: "/goform/setPortArpAttackInfo", Body: []string{"arpReceptRate"}},
			Fields: []OLTField{
				{Leaf: "ReceiveRate", Vendor: "arpReceptRate", Codec: "uint", Write: true, Min: i64(30), Max: i64(300), Units: "pps", Label: "ARP receive rate limit"},
			},
		}},
	},
	{
		Route: "(orphan) antiDosAttack.js", Title: "Anti DoS attack", Group: "Security", Section: "AntiDoS",
		Forms: []OLTForm{{
			Object: "Security.AntiDoS",
			Get:    OLTCall{Path: "/goform/getDosAttackInfo"},
			Set: &OLTWrite{Path: "/goform/setDosAttackInfo", Body: []string{"arpMacCheckEn", "tcpPackageCheckEn", "tcpFlagZeroEn",
				"tcpPackageFlagsEn", "tcpPackageSynEn", "tcpPackageRstEn", "tcpPortZeroEn", "tcpSycDataEn", "icmpFragEn"}},
			Fields: []OLTField{
				{Leaf: "ARPMACCheck", Vendor: "arpMacCheckEn", Codec: "bool01", Write: true, Label: "ARP source MAC check"},
				{Leaf: "TCPCheck", Vendor: "tcpPackageCheckEn", Codec: "bool01", Write: true, Label: "TCP packet check"},
				{Leaf: "TCPFlagZero", Vendor: "tcpFlagZeroEn", Codec: "bool01", Write: true, Label: "Drop TCP with all flags zero"},
				{Leaf: "TCPFlags", Vendor: "tcpPackageFlagsEn", Codec: "bool01", Write: true, Label: "Drop TCP FIN/URG/PSH"},
				{Leaf: "TCPSynFin", Vendor: "tcpPackageSynEn", Codec: "bool01", Write: true, Label: "Drop TCP SYN+FIN"},
				{Leaf: "TCPSynRst", Vendor: "tcpPackageRstEn", Codec: "bool01", Write: true, Label: "Drop TCP SYN+RST"},
				{Leaf: "TCPPortZero", Vendor: "tcpPortZeroEn", Codec: "bool01", Write: true, Label: "Drop TCP/UDP port 0"},
				{Leaf: "TCPSynData", Vendor: "tcpSycDataEn", Codec: "bool01", Write: true, Label: "Drop SYN with data"},
				{Leaf: "ICMPFragment", Vendor: "icmpFragEn", Codec: "bool01", Write: true, Label: "Drop fragmented ICMP"},
			},
		}},
	},
	{
		Route: "(orphan) antiMacAttack.js", Title: "Anti MAC attack", Group: "Security", Section: "AntiMAC",
		Tables: []OLTTable{{
			Object: "Security.AntiMAC.Port",
			Label:  "Anti MAC attack",
			Get:    OLTCall{Path: "/goform/getPortMacAttackList"},
			Key:    []string{"portNum"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portNum", Label: "Port"},
				{Leaf: "DropEnable", Vendor: "macDropEn", Codec: "bool01", Write: true, Label: "Drop MAC attack packets"},
			},
			// No action key on this page: {port:[row.portNum], macDropEn}.
			Edit: &OLTWrite{Path: "/goform/setPortMacAttackInfo", Body: []string{"macDropEn"}, Port: "num"},
		}},
	},
	{
		Route: "(orphan) ipMacFilter.js", Title: "IP-MAC filter", Group: "Security", Section: "IPMACFilter",
		Tables: []OLTTable{{
			Object: "Security.IPMACFilter",
			Label:  "IP-MAC filter",
			Get:    OLTCall{Path: "/goform/getIpMacFilterList"},
			Key:    []string{"mac", "vlanId"},
			Columns: []OLTField{
				{Leaf: "MAC", Vendor: "mac", Required: true, Label: "MAC (xxxx-xxxx-xxxx)"},
				{Leaf: "VLAN", Vendor: "vlanId", Required: true, Min: i64(1), Max: i64(4094), Label: "VLAN ID"},
			},
			// The UI posts action:"action" (sic) on add.
			Add:    &OLTWrite{Path: "/goform/setIpMacFilterList", Body: []string{"vlanId", "mac"}, Extra: map[string]any{"action": "action"}},
			Delete: &OLTWrite{Path: "/goform/delIpMacFilterList"},
		}},
	},
	{
		Route: "(orphan) netAuthIndex.js", Title: "802.1X / network auth", Group: "Security", Section: "Dot1X",
		Forms: []OLTForm{
			{
				Object: "Security.Dot1X",
				Get:    OLTCall{Path: "/goform/getNetAuthEn"},
				Fields: []OLTField{
					{Leaf: "Enable", Vendor: "authEn", Codec: "bool01", Write: true, Effect: OLTEffectDisruptive, Label: "802.1X authentication",
						Help: "Enabling 802.1X with auto/auth ports blocks unauthenticated traffic on them, possibly the agent's.",
						Set:  &OLTWrite{Path: "/goform/setNetAuthEn", Body: []string{"authEn"}}},
				},
			},
			{
				// The shared key is returned by the getter but never exposed;
				// it is re-sent unchanged and set only via SetSharedKey().
				Object: "Security.Dot1X.Server",
				Get:    OLTCall{Path: "/goform/getAuthGlobalInfo"},
				Set:    &OLTWrite{Path: "/goform/setAuthGlobalInfo", Body: []string{"authIp", "shareKey"}},
				Fields: []OLTField{
					{Leaf: "Address", Vendor: "authIp", Write: true, Label: "RADIUS server IP"},
				},
			},
		},
		Tables: []OLTTable{{
			Object: "Security.Dot1X.Port",
			Label:  "802.1X ports",
			Get:    OLTCall{Path: "/goform/getNetPortList"},
			Key:    []string{"portNum"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portNum", Label: "Port"},
				{Leaf: "ControlType", Vendor: "portControlType", Write: true, Effect: OLTEffectDisruptive, Label: "Port control",
					Enum: []string{"auto", "auth", "unauth", "close"}, EnumLabels: []string{"Auto", "Force authorized", "Force unauthorized", "Disable"}},
				{Leaf: "AuthStatus", Vendor: "portAuthStatus", Label: "Authorized (1) / not"},
				{Leaf: "ReAuthEnable", Vendor: "reAuthEn", Codec: "bool01", Write: true, Label: "Re-authentication"},
				{Leaf: "ReAuthTimeout", Vendor: "reAuthTimeout", Codec: "uint", Write: true, Min: i64(1), Max: i64(65535), Units: "s", Label: "Re-auth period"},
				{Leaf: "ClientTimeout", Vendor: "clientTimeout", Codec: "uint", Write: true, Min: i64(1), Max: i64(65535), Units: "s", Label: "Client timeout"},
				{Leaf: "ReAuthMax", Vendor: "reAuthMaxNum", Codec: "uint", Write: true, Min: i64(1), Max: i64(10), Label: "Max re-auth attempts"},
			},
			// No action key: {port:[row.portNum], <fields>, originData: row}.
			Edit: &OLTWrite{Path: "/goform/setNetPortInfo", Body: []string{"portControlType", "reAuthEn", "reAuthTimeout", "clientTimeout", "reAuthMaxNum"},
				Port: "num", Origin: "row"},
		}},
		Actions: []OLTAction{{
			Command: "Security.Dot1X.SetSharedKey()", Label: "Set 802.1X RADIUS shared key", Effect: OLTEffectConfig,
			Help:  "setAuthGlobalInfo {authIp, shareKey}; the server address is kept unless Address is given.",
			Read:  &OLTCall{Path: "/goform/getAuthGlobalInfo"},
			Write: OLTWrite{Path: "/goform/setAuthGlobalInfo", Body: []string{"authIp", "shareKey"}},
			Inputs: []OLTField{
				{Leaf: "SharedKey", Vendor: "shareKey", Required: true, MaxLength: 64, Label: "Shared key (ASCII, up to 64)"},
				{Leaf: "Address", Vendor: "authIp", Label: "RADIUS server IP (optional)"},
			},
		}},
	},

	// ---- hidden pages without a usable backend ----

	{Route: "/network/acl/list", Title: "ACL List",
		Unsupported: "hidden page (hide:true); the same getAclList/setAclListInfo/delAclList API is Device.WUSP_OLT.Network.ACL.{i} with Add()/Delete()"},
	{Route: "/network/acl/macacl", Title: "MAC ACL",
		Unsupported: "hidden page; getMacAclList/setMacAcInfo/delMacAclList have no handler in firmware 1.1.3.18"},
	{Route: "/network/acl/ipv6acl", Title: "IPv6 ACL",
		Unsupported: "CONFIG_HAVE_IPV6=n; getIpv6AclList/setIpv6AclInfo/delIpv6AclList have no handler in firmware 1.1.3.18"},
	{Route: "(orphan) gponPortMacFlapping.js", Title: "PON port MAC flapping",
		Unsupported: "orphan chunk; getPortMacFlappingConfig/setPortMacFlappingConfig have no handler (use Security.MACFlapping.Port)"},
	{Route: "(orphan) radiusConfig.js", Title: "RADIUS config",
		Unsupported: "stale orphan of the AAA page: same getRadiusInfo/setRadiusInfo handler with an old key set (radiusServer, sharedKey); use Device.WUSP_OLT.Management.AAA"},
}
