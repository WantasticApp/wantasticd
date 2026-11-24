package wusp

// Core pages written with the agent's own safety in mind (guards).
var oltPagesCore = []OLTPage{
	{
		Route: "/device/loginmanage/servicePort", Title: "Login Manage > Service Port", Group: "Management", Section: "ServicePorts",
		Forms: []OLTForm{{
			// Management service ports of the OLT itself (NOT GPON service
			// ports). Read-only; changed only through SetServicePorts().
			Object: "Management.ServicePorts",
			Get:    OLTCall{Path: "/goform/getServicePort"},
			Fields: []OLTField{
				{Leaf: "Telnet", Vendor: "telnetport", Codec: "uint", Label: "Telnet port"},
				{Leaf: "SSH", Vendor: "sshport", Codec: "uint", Label: "SSH port"},
				{Leaf: "HTTP", Vendor: "httpport", Codec: "uint", Label: "HTTP port"},
				{Leaf: "HTTPS", Vendor: "httpsport", Codec: "uint", Label: "HTTPS port"},
				{Leaf: "SNMP", Vendor: "snmpport", Codec: "uint", Label: "SNMP port"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Management.ServicePorts.SetPorts()",
			Label:   "Change service ports", Effect: OLTEffectDisruptive,
			Help:  "setServicePort (whole form). Valid ports: 1024-65535 or the protocol default. Refuses changing the HTTP/HTTPS port the agent uses.",
			Read:  &OLTCall{Path: "/goform/getServicePort"},
			Write: OLTWrite{Path: "/goform/setServicePort", Body: []string{"telnetport", "sshport", "httpport", "httpsport", "snmpport"}, Guard: "servicePorts"},
			Inputs: []OLTField{
				{Leaf: "Telnet", Vendor: "telnetport", Codec: "uint"},
				{Leaf: "SSH", Vendor: "sshport", Codec: "uint"},
				{Leaf: "HTTP", Vendor: "httpport", Codec: "uint"},
				{Leaf: "HTTPS", Vendor: "httpsport", Codec: "uint"},
				{Leaf: "SNMP", Vendor: "snmpport", Codec: "uint"},
			},
		}},
	},
	{
		Route: "/device/loginmanage/loginmanage", Title: "Login Manage > Login Manage", Group: "Management", Section: "Login",
		Forms: []OLTForm{{
			Object: "Management.Login",
			Get:    OLTCall{Path: "/goform/getVerifyCode"},
			Set:    &OLTWrite{Path: "/goform/setVerifyCode", Body: []string{"telnetEn", "sshEn", "httpEn", "httpsEn", "snmpEn", "isShowverify"}, Guard: "loginManage"},
			Fields: []OLTField{
				{Leaf: "TelnetEnable", Vendor: "telnetEn", Codec: "bool", Write: true, Effect: OLTEffectDisruptive, Label: "Telnet"},
				{Leaf: "SSHEnable", Vendor: "sshEn", Codec: "bool", Write: true, Effect: OLTEffectDisruptive, Label: "SSH"},
				{Leaf: "HTTPEnable", Vendor: "httpEn", Codec: "bool", Write: true, Effect: OLTEffectDisruptive, Label: "HTTP"},
				{Leaf: "HTTPSEnable", Vendor: "httpsEn", Codec: "bool", Write: true, Effect: OLTEffectDisruptive, Label: "HTTPS"},
				{Leaf: "SNMPEnable", Vendor: "snmpEn", Codec: "bool", Write: true, Effect: OLTEffectDisruptive, Label: "SNMP"},
				{Leaf: "VerifyCode", Vendor: "isShowverify", Codec: "bool", Write: true, Label: "Login verify code"},
			},
		}},
	},
}
