package wusp

// Web-UI pages of the Basics menu (see olt_spec.go).
//
// Already covered elsewhere and not repeated here: CPU/memory/temperatures/
// fans/uptime and the temperature alarm thresholds (top-level health
// leaves), management IP/mask/gateway/MAC (Network.Mgmt), DNS
// (Network.DNS), the per-port status panel (PONPort.{i}).
var oltPagesBasics = []OLTPage{
	{
		Route: "/commonFunc/summary/summary", Title: "System Summary", Group: "System", Section: "Info",
		Forms: []OLTForm{{
			Object: "System.Info",
			Get:    OLTCall{Path: "/goform/getSysStatus"},
			// "Edit Device Info" dialog: the whole form is re-posted with
			// editdevice:1 and originData = the getSysStatus document.
			// deviceLocation is already Base64 in the getter, so it is
			// re-posted as read. Guarded: the agent refuses to move the
			// address it reaches the OLT through.
			Set: &OLTWrite{
				Path: "/goform/setDeviceInfo",
				Body: []string{"deviceName", "deviceLocation", "ip", "dnsType", "preferredDNS", "alternateDNS",
					"ipType", "mask", "inbandip", "inbandmask", "mngvlan", "gateway", "mnghost"},
				Extra:  map[string]any{"editdevice": "1"},
				Origin: "row",
				Guard:  "mgmtAddress",
			},
			Fields: []OLTField{
				{Leaf: "DeviceName", Vendor: "deviceName", Write: true, MaxLength: 32, Label: "Device name", Help: "Device name (1-32 characters), setDeviceInfo."},
				{Leaf: "Location", Vendor: "deviceLocation", Codec: "base64", Write: true, MaxLength: 64, Label: "Device location", Help: "Device location; Base64-encoded on the wire."},
				{Leaf: "InbandIPAddress", Vendor: "inbandip", Write: true, Effect: OLTEffectDisruptive, MaxLength: 32, Label: "In-band IP address",
					Help: "In-band management IP address. Refused when the agent reaches the OLT through it."},
				{Leaf: "InbandSubnetMask", Vendor: "inbandmask", Write: true, Effect: OLTEffectDisruptive, MaxLength: 32, Label: "In-band subnet mask",
					Help: "In-band management subnet mask. Refused when the agent reaches the OLT through the in-band address."},
				{Leaf: "ManagementHost", Vendor: "mnghost", MaxLength: 64, Label: "Management host"},
				{Leaf: "SerialNumber", Vendor: "sn", MaxLength: 64, Label: "Device SN"},
				{Leaf: "SoftwareVersion", Vendor: "softwareVersion", MaxLength: 64, Label: "Firmware version"},
				{Leaf: "HardwareVersion", Vendor: "hardwareVersion", MaxLength: 32, Label: "Hardware version"},
				{Leaf: "Created", Vendor: "created", MaxLength: 32, Label: "Created", Help: "Firmware build/creation time as reported by the OLT."},
				{Leaf: "ProductOID", Vendor: "productOid", MaxLength: 64, Label: "Product OID"},
				{Leaf: "SystemTime", Vendor: "sysTime", MaxLength: 32, Label: "System time"},
				{Leaf: "Power1", Vendor: "power1", MaxLength: 32, Label: "PWR1", Help: "Power supply 1 state (ON/OFF; vendor-padded)."},
				{Leaf: "Power2", Vendor: "power2", MaxLength: 32, Label: "PWR2", Help: "Power supply 2 state (ON/OFF; vendor-padded)."},
				{Leaf: "PONNotStarted", Vendor: "pon_not_start", Codec: "bool01", Label: "PON not started",
					Help: "True when the OLT reports its PON service could not start (summary page lock banner)."},
			},
		}},
	},
	{
		Route: "/commonFunc/summary/portStat", Title: "Port Traffic", Group: "System", Section: "Statistics",
		Forms: []OLTForm{{
			// Hourly traffic graph: per port (0-7 pon1-8, 8-13 ge1-6,
			// 14-15 xge1-2) up to 60 one-minute samples {percent, rate}.
			Object: "System.PortTraffic",
			Get:    OLTCall{Path: "/goform/getPackageStatisticsListGraph"},
			Fields: []OLTField{
				{Leaf: "StartTime", Vendor: "list.SZHourTime", Codec: "uint", Units: "unix-s", Label: "First sample time"},
				{Leaf: "RxHistory", Vendor: "list.SZHourDataIn", MaxLength: 1 << 20, Label: "RX history",
					Help: "JSON: one array per port of up to 60 one-minute samples {percent, rate}."},
				{Leaf: "TxHistory", Vendor: "list.SZHourDataOut", MaxLength: 1 << 20, Label: "TX history",
					Help: "JSON: one array per port of up to 60 one-minute samples {percent, rate}."},
			},
		}},
	},
	{
		Route: "/commonFunc/diy", Title: "DIY", Group: "System", Section: "Branding",
		Forms: []OLTForm{{
			Object: "System.Branding",
			Get:    OLTCall{Path: "/goform/getDiyInfo"},
			Set:    &OLTWrite{Path: "/goform/setDiyInfo", Body: []string{"hide", "website", "deviceModel", "hotline", "copyright"}},
			Fields: []OLTField{
				{Leaf: "Website", Vendor: "website", Write: true, MaxLength: 255, Label: "Official website"},
				{Leaf: "Hotline", Vendor: "hotline", Write: true, MaxLength: 255, Label: "Hotline"},
				{Leaf: "Copyright", Vendor: "copyright", Write: true, MaxLength: 255, Label: "Copyright"},
				{Leaf: "DeviceModel", Vendor: "deviceModel", Write: true, MaxLength: 64, Label: "Device model"},
				{Leaf: "HideFooter", Vendor: "hide", Codec: "bool01", Write: true, Label: "Hide information", Help: "Hide the footer information (website/hotline/copyright)."},
			},
		}},
		Actions: []OLTAction{{
			Command: "System.Branding.Clear()",
			Label:   "Clear branding", Effect: OLTEffectDestructive,
			Help:  "clearDiyInfo: restore the default branding (website, hotline, copyright, device model, logo).",
			Write: OLTWrite{Path: "/goform/clearDiyInfo"},
		}},
	},
}
