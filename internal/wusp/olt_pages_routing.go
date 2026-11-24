package wusp

// Web-UI pages of the Routing menu (see olt_spec.go).
//
// Static routes are listed/added/deleted by the hand-written
// Network.Route table and its Add()/Delete() commands; this file only adds
// the next-hop edit the UI offers (Routing.StaticRoute).
var oltPagesRouting = []OLTPage{
	{
		Route: "/router/static/ipv4", Title: "Static Routing",
		Tables: []OLTTable{{
			Object: "Routing.StaticRoute",
			Get:    OLTCall{Path: "/goform/getStaticRouteList"},
			Key:    []string{"destIp", "mask"},
			Label:  "Static routes (next-hop edit)",
			Help:   "Same rows as Network.Route; only the next hop is editable (add/delete via Network.Route.Add()/Delete()).",
			Edit:   &OLTWrite{Path: "/goform/setStaticRouteInfo", Body: []string{"destIp", "mask", "nextHop"}, Extra: map[string]any{"action": "edit"}, Origin: "row"},
			Columns: []OLTField{
				{Leaf: "Destination", Vendor: "destIp", Label: "Destination IP"},
				{Leaf: "Mask", Vendor: "mask", Label: "Subnet mask"},
				{Leaf: "NextHop", Vendor: "nextHop", Write: true, MaxLength: 15, Label: "Next hop"},
			},
		}},
	},
	{
		Route: "/router/arp/table", Title: "ARP Table",
		Forms: []OLTForm{{
			Object: "Routing.ARP",
			Get:    OLTCall{Path: "/goform/getArpTableList"},
			Fields: []OLTField{
				{Leaf: "AgingTime", Vendor: "agingTime", Codec: "uint", Write: true, Units: "s", Label: "ARP aging time",
					Min: i64(100), Max: i64(3000),
					Set: &OLTWrite{Path: "/goform/setAgingTime", Body: []string{}}},
			},
		}},
		Tables: []OLTTable{{
			Object: "Routing.ARP.Entry",
			Get:    OLTCall{Path: "/goform/getArpTableList"},
			Key:    []string{"ip"},
			Label:  "ARP table",
			Help:   "Add creates a static ARP entry. Entries with StaticLocal=1 cannot be deleted in the UI.",
			Add:    &OLTWrite{Path: "/goform/setArpTable", Body: []string{"ip", "mac", "port"}, Extra: map[string]any{"action": "add"}},
			Delete: &OLTWrite{Path: "/goform/delArpTable"},
			Columns: []OLTField{
				{Leaf: "IPAddress", Vendor: "ip", Required: true, MaxLength: 15, Label: "IP address"},
				{Leaf: "MACAddress", Vendor: "mac", Required: true, MaxLength: 17, Label: "MAC address"},
				{Leaf: "VLAN", Vendor: "port", Required: true, Min: i64(1), Max: i64(4094), Label: "VLAN ID",
					Help: "Vendor field 'port' holds the VLAN ID."},
				{Leaf: "Type", Vendor: "type", Label: "Type", Help: "dhcp = dynamic, anything else = static."},
				{Leaf: "AgingTime", Vendor: "agingTime", Label: "Aging time"},
				{Leaf: "StaticLocal", Vendor: "staticLocal", Codec: "bool01", Label: "Local static entry"},
			},
		}},
	},
	// Hidden pages of the Routing menu.
	{Route: "/router/static/ipv6", Title: "IPv6 static routing", Unsupported: "menu hidden: firmware built without IPv6 (CONFIG_HAVE_IPV6=n)"},
	{Route: "/router/dynamic/rip", Title: "RIP Dynamic Routing", Unsupported: "menu hidden (CONFIG_HAVE_RIPD=n); RIP goform endpoints have no backend handler"},
	{Route: "/router/routingTable/ipv4", Title: "Routing Table", Unsupported: "menu hidden (parent gated by CONFIG_HAVE_RIPD=n); getIPv4RoutingTable not verified on device"},
	{Route: "/router/routingTable/ipv6", Title: "IPv6 routing table", Unsupported: "menu hidden: firmware built without RIPD/IPv6"},
	{Route: "/router/dhcp/set", Title: "DHCP Server > DHCP Settings", Unsupported: "DHCP server menu hidden; address-pool endpoints have no backend handler"},
	{Route: "/router/dhcp/static-addr-assign", Title: "DHCP Reservation", Unsupported: "DHCP server menu hidden; endpoints have no backend handler"},
	{Route: "/router/dhcp/client-list", Title: "Client List", Unsupported: "DHCP server menu hidden; endpoints have no backend handler"},
	{Route: "/router/ipv6Setting/interface", Title: "IPv6 interface", Unsupported: "menu hidden: firmware built without IPv6 (CONFIG_HAVE_IPV6=n)"},
	{Route: "/router/ipv6Setting/ND", Title: "IPv6 ND", Unsupported: "menu hidden: firmware built without IPv6 (CONFIG_HAVE_IPV6=n)"},
}
