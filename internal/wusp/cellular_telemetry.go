package wusp

const WUSPCellularTelemetryPrefix = "Device.WUSP_CellularTelemetry."

var WUSPCellularTelemetryObjects = []Object{
	{Path: WUSPCellularTelemetryPrefix, SinceVersion: "1.0"},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.", MultiInstance: true, SinceVersion: "1.0"},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.", MultiInstance: true, SinceVersion: "1.0"},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.", MultiInstance: true, SinceVersion: "1.0"},
}

var AllWUSPCellularTelemetryParams = []Param{
	{Path: WUSPCellularTelemetryPrefix + "InterfaceNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of cellular modem telemetry interface rows.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Alias", Type: TypeAlias, Access: ReadOnly, SinceVersion: "1.0", Description: "USP non-functional unique key for this cellular telemetry interface."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.InterfaceReference", Type: TypePathRef, Access: ReadOnly, SinceVersion: "1.0", Description: "Reference to the matching Device.Cellular.Interface row."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.ModemPath", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Linux modem device path or network interface used by the collector.", Limits: Limits{MaxLength: 128}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Protocol", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Collection protocol used for this modem.", Limits: Limits{Enums: []string{"at", "qmi", "mbim", "modemmanager", "sysfs", "unknown"}}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NRMode", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "5G NR mode detected from modem telemetry.", Limits: Limits{Enums: []string{"Standalone", "NonStandalone", "Unknown"}}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Band", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Primary serving LTE or NR band reported by the modem.", Limits: Limits{MaxLength: 32}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.CellID", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Primary serving cell identifier.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.TAC", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "LTE/NR tracking area code.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.LAC", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Legacy location area code.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.DNS1", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Primary DNS server from the data profile.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.DNS2", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Secondary DNS server from the data profile.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.IPv4Address", Type: TypeIPv4Address, Access: ReadOnly, SinceVersion: "1.0", Description: "IPv4 address assigned to the modem data profile."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.IPv6Address", Type: TypeIPv6Address, Access: ReadOnly, SinceVersion: "1.0", Description: "IPv6 address assigned to the modem data profile."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.CarrierNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of Quectel AT+QCAINFO serving or aggregated carrier rows.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCellNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of LTE/NR neighbor measurement rows.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.Role", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Carrier role reported by Quectel QCAINFO, for example PCC, SCC, or NR5G.", Limits: Limits{MaxLength: 32}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.RAT", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Radio access technology for this carrier.", Limits: Limits{Enums: []string{"LTE", "NR", "Unknown"}}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.Band", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "LTE or NR band for this carrier.", Limits: Limits{MaxLength: 16}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.EARFCN", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "LTE EARFCN or NR ARFCN.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.PCI", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Physical cell identifier.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.Bandwidth", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Carrier bandwidth as reported by the modem.", Limits: Limits{MaxLength: 32}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.RSRP", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Carrier RSRP in dBm."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.RSRQ", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Carrier RSRQ in dB."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.SINR", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Carrier SINR in dB."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.Carrier.{i}.Raw", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw modem response line used for diagnostics.", Limits: Limits{MaxLength: 512}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.RAT", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor radio access technology.", Limits: Limits{Enums: []string{"LTE", "NR", "Unknown"}}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.Relation", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor relation such as intra, inter, or nr5g.", Limits: Limits{MaxLength: 32}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.Frequency", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor EARFCN or NR ARFCN.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.PCI", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor physical cell identifier.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.RSRP", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor RSRP in dBm."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.RSRQ", Type: TypeInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Neighbor RSRQ in dB."},
	{Path: WUSPCellularTelemetryPrefix + "Interface.{i}.NeighborCell.{i}.Raw", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw modem response line used for diagnostics.", Limits: Limits{MaxLength: 512}},
}
