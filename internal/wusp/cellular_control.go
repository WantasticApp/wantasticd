package wusp

const WUSPCellularControlPrefix = "Device.WUSP_CellularControl."

var WUSPCellularControlObjects = []Object{
	{Path: WUSPCellularControlPrefix, SinceVersion: "1.0"},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.", MultiInstance: true, SinceVersion: "1.0"},
}

var AllWUSPCellularControlParams = []Param{
	{Path: WUSPCellularControlPrefix + "InterfaceNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of cellular modem control rows.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.Alias", Type: TypeAlias, Access: ReadOnly, SinceVersion: "1.0", Description: "USP non-functional unique key for this cellular control interface."},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.InterfaceReference", Type: TypePathRef, Access: ReadOnly, SinceVersion: "1.0", Description: "Reference to the matching Device.Cellular.Interface row."},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.ModemPath", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Linux modem device path or network interface used for control commands.", Limits: Limits{MaxLength: 128}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.SupportedOperations", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Comma-separated cellular Operate command names supported by this row.", Limits: Limits{MaxLength: 256}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.ModemFunctionality", Type: TypeString, Access: ReadWrite, SinceVersion: "1.0", Description: "Requested 3GPP modem functionality state mapped to AT+CFUN.", Limits: Limits{Enums: []string{"Full", "Disabled", "LowPower", "Reset", "Unknown"}}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.SIMSlot", Type: TypeUnsignedInt, Access: ReadWrite, SinceVersion: "1.0", Description: "Active SIM slot mapped to Quectel AT+QUIMSLOT.", Limits: Limits{Min: iptr(1), Max: iptr(4)}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.IMEIOverride", Type: TypeString, Access: WriteOnly, SinceVersion: "1.0", Description: "IMEI value to apply through Quectel AT+EGMR when explicitly operated.", Limits: Limits{MaxLength: 15, Pattern: "^[0-9]{15}$"}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.APNProfileNumber", Type: TypeUnsignedInt, Access: ReadWrite, SinceVersion: "1.0", Description: "PDP context profile number used when applying APN settings.", Limits: Limits{Min: iptr(1), Max: iptr(16)}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.APNPDPType", Type: TypeString, Access: ReadWrite, SinceVersion: "1.0", Description: "PDP type used for APN settings.", Limits: Limits{Enums: []string{"IP", "IPV6", "IPV4V6"}}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.APN", Type: TypeString, Access: ReadWrite, SinceVersion: "1.0", Description: "APN value applied with AT+CGDCONT.", Limits: Limits{MaxLength: 100}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.SMSInboxJSON", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "JSON SMS inbox payload returned by sms_tool -j recv.", Limits: Limits{MaxLength: 16384}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.LastCommandStatus", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Status of the most recent cellular control operation.", Limits: Limits{Enums: []string{"Idle", "Success", "Error"}}},
	{Path: WUSPCellularControlPrefix + "Interface.{i}.LastCommandOutput", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Short output or error from the most recent cellular control operation.", Limits: Limits{MaxLength: 4096}},
}
