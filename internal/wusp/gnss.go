package wusp

const WUSPGNSSPrefix = "Device.WUSP_GNSS."

var WUSPGNSSObjects = []Object{
	{Path: WUSPGNSSPrefix, SinceVersion: "1.0"},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.", MultiInstance: true, SinceVersion: "1.0"},
}

var AllWUSPGNSSParams = []Param{
	{Path: WUSPGNSSPrefix + "ReceiverNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of GNSS receiver rows exposed by Wantastic cellular or GPS collectors.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Alias", Type: TypeAlias, Access: ReadOnly, SinceVersion: "1.0", Description: "USP non-functional unique key for this GNSS receiver."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.LocationReference", Type: TypePathRef, Access: ReadOnly, SinceVersion: "1.0", Description: "Reference to the standard Device.DeviceInfo.Location row containing the PIDF-LO location object."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.ModemPath", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Linux modem, ModemManager object, or GPS device path used by the GNSS collector.", Limits: Limits{MaxLength: 128}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Protocol", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS collection protocol used for this row.", Limits: Limits{Enums: []string{"gpsd", "modemmanager", "quectel-at", "file", "unknown"}}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Enable", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "Current GNSS session state for modem-backed receivers."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Status", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Current GNSS receiver status.", Limits: Limits{Enums: []string{"Disabled", "Searching", "NoFix", "Fix2D", "Fix3D", "Error", "Unknown"}}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Latitude", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS latitude in decimal degrees.", Limits: Limits{MinF: fptr(-90), MaxF: fptr(90)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Longitude", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS longitude in decimal degrees.", Limits: Limits{MinF: fptr(-180), MaxF: fptr(180)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Altitude", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS altitude above sea level in meters."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.SpeedKPH", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS ground speed in kilometers per hour.", Limits: Limits{MinF: fptr(0)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.Course", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "GNSS course over ground in degrees.", Limits: Limits{MinF: fptr(0), MaxF: fptr(360)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.HDOP", Type: TypeDecimal, Access: ReadOnly, SinceVersion: "1.0", Description: "Horizontal dilution of precision reported by GNSS."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.FixQuality", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw or normalized GNSS fix quality value.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.SatellitesUsed", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of satellites used for the current GNSS fix.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.SatellitesInView", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of satellites currently visible to the GNSS receiver.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.UTC", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "UTC timestamp reported by GNSS when available."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.LastFixTime", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Time when the current GNSS fix was acquired by the collector."},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.RawLocation", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw AT+QGPSLOC or source-specific location response used for diagnostics.", Limits: Limits{MaxLength: 1024}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.RawGGA", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw GGA NMEA sentence returned by the GNSS receiver.", Limits: Limits{MaxLength: 512}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.RawRMC", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw RMC NMEA sentence returned by the GNSS receiver.", Limits: Limits{MaxLength: 512}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.RawGSA", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw GSA NMEA sentence returned by the GNSS receiver.", Limits: Limits{MaxLength: 512}},
	{Path: WUSPGNSSPrefix + "Receiver.{i}.RawGSV", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Raw GSV NMEA sentence returned by the GNSS receiver.", Limits: Limits{MaxLength: 1024}},
}
