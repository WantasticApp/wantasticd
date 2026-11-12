package wusp

// WUSPStoragePrefix reports the device's filesystems. A router's flash
// overlay (OpenWrt/QSDK /overlay, ~60 MB) filling up breaks every settings
// write (uci commit "I/O error"); KB keeps that visible where TR-181
// StorageService's MB would show "59 of 59".
const WUSPStoragePrefix = "Device.WUSP_Storage."

var WUSPStorageObjects = []Object{
	{Path: WUSPStoragePrefix, SinceVersion: "1.0"},
	{Path: WUSPStoragePrefix + "Volume.{i}.", SinceVersion: "1.0", MultiInstance: true},
}

var AllWUSPStorageParams = []Param{
	{Path: WUSPStoragePrefix + "VolumeNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Number of Volume entries."},
	{Path: WUSPStoragePrefix + "Volume.{i}.MountPoint", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Where the filesystem is mounted (/, /overlay, /tmp, /data).", Limits: Limits{MaxLength: 256}},
	{Path: WUSPStoragePrefix + "Volume.{i}.FileSystem", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Filesystem type (ubifs, jffs2, ext4, overlay, tmpfs…).", Limits: Limits{MaxLength: 32}},
	{Path: WUSPStoragePrefix + "Volume.{i}.Role", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "What the volume holds: Config is the writable flash with /etc/config; RAM is tmpfs.", Limits: Limits{Enums: []string{"Root", "Config", "Data", "RAM"}}},
	{Path: WUSPStoragePrefix + "Volume.{i}.TotalKB", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Size in KiB."},
	{Path: WUSPStoragePrefix + "Volume.{i}.UsedKB", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Used space in KiB."},
	{Path: WUSPStoragePrefix + "Volume.{i}.AvailableKB", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Space a non-root writer can still use, in KiB."},
	{Path: WUSPStoragePrefix + "Volume.{i}.ReadOnly", Type: TypeBoolean, Access: ReadOnly, SinceVersion: "1.0", Description: "Mounted read-only."},
}
