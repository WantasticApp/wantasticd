package wusp

const WUSPNetworkTelemetryPrefix = "Device.WUSP_NetworkTelemetry."

var WUSPNetworkTelemetryObjects = []Object{
	{Path: WUSPNetworkTelemetryPrefix, SinceVersion: "1.0"},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.", SinceVersion: "1.0"},
}

var AllWUSPNetworkTelemetryParams = []Param{
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.Status", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Agent-owned measurement scheduler state. Reading telemetry never starts a speed test.", Limits: Limits{Enums: []string{"Scheduled", "Running", "Ready", "RetryScheduled", "Unavailable"}}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.IntervalSeconds", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Minimum interval between successful agent-owned internet speed measurements.", Limits: Limits{Min: iptr(3600)}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.LastAttemptAt", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Time the agent last attempted an internet speed measurement."},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.NextRunAt", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Earliest time the agent scheduler may run the next measurement."},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.DownloadBps", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Last valid independently measured downstream internet throughput in bits per second.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.UploadBps", Type: TypeUnsignedLong, Access: ReadOnly, SinceVersion: "1.0", Description: "Last valid independently measured upstream internet throughput in bits per second.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.LatencyMilliseconds", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Latency reported by the selected public measurement server in milliseconds.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.JitterMilliseconds", Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.0", Description: "Latency standard deviation reported by the selected public measurement server in milliseconds.", Limits: Limits{Min: iptr(0)}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.ServerID", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Identifier of the public measurement server.", Limits: Limits{MaxLength: 64}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.ServerName", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Location name of the public measurement server.", Limits: Limits{MaxLength: 128}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.ServerSponsor", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Operator of the public measurement server.", Limits: Limits{MaxLength: 128}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.Source", Type: TypeString, Access: ReadOnly, SinceVersion: "1.0", Description: "Measurement network used for this result.", Limits: Limits{Enums: []string{"speedtest.net"}}},
	{Path: WUSPNetworkTelemetryPrefix + "SpeedTest.ObservedAt", Type: TypeDateTime, Access: ReadOnly, SinceVersion: "1.0", Description: "Time when the last valid daily internet speed measurement completed."},
}
