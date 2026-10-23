package platforms

// kernelClockSync reports whether an NTP client (busybox ntpd, chrony,
// systemd-timesyncd, ntpd) has disciplined the kernel clock: synced, and
// whether the platform can tell at all. Tests replace it.
var kernelClockSync = readKernelClockSync

// ntpClientStatus maps the client state to TR-181 Time.Client.{i}.Status.
func ntpClientStatus(enabled bool) string {
	if !enabled {
		return "Disabled"
	}
	if synced, known := kernelClockSync(); known && synced {
		return "Synchronized"
	}
	return "Unsynchronized"
}
