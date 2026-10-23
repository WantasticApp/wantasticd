//go:build linux && (qmi || mbim)

package modem

// CGo QMI/MBIM builds talk to the modem directly and do not link the
// ModemManager client.
func mergeModemManagerInfo(*Info) bool { return false }
