//go:build linux && cgo && (amd64 || arm64) && !nosystray

package runner

import "errors"

// The Linux service logs to the journal (journalctl -u wantasticd), not a
// file the menu could open.
func trayLogPath() string { return "" }

func openLogFile(string) error {
	return errors.New("the service logs to the journal: journalctl -u wantasticd")
}
