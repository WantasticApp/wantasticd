//go:build darwin

package platforms

import (
	"wantastic-agent/internal/wusp/osusers"
)

// osUsersSupported: macOS exposes its local accounts through OpenDirectory's
// local node and its sessions through the utmpx table, both readable, and the
// account actions through the system tools.
const osUsersSupported = true

func newOSUsersBackend(run CommandRunner) osusers.Backend {
	if run == nil {
		return nil
	}
	return osusers.NewMacBackend(osusers.Runner(run), nil)
}
