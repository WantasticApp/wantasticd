//go:build !darwin && !windows

package platforms

import "wantastic-agent/internal/wusp/osusers"

// osUsersSupported: Device.WUSP_OSUsers. is a Windows and macOS model. On any
// other platform the backend reports itself not installed rather than
// inventing an account table or accepting an account command.
const osUsersSupported = false

func newOSUsersBackend(CommandRunner) osusers.Backend { return nil }
