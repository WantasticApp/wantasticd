// Package systemd calls systemd's D-Bus services directly (hostnamed,
// timedated and the service manager) so the agent needs no hostnamectl,
// timedatectl or systemctl process. Every call returns an error on systems
// without systemd or a system bus; callers then fall back.
package systemd

import "errors"

// ErrUnavailable is returned where systemd cannot be reached.
var ErrUnavailable = errors.New("systemd D-Bus API unavailable")
