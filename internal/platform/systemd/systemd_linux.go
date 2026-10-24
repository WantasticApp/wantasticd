//go:build linux

package systemd

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const callTimeout = 15 * time.Second

func call(ctx context.Context, dest, path, method string, out any, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()
	result := conn.Object(dest, dbus.ObjectPath(path)).CallWithContext(ctx, method, 0, args...)
	if result.Err != nil {
		return result.Err
	}
	if out != nil {
		return result.Store(out)
	}
	return nil
}

// SetHostname sets the static and transient hostname through
// org.freedesktop.hostname1 (what hostnamectl set-hostname does).
func SetHostname(ctx context.Context, hostname string) error {
	if err := call(ctx, "org.freedesktop.hostname1", "/org/freedesktop/hostname1",
		"org.freedesktop.hostname1.SetStaticHostname", nil, hostname, false); err != nil {
		return err
	}
	return call(ctx, "org.freedesktop.hostname1", "/org/freedesktop/hostname1",
		"org.freedesktop.hostname1.SetHostname", nil, hostname, false)
}

// SetNTP turns network time synchronisation on or off through
// org.freedesktop.timedate1 (timedatectl set-ntp).
func SetNTP(ctx context.Context, enabled bool) error {
	return call(ctx, "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
		"org.freedesktop.timedate1.SetNTP", nil, enabled, false)
}

// SetTimezone sets the system time zone (timedatectl set-timezone).
func SetTimezone(ctx context.Context, zone string) error {
	return call(ctx, "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
		"org.freedesktop.timedate1.SetTimezone", nil, zone, false)
}

// ReloadOrTryRestartUnit reloads a running unit, restarting it when it has
// no reload action, and leaves a stopped unit alone (systemctl
// try-reload-or-restart).
func ReloadOrTryRestartUnit(ctx context.Context, unit string) error {
	var job dbus.ObjectPath
	return call(ctx, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager.ReloadOrTryRestartUnit", &job, unit, "replace")
}
