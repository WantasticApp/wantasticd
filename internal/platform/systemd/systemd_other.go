//go:build !linux

package systemd

import "context"

func SetHostname(context.Context, string) error            { return ErrUnavailable }
func SetNTP(context.Context, bool) error                    { return ErrUnavailable }
func SetTimezone(context.Context, string) error             { return ErrUnavailable }
func ReloadOrTryRestartUnit(context.Context, string) error  { return ErrUnavailable }
