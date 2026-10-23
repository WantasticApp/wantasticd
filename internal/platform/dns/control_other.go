//go:build !linux && !darwin && !windows

package dns

import (
	"context"
	"errors"
)

func ReadControl(context.Context) ControlState {
	return ControlState{Method: "unsupported", Reason: "DNS control is not available on this platform"}
}

func SetServers(context.Context, []string) error {
	return errors.New("DNS control is not available on this platform")
}
