//go:build !windows
// +build !windows

package runner

import (
	"context"
)

func RunServiceHook(runFunc func(context.Context)) {
	runFunc(context.Background())
}
