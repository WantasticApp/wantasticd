//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runServiceCommand(args []string) int {
	fmt.Fprintln(os.Stderr, "wantasticd service manages the Windows service. On Linux and macOS, install.sh sets up systemd, launchd or the init system.")
	return 2
}
