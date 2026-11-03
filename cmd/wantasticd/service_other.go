//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
)

func runServiceCommand(args []string) int {
	fmt.Fprintln(os.Stderr, "wantasticd service manages the Windows and macOS service. On Linux, install.sh sets up systemd or the init system.")
	return 2
}
