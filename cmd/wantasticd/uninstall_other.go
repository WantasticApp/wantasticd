//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
)

func runUninstall([]string) int {
	fmt.Fprintln(os.Stderr, "On Linux, uninstall with: curl -sSL https://get.wantastic.app/install.sh | sudo sh -s -- --uninstall [--purge]")
	return 2
}
