//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// ensureUpdatePrivileges fails early, before downloading, when the install
// directory needs an elevated prompt.
func ensureUpdatePrivileges(execPath string) error {
	probe, err := os.CreateTemp(filepath.Dir(execPath), ".wantasticd-update-*")
	if err != nil {
		return fmt.Errorf("%s is not writable; run the update from an Administrator prompt", filepath.Dir(execPath))
	}
	probe.Close()
	os.Remove(probe.Name())
	return nil
}
