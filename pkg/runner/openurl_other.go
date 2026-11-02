//go:build !darwin && !windows

package runner

import "os/exec"

func openBrowser(link string) error { return exec.Command("xdg-open", link).Start() }
