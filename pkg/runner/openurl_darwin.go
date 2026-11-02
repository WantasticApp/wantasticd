//go:build darwin

package runner

import "os/exec"

func openBrowser(link string) error { return exec.Command("open", link).Start() }
