//go:build darwin && !nosystray

package runner

import "os/exec"

func openBrowser(link string) error { return exec.Command("open", link).Start() }
