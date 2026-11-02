//go:build linux && cgo && (amd64 || arm64) && !nosystray

package runner

import "os/exec"

func openBrowser(link string) error { return exec.Command("xdg-open", link).Start() }
