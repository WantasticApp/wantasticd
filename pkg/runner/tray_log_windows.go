//go:build windows && !nosystray

package runner

import "os/exec"

func trayLogPath() string { return ServiceLogPath() }

func openLogFile(path string) error { return exec.Command("notepad.exe", path).Start() }
