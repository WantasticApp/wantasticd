//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	user32                    = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procShowWindow            = user32.NewProc("ShowWindow")
)

// releaseOwnConsole closes the console window Windows opens for wantasticd
// when it starts outside a terminal (the tray at logon). wantasticd is a
// console program so commands print in PowerShell and cmd; a console shared
// with a terminal (more than one attached process) is left alone.
func releaseOwnConsole() {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return
	}
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		const swHide = 0
		procShowWindow.Call(hwnd, swHide)
	}
	procFreeConsole.Call()
}
