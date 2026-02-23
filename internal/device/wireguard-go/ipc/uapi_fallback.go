//go:build !linux && !darwin && !freebsd && !openbsd && !windows && !wasm
// +build !linux,!darwin,!freebsd,!openbsd,!windows,!wasm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"net"
	"os"
)

const (
	IpcErrorIO        = 1
	IpcErrorProtocol  = 2
	IpcErrorInvalid   = 3
	IpcErrorPortInUse = 4
	IpcErrorUnknown   = 5
)

type UAPIListener struct{}

func (l *UAPIListener) Accept() (net.Conn, error) { return nil, errors.New("unsupported") }
func (l *UAPIListener) Close() error              { return nil }
func (l *UAPIListener) Addr() net.Addr            { return nil }

func UAPIListen(name string, file *os.File) (net.Listener, error) {
	return nil, errors.New("unsupported on this OS")
}

func UAPIOpen(name string) (*os.File, error) {
	return nil, errors.New("unsupported on this OS")
}
