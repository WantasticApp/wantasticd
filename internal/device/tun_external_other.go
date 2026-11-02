//go:build !linux

package device

import (
	"errors"

	"wantastic-agent/internal/device/wireguard-go/tun"
)

func openExternalTUN(int) (tun.Device, string, error) {
	return nil, "", errors.New("an external TUN is only supported on Linux and Android")
}
