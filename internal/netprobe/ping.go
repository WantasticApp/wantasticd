package netprobe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
)

// Ping sends one native ICMP echo without launching a platform command.
func Ping(ctx context.Context, target string) (time.Duration, string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return 0, "", errors.New("invalid ping address")
	}
	return ping(ctx, addr.Unmap())
}
