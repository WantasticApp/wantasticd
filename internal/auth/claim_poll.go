//go:build tinygo

package auth

import (
	"context"
	"fmt"
	"time"
)

func WaitClaimConfig(ctx context.Context, portalURL, hashedDeviceID, publicKey string) (*ClaimConfig, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		cfg, err := FetchClaimConfig(ctx, portalURL, hashedDeviceID, publicKey)
		if err == nil && cfg != nil && cfg.Claimed {
			return cfg, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("claim wait cancelled: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
