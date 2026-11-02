// Package mobile is the Wantastic engine as the Android app sees it, built
// with gomobile bind. It reuses the agent's own code, so the phone claims and
// connects exactly as the desktop agent does.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"wantastic-agent/internal/auth"
)

// Init points the engine's identity and state files at the app's private
// folder; Android has no /etc or machine-id for it to use.
func Init(stateDir string) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return errors.New("state dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.Setenv("WANTASTIC_STATE_DIR", stateDir)
}

// WaitClaim waits up to timeoutSeconds for the console to approve publicKey,
// then checks once more with a signed request. It returns the claim as JSON
// once approved, or "" if not yet: the app simply calls again.
func WaitClaim(server, publicKey string, timeoutSeconds int) (string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	deviceID, err := auth.HashedDeviceID()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	claim, waitErr := auth.WaitClaimConfig(ctx, server, deviceID, publicKey)
	cancel()
	if waitErr != nil || claim == nil || !claim.Claimed {
		// The websocket timed out or is unavailable: ask directly.
		fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 20*time.Second)
		claim, err = auth.FetchClaimConfig(fetchCtx, server, deviceID, publicKey)
		fetchCancel()
		if err != nil {
			return "", err
		}
	}
	if claim == nil || !claim.Claimed {
		return "", nil
	}
	out, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
