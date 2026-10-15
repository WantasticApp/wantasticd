//go:build !darwin

package main

import "wantastic-agent/internal/config"

func runPrivilegedAgentMode() (bool, error) { return false, nil }

func (a *App) startPrivilegedAgentIfNeeded(*config.Config) (bool, error) {
	return false, nil
}
