//go:build !linux

package platforms

import "wantastic-agent/internal/wusp"

func collectMeshStatic(msg *wusp.Message) {}
