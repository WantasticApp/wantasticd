//go:build windows

package ssh

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func monitorWindowResize(ctx context.Context, fd int, session *ssh.Session) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastW, lastH int
	// Initial check
	if w, h, err := term.GetSize(fd); err == nil {
		lastW, lastH = w, h
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w, h, err := term.GetSize(fd)
			if err == nil {
				if w != lastW || h != lastH {
					_ = session.WindowChange(h, w)
					lastW, lastH = w, h
				}
			}
		}
	}
}
