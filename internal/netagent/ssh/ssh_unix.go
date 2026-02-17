//go:build !windows

package ssh

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func monitorWindowResize(ctx context.Context, fd int, session *ssh.Session) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			w, h, err := term.GetSize(fd)
			if err == nil {
				_ = session.WindowChange(h, w)
			}
		}
	}
}
