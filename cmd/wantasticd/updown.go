package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"wantastic-agent/internal/agent"
)

// runUpDown connects or disconnects the tunnel of the running daemon; the
// daemon itself keeps running so the tray and CLI stay usable.
func runUpDown(cmd string, w io.Writer) int {
	path := "/api/connect"
	if cmd == "down" {
		path = "/api/disconnect"
	}
	var resp agent.ConnectionResponse
	if err := daemonPost(path, 30*time.Second, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return exitUnreachable
	}
	if !resp.OK {
		fmt.Fprintln(os.Stderr, "Error:", resp.Error)
		return 1
	}
	if resp.Connected {
		fmt.Fprintln(w, "Connected.")
	} else {
		fmt.Fprintln(w, "Disconnected; the daemon keeps running. Reconnect with: wantasticd up")
	}
	return exitOK
}
