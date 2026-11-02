package main

import (
	"fmt"
	"io"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/pkg/runner"
)

// runOpenLogin opens the claim link in the browser once the service is up:
// the Windows setup's "Log in to Wantastic" finish option. A device that is
// already signed in has nothing to open.
func runOpenLogin(w io.Writer) int {
	deadline := time.Now().Add(45 * time.Second)
	for {
		var st agent.StatusResponse
		err := daemonGet("/api/status", 3*time.Second, &st)
		switch {
		case err == nil && st.Claim != nil:
			if err := runner.OpenURL(st.Claim.URL); err != nil {
				fmt.Fprintf(w, "Open this link to add the device: %s\n", st.Claim.URL)
				return exitOK
			}
			fmt.Fprintln(w, "Opened the browser to add this device to your account.")
			return exitOK
		case err == nil:
			fmt.Fprintln(w, "This device is already signed in.")
			return exitOK
		case time.Now().After(deadline):
			fmt.Fprintf(w, "The service did not answer: %v\n", err)
			return exitUnreachable
		}
		time.Sleep(time.Second)
	}
}
