package main

// Exit-node CLI: `exit-node on|off|status`, `jumpto <vpn-ip>`, `comeback`.
// All of them drive the running daemon over the local IPC API.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

func daemonPost(path string, timeout time.Duration, v any) error {
	return daemonPostTo("http://127.0.0.1:"+agent.GetIPCPort(), path, timeout, v)
}

func daemonPostTo(base, path string, timeout time.Duration, v any) error {
	req, err := http.NewRequest(http.MethodPost, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(agent.ControlHeader, "1")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return errDaemonDown
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		route, _, _ := strings.Cut(path, "?")
		return fmt.Errorf("the running daemon is older than this CLI and has no %s; restart it to load the installed version (%s)", route, daemonRestartHint())
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// exitCommand is a parsed exit-node CLI invocation.
type exitCommand struct {
	Kind   string // offer | status | jumpto | comeback
	On     bool
	Target string
	Wait   time.Duration
	JSON   bool
}

var errExitUsage = errors.New("usage: wantasticd exit-node on|off|status [--json] | jumpto <vpn-ip> [--wait 12s] | comeback")

func parseExitCommand(cmd string, args []string) (exitCommand, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "Print JSON")
	wait := fs.Duration("wait", 12*time.Second, "How long jumpto waits for the exit route to go live")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitCommand{}, errExitUsage
	}
	pos := fs.Args()
	c := exitCommand{JSON: *asJSON, Wait: *wait}
	switch cmd {
	case "exit-node":
		if len(pos) != 1 {
			return c, errExitUsage
		}
		switch strings.ToLower(pos[0]) {
		case "on", "enable":
			c.Kind, c.On = "offer", true
		case "off", "disable":
			c.Kind, c.On = "offer", false
		case "status":
			c.Kind = "status"
		default:
			return c, errExitUsage
		}
	case "jumpto":
		if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
			return c, errExitUsage
		}
		c.Kind, c.Target = "jumpto", strings.TrimSpace(pos[0])
	case "comeback":
		if len(pos) != 0 {
			return c, errExitUsage
		}
		c.Kind = "comeback"
	default:
		return c, errExitUsage
	}
	return c, nil
}

func runExitCommand(cmd string, args []string, w io.Writer) int {
	c, err := parseExitCommand(cmd, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitFailed
	}
	var resp agent.ExitNodeResponse
	switch c.Kind {
	case "status":
		err = daemonGet("/api/exitnode", 5*time.Second, &resp)
	case "offer":
		on := "off"
		if c.On {
			on = "on"
		}
		err = daemonPost("/api/exitnode/offer?enabled="+on, 30*time.Second, &resp)
	case "jumpto":
		q := url.Values{"ip": {c.Target}, "wait": {fmt.Sprint(c.Wait.Milliseconds())}}
		err = daemonPost("/api/exitnode/jumpto?"+q.Encode(), c.Wait+20*time.Second, &resp)
	case "comeback":
		err = daemonPost("/api/exitnode/comeback", 30*time.Second, &resp)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUnreachable
	}
	if c.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(resp)
	} else {
		printExitResult(w, c, resp)
	}
	if !resp.OK {
		return exitFailed
	}
	return exitOK
}

func printExitResult(w io.Writer, c exitCommand, resp agent.ExitNodeResponse) {
	if resp.Error != "" {
		fmt.Fprintf(w, "Error: %s\n", resp.Error)
		return
	}
	st := resp.State
	switch c.Kind {
	case "offer":
		if c.On {
			fmt.Fprintf(w, "This device is now an exit node (%s NAT). Peers can run: sudo wantasticd jumpto <this VPN IP>\n", orDash(st.Backend))
		} else {
			fmt.Fprintln(w, "Exit-node sharing is off; peers' internet traffic is refused.")
		}
	case "jumpto":
		u := st.Using
		if u != nil && u.State == "active" {
			fmt.Fprintf(w, "Internet traffic now goes through %s (%s path). Undo with: sudo wantasticd comeback\n", exitUseName(u), u.Path)
		} else if u != nil {
			fmt.Fprintf(w, "Exit node set to %s, but it is not active yet: %s\nRouting stays normal until it is; check with: wantasticd status\n", exitUseName(u), orDash(resp.Notice))
		}
	case "comeback":
		fmt.Fprintln(w, "Normal routing restored; no exit node in use.")
	case "status":
		printExitStatus(w, st)
	}
}

func exitUseName(u *device.ExitUse) string {
	if u.Hostname != "" {
		return fmt.Sprintf("%s (%s)", u.IP, u.Hostname)
	}
	return u.IP
}

// exitOfferLine / exitUseLine summarise exit-node state for `status`.
func exitOfferLine(st *device.ExitNodeStatus) string {
	switch {
	case st == nil:
		return "unknown"
	case st.Offering:
		s := "on (" + orDash(st.Backend) + ")"
		if n := len(st.Users); n > 0 {
			s += fmt.Sprintf(", used by %d peer(s)", n)
		}
		return s
	case !st.Supported:
		return "unsupported: " + st.UnsupportedReason
	case st.OfferError != "":
		return "off (error: " + st.OfferError + ")"
	}
	return "off"
}

func exitUseLine(st *device.ExitNodeStatus) string {
	if st == nil || st.Using == nil {
		return "none"
	}
	u := st.Using
	s := exitUseName(u) + " — " + u.State + ", " + u.Path
	if u.Endpoint != "" && u.Path == "direct" {
		s += " via " + u.Endpoint
	}
	if u.Reason != "" && u.State != "active" {
		s += " (" + u.Reason + ")"
	}
	return s
}

func printExitStatus(w io.Writer, st device.ExitNodeStatus) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Offer exit node:\t%s\n", exitOfferLine(&st))
	fmt.Fprintf(tw, "Using exit node:\t%s\n", exitUseLine(&st))
	tw.Flush()
	if len(st.Users) > 0 {
		fmt.Fprintln(w, "\nPeers using this device as exit:")
		now := time.Now()
		for _, u := range st.Users {
			fmt.Fprintf(w, "  %s  %s  last seen %s\n", u.IP, orDash(u.Hostname), handshakeAge(u.LastSeen, now))
		}
	}
	if len(st.Candidates) > 0 {
		fmt.Fprintln(w, "\nCandidates:")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  VPN IP\tHOSTNAME\tPATH\tOFFERS EXIT\tONLINE")
		for _, c := range st.Candidates {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%t\n", c.IP, orDash(c.Hostname), c.Path, c.Offers, c.Online)
		}
		tw.Flush()
	}
}
