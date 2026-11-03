package main

// Account CLI: one device in several accounts, switched like profiles.
// Every command drives the running daemon over the local IPC API.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"

	"wantastic-agent/internal/agent"
)

const accountUsage = `Usage: wantasticd account <command>
  list                          accounts on this device (* = active)
  add [--name NAME] [--server URL] [--use]
                                add this device to another account: prints a claim
                                link and QR code, waits for the claim
  use <id|name>                 switch to another account (reconnects)
  rename <id|name> <new name>
  remove <id|name>              forget an account on this device`

func runAccountCommand(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, accountUsage)
		return 2
	}
	var err error
	switch args[0] {
	case "list", "ls":
		err = accountList(out)
	case "add":
		err = accountAdd(args[1:], out)
	case "use", "switch":
		if len(args) != 2 {
			err = errors.New("usage: wantasticd account use <id|name>")
			break
		}
		err = accountPost("/api/accounts/use?"+url.Values{"id": {args[1]}}.Encode(), out)
	case "rename":
		if len(args) != 3 {
			err = errors.New("usage: wantasticd account rename <id|name> <new name>")
			break
		}
		err = accountPost("/api/accounts/rename?"+url.Values{"id": {args[1]}, "name": {args[2]}}.Encode(), out)
	case "remove", "rm":
		if len(args) != 2 {
			err = errors.New("usage: wantasticd account remove <id|name>")
			break
		}
		err = accountPost("/api/accounts/remove?"+url.Values{"id": {args[1]}}.Encode(), out)
	default:
		fmt.Fprintln(os.Stderr, accountUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wantasticd account %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func accountList(out io.Writer) error {
	var resp agent.AccountsResponse
	if err := daemonGet("/api/accounts", 5*time.Second, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	printAccounts(out, resp)
	return nil
}

func printAccounts(out io.Writer, resp agent.AccountsResponse) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\tID\tNAME\tADDRESS\tSTATE")
	for _, a := range resp.Accounts {
		mark, state := " ", "saved"
		switch {
		case a.Active:
			mark, state = "*", "active"
		case a.Pending:
			state = "waiting for claim"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, a.ID, a.Name, orDefault(a.Address, "—"), state)
	}
	tw.Flush()
}

func accountPost(path string, out io.Writer) error {
	var resp agent.AccountsResponse
	if err := daemonPost(path, 15*time.Second, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if resp.Notice != "" {
		fmt.Fprintln(out, resp.Notice)
	}
	return nil
}

func accountAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("account add", flag.ContinueOnError)
	name := fs.String("name", "", "Name for the account on this device")
	server := fs.String("server", "", "Wantastic server URL (default: the Wantastic cloud)")
	use := fs.Bool("use", false, "Switch to the account once it is claimed")
	wait := fs.Duration("wait", 15*time.Minute, "How long to wait for the claim (0: do not wait)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{"name": {*name}}
	if *server != "" {
		q.Set("server", *server)
	}
	var resp agent.AccountsResponse
	if err := daemonPost("/api/accounts/add?"+q.Encode(), 15*time.Second, &resp); err != nil {
		return err
	}
	if !resp.OK || resp.Added == nil {
		return errors.New(orDefault(resp.Error, "the daemon did not add the account"))
	}
	added := *resp.Added
	fmt.Fprintf(out, "Added %s (%s). Open this link signed in to the other account, or scan it:\n%s\n\n", added.Name, added.ID, added.ClaimURL)
	qrterminal.GenerateWithConfig(added.ClaimURL, qrterminal.Config{Level: qrterminal.L, Writer: out, HalfBlocks: true})
	if *wait <= 0 {
		fmt.Fprintf(out, "\nThe daemon finishes the account once it is claimed. Then: wantasticd account use %s\n", added.ID)
		return nil
	}
	fmt.Fprintln(out, "\nWaiting for the claim… (Ctrl-C stops waiting; the daemon keeps watching)")
	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		var list agent.AccountsResponse
		if err := daemonGet("/api/accounts", 5*time.Second, &list); err != nil {
			continue
		}
		for _, a := range list.Accounts {
			if a.ID != added.ID || a.Pending {
				continue
			}
			fmt.Fprintf(out, "Claimed: %s is ready.\n", a.Name)
			if *use {
				return accountPost("/api/accounts/use?"+url.Values{"id": {a.ID}}.Encode(), out)
			}
			fmt.Fprintf(out, "Switch to it with: wantasticd account use %s\n", a.ID)
			return nil
		}
	}
	return fmt.Errorf("not claimed within %s; the daemon keeps watching (wantasticd account list)", *wait)
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
