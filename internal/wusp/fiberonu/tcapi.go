package fiberonu

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The EcoNet/ECNT firmware keeps its configuration in a node tree served by
// cfg_manager; /userfs/bin/tcapi is its command-line client. The firmware's
// own pages and cgi scripts read it with `tcapi get <Node> <Attr>` (e.g.
// sec_portfilterinlist.cgi runs `/userfs/bin/tcapi get WebCustom_Entry
// isCMCCSupported`), which prints the value on one line. Unset attributes
// read as "N/A", and the client prints one of a few fixed messages when the
// node or attribute is missing; both read as empty here.
const defaultTcapiPath = "/userfs/bin/tcapi"

// tcapiBudget bounds all tcapi reads in one collection. Each read is one
// short-lived process; a wedged cfg_manager must not stall the collect.
const tcapiBudget = 15 * time.Second

func (o Options) tcapiPath() string {
	if o.TcapiPath == "" {
		return defaultTcapiPath
	}
	return o.TcapiPath
}

func (o Options) procNetDir() string {
	if o.ProcNetDir == "" {
		return "/proc/net"
	}
	return o.ProcNetDir
}

func (o Options) sysClassNetDir() string {
	if o.SysClassNetDir == "" {
		return "/sys/class/net"
	}
	return o.SysClassNetDir
}

func (o Options) tmpDir() string {
	if o.TmpDir == "" {
		return "/tmp"
	}
	return o.TmpDir
}

// run executes a read-only command, through Options.Exec when a test
// injects one.
func (o Options) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if o.Exec != nil {
		return o.Exec(ctx, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, name, args...).Output()
}

// tcapiReader issues `tcapi get` reads under one shared deadline and counts
// them so tests can bound the exec cost of a collection.
type tcapiReader struct {
	ctx   context.Context
	opts  Options
	calls int
}

// newTcapi returns nil when the firmware has no tcapi (not an ECNT ONU, or
// a test without an injected runner); callers skip the tcapi sources then.
func newTcapi(ctx context.Context, opts Options) (*tcapiReader, context.CancelFunc) {
	if opts.Exec == nil {
		if _, err := os.Stat(opts.tcapiPath()); err != nil {
			return nil, func() {}
		}
	}
	tctx, cancel := context.WithTimeout(ctx, tcapiBudget)
	return &tcapiReader{ctx: tctx, opts: opts}, cancel
}

// get reads one attribute; "" when unset, missing or unreadable.
func (t *tcapiReader) get(node, attr string) string {
	if t == nil || t.ctx.Err() != nil {
		return ""
	}
	t.calls++
	out, err := t.opts.run(t.ctx, t.opts.tcapiPath(), "get", node, attr)
	if err != nil {
		return ""
	}
	return cleanTcapiValue(string(out))
}

// tcapiNoValue are the messages the tcapi client prints instead of a value
// (strings in /userfs/bin/tcapi), plus "N/A", the value of an unset
// attribute that the web pages test for.
var tcapiNoValue = map[string]bool{
	"N/A":                      true,
	"no node information":      true,
	"no attribute information": true,
	"no specific node":         true,
	"no specific attribute":    true,
	"connection error":         true,
	"unknown error":            true,
}

func cleanTcapiValue(out string) string {
	out = strings.TrimRight(out, "\r\n")
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	out = strings.TrimRight(out, "\r")
	if tcapiNoValue[strings.TrimSpace(out)] {
		return ""
	}
	return strings.TrimSpace(out)
}

// readListFile reads a cfg_manager list file (one value per line) as the
// firmware's cgi scripts do with `cat <file> | while read LINE`. A file
// older than since (the moment the count was read, which makes cfg_manager
// rewrite it) is stale and reads as absent.
func readListFile(dir, name string, since time.Time) ([]string, bool) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil || info.ModTime().Before(since.Add(-2*time.Second)) {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	text := strings.ReplaceAll(string(data), "\r", "")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil, true
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "N/A" {
			line = ""
		}
		lines[i] = line
	}
	return lines, true
}
