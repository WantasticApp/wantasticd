// Package exitnode plans and applies the host changes behind exit-node mode:
// the routes a client installs to send its internet traffic through a peer,
// and the forwarding/NAT an exit host enables to carry it.
//
// Every host change is a Cmd (program + argv, optional stdin) built by a pure
// function, so the exact commands are unit tested on any OS and nothing ever
// goes through a shell.
package exitnode

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cmd is one program invocation. Stdin, when set, is written to the process.
type Cmd struct {
	Name  string
	Args  []string
	Stdin string
}

func (c Cmd) String() string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// Runner executes a Cmd and returns its combined output.
type Runner func(Cmd) ([]byte, error)

// ExecRunner runs commands directly (exec, never a shell).
func ExecRunner(c Cmd) ([]byte, error) {
	cmd := exec.Command(c.Name, c.Args...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", c.String(), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

// Host bundles the side effects the managers need so tests can fake them.
type Host struct {
	OS        string // runtime.GOOS value: darwin, linux, windows
	Run       Runner
	ReadFile  func(string) ([]byte, error)
	WriteFile func(string, []byte) error
	// Exists reports whether a binary/file path exists.
	Exists func(string) bool
}

// SystemHost returns a Host acting on the real machine.
func SystemHost(goos string) Host {
	return Host{
		OS:       goos,
		Run:      ExecRunner,
		ReadFile: os.ReadFile,
		WriteFile: func(p string, b []byte) error {
			return os.WriteFile(p, b, 0o644)
		},
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
	}
}

// firstExisting returns the first existing path, else fallback.
func (h Host) firstExisting(fallback string, paths ...string) string {
	if h.Exists == nil {
		return fallback
	}
	for _, p := range paths {
		if h.Exists(p) {
			return p
		}
	}
	return fallback
}
