package fiberolt

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// CLI is a minimal telnet client for the FOS OLT command line (port 23).
// It logs in with the admin credentials and runs show commands; the output
// is parsed into structured rows. Used by the collector to reach data the
// web API does not expose (unprovisioned ONUs, optical readings).
type CLI struct {
	host string
	user string
	pass string
	// conn is kept open between runs; reconnected on failure.
	conn net.Conn
	rd   *bufio.Reader
}

// NewCLI builds a CLI client; host defaults to 127.0.0.1:23 (agent on the
// OLT) and must be set explicitly for proxy deployments.
func NewCLI(host, user, pass string) *CLI {
	if host == "" {
		host = "127.0.0.1:23"
	}
	if user == "" {
		user = "admin"
	}
	if pass == "" {
		pass = "admin"
	}
	return &CLI{host: host, user: user, pass: pass}
}

// Run executes one command and returns everything up to the next prompt.
// The vendor prompts are not line-terminated, so reads are chunk-based.
func (c *CLI) Run(cmd string) (string, error) {
	if err := c.ensure(); err != nil {
		return "", err
	}
	c.conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.conn.Write([]byte(cmd + "\r\n")); err != nil {
		c.close()
		return "", err
	}
	return c.readUntilPrompt(), nil
}

// readUntilPrompt accumulates raw reads until the buffer ends with the CLI
// prompt ("#" or ">"), then returns everything received.
func (c *CLI) readUntilPrompt() string {
	var out strings.Builder
	buf := make([]byte, 2048)
	for {
		n, err := c.rd.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err != nil {
			break
		}
		trimmed := strings.TrimSpace(out.String())
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			break
		}
	}
	return out.String()
}

func (c *CLI) ensure() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.host, 8*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	c.rd = bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	// The banner and "Username:" may arrive without newlines; send the
	// credentials as soon as the markers appear in the accumulated buffer.
	accum := ""
	stage := 0
	for {
		buf := make([]byte, 512)
		n, err := c.rd.Read(buf)
		if n > 0 {
			accum += string(buf[:n])
		}
		if err != nil {
			c.close()
			return fmt.Errorf("cli login read: %w", err)
		}
		trimmed := strings.TrimSpace(accum)
		switch {
		case stage == 0 && (strings.HasSuffix(trimmed, "Username:") || strings.HasSuffix(trimmed, "login:")):
			// Send credentials only once the prompt is complete: sending
			// mid-banner makes the vendor telnetd log "unknow user".
			conn.Write([]byte(c.user + "\r\n"))
			stage = 1
		case stage == 1 && strings.HasSuffix(trimmed, "Password:"):
			conn.Write([]byte(c.pass + "\r\n"))
			stage = 2
		case stage == 2:
			if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
				return nil
			}
			// The login was rejected: the device re-prompts for the user.
			if strings.HasSuffix(trimmed, "Username:") {
				stage = 0
			}
		}
	}
}

func (c *CLI) close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.rd = nil
	}
}

// ONUInfo is one row of "show ont info ..." output.
type ONUInfo struct {
	ID          string
	SN          string
	UpTime      string
	ConfigState string
	MemberState string
}

// ONUOptical is one row of "show ont optical-info <id>" output.
type ONUOptical struct {
	VoltageV    float64
	RxPowerDBm  float64
	TxPowerDBm  float64
	BiasCurrent float64
	TempC       float64
	EthPortUp   bool
	EthKnown    bool
}

// ParseONUInfos parses the table emitted by "show ont info <ids>".
// Rows look like:  0/1/1  HWTC-93bb0308  0d0h40m  Normal  working
func ParseONUInfos(out string) []ONUInfo {
	var rows []ONUInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || !strings.Contains(fields[0], "/") {
			continue
		}
		row := ONUInfo{ID: fields[0]}
		// SN is the second column; the tail columns vary by release.
		if len(fields) > 1 && fields[1] != "SN" {
			row.SN = fields[1]
		}
		if len(fields) > 2 {
			row.UpTime = fields[2]
		}
		if len(fields) > 3 {
			row.ConfigState = fields[3]
		}
		if len(fields) > 4 {
			row.MemberState = fields[4]
		}
		rows = append(rows, row)
	}
	return rows
}

// ParseONUOptical parses "show ont optical-info <id>" output.
func ParseONUOptical(out string) ONUOptical {
	var o ONUOptical
	value := func(key string) (float64, bool) {
		idx := strings.Index(out, key)
		if idx < 0 {
			return 0, false
		}
		rest := out[idx+len(key):]
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			rest = rest[:i]
		}
		rest = strings.TrimSpace(rest)
		rest = strings.TrimPrefix(rest, ":")
		rest = strings.TrimSpace(rest)
		// cut trailing parentheticals like "(OLT TX: 9.510)"
		if p := strings.Index(rest, "("); p >= 0 {
			rest = strings.TrimSpace(rest[:p])
		}
		if rest == "-" || rest == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	if v, ok := value("Power Feed Voltage(V)"); ok {
		o.VoltageV = v
	}
	if v, ok := value("RX Optical Power(dBm)"); ok {
		o.RxPowerDBm = v
	}
	if v, ok := value("TX Optical Power(dBm)"); ok {
		o.TxPowerDBm = v
	}
	if v, ok := value("Laser Bias Current(mA)"); ok {
		o.BiasCurrent = v
	}
	if v, ok := value("Temperature(C)"); ok {
		o.TempC = v
	}
	// "show ont port-status <id> eth 1" → "Port status is Enable, Linkdown"
	if idx := strings.Index(out, "Port status is"); idx >= 0 {
		o.EthKnown = true
		o.EthPortUp = strings.Contains(out[idx:], "Linkup")
	}
	return o
}
