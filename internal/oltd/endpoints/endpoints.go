// Package endpoints maps goform endpoint names to the vendor daemon
// requests the GoAhead handler would send, and rebuilds the JSON the
// handler would print from the daemon's text reply (see package cemu for
// the C-semantics emulation and package wire for the datagram format).
//
// Coverage (see Catalog):
//   - "daemon": the handler is a pure daemon round trip; the port is exact.
//   - "hybrid": daemon round trips plus local reads (/proc, /etc, i2c);
//     fields that cannot be reproduced natively are listed in
//     "_helperUnsupported" of the reply.
//   - anything not listed is answered "unsupported via helper" and the agent
//     uses the web client for it.
package endpoints

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/wire"
)

// Daemon sockets (bound by the vendor daemons at boot).
const (
	SockNSM   = "/tmp/sm_web"
	SockPON   = "/tmp/pon_web"
	SockUM    = "/tmp/um_web"
	SockSNTP  = "/tmp/sntp_web"
	SockMSTP  = "/tmp/mstp_web"
	SockAUTHD = "/tmp/authd_web"
	SockDHCPS = "/tmp/dhcps_web"
	SockNLDP  = "/tmp/nldp_web"
	SockMQTT  = "/tmp/mqtt_web"
)

// ErrUnsupported means the endpoint is not served by the helper; the agent
// falls back to the web client.
var ErrUnsupported = errors.New("unsupported via helper")

// ErrSetDisabled means writes are switched off on this helper (-allow-set).
var ErrSetDisabled = errors.New("set disabled on this helper (-allow-set=false)")

// Backend performs one daemon round trip. build gets the reply path to
// embed; the result is the payload as the webserver would see it with a
// bufSize-byte buffer.
type Backend interface {
	Query(sock string, build func(replyPath string) (wire.Msg, error), bufSize int) (string, error)
}

// Params are the request arguments (query string and/or JSON body).
type Params map[string]any

// Str returns the parameter as the vendor would read it: websGetVar /
// cJSON_GetString with default "".
func (p Params) Str(name string) string {
	v, ok := p[name]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case int:
		return strconv.Itoa(t)
	}
	return ""
}

// Env carries local-read options.
type Env struct {
	Root       string // filesystem root for /proc, /etc, /mnt reads ("" = "/")
	I2C        bool   // read board temperatures over /dev/i2c-1 like board_temp_get
	sysPrevCPU cpuSample
}

// Endpoint describes one served goform endpoint.
type Endpoint struct {
	Name    string
	Op      string // "get" or "set"
	Source  string // "daemon" or "hybrid"
	Handler string // vendor C handler
	Hot     bool   // coalesced/cached getter
	fn      func(b Backend, p Params, env *Env) ([]byte, error)
}

var registry = map[string]*Endpoint{}

func register(e *Endpoint) { registry[e.Op+":"+e.Name] = e }

// Lookup returns the endpoint for op ("get"/"set") and goform name.
func Lookup(op, name string) (*Endpoint, bool) {
	name = strings.TrimPrefix(name, "/goform/")
	e, ok := registry[op+":"+name]
	return e, ok
}

// Call runs the endpoint.
func (e *Endpoint) Call(b Backend, p Params, env *Env) ([]byte, error) {
	if p == nil {
		p = Params{}
	}
	if env == nil {
		env = &Env{}
	}
	return e.fn(b, p, env)
}

// Catalog lists every served endpoint (sorted), for ping/selftest/docs.
func Catalog() []*Endpoint {
	out := make([]*Endpoint, 0, len(registry))
	for _, e := range registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Op != out[j].Op {
			return out[i].Op < out[j].Op
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// simpleMsg builds a parameterless request (memset + code + reply path).
func simpleMsg(code uint16) func(string) (wire.Msg, error) {
	return func(path string) (wire.Msg, error) { return wire.NewMsg(code, path) }
}

// ---- formGetListCommon family (38 endpoints) ----------------------------
//
// listQuickSpecs are the getters that call formQuickListStrToJson
// themselves: same reply shape, but their own socket, buffer size and
// token delimiter, and never a ponPortList.

type listCommonSpec struct {
	Name, Handler string
	Code          uint16
	Vars          []string // formQuickParamToBuf variable names
	Desc          []string // column keys; nil = "key:value" tokens
	DescOverflow  []string // data words after the desc table (C reads past it)
	PonPortList   bool     // flags&1: append ponPortList
	Socket        string   // "" = /tmp/pon_web
	Buf           int      // 0 = listCommonBuf
	Delim         string   // "" = ","
}

// pPortName is the webserver's static port name table (.data 0x170f8c).
var pPortName = []string{"pon1", "pon2", "pon3", "pon4", "pon5", "pon6", "pon7", "pon8",
	"ge1", "ge2", "ge3", "ge4", "ge5", "ge6", "xge1", "xge2"}

const listCommonBuf = 98304 // getCmdResultWebService buffer in formGetListCommon

func (s listCommonSpec) get(b Backend, p Params, _ *Env) ([]byte, error) {
	vals := make([]string, len(s.Vars))
	for i, v := range s.Vars {
		vals[i] = p.Str(v)
	}
	sock, buf, delim := s.Socket, s.Buf, s.Delim
	if sock == "" {
		sock = SockPON
	}
	if buf == 0 {
		buf = listCommonBuf
	}
	if delim == "" {
		delim = ","
	}
	reply, err := b.Query(sock, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(s.Code, path)
		if err != nil {
			return nil, err
		}
		if len(vals) > 0 {
			_ = m.PutQuick(vals) // the vendor ignores the packing result too
		}
		return m, nil
	}, buf)
	if err != nil {
		return nil, err
	}
	return listCommonJSON(reply, s.Desc, s.DescOverflow, s.PonPortList, delim), nil
}

// listCommonJSON is formQuickListStrToJson + formQuickStrToJson +
// formAddPonPortList. formQuickListStrToJson ignores formQuickStrToJson's
// result: a malformed "key:value" token ends that line's conversion (the
// vendor logs it to the console) and the next line is processed.
func listCommonJSON(reply string, desc, overflow []string, ponList bool, delim string) []byte {
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	if reply != "ERROR" {
		for _, line := range cemu.Strtok(reply, "\n") {
			row := cemu.Object()
			list.AddItem("", row)
			rowToJSON(row, line, desc, overflow, delim)
		}
	}
	if ponList {
		arr := cemu.Array()
		root.AddItem("ponPortList", arr)
		for _, n := range pPortName {
			if strings.HasPrefix(n, "pon") {
				arr.AddString("", n)
			}
		}
		arr.AddString("", "all")
	}
	return root.Print()
}

// rowToJSON is formQuickStrToJson: tokens are split on delim; with a desc
// table the i-th token is stored under desc[i] (the C reads past the table
// into the following data words, DescOverflow); without one each token
// must be "key:value" with both parts at most 2000 bytes, and the first
// token that is not stops the line (return -4 in the vendor code).
func rowToJSON(row *cemu.JSON, line string, desc, overflow []string, delim string) bool {
	for i, tok := range cemu.Strtok(line, delim) {
		if desc != nil {
			switch {
			case i < len(desc):
				row.AddString(desc[i], tok)
			case i-len(desc) < len(overflow):
				row.AddString(overflow[i-len(desc)], tok)
			}
			continue
		}
		var k, v string
		n := cemu.Sscanf(tok, "%[^:]:%[^\n]", func(j int, s string) {
			if j == 0 {
				k = s
			} else {
				v = s
			}
		})
		if n != 2 || len(k) > 2000 || len(v) > 2000 {
			return false
		}
		row.AddString(k, v)
	}
	return true
}

// ---- formQuick setters (30 endpoints) -----------------------------------

type quickSetterSpec struct {
	Name, Handler string
	Code          uint16
	Socket        string
	Vars          []string
}

const setterBuf = 0x200 // setCmdResultWebServiceWithString reply buffer

func (s quickSetterSpec) set(b Backend, p Params, _ *Env) ([]byte, error) {
	vals := make([]string, len(s.Vars))
	for i, v := range s.Vars {
		vals[i] = p.Str(v)
	}
	reply, err := b.Query(s.Socket, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(s.Code, path)
		if err != nil {
			return nil, err
		}
		_ = m.PutQuick(vals)
		return m, nil
	}, setterBuf)
	if err != nil {
		// web_service_cmd on a select() timeout copies "-1" into the reply:
		// the web UI then shows {"errCode":"-1"}. Report the same instead of
		// an error so the agent does not repeat the write on the web path.
		if isTimeout(err) {
			reply = "-1"
		} else {
			return nil, err
		}
	}
	return setterJSON(reply), nil
}

// setterJSON is setCmdResultWebServiceWithString's output (raw sprintf, no
// escaping, non-printables replaced by spaces).
func setterJSON(reply string) []byte {
	if len(reply) > 0 && reply[0] == '0' {
		return []byte(`{"errCode":"0"}`)
	}
	b := []byte(reply)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = ' '
		}
	}
	return []byte(fmt.Sprintf(`{"errCode":"%s"}`, b))
}

// IsTimeout lets the backend mark timeouts (any error with Timeout() true).
func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func init() {
	for i := range listCommonSpecs {
		s := listCommonSpecs[i]
		hot := s.Name == "getOntListBrife" || s.Name == "getOntListConfig" || s.Name == "getOntListOptical"
		register(&Endpoint{Name: s.Name, Op: "get", Source: "daemon", Handler: s.Handler, Hot: hot, fn: s.get})
	}
	for i := range listQuickSpecs {
		s := listQuickSpecs[i]
		register(&Endpoint{Name: s.Name, Op: "get", Source: "daemon", Handler: s.Handler, fn: s.get})
	}
	for i := range rowSpecs {
		s := rowSpecs[i]
		if _, dup := registry["get:"+s.Name]; dup {
			continue // a hand port exists (getQvlanList); the generated spec is cross-checked in tests
		}
		register(&Endpoint{Name: s.Name, Op: "get", Source: "daemon", Handler: s.Handler, fn: s.get})
	}
	for i := range quickSetterSpecs {
		s := quickSetterSpecs[i]
		register(&Endpoint{Name: s.Name, Op: "set", Source: "daemon", Handler: s.Handler, fn: s.set})
	}
	register(&Endpoint{Name: "getPortBasicList", Op: "get", Source: "daemon", Handler: "formGetPortBasicList", Hot: true, fn: getPortBasicList})
	register(&Endpoint{Name: "getQvlanList", Op: "get", Source: "daemon", Handler: "formGetVlanList", Hot: true, fn: getQvlanList})
	register(&Endpoint{Name: "getPonPortBasicList", Op: "get", Source: "daemon", Handler: "formGetPonPortBasicList", fn: getPonPortBasicList})
	register(&Endpoint{Name: "getSysStatus", Op: "get", Source: "hybrid", Handler: "formGetSysStatus", Hot: true, fn: getSysStatus})
}
