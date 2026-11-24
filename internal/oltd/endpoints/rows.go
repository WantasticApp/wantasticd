package endpoints

import (
	"strconv"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/wire"
)

// rowSpec describes a vendor getter of the most common bespoke shape, as
// recovered by tools/oltre (oltre.py rows): one daemon request (code,
// optional formQuick / legacy parameters), one strtok_r loop over the
// reply, one sscanf per line into fixed stack buffers, one JSON object per
// line whose keys read those buffers. The offsets are the vendor's
// stack-frame offsets, so overlapping buffers and stale values behave as
// in the C handler (see package cemu).
type rowSpec struct {
	Name, Handler string
	Socket        string
	Code          uint16
	Buf           int          // getCmdResultWebService buffer size
	Frame         int          // largest stack offset used
	Vars          []string     // formQuickParamToBuf (websGetVar) parameters; nil = none
	Param         *legacyParam // one websGetVar value sprintf'ed at a fixed offset
	U16           []u16Field   // constant u16 fields in the request
	ListKey       string
	Delim         string       // strtok_r delimiter
	ErrorEmpty    bool         // strcmp(reply,"ERROR")==0 -> empty list
	RowZero       []zeroRegion // memsets at the top of the loop body
	Fmt           string       // sscanf format
	Offs          []int        // sscanf destinations (frame offsets)
	Counter       int          // buffer of sprintf("%d", n) with n from 1; 0 = none
	Cols          []rowCol
}

type legacyParam struct {
	Name, Default string
	Off           int
}

type u16Field struct {
	Off int
	Val uint16
}

type zeroRegion struct {
	Off, N int
}

type rowCol struct {
	Key     string
	Off     int    // frame offset of the C string (default kind)
	Const   string // constant value
	IsConst bool
	Counter bool // the sprintf("%d", n) buffer
}

func (s rowSpec) get(b Backend, p Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(s.Socket, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(s.Code, path)
		if err != nil {
			return nil, err
		}
		if s.Vars != nil {
			vals := make([]string, len(s.Vars))
			for i, v := range s.Vars {
				vals[i] = p.Str(v)
			}
			_ = m.PutQuick(vals)
		}
		if s.Param != nil {
			v := s.Param.Default
			if _, ok := p[s.Param.Name]; ok {
				v = p.Str(s.Param.Name)
			}
			m.PutString(s.Param.Off, v)
		}
		for _, u := range s.U16 {
			m.PutU16(u.Off, u.Val)
		}
		return m, nil
	}, s.Buf)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem(s.ListKey, list)
	if s.ErrorEmpty && reply == "ERROR" {
		return root.Print(), nil
	}
	f := cemu.GetFrame(s.Frame + 0x40)
	defer f.Release()
	n := 1
	for _, line := range cemu.Strtok(reply, s.Delim) {
		for _, z := range s.RowZero {
			f.Zero(z.Off, z.N)
		}
		f.Sscanf(line, s.Fmt, s.Offs...)
		row := cemu.Object()
		list.AddItem("", row)
		if s.Counter != 0 {
			f.Write(s.Counter, strconv.Itoa(n))
		}
		for _, c := range s.Cols {
			switch {
			case c.IsConst:
				row.AddString(c.Key, c.Const)
			case c.Counter:
				row.AddString(c.Key, f.Str(s.Counter))
			default:
				row.AddString(c.Key, f.Str(c.Off))
			}
		}
		n++
	}
	return root.Print(), nil
}
