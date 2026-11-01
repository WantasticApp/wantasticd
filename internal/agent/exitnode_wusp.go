package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/internal/wusp"
)

// exitNodeUseWait bounds how long a controller Set of Use waits for the exit
// peer to answer, well inside the hub's 30s SendSet deadline.
const exitNodeUseWait = 10 * time.Second

// exitNodeController is the part of the tunnel device the controller drives.
type exitNodeController interface {
	ExitStatus() device.ExitNodeStatus
	SetExitOffer(on bool) error
	UseExitNode(target string, wait time.Duration) (*device.ExitUse, error)
	ClearExitNode() error
}

// exitNodeBackend adds Device.WUSP_ExitNode. to the data model so the console
// can share this device as an exit node or route it through one, the same
// switches as `wantasticd exit-node on|off` and `jumpto`/`comeback`.
type exitNodeBackend struct {
	backend wusp.DataBackend
	exit    exitNodeController
}

func (b *exitNodeBackend) Collect(ctx context.Context, paths ...string) (*wusp.Message, error) {
	msg, err := b.backend.Collect(ctx, paths...)
	if err != nil {
		return nil, err
	}
	if !exitNodePathsRequested(paths) {
		return msg, nil
	}
	fields := wusp.NewMessage()
	appendExitNodeFields(fields, b.exit.ExitStatus())
	for _, field := range fields.Fields {
		if exitNodeFieldRequested(field.Path, paths) {
			msg.Set(field.Path, field.Val)
		}
	}
	return msg, nil
}

func exitNodePathsRequested(paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, wusp.WUSPExitNodePrefix) || strings.HasPrefix(wusp.WUSPExitNodePrefix, p) {
			return true
		}
	}
	return false
}

func exitNodeFieldRequested(path string, paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == path || (strings.HasSuffix(p, ".") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

func appendExitNodeFields(msg *wusp.Message, st device.ExitNodeStatus) {
	p := wusp.WUSPExitNodePrefix
	msg.Set(p+"Supported", wusp.Bool(st.Supported))
	msg.Set(p+"UnsupportedReason", wusp.String(st.UnsupportedReason))
	msg.Set(p+"ClientSupported", wusp.Bool(st.ClientSupported))
	msg.Set(p+"Offer", wusp.Bool(st.Offering))
	msg.Set(p+"OfferBackend", wusp.String(st.Backend))
	msg.Set(p+"OfferError", wusp.String(st.OfferError))
	msg.Set(p+"ActiveUsers", wusp.Uint(uint64(len(st.Users))))

	use := st.Using
	if use == nil {
		// UsePath is an enum; "offline" stands for "no exit node".
		use = &device.ExitUse{State: "off", Path: "offline"}
	}
	msg.Set(p+"Use", wusp.String(use.IP))
	msg.Set(p+"UseState", wusp.String(use.State))
	msg.Set(p+"UseHostname", wusp.String(use.Hostname))
	msg.Set(p+"UsePath", wusp.String(use.Path))
	msg.Set(p+"UseReason", wusp.String(use.Reason))

	candidates := st.Candidates
	if len(candidates) > wusp.WUSPExitNodeMaxCandidates {
		candidates = candidates[:wusp.WUSPExitNodeMaxCandidates]
	}
	msg.Set(p+"CandidateNumberOfEntries", wusp.Uint(uint64(len(candidates))))
	for i, c := range candidates {
		row := p + "Candidate." + strconv.Itoa(i+1) + "."
		msg.Set(row+"IP", wusp.String(c.IP))
		msg.Set(row+"Hostname", wusp.String(c.Hostname))
		msg.Set(row+"Offers", wusp.String(c.Offers))
		msg.Set(row+"Online", wusp.Bool(c.Online))
		msg.Set(row+"Path", wusp.String(c.Path))
	}
}

func (b *exitNodeBackend) Set(ctx context.Context, path string, value wusp.Value) error {
	switch strings.TrimSpace(path) {
	case wusp.WUSPExitNodePrefix + "Offer":
		if !b.exit.ExitStatus().Supported {
			return errors.New("this device cannot share its internet as an exit node")
		}
		return b.exit.SetExitOffer(value.AsBool())
	case wusp.WUSPExitNodePrefix + "Use":
		target := strings.TrimSpace(wusp.ValueToString(value))
		if target == "" {
			return b.exit.ClearExitNode()
		}
		addr, err := netip.ParseAddr(target)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("exit node must be a peer VPN IPv4 address")
		}
		if !b.exit.ExitStatus().ClientSupported {
			return errors.New("this device cannot use an exit node")
		}
		_, err = b.exit.UseExitNode(addr.String(), exitNodeUseWait)
		return err
	}
	return b.backend.Set(ctx, path, value)
}

func (b *exitNodeBackend) Delete(ctx context.Context, paths ...string) error {
	return b.backend.Delete(ctx, paths...)
}

func (b *exitNodeBackend) Add(ctx context.Context, path string, initial *wusp.Message) ([]string, error) {
	adder, ok := b.backend.(wusp.DataAdder)
	if !ok {
		return nil, wusp.ErrUSPPathUnsupported
	}
	return adder.Add(ctx, path, initial)
}

func (b *exitNodeBackend) Warmup(ctx context.Context) error {
	if warmer, ok := b.backend.(interface{ Warmup(context.Context) error }); ok {
		return warmer.Warmup(ctx)
	}
	return nil
}
