//go:build linux || darwin

package dgram

import (
	"time"

	"wantastic-agent/internal/oltd/wire"
)

// Backend adapts a Pool to endpoints.Backend.
type Backend struct {
	Pool    *Pool
	Timeout time.Duration
	// Map rewrites daemon socket paths (tests point /tmp/sm_web elsewhere).
	Map func(string) string
	// Trace and Grace are diagnostics (selftest); see Opts.
	Trace func(Event)
	Grace time.Duration
}

// Query sends one request to the daemon socket sock.
func (b *Backend) Query(sock string, build func(replyPath string) (wire.Msg, error), bufSize int) (string, error) {
	if b.Map != nil {
		sock = b.Map(sock)
	}
	t := b.Timeout
	if t <= 0 {
		t = 5 * time.Second
	}
	return b.Pool.Conn(sock).Do(build, bufSize, Opts{Timeout: t, Grace: b.Grace, Trace: b.Trace})
}
