//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"sync"

	"wantastic-agent/internal/agent"

	"github.com/getlantern/systray"
)

// trayLocalAccess is the "Share this device's local network" switch: it lets
// the other devices of the network reach the LANs this one is plugged into.
type trayLocalAccess struct {
	item *systray.MenuItem

	mu      sync.Mutex
	on      bool
	pending string

	onChange func()
	report   func(okText, notice string, err error)
}

func newTrayLocalAccess() *trayLocalAccess {
	l := &trayLocalAccess{item: systray.AddMenuItemCheckbox(T("local.title"), T("local.tooltip"), false)}
	keepMenuOpen(l.item)
	go l.watch()
	return l
}

// watch applies each click, one at a time.
func (l *trayLocalAccess) watch() {
	for range l.item.ClickedCh {
		l.mu.Lock()
		if l.pending != "" {
			l.mu.Unlock()
			continue
		}
		on := !l.on
		l.pending = T("local.pending.off")
		if on {
			l.pending = T("local.pending.on")
		}
		l.mu.Unlock()
		l.changed()
		go func() {
			path, okText := "/api/localaccess?enabled=off", T("local.off.ok")
			if on {
				path, okText = "/api/localaccess?enabled=on", T("local.on.ok")
			}
			n, err := postControl(path)
			l.mu.Lock()
			l.pending = ""
			if err == nil {
				l.on = on
			}
			l.mu.Unlock()
			if l.report != nil {
				l.report(okText, n, err)
			}
			l.changed()
		}()
	}
}

func (l *trayLocalAccess) changed() {
	if l.onChange != nil {
		l.onChange()
	}
}

// apply shows the daemon's setting; it can be changed while connected or not
// (the daemon applies it on the next connect).
func (l *trayLocalAccess) apply(st *agent.StatusResponse) {
	l.mu.Lock()
	defer l.mu.Unlock()
	usable := st != nil && st.Running && st.Claim == nil
	if usable && l.pending == "" {
		l.on = st.LocalAccess
	}
	title := T("local.title")
	if l.pending != "" {
		title += " · " + l.pending
	}
	setTitle(l.item, title)
	setChecked(l.item, l.on)
	setEnabled(l.item, usable)
	tip := T("local.tooltip")
	if !usable {
		tip = T("exit.daemon.down")
		if st != nil && st.Claim != nil {
			tip = T("exit.login.first")
		}
	}
	setTooltip(l.item, tip)
}
