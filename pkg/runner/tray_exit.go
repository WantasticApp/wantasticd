//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"net/url"
	"sync"

	"github.com/getlantern/systray"
)

// trayExitMenu is the "Exit node" submenu. Clicks post to the daemon from
// their own goroutines; the menu itself only ever reflects polled state.
type trayExitMenu struct {
	root  *systray.MenuItem
	offer *systray.MenuItem
	use   *systray.MenuItem
	none  *systray.MenuItem

	mu       sync.Mutex
	items    []*systray.MenuItem
	itemIPs  []string
	offering bool
	// pending is what a running action shows after its item's title
	// ("switching…"), so progress is visible while the menu stays open.
	pending  map[*systray.MenuItem]string
	onChange func()
	// report shows an action's outcome in the menu.
	report func(okText, notice string, err error)
}

func newTrayExitMenu() *trayExitMenu {
	m := &trayExitMenu{pending: map[*systray.MenuItem]string{}}
	// The sharing switch sits in the main menu; the submenu picks the
	// exit node this device uses.
	m.offer = systray.AddMenuItemCheckbox("Allow this device as exit node", "", false)
	m.root = systray.AddMenuItem("Exit node: off", "Send all internet traffic through a peer")
	m.use = m.root
	m.none = m.use.AddSubMenuItemCheckbox(exitNoneTitle, "Normal routing", true)
	keepMenuOpen(m.none)
	go m.watch(m.offer, func() string {
		if m.offering {
			return "turning off…"
		}
		return "turning on…"
	}, func() (string, string, error) {
		m.mu.Lock()
		on := !m.offering
		m.mu.Unlock()
		if on {
			n, err := postControl("/api/exitnode/offer?enabled=on")
			return "This device is now an exit node", n, err
		}
		n, err := postControl("/api/exitnode/offer?enabled=off")
		return "Exit-node sharing off", n, err
	})
	go m.watch(m.none, func() string { return "restoring…" }, func() (string, string, error) {
		n, err := postControl("/api/exitnode/comeback")
		return "Normal routing restored", n, err
	})
	return m
}

// watch runs action for each click, one at a time per item; pending says
// what the item shows meanwhile.
func (m *trayExitMenu) watch(item *systray.MenuItem, pending func() string, action func() (okText, notice string, err error)) {
	for range item.ClickedCh {
		m.mu.Lock()
		_, busy := m.pending[item]
		if !busy {
			m.pending[item] = pending()
		}
		m.mu.Unlock()
		if busy {
			continue
		}
		m.changed()
		go func() {
			okText, notice, err := action()
			m.mu.Lock()
			delete(m.pending, item)
			m.mu.Unlock()
			if m.report != nil && okText != "" {
				m.report(okText, notice, err)
			}
			m.changed()
		}()
	}
}

func (m *trayExitMenu) changed() {
	if m.onChange != nil {
		m.onChange()
	}
}

// title is base plus the running action's progress, if any. Callers hold mu.
func (m *trayExitMenu) title(item *systray.MenuItem, base string) string {
	if p := m.pending[item]; p != "" {
		return base + " · " + p
	}
	return base
}

func (m *trayExitMenu) apply(s exitMenuState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.offering = s.OfferChecked
	setTitle(m.root, s.Header)
	setTitle(m.offer, m.title(m.offer, s.OfferTitle))
	setTooltip(m.offer, s.OfferTooltip)
	setChecked(m.offer, s.OfferChecked)
	setEnabled(m.offer, s.OfferEnabled)
	setTooltip(m.use, s.UseTooltip)
	setEnabled(m.use, s.UseEnabled)
	setTitle(m.none, m.title(m.none, exitNoneTitle))
	setChecked(m.none, s.NoneChecked)
	setEnabled(m.none, s.NoneEnabled)

	for len(m.items) < len(s.Items) {
		idx := len(m.items)
		it := m.use.AddSubMenuItemCheckbox("", "", false)
		m.items = append(m.items, it)
		m.itemIPs = append(m.itemIPs, "")
		keepMenuOpen(it)
		go m.watch(it, func() string { return "switching…" }, func() (string, string, error) {
			m.mu.Lock()
			ip := m.itemIPs[idx]
			m.mu.Unlock()
			if ip == "" {
				return "", "", nil
			}
			// A few seconds' wait lets the menu report "active" instead of
			// "pending" when a direct path is already up.
			n, err := postControl("/api/exitnode/jumpto?" + url.Values{"ip": {ip}, "wait": {"5000"}}.Encode())
			return "Internet now goes through " + ip, n, err
		})
	}
	for i, it := range m.items {
		if i >= len(s.Items) {
			m.itemIPs[i] = ""
			it.Hide()
			continue
		}
		e := s.Items[i]
		m.itemIPs[i] = e.IP
		setTitle(it, m.title(it, e.Title))
		setTooltip(it, e.Tooltip)
		setChecked(it, e.Checked)
		setEnabled(it, e.Enabled)
		it.Show()
	}
}

const exitNoneTitle = "Don't use an exit node"

func setChecked(it *systray.MenuItem, on bool) {
	if on {
		it.Check()
	} else {
		it.Uncheck()
	}
}

func setEnabled(it *systray.MenuItem, on bool) {
	if on {
		it.Enable()
	} else {
		it.Disable()
	}
}
