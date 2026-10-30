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
	onChange func()
	// report shows an action's outcome in the menu.
	report func(okText, notice string, err error)
}

func newTrayExitMenu() *trayExitMenu {
	m := &trayExitMenu{}
	m.root = systray.AddMenuItem("Exit node: off", "Route internet traffic through another device")
	m.offer = m.root.AddSubMenuItemCheckbox("Allow this device as exit node", "", false)
	m.use = m.root.AddSubMenuItem("Use exit node", "Send all internet traffic through a peer")
	m.none = m.use.AddSubMenuItemCheckbox("Don't use an exit node", "Normal routing", true)
	go m.watch(m.offer, func() (string, string, error) {
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
	go m.watch(m.none, func() (string, string, error) {
		n, err := postControl("/api/exitnode/comeback")
		return "Normal routing restored", n, err
	})
	return m
}

func (m *trayExitMenu) watch(item *systray.MenuItem, action func() (okText, notice string, err error)) {
	for range item.ClickedCh {
		go func() {
			okText, notice, err := action()
			if m.report != nil && okText != "" {
				m.report(okText, notice, err)
			}
			if m.onChange != nil {
				m.onChange()
			}
		}()
	}
}

func (m *trayExitMenu) apply(s exitMenuState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.offering = s.OfferChecked
	m.root.SetTitle(s.Header)
	m.offer.SetTitle(s.OfferTitle)
	m.offer.SetTooltip(s.OfferTooltip)
	setChecked(m.offer, s.OfferChecked)
	setEnabled(m.offer, s.OfferEnabled)
	m.use.SetTooltip(s.UseTooltip)
	setEnabled(m.use, s.UseEnabled)
	setChecked(m.none, s.NoneChecked)
	setEnabled(m.none, s.NoneEnabled)

	for len(m.items) < len(s.Items) {
		idx := len(m.items)
		it := m.use.AddSubMenuItemCheckbox("", "", false)
		m.items = append(m.items, it)
		m.itemIPs = append(m.itemIPs, "")
		go m.watch(it, func() (string, string, error) {
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
		it.SetTitle(e.Title)
		it.SetTooltip(e.Tooltip)
		setChecked(it, e.Checked)
		setEnabled(it, e.Enabled)
		it.Show()
	}
}

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
