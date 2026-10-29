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
}

func newTrayExitMenu() *trayExitMenu {
	m := &trayExitMenu{}
	m.root = systray.AddMenuItem("Exit node: off", "Route internet traffic through another device")
	m.offer = m.root.AddSubMenuItemCheckbox("Allow this device as exit node", "", false)
	m.use = m.root.AddSubMenuItem("Use exit node", "Send all internet traffic through a peer")
	m.none = m.use.AddSubMenuItemCheckbox("Don't use an exit node", "Normal routing", true)
	go m.watch(m.offer, func() {
		m.mu.Lock()
		on := !m.offering
		m.mu.Unlock()
		v := "off"
		if on {
			v = "on"
		}
		postIPC("/api/exitnode/offer?enabled=" + v)
	})
	go m.watch(m.none, func() { postIPC("/api/exitnode/comeback") })
	return m
}

func (m *trayExitMenu) watch(item *systray.MenuItem, action func()) {
	for range item.ClickedCh {
		go func() {
			action()
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
		go m.watch(it, func() {
			m.mu.Lock()
			ip := m.itemIPs[idx]
			m.mu.Unlock()
			if ip != "" {
				postIPC("/api/exitnode/jumpto?" + url.Values{"ip": {ip}, "wait": {"0"}}.Encode())
			}
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
