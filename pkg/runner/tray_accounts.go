//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"net/url"
	"sync"
	"time"

	"wantastic-agent/internal/accounts"
	"wantastic-agent/internal/agent"

	"github.com/getlantern/systray"
)

// trayAccountsEvery is how often the account list is re-read while the
// menu is closed (it is read on every refresh while open).
const trayAccountsEvery = 10 * time.Second

// trayAccountMenu is the "Account" submenu: the accounts on this device,
// the active one checked, a click switches; "Add another account…" shows
// the new account's claim QR code.
type trayAccountMenu struct {
	root  *systray.MenuItem
	add   *systray.MenuItem
	qr    *systray.MenuItem
	empty *systray.MenuItem

	mu       sync.Mutex
	rows     []*systray.MenuItem
	ids      []string
	claims   []string // claim link of a pending row
	pending  map[string]string
	claimURL string // the QR's link
	qrFor    string
	lastRead time.Time

	report   func(okText, notice string, err error)
	onChange func()
}

func newTrayAccountMenu() *trayAccountMenu {
	m := &trayAccountMenu{pending: map[string]string{}}
	m.root = systray.AddMenuItem("Account", "Accounts this device belongs to; click one to switch")
	m.empty = m.root.AddSubMenuItem("This device is in one account", "")
	m.empty.Disable()
	m.add = m.root.AddSubMenuItem("Add another account…", "Add this device to another Wantastic account with a claim link")
	m.qr = m.root.AddSubMenuItem("Scan to add the account", "Scan with a phone signed in to the other account, or click to open the link here")
	m.qr.Hide()
	keepMenuOpen(m.add)
	go m.watchAdd()
	go func() {
		for range m.qr.ClickedCh {
			m.mu.Lock()
			link := m.claimURL
			m.mu.Unlock()
			m.open(link)
		}
	}()
	return m
}

func (m *trayAccountMenu) open(link string) {
	if link == "" {
		return
	}
	if err := OpenURL(link); err != nil && m.report != nil {
		m.report("", "", err)
	}
}

func (m *trayAccountMenu) watchAdd() {
	for range m.add.ClickedCh {
		setTitle(m.add, "Adding an account…")
		var resp agent.AccountsResponse
		err := postAccounts("/api/accounts/add", &resp)
		setTitle(m.add, "Add another account…")
		if err != nil {
			m.report("", "", err)
			continue
		}
		if resp.Added != nil {
			m.showClaim(resp.Added.ClaimURL)
			m.report("", "Scan the code or click it, signed in to the other account", nil)
		}
		m.apply(resp.Accounts)
		m.changed()
	}
}

// showClaim puts link's QR code in the submenu (macOS draws it full size;
// elsewhere the row opens the link).
func (m *trayAccountMenu) showClaim(link string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimURL = link
	if link == "" {
		m.qr.Hide()
		return
	}
	if link != m.qrFor {
		m.qrFor = link
		if png, err := loginQRPNG(link); err == nil {
			setMenuImage(m.qr, png, loginQRPoints)
		}
	}
	m.qr.Show()
}

func (m *trayAccountMenu) changed() {
	if m.onChange != nil {
		m.onChange()
	}
}

// refresh re-reads the list when due; force reads now (menu open).
func (m *trayAccountMenu) refresh(force bool) {
	m.mu.Lock()
	due := force || time.Since(m.lastRead) >= trayAccountsEvery
	if due {
		m.lastRead = time.Now()
	}
	m.mu.Unlock()
	if !due {
		return
	}
	var resp agent.AccountsResponse
	if err := fetchJSON(trayClient, "/api/accounts", &resp); err != nil {
		// An older daemon has no accounts; keep the submenu to its add row.
		m.apply(nil)
		return
	}
	m.apply(resp.Accounts)
}

func (m *trayAccountMenu) apply(list []accounts.Account) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := "—"
	stillPending := false
	for _, a := range list {
		if a.Active {
			active = a.Name
		}
		if a.Pending && a.ClaimURL == m.claimURL {
			stillPending = true
		}
	}
	setTitle(m.root, "Account: "+active)
	// The QR goes once its account is claimed.
	if m.claimURL != "" && !stillPending {
		m.claimURL = ""
		m.qr.Hide()
	}
	if len(list) <= 1 {
		m.empty.Show()
	} else {
		m.empty.Hide()
	}
	for len(m.rows) < len(list) {
		idx := len(m.rows)
		row := m.root.AddSubMenuItemCheckbox("", "", false)
		m.rows = append(m.rows, row)
		m.ids = append(m.ids, "")
		m.claims = append(m.claims, "")
		keepMenuOpen(row)
		go m.watchRow(row, idx)
	}
	for i, row := range m.rows {
		if i >= len(list) || len(list) <= 1 {
			m.ids[i] = ""
			row.Hide()
			continue
		}
		a := list[i]
		m.ids[i], m.claims[i] = a.ID, a.ClaimURL
		title := a.Name
		switch {
		case m.pending[a.ID] != "":
			title += " · " + m.pending[a.ID]
		case a.Pending:
			title += " · waiting for claim"
		case a.Address != "":
			title += " · " + a.Address
		}
		setTitle(row, title)
		setChecked(row, a.Active)
		if a.Pending {
			setTooltip(row, "Click to show its claim code again")
		} else {
			setTooltip(row, "Switch to "+a.Name+"; the VPN reconnects")
		}
		row.Show()
	}
}

func (m *trayAccountMenu) watchRow(row *systray.MenuItem, idx int) {
	for range row.ClickedCh {
		m.mu.Lock()
		id, claim := m.ids[idx], m.claims[idx]
		busy := m.pending[id] != ""
		if id != "" && claim == "" && !busy {
			m.pending[id] = "switching…"
		}
		m.mu.Unlock()
		switch {
		case id == "" || busy:
			continue
		case claim != "":
			m.showClaim(claim)
			continue
		}
		m.changed()
		var resp agent.AccountsResponse
		err := postAccounts("/api/accounts/use?"+url.Values{"id": {id}}.Encode(), &resp)
		m.report("", resp.Notice, err)
		// The daemon reconnects on the other account; give it a moment
		// before the row stops saying "switching…".
		time.Sleep(3 * time.Second)
		m.mu.Lock()
		delete(m.pending, id)
		m.lastRead = time.Time{}
		m.mu.Unlock()
		m.changed()
	}
}

// postAccounts runs an account action and decodes the account list reply.
func postAccounts(path string, resp *agent.AccountsResponse) error {
	_, err := postControlInto(path, resp)
	return err
}
