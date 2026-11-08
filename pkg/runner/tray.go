//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/pkg/version"

	"github.com/getlantern/systray"
)

// trayRefresh is how often the menu re-reads the daemon: often enough that
// speeds and peer paths look live while the menu is open.
const trayRefresh = time.Second

// noticeTTL is how long an action's result stays in the menu.
const noticeTTL = 20 * time.Second

// livePingEvery is how often peers are pinged while the menu is open (macOS,
// where the tray sees the menu open); nothing is pinged while it is closed.
const livePingEvery = 3 * time.Second

// trayClient talks to the daemon's local IPC API. Every call is bounded so a
// wedged daemon can never freeze the menu; actions that wait on the network
// (connect, exit node, ping) get their own longer client.
var (
	trayClient   = &http.Client{Timeout: 3 * time.Second}
	actionClient = &http.Client{Timeout: 45 * time.Second}
)

func ipcURL(path string) string {
	return "http://127.0.0.1:" + agent.GetIPCPort() + path
}

// postControl runs a state-changing daemon action and returns the daemon's
// notice, or its error. Every control endpoint answers {ok, error, notice}.
func postControl(path string) (string, error) { return postControlInto(path, nil) }

// postControlInto is postControl that also decodes the whole reply into v.
func postControlInto(path string, v any) (string, error) {
	req, err := http.NewRequest(http.MethodPost, ipcURL(path), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(agent.ControlHeader, "1")
	resp, err := actionClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s", T("error.daemon.unreachable"))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("%s", T("error.daemon.old"))
	}
	var r struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Notice string `json:"notice"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("%s", T("error.daemon.http", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	if v != nil {
		_ = json.Unmarshal(body, v)
	}
	if !r.OK {
		return "", fmt.Errorf("%s", firstNonEmpty(r.Error, fmt.Sprintf("HTTP %d", resp.StatusCode)))
	}
	return r.Notice, nil
}

func fetchJSON(client *http.Client, path string, v any) error {
	resp, err := client.Get(ipcURL(path))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func fetchStatus() (*agent.StatusResponse, error) {
	var st agent.StatusResponse
	if err := fetchJSON(trayClient, "/api/status", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// trayNotice is the one-line result of the last action ("✓ Connected",
// "⚠ …"), hidden again after noticeTTL.
type trayNotice struct {
	item *systray.MenuItem
	mu   sync.Mutex
	at   time.Time
}

func (n *trayNotice) set(text string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.at = time.Now()
	n.item.SetTitle(text)
	n.item.SetTooltip(text)
}

// expire returns the row to its idle placeholder once a notice has aged out.
// The row is never hidden: showing and hiding it was the menu's main layout
// wiggle (a row appeared on every connect/disconnect/toggle and vanished
// noticeTTL later). It stays in place and only its text changes.
func (n *trayNotice) expire() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.at.IsZero() && time.Since(n.at) > noticeTTL {
		n.at = time.Time{}
		n.item.SetTitle(T("notice.idle"))
		n.item.SetTooltip("")
	}
}

func (n *trayNotice) report(okText string, notice string, err error) {
	switch {
	case err != nil:
		n.set("⚠ " + err.Error())
	case notice != "":
		n.set("ℹ " + notice)
	default:
		n.set("✓ " + okText)
	}
}

// menuText remembers what each item shows so a refresh touches only the lines
// that changed: rewriting every line each second makes some menus flicker
// and drops hover state.
var menuText sync.Map // menuTextKey -> string

type menuTextKey struct {
	item    *systray.MenuItem
	tooltip bool
}

func setMenuText(key menuTextKey, text string, apply func(string)) {
	if prev, ok := menuText.Load(key); ok && prev.(string) == text {
		return
	}
	menuText.Store(key, text)
	apply(text)
}

func setTitle(item *systray.MenuItem, text string) {
	setMenuText(menuTextKey{item: item}, text, item.SetTitle)
}

func setTooltip(item *systray.MenuItem, text string) {
	setMenuText(menuTextKey{item: item, tooltip: true}, text, item.SetTooltip)
}

func setTrayTooltip(text string) {
	setMenuText(menuTextKey{tooltip: true}, text, systray.SetTooltip)
}

func setTrayIcon(s trayState) {
	if runtime.GOOS == "windows" {
		systray.SetIcon(pngToICO(trayIconPNG(s, 32), 32))
		return
	}
	systray.SetIcon(trayIconPNG(s, 44))
}

// RunSystray starts the system tray GUI and handles user interactions via IPC.
// It blocks until the systray is quit.
func RunSystray(ctx context.Context, cancel context.CancelFunc) {
	watch := newBinaryWatch()
	systray.Run(
		func() { // onReady
			setTrayIcon(trayDaemonDown)
			setTrayTooltip("Wantastic")

			// Status: state, address and live traffic.
			mHeader := systray.AddMenuItem(T("header.connecting"), T("header.tooltip"))
			mHeader.Disable()
			mAddress := systray.AddMenuItem(T("addr.empty"), T("address.tooltip"))
			mRate := systray.AddMenuItem(T("speed.empty"), T("speed.tooltip"))
			mRate.Disable()
			mTraffic := systray.AddMenuItem(T("traffic.empty"), T("traffic.tooltip"))
			mTraffic.Disable()
			// Not signed in: a QR code to scan with a phone (macOS draws it
			// full size) and a link that opens the same page here.
			mLoginQR := systray.AddMenuItem(T("login.qr"), T("login.qr.tooltip"))
			mLoginQR.Hide()
			mLogin := systray.AddMenuItem(T("login.browser"), T("login.browser.tooltip"))
			mLogin.Hide()
			var (
				loginMu    sync.Mutex
				loginURL   string
				loginShown bool
				loginQRFor string
			)

			// Controls: the tunnel and exit-node mode, as switches.
			systray.AddSeparator()
			mToggle := systray.AddMenuItemCheckbox(T("toggle.connect"), T("toggle.tooltip"), false)
			exitMenu := newTrayExitMenu()
			accountMenu := newTrayAccountMenu()

			// Peers and their latency.
			systray.AddSeparator()
			mPeers := systray.AddMenuItem(T("peers.empty"), T("peers.tooltip"))
			peerMenu := newPeerMenuGroup(mPeers, T("peers.none"))
			mPing := systray.AddMenuItem(T("ping.title"), T("ping.tooltip"))
			// The ping-result and notice rows are permanent, with an idle
			// placeholder, so the menu keeps the same item count (and height)
			// across every state and action. Only their titles change.
			mPingResult := systray.AddMenuItem(T("ping.idle"), "")
			mPingResult.Disable()

			mNotice := systray.AddMenuItem(T("notice.idle"), "")
			mNotice.Disable()
			notice := &trayNotice{item: mNotice}
			exitMenu.report = notice.report
			accountMenu.report = notice.report

			// More: service details and shortcuts.
			systray.AddSeparator()
			mMore := systray.AddMenuItem(T("more"), T("more.tooltip"))
			mDetails := mMore.AddSubMenuItem("", "")
			mDetails.Disable()
			mServer := newCopyMenuItem(mMore)
			mKey := newCopyMenuItem(mMore)
			mConsole := mMore.AddSubMenuItem(T("console"), T("console.tooltip", trayConsoleURL))
			mLogs := mMore.AddSubMenuItem(T("log"), T("log.tooltip"))
			logPath := trayLogPath()
			if logPath == "" {
				mLogs.Hide()
			}
			mVersion := mMore.AddSubMenuItem(T("version", version.Version), T("version.tooltip"))
			mVersion.Disable()
			mQuit := systray.AddMenuItem(T("menu.quit"), T("menu.quit.tooltip"))

			keepMenuOpen(mToggle, mPing)
			menuSwitch(mToggle, exitMenu.offer)

			var (
				refreshMu sync.Mutex
				// ratePrev/rateCur are the two samples the live traffic rate is
				// measured between. The pair only advances on a cadence (see
				// advanceRateSample), so the rate shown is always averaged over
				// a real ≥minRateWindow interval; a burst of refreshes a few ms
				// apart reuses the frozen pair instead of dividing a tiny byte
				// delta by a near-zero gap (which showed a garbage spike).
				ratePrev, rateCur trafficSample
				lastState         = trayState(-1)
				latency           map[string]agent.PingResult
				address           string
				// toggling is the VPN row's title while a connect or
				// disconnect runs ("Connecting…"), "" otherwise.
				toggling atomic.Value
				lastPoll time.Time
				menuOpen atomic.Bool
			)
			toggling.Store("")
			// Clicks refresh from their own goroutines; menu updates are
			// serialised here.
			refresh := func() {
				refreshMu.Lock()
				defer refreshMu.Unlock()
				st, err := fetchStatus()
				if err != nil {
					st = nil
				}
				now := time.Now()
				var cur trafficSample
				if st != nil {
					cur = trafficSample{rx: st.RxBytes, tx: st.TxBytes, at: now}
				}
				// Advance the displayed pair only on a cadence (or a counter
				// reset); between advances the frozen pair is reused, so the
				// rate is never divided by a near-zero interval.
				if st == nil {
					ratePrev, rateCur = trafficSample{}, trafficSample{}
				} else if advanceRateSample(rateCur, cur) {
					ratePrev, rateCur = rateCur, cur
				}
				v := deriveTrayView(st, ratePrev, rateCur)

				if v.State != lastState {
					setTrayIcon(v.State)
					lastState = v.State
				}
				setTrayTooltip(v.Tooltip)
				setTitle(mHeader, v.Header)
				setTitle(mAddress, v.Address)
				address = strings.TrimPrefix(v.Address, "IP: ")
				setTitle(mTraffic, v.Traffic)
				setTitle(mRate, v.Rate)
				setTitle(mDetails, firstNonEmpty(v.Details, T("details.placeholder")))
				if st != nil {
					mServer.set(T("copy.server"), st.ServerEndpoint)
					mKey.set(T("copy.pubkey"), st.PubKey)
				} else {
					mServer.set(T("copy.server"), "")
					mKey.set(T("copy.pubkey"), "")
				}
				loginMu.Lock()
				loginURL = v.LoginURL
				if show := v.LoginURL != ""; show != loginShown {
					if show {
						mLogin.Show()
					} else {
						mLogin.Hide()
						mLoginQR.Hide()
					}
					loginShown = show
				}
				if v.LoginURL != "" && v.LoginURL != loginQRFor {
					loginQRFor = v.LoginURL
					if png, err := loginQRPNG(v.LoginURL); err == nil && setMenuImage(mLoginQR, png, loginQRPoints) {
						mLoginQR.Show()
					}
				}
				loginMu.Unlock()
				setTitle(mToggle, firstNonEmpty(toggling.Load().(string), v.ToggleTitle))
				setChecked(mToggle, v.State == trayConnected || v.State == trayExitActive)
				setEnabled(mToggle, v.ToggleEnabled)
				setTitle(mPeers, v.PeersTitle)
				setEnabled(mPing, v.State == trayConnected || v.State == trayExitActive)

				if st != nil {
					syncPeerMenuGroup(peerMenu, buildPeerMenuEntries(st.Peers, latency, now))
				} else {
					syncPeerMenuGroup(peerMenu, nil)
				}
				exitMenu.apply(withExitLatency(deriveExitMenu(st), latency))
				if st != nil && st.Claim == nil {
					accountMenu.refresh(menuOpen.Load())
				}
				notice.expire()

				ver := T("version", version.Version)
				if st != nil && st.Version != "" && st.Version != version.Version {
					ver += T("version.service", st.Version)
				}
				setTitle(mVersion, ver)

				// The daemon moved to a new build and our binary on disk was
				// replaced: restart onto it so the menu matches the daemon.
				if st != nil && st.Version != "" && st.Version != version.Version && watch.replaced() {
					log.Printf("tray: daemon runs %s, tray %s; restarting on the updated binary", st.Version, version.Version)
					watch.restart()
				}
			}

			exitMenu.onChange = func() { go refresh() }
			accountMenu.onChange = func() { go refresh() }

			// pingAll measures every peer. A click sends three probes each and
			// says so in the item; the live pings while the menu is open send
			// one and only update the results.
			// A click waits for a live ping already running; a live ping
			// skips while anything runs.
			var (
				pinging     sync.Mutex
				manualQueue atomic.Bool
			)
			pingAll := func(manual bool) {
				query := "/api/ping?count=1&timeout=1000"
				if manual {
					if !manualQueue.CompareAndSwap(false, true) {
						return
					}
					mPing.SetTitle(T("ping.running"))
					mPing.Disable()
					pinging.Lock()
					manualQueue.Store(false)
					query = "/api/ping?count=3&interval=200&timeout=1000"
				} else if !pinging.TryLock() {
					return
				}
				defer pinging.Unlock()
				var pr agent.PingResponse
				err := fetchJSON(actionClient, query, &pr)
				if err == nil && pr.Error == "" {
					m := make(map[string]agent.PingResult, len(pr.Results))
					for _, r := range pr.Results {
						m[r.IP] = r
					}
					refreshMu.Lock()
					latency = m
					refreshMu.Unlock()
				}
				if manual {
					mPing.SetTitle(T("ping.title"))
				}
				mPingResult.SetTitle(pingSummary(&pr, err) + " · " + time.Now().Format("15:04:05"))
				refresh()
			}

			connected := func() bool {
				refreshMu.Lock()
				defer refreshMu.Unlock()
				return lastState == trayConnected || lastState == trayExitActive
			}

			// While the menu is open it pings on its own and refreshes at
			// once, so what it shows is live from the moment it opens.
			liveWake := make(chan struct{}, 1)
			watchMenu(nil, func() {
				menuOpen.Store(true)
				select {
				case liveWake <- struct{}{}:
				default:
				}
				refresh()
			}, func() { menuOpen.Store(false) })
			watchMenu(exitMenu.root, refresh, nil)
			watchMenu(accountMenu.root, refresh, nil)
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-liveWake:
					}
					for menuOpen.Load() {
						if connected() {
							pingAll(false)
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(livePingEvery):
						}
					}
				}
			}()

			toggle := func() {
				refreshMu.Lock()
				disconnect := lastState == trayConnected || lastState == trayExitActive
				refreshMu.Unlock()
				if !toggling.CompareAndSwap("", "pending") {
					return
				}
				if disconnect {
					toggling.Store(T("toggle.disconnecting"))
				} else {
					toggling.Store(T("toggle.connecting"))
				}
				refresh()
				var (
					n   string
					err error
				)
				if disconnect {
					n, err = postControl("/api/disconnect")
					notice.report(T("notice.disconnected"), n, err)
				} else {
					n, err = postControl("/api/connect")
					notice.report(T("notice.connected"), n, err)
				}
				toggling.Store("")
				refresh()
			}

			openLogin := func() {
				loginMu.Lock()
				url := loginURL
				loginMu.Unlock()
				if err := OpenURL(url); err != nil {
					notice.report("", "", fmt.Errorf("%s: %w", T("error.open.browser"), err))
				}
			}

			go func() {
				ticker := time.NewTicker(trayRefresh)
				defer ticker.Stop()
				refresh()

				for {
					select {
					case <-ctx.Done():
						systray.Quit()
						return

					case <-mQuit.ClickedCh:
						// Quit disconnects the tunnel first; users expect "Quit" to
						// stop the VPN, not leave it running after the tray closes.
						// Bound the wait so a wedged (but still listening) daemon can
						// never freeze the quit — give the disconnect ~3s, then close.
						done := make(chan struct{})
						go func() { _, _ = postControl("/api/disconnect"); close(done) }()
						select {
						case <-done:
						case <-time.After(3 * time.Second):
						}
						cancel()
						systray.Quit()
						return

					case <-mToggle.ClickedCh:
						go toggle()

					case <-mLogin.ClickedCh:
						openLogin()

					case <-mLoginQR.ClickedCh:
						openLogin()

					case <-mConsole.ClickedCh:
						if err := OpenURL(trayConsoleURL); err != nil {
							notice.report("", "", fmt.Errorf("%s: %w", T("error.open.browser"), err))
						}

					case <-mLogs.ClickedCh:
						if err := openLogFile(logPath); err != nil {
							notice.report("", "", fmt.Errorf("%s: %w", T("error.open.log"), err))
						}

					case <-mPing.ClickedCh:
						go pingAll(true)

					case <-mAddress.ClickedCh:
						refreshMu.Lock()
						ip := address
						refreshMu.Unlock()
						if ip != "" && ip != "—" {
							if err := copyToClipboard(ip); err != nil {
								notice.set("⚠ " + T("copy.failed", err.Error()))
							} else {
								notice.set("✓ " + T("copy.done", ip))
							}
						}

					case <-ticker.C:
						// With the menu closed only the icon shows, which a
						// slower poll keeps current at less cost.
						if trayKnowsMenuOpen && !menuOpen.Load() && time.Since(lastPoll) < trayIdleRefresh {
							continue
						}
						lastPoll = time.Now()
						refresh()
					}
				}
			}()
		},
		func() { // onExit
			log.Println("Systray finished")
		},
	)
}

type peerMenuGroup struct {
	parent     *systray.MenuItem
	emptyTitle string
	emptyItem  *systray.MenuItem
	peerItems  []*peerMenuItemState
}

// peerMenuItemState is one peer row: its title opens a submenu with the
// peer's VPN IP and public IP, each copied on click.
type peerMenuItemState struct {
	item     *systray.MenuItem
	detail   *systray.MenuItem
	vpnIP    *copyMenuItem
	publicIP *copyMenuItem
}

type copyMenuItem struct {
	item *systray.MenuItem

	mu       sync.RWMutex
	copyText string
}

func newPeerMenuGroup(parent *systray.MenuItem, emptyTitle string) *peerMenuGroup {
	emptyItem := parent.AddSubMenuItem(emptyTitle, emptyTitle)
	emptyItem.Disable()
	return &peerMenuGroup{
		parent:     parent,
		emptyTitle: emptyTitle,
		emptyItem:  emptyItem,
	}
}

func syncPeerMenuGroup(group *peerMenuGroup, entries []peerMenuEntry) {
	if len(entries) == 0 {
		group.emptyItem.Show()
		for _, item := range group.peerItems {
			item.vpnIP.set(T("copy.vpnip"), "")
			item.publicIP.set(T("copy.publicip"), "")
			item.item.Hide()
		}
		return
	}

	group.emptyItem.Hide()
	for len(group.peerItems) < len(entries) {
		item := group.parent.AddSubMenuItem("", "")
		detail := item.AddSubMenuItem("", "")
		detail.Disable()
		state := &peerMenuItemState{
			item:     item,
			detail:   detail,
			vpnIP:    newCopyMenuItem(item),
			publicIP: newCopyMenuItem(item),
		}
		group.peerItems = append(group.peerItems, state)
	}
	for i, entry := range entries {
		row := group.peerItems[i]
		setTitle(row.item, entry.Title)
		setTooltip(row.item, entry.Tooltip)
		setTitle(row.detail, entry.Detail)
		row.vpnIP.set(T("copy.vpnip"), entry.VPNIP)
		row.publicIP.set(T("copy.publicip"), entry.PublicIP)
		row.item.Show()
	}
	for i := len(entries); i < len(group.peerItems); i++ {
		group.peerItems[i].vpnIP.set(T("copy.vpnip"), "")
		group.peerItems[i].publicIP.set(T("copy.publicip"), "")
		group.peerItems[i].item.Hide()
	}
}

func newCopyMenuItem(parent *systray.MenuItem) *copyMenuItem {
	c := &copyMenuItem{item: parent.AddSubMenuItem("", "")}
	go c.handleClicks()
	return c
}

// set shows "<label>  <value>" and copies value on click; with no value the
// line reads "<label>  —" and is disabled.
func (c *copyMenuItem) set(label, value string) {
	c.mu.Lock()
	c.copyText = value
	c.mu.Unlock()
	if value == "" {
		setTitle(c.item, label+"  —")
		setTooltip(c.item, "")
		c.item.Disable()
		return
	}
	setTitle(c.item, label+"  "+value)
	setTooltip(c.item, T("copy.tooltip", value))
	c.item.Enable()
}

func (c *copyMenuItem) getCopyText() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.copyText
}

func (c *copyMenuItem) handleClicks() {
	for range c.item.ClickedCh {
		copyText := c.getCopyText()
		if copyText == "" {
			continue
		}
		if err := copyToClipboard(copyText); err != nil {
			log.Printf("[Tray] Failed to copy peer value to clipboard: %v", err)
		}
	}
}
