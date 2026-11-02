//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"context"
	"encoding/json"
	"errors"
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
func postControl(path string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, ipcURL(path), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(agent.ControlHeader, "1")
	resp, err := actionClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("daemon not reachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("the running daemon is older than this tray; restart the service")
	}
	var r struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Notice string `json:"notice"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("daemon: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
	n.item.Show()
}

func (n *trayNotice) expire() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.at.IsZero() && time.Since(n.at) > noticeTTL {
		n.at = time.Time{}
		n.item.Hide()
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

			mHeader := systray.AddMenuItem("○ Connecting…", "Connection state")
			mHeader.Disable()
			mAddress := systray.AddMenuItem("IP: —", "Click to copy this device's VPN IP")
			mTraffic := systray.AddMenuItem("Traffic: —", "Total since the daemon started")
			mTraffic.Disable()
			mRate := systray.AddMenuItem("Speed: —", "Current throughput")
			mRate.Disable()
			mDetails := systray.AddMenuItem("", "")
			mDetails.Disable()
			mLogin := systray.AddMenuItem("Log in…", "Open the browser to add this device to your account")
			mLogin.Hide()
			var (
				loginMu    sync.Mutex
				loginURL   string
				loginShown bool
			)

			systray.AddSeparator()
			mToggle := systray.AddMenuItem("Disconnect", "Connect or disconnect the tunnel; the service keeps running")

			mPeers := systray.AddMenuItem("Peers: —", "Devices in this network; click one to copy its IP")
			peerMenu := newPeerMenuGroup(mPeers, "No peers")
			mPing := systray.AddMenuItem("Ping all peers", "Measure latency to every peer over the tunnel")
			mPingResult := systray.AddMenuItem("", "")
			mPingResult.Disable()
			mPingResult.Hide()

			exitMenu := newTrayExitMenu()

			mNotice := systray.AddMenuItem("", "")
			mNotice.Disable()
			mNotice.Hide()
			notice := &trayNotice{item: mNotice}
			exitMenu.report = notice.report

			systray.AddSeparator()
			mVersion := systray.AddMenuItem("Version "+version.Version, "Installed version")
			mVersion.Disable()
			var uninstallClicked chan struct{} // nil: never fires
			if trayCanUninstall {
				uninstallClicked = systray.AddMenuItem("Uninstall Wantastic…", "Remove the VPN service, this menu and the program; your login is kept").ClickedCh
			}
			var uninstalling atomic.Bool
			mQuit := systray.AddMenuItem("Quit tray", "Close this menu; the VPN service keeps running")

			var (
				refreshMu sync.Mutex
				prev      trafficSample
				lastState = trayState(-1)
				latency   map[string]agent.PingResult
				address   string
			)
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
				v := deriveTrayView(st, prev, cur)
				prev = cur

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
				setTitle(mDetails, v.Details)
				loginMu.Lock()
				loginURL = v.LoginURL
				if show := v.LoginURL != ""; show != loginShown {
					if show {
						mLogin.Show()
					} else {
						mLogin.Hide()
					}
					loginShown = show
				}
				loginMu.Unlock()
				setTitle(mToggle, v.ToggleTitle)
				setEnabled(mToggle, v.ToggleEnabled)
				setTitle(mPeers, v.PeersTitle)
				setEnabled(mPing, v.State == trayConnected || v.State == trayExitActive)

				if st != nil {
					syncPeerMenuGroup(peerMenu, buildPeerMenuEntries(st.Peers, latency, now))
				} else {
					syncPeerMenuGroup(peerMenu, nil)
				}
				exitMenu.apply(deriveExitMenu(st))
				notice.expire()

				ver := "Version " + version.Version
				if st != nil && st.Version != "" && st.Version != version.Version {
					ver += " (service " + st.Version + ")"
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

			var pinging sync.Mutex
			pingAll := func() {
				if !pinging.TryLock() {
					return
				}
				defer pinging.Unlock()
				mPing.SetTitle("Pinging all peers…")
				mPing.Disable()
				var pr agent.PingResponse
				err := fetchJSON(actionClient, "/api/ping?count=3&interval=200&timeout=1000", &pr)
				if err == nil && pr.Error == "" {
					m := make(map[string]agent.PingResult, len(pr.Results))
					for _, r := range pr.Results {
						m[r.IP] = r
					}
					refreshMu.Lock()
					latency = m
					refreshMu.Unlock()
				}
				mPing.SetTitle("Ping all peers")
				mPingResult.SetTitle(pingSummary(&pr, err) + " · " + time.Now().Format("15:04:05"))
				mPingResult.Show()
				refresh()
			}

			toggle := func() {
				refreshMu.Lock()
				disconnect := lastState == trayConnected || lastState == trayExitActive
				refreshMu.Unlock()
				mToggle.Disable()
				if disconnect {
					setTitle(mToggle, "Disconnecting…")
					n, err := postControl("/api/disconnect")
					notice.report("Disconnected; the service keeps running", n, err)
				} else {
					setTitle(mToggle, "Connecting…")
					n, err := postControl("/api/connect")
					notice.report("Connected", n, err)
				}
				refresh()
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
						cancel()
						systray.Quit()
						return

					case <-mToggle.ClickedCh:
						go toggle()

					case <-mLogin.ClickedCh:
						loginMu.Lock()
						url := loginURL
						loginMu.Unlock()
						if err := OpenURL(url); err != nil {
							notice.report("", "", fmt.Errorf("open the browser: %w", err))
						}

					case <-uninstallClicked:
						if !uninstalling.CompareAndSwap(false, true) {
							continue
						}
						go func() {
							defer uninstalling.Store(false)
							if err := trayUninstall(); errors.Is(err, errUninstallCanceled) {
								return
							} else if err != nil {
								notice.report("", "", fmt.Errorf("uninstall: %w", err))
							}
						}()

					case <-mPing.ClickedCh:
						go pingAll()

					case <-mAddress.ClickedCh:
						refreshMu.Lock()
						ip := address
						refreshMu.Unlock()
						if ip != "" && ip != "—" {
							if err := copyToClipboard(ip); err != nil {
								notice.set("⚠ Copy failed: " + err.Error())
							} else {
								notice.set("✓ Copied " + ip)
							}
						}

					case <-ticker.C:
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
			item.vpnIP.set("VPN IP", "")
			item.publicIP.set("Public IP", "")
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
		row.vpnIP.set("VPN IP", entry.VPNIP)
		row.publicIP.set("Public IP", entry.PublicIP)
		row.item.Show()
	}
	for i := len(entries); i < len(group.peerItems); i++ {
		group.peerItems[i].vpnIP.set("VPN IP", "")
		group.peerItems[i].publicIP.set("Public IP", "")
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
	setTooltip(c.item, "Click to copy "+value)
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
