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
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/pkg/version"

	"github.com/getlantern/systray"
)

// trayRefresh is how often the menu re-reads the daemon: often enough that
// speeds and peer paths look live while the menu is open.
const trayRefresh = 2 * time.Second

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
			systray.SetTooltip("Wantastic")

			mHeader := systray.AddMenuItem("○ Connecting…", "Connection state")
			mHeader.Disable()
			mAddress := systray.AddMenuItem("IP: —", "Click to copy this device's VPN IP")
			mTraffic := systray.AddMenuItem("Traffic: —", "Total since the daemon started")
			mTraffic.Disable()
			mRate := systray.AddMenuItem("Speed: —", "Current throughput")
			mRate.Disable()
			mDetails := systray.AddMenuItem("", "")
			mDetails.Disable()

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
				systray.SetTooltip(v.Tooltip)
				mHeader.SetTitle(v.Header)
				mAddress.SetTitle(v.Address)
				address = strings.TrimPrefix(v.Address, "IP: ")
				mTraffic.SetTitle(v.Traffic)
				mRate.SetTitle(v.Rate)
				mDetails.SetTitle(v.Details)
				mToggle.SetTitle(v.ToggleTitle)
				setEnabled(mToggle, v.ToggleEnabled)
				mPeers.SetTitle(v.PeersTitle)
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
				mVersion.SetTitle(ver)

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
					mToggle.SetTitle("Disconnecting…")
					n, err := postControl("/api/disconnect")
					notice.report("Disconnected; the service keeps running", n, err)
				} else {
					mToggle.SetTitle("Connecting…")
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

type peerMenuItemState struct {
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
			item.setCopyText("")
			item.item.Hide()
		}
		return
	}

	group.emptyItem.Hide()
	for len(group.peerItems) < len(entries) {
		item := group.parent.AddSubMenuItem("", "")
		state := &peerMenuItemState{item: item}
		go state.handleClicks()
		group.peerItems = append(group.peerItems, state)
	}
	for i, entry := range entries {
		group.peerItems[i].setCopyText(entry.CopyText)
		group.peerItems[i].item.SetTitle(entry.Title)
		group.peerItems[i].item.SetTooltip(entry.Tooltip)
		group.peerItems[i].item.Show()
	}
	for i := len(entries); i < len(group.peerItems); i++ {
		group.peerItems[i].setCopyText("")
		group.peerItems[i].item.Hide()
	}
}

func (item *peerMenuItemState) setCopyText(copyText string) {
	item.mu.Lock()
	item.copyText = copyText
	item.mu.Unlock()
}

func (item *peerMenuItemState) getCopyText() string {
	item.mu.RLock()
	defer item.mu.RUnlock()
	return item.copyText
}

func (item *peerMenuItemState) handleClicks() {
	for range item.item.ClickedCh {
		copyText := item.getCopyText()
		if copyText == "" {
			continue
		}
		if err := copyToClipboard(copyText); err != nil {
			log.Printf("[Tray] Failed to copy peer value to clipboard: %v", err)
		}
	}
}
