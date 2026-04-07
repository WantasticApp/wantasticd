//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"

	"github.com/getlantern/systray"
)

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

type peerMenuEntry struct {
	Title    string
	Tooltip  string
	CopyText string
}

// RunSystray starts the system tray GUI and handles user interactions via IPC.
// It blocks until the systray is quit.
func RunSystray(ctx context.Context, cancel context.CancelFunc) {
	systray.Run(
		func() { // onReady
			systray.SetTitle("W")
			systray.SetTooltip("Wantastic VPN Agent")

			mStatus := systray.AddMenuItem("Status: Connecting...", "Current Mode")
			mStatus.Disable()

			mIP := systray.AddMenuItem("IP: N/A", "Assigned IP Address")
			mIP.Disable()

			mPubKey := systray.AddMenuItem("PubKey: N/A", "Device Public Key")
			mPubKey.Disable()

			mStats := systray.AddMenuItem("Traffic: 0 B / 0 B", "Rx / Tx Bytes")
			mStats.Disable()

			mPeers := systray.AddMenuItem("Peers: 0 (P2P: 0, Relay: 0)", "Peer overview")
			mP2PPeers := mPeers.AddSubMenuItem("P2P Peers: 0", "Direct peer connections")
			mRelayPeers := mPeers.AddSubMenuItem("Relay Peers: 0", "Relayed peer connections")
			p2pMenu := newPeerMenuGroup(mP2PPeers, "No direct peers")
			relayMenu := newPeerMenuGroup(mRelayPeers, "No relay peers")

			systray.AddSeparator()

			mToggleOnOff := systray.AddMenuItem("Disconnect", "Toggle VPN On/Off")

			mToggleExit := systray.AddMenuItem("Enable Exit Node", "Allow others to route through this device")

			systray.AddSeparator()
			mQuit := systray.AddMenuItem("Quit", "Exit Tray")

			// Handler loop for tray updates and interactions
			go func() {
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						systray.Quit()
						return

					case <-mQuit.ClickedCh:
						cancel()
						systray.Quit()
						return

					case <-mToggleOnOff.ClickedCh:
						go http.Post("http://127.0.0.1:9034/api/state/toggle", "application/json", nil)

					case <-mToggleExit.ClickedCh:
						go http.Post("http://127.0.0.1:9034/api/exitnode/toggle", "application/json", nil)

					case <-ticker.C:
						// Fetch latest status via local API
						resp, err := http.Get("http://127.0.0.1:9034/api/status")
						if err != nil {
							continue
						}
						var st agent.StatusResponse
						if err := json.NewDecoder(resp.Body).Decode(&st); err == nil {
							// Update Menu Items
							statusText := "Offline"
							if st.Running {
								statusText = "Online"
							}
							mStatus.SetTitle(fmt.Sprintf("Status: %s", statusText))

							ipText := "N/A"
							if len(st.IPs) > 0 {
								ipText = st.IPs[0]
							}
							mIP.SetTitle(fmt.Sprintf("IP: %s", ipText))

							pubKeyText := "N/A"
							if len(st.PubKey) > 8 {
								pubKeyText = st.PubKey[:8]
							}
							mPubKey.SetTitle(fmt.Sprintf("PubKey: %s...", pubKeyText))

							mStats.SetTitle(fmt.Sprintf("Traffic: %v / %v", st.RxBytes, st.TxBytes))

							p2pEntries, relayEntries := buildPeerMenuEntries(st.Peers)
							p2pCount := len(p2pEntries)
							relayCount := len(relayEntries)
							mPeers.SetTitle(fmt.Sprintf("Peers: %d (P2P: %d, Relay: %d)", len(st.Peers), p2pCount, relayCount))
							mP2PPeers.SetTitle(fmt.Sprintf("P2P Peers: %d", p2pCount))
							mRelayPeers.SetTitle(fmt.Sprintf("Relay Peers: %d", relayCount))
							syncPeerMenuGroup(p2pMenu, p2pEntries)
							syncPeerMenuGroup(relayMenu, relayEntries)

							if st.Running {
								mToggleOnOff.SetTitle("Disconnect")
							} else {
								mToggleOnOff.SetTitle("Connect")
							}

							if st.ExitNode {
								mToggleExit.Check()
							} else {
								mToggleExit.Uncheck()
							}
						}
						resp.Body.Close()
					}
				}
			}()
		},
		func() { // onExit
			log.Println("Systray finished")
		},
	)
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
		group.emptyItem.SetTitle(group.emptyTitle)
		group.emptyItem.SetTooltip(group.emptyTitle)
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

func buildPeerMenuEntries(peers []device.PeerInfo) ([]peerMenuEntry, []peerMenuEntry) {
	var p2pEntries []peerMenuEntry
	var relayEntries []peerMenuEntry

	for _, peer := range peers {
		entry := peerMenuEntry{
			Title:    formatPeerMenuTitle(peer),
			Tooltip:  formatPeerMenuTooltip(peer),
			CopyText: formatPeerCopyText(peer),
		}
		if isDirectPeer(peer) {
			p2pEntries = append(p2pEntries, entry)
		} else {
			relayEntries = append(relayEntries, entry)
		}
	}

	return p2pEntries, relayEntries
}

func isDirectPeer(peer device.PeerInfo) bool {
	return peer.IsP2P && peer.P2PState == "established"
}

func formatPeerMenuTitle(peer device.PeerInfo) string {
	hostname := strings.TrimSpace(peer.Hostname)
	ip := strings.TrimSpace(peer.AssignedIP)
	var base string

	switch {
	case hostname != "" && ip != "":
		base = fmt.Sprintf("%s (%s)", hostname, ip)
	case ip != "":
		base = ip
	case hostname != "":
		base = hostname
	case !peer.IsP2P && peer.Endpoint != "":
		base = fmt.Sprintf("Server (%s)", peer.Endpoint)
	case peer.Endpoint != "":
		base = fmt.Sprintf("Relay (%s)", peer.Endpoint)
	default:
		base = abbreviatePeerKey(peer.PublicKey)
	}

	if peer.IsP2P && peer.P2PState != "" && peer.P2PState != "established" {
		return fmt.Sprintf("%s [%s]", base, peer.P2PState)
	}
	return base
}

func formatPeerMenuTooltip(peer device.PeerInfo) string {
	var parts []string
	if peer.Hostname != "" {
		parts = append(parts, "Host: "+peer.Hostname)
	}
	if peer.AssignedIP != "" {
		parts = append(parts, "IP: "+peer.AssignedIP)
	}
	if peer.Endpoint != "" {
		parts = append(parts, "Endpoint: "+peer.Endpoint)
	}
	if peer.P2PState != "" {
		parts = append(parts, "State: "+peer.P2PState)
	} else if peer.IsP2P {
		parts = append(parts, "State: direct")
	} else {
		parts = append(parts, "State: relay")
	}
	if copyText := formatPeerCopyText(peer); copyText != "" {
		parts = append(parts, "Click copies: "+copyText)
	}
	parts = append(parts, "PubKey: "+abbreviatePeerKey(peer.PublicKey))
	return strings.Join(parts, " | ")
}

func formatPeerCopyText(peer device.PeerInfo) string {
	switch {
	case strings.TrimSpace(peer.AssignedIP) != "":
		return strings.TrimSpace(peer.AssignedIP)
	case strings.TrimSpace(peer.Endpoint) != "":
		return strings.TrimSpace(peer.Endpoint)
	case strings.TrimSpace(peer.Hostname) != "":
		return strings.TrimSpace(peer.Hostname)
	default:
		return strings.TrimSpace(peer.PublicKey)
	}
}

func abbreviatePeerKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "..." + key[len(key)-4:]
}
