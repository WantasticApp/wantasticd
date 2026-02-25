//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"wantastic-agent/internal/agent"

	"github.com/getlantern/systray"
)

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

			mPeers := systray.AddMenuItem("Peers: 0 (P2P: 0, Relay: 0)", "Active connections")
			mPeers.Disable()

			systray.AddSeparator()

			mToggleOnOff := systray.AddMenuItem("Disconnect", "Toggle VPN On/Off")

			mToggleExit := systray.AddMenuItem("Enable Exit Node", "Allow others to route through this device")
			mToggleTUN := systray.AddMenuItem("Toggle TUN Mode", "Switch between TUN and Userspace")

			systray.AddSeparator()
			mQuit := systray.AddMenuItem("Quit", "Exit Tray")

			// Handler loop for tray updates and interactions
			go func() {
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						return

					case <-mQuit.ClickedCh:
						cancel()
						return

					case <-mToggleOnOff.ClickedCh:
						// Simple toggle logic via IPC loopback
						go func() {
							if mToggleOnOff.String() == "Connect" {
								http.Post("http://127.0.0.1:9034/api/connect", "application/json", nil)
							} else {
								http.Post("http://127.0.0.1:9034/api/disconnect", "application/json", nil)
							}
						}()

					case <-mToggleExit.ClickedCh:
						go http.Post("http://127.0.0.1:9034/api/toggle-exit", "application/json", nil)

					case <-mToggleTUN.ClickedCh:
						go http.Post("http://127.0.0.1:9034/api/toggle-tun", "application/json", nil)

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

							p2pCount := 0
							relayCount := 0
							for _, p := range st.Peers {
								if p.Endpoint != "" && !strings.Contains(p.Endpoint, "0.250.250.254") {
									p2pCount++
								} else {
									relayCount++
								}
							}
							mPeers.SetTitle(fmt.Sprintf("Peers: %d (P2P: %d, Relay: %d)", len(st.Peers), p2pCount, relayCount))

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
