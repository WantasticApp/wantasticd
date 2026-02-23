//go:build windows || darwin || (linux && cgo)
// +build windows darwin linux,cgo

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

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
			mToggleExit := systray.AddMenuItem("Enable Exit Node", "Toggle Exit Node configuration")
			mToggleTUN := systray.AddMenuItem("Toggle TUN Mode", "Switch between TUN and Userspace")

			systray.AddSeparator()
			mQuit := systray.AddMenuItem("Quit", "Exit Tray")

			// Poll status periodically
			go func() {
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						resp, err := http.Get("http://127.0.0.1:9034/api/status")
						if err != nil {
							mStatus.SetTitle("Status: Daemon Offline")
							continue
						}

						var status struct {
							TUNMode       bool     `json:"tun_mode"`
							TUNName       string   `json:"tun_name"`
							Running       bool     `json:"running"`        // Agent process
							DeviceRunning bool     `json:"device_running"` // VPN Tunnel
							ExitNode      bool     `json:"exit_node"`
							IPs           []string `json:"ips"`
							PubKey        string   `json:"pubkey"`
							RxBytes       uint64   `json:"rx_bytes"`
							TxBytes       uint64   `json:"tx_bytes"`
							Peers         []struct {
								IsP2P bool `json:"is_p2p"`
							} `json:"peers"`
						}

						if err := json.NewDecoder(resp.Body).Decode(&status); err == nil {
							modeStr := "Userspace"
							if status.TUNMode {
								modeStr = "TUN (" + status.TUNName + ")"
							}

							if status.DeviceRunning {
								mStatus.SetTitle("Status: Connected - " + modeStr)
								mToggleOnOff.SetTitle("Disconnect")
							} else {
								mStatus.SetTitle("Status: Stopped - " + modeStr)
								mToggleOnOff.SetTitle("Connect")
							}

							if len(status.IPs) > 0 {
								mIP.SetTitle("IP: " + status.IPs[0])
							} else {
								mIP.SetTitle("IP: N/A")
							}

							if len(status.PubKey) > 8 {
								mPubKey.SetTitle("PubKey: " + status.PubKey[:8] + "...")
							} else {
								mPubKey.SetTitle("PubKey: N/A")
							}

							mStats.SetTitle("Traffic: " + formatBytes(status.RxBytes) + " ↓ / " + formatBytes(status.TxBytes) + " ↑")

							p2pCount := 0
							relayCount := 0
							for _, p := range status.Peers {
								if p.IsP2P {
									p2pCount++
								} else {
									relayCount++
								}
							}
							mPeers.SetTitle(fmt.Sprintf("Peers: %d (P2P: %d, Relay: %d)", len(status.Peers), p2pCount, relayCount))

							if status.ExitNode {
								mToggleExit.SetTitle("Disable Exit Node")
							} else {
								mToggleExit.SetTitle("Enable Exit Node")
							}
						}
						resp.Body.Close()
					case <-ctx.Done():
						return
					}
				}
			}()

			go func() {
				for {
					select {
					case <-mToggleOnOff.ClickedCh:
						http.Post("http://127.0.0.1:9034/api/state/toggle", "application/json", nil)
					case <-mToggleExit.ClickedCh:
						http.Post("http://127.0.0.1:9034/api/exitnode/toggle", "application/json", nil)
					case <-mToggleTUN.ClickedCh:
						http.Post("http://127.0.0.1:9034/api/mode/toggle", "application/json", nil)

					case <-mQuit.ClickedCh:
						log.Println("Systray quit requested")
						systray.Quit()
						cancel() // Signal the application to exit (if we want the tray to kill the local process)
						return

					case <-ctx.Done():
						systray.Quit()
						return
					}
				}
			}()
		},
		func() { // onExit
			log.Println("Systray exited")
		},
	)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
