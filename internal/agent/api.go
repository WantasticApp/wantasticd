package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"wantastic-agent/internal/device"
)

// APIServer represents the local IPC server for the systray and CLI
type APIServer struct {
	agent  *Agent
	server *http.Server
}

// NewAPIServer creates a new API Server instance
func NewAPIServer(a *Agent) *APIServer {
	mux := http.NewServeMux()
	s := &APIServer{
		agent: a,
	}

	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/mode/toggle", s.handleToggleMode)
	mux.HandleFunc("/api/state/toggle", s.handleToggleState)
	mux.HandleFunc("/api/exitnode/toggle", s.handleToggleExitNode)

	s.server = &http.Server{
		Addr:    "127.0.0.1:9034",
		Handler: mux,
	}

	return s
}

// Start begins serving the local IPC API
func (s *APIServer) Start() error {
	log.Printf("Starting local IPC API on %s", s.server.Addr)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("IPC API Error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the API
func (s *APIServer) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

type StatusResponse struct {
	TUNMode       bool              `json:"tun_mode"`
	TUNName       string            `json:"tun_name"`
	Running       bool              `json:"running"`
	DeviceRunning bool              `json:"device_running"`
	ExitNode      bool              `json:"exit_node"`
	IPs           []string          `json:"ips"`
	PubKey        string            `json:"pubkey"`
	RxBytes       uint64            `json:"rx_bytes"`
	TxBytes       uint64            `json:"tx_bytes"`
	Peers         []device.PeerInfo `json:"peers"`
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ips []string
	for _, addr := range s.agent.config.Interface.Addresses {
		ips = append(ips, addr.String())
	}

	rx, tx, _ := s.agent.device.GetTransferStats()

	status := StatusResponse{
		TUNMode:       s.agent.config.Interface.TUNMode,
		TUNName:       s.agent.config.Interface.TUNName,
		Running:       s.agent.IsRunning(),
		DeviceRunning: s.agent.device.IsRunning(),
		ExitNode:      s.agent.config.ExitNode.Enabled,
		IPs:           ips,
		PubKey:        s.agent.device.GetPublicKey(),
		RxBytes:       rx,
		TxBytes:       tx,
		Peers:         s.agent.device.GetDetailedPeers(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *APIServer) handleToggleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[API] Toggle mode requested via IPC")

	// Trigger an asynchronous agent restart to toggle the mode
	go func() {
		s.agent.mu.Lock()
		s.agent.config.Interface.TUNMode = !s.agent.config.Interface.TUNMode
		cfg := s.agent.config
		s.agent.mu.Unlock()

		// Stop the current device
		if err := s.agent.device.Stop(); err != nil {
			log.Printf("[API] Failed to stop device during toggle: %v", err)
		}

		// Rebuild device with new config state
		// Note: A full robust reload might require recreating the device or calling a specific Reconfigure method,
		// but since the original tray logic just restarted the agent using startAgentWithRetry, we'll implement
		// a simplified device restart here.
		s.agent.device.Start()
		log.Printf("[API] Toggled TUN mode to %v", cfg.Interface.TUNMode)
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\":\"toggled\"}")
}

func (s *APIServer) handleToggleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[API] VPN State toggle requested via IPC")

	go func() {
		if s.agent.device.IsRunning() {
			s.agent.device.Stop()
			log.Println("[API] Stopped VPN Device via API")
		} else {
			s.agent.device.Start()
			log.Println("[API] Started VPN Device via API")
		}
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\":\"toggled\"}")
}

func (s *APIServer) handleToggleExitNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[API] Exit Node toggle requested via IPC")

	s.agent.mu.Lock()
	s.agent.config.ExitNode.Enabled = !s.agent.config.ExitNode.Enabled
	s.agent.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\":\"toggled\"}")
}
