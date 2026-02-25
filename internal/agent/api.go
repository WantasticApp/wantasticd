package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	mux.HandleFunc("/api/exitnode/use", s.handleSetExitNode)

	s.server = &http.Server{
		Addr:    "127.0.0.1:9034",
		Handler: mux,
	}

	return s
}

// Start begins serving the local IPC API
func (s *APIServer) Start() error {
	port := 9034

	// Support dynamic IPC ports via WTC_IPC_PORT env to avoid conflicts in localized e2e
	if customPort := os.Getenv("WTC_IPC_PORT"); customPort != "" {
		fmt.Sscanf(customPort, "%d", &port)
	}

	var listener net.Listener
	var err error

	for port <= 9100 {
		s.server.Addr = fmt.Sprintf("127.0.0.1:%d", port)
		listener, err = net.Listen("tcp", s.server.Addr)
		if err == nil {
			break
		}
		log.Printf("IPC API Error binding to %s: %v, trying next port...", s.server.Addr, err)
		port++
	}

	if err != nil {
		log.Printf("IPC API Error: failed to find open port")
		return nil // Non-fatal for the agent core
	}

	// Share selected port for local tray & cli clients
	os.Setenv("WTC_IPC_PORT", fmt.Sprintf("%d", port))
	portFile := filepath.Join(os.TempDir(), "wantasticd_ipc_port")
	os.WriteFile(portFile, []byte(fmt.Sprintf("%d", port)), 0644)

	log.Printf("Starting local IPC API on %s", s.server.Addr)

	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("IPC API HTTP Error: %v", err)
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

	log.Println("[API] Exit Node offer toggle requested via IPC")

	go func() {
		if err := s.agent.ToggleOfferExitNode(); err != nil {
			log.Printf("[API] Failed to toggle exit node offer: %v", err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\":\"pending\"}")
}

func (s *APIServer) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerPubKey := r.URL.Query().Get("peer")
	log.Printf("[API] Exit Node set requested via IPC to peer: %s", peerPubKey)

	go func() {
		if err := s.agent.SetExitNode(peerPubKey); err != nil {
			log.Printf("[API] Failed to set exit node routing: %v", err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\":\"pending\"}")
}
