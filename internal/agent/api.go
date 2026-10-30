package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/pkg/version"
)

// APIServer represents the local IPC server for the systray and CLI
type APIServer struct {
	agent  *Agent
	server *http.Server
	// peers returns the live peer table; replaced in tests.
	peers func() []device.PeerInfo
}

// NewAPIServer creates a new API Server instance
func NewAPIServer(a *Agent) *APIServer {
	mux := http.NewServeMux()
	s := &APIServer{
		agent: a,
	}
	if a != nil && a.device != nil {
		s.peers = a.device.GetDetailedPeers
	}

	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/state/toggle", s.handleToggleState)
	mux.HandleFunc("/api/connect", s.handleConnect)
	mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/exitnode", s.handleExitNodeStatus)
	mux.HandleFunc("/api/exitnode/offer", s.handleExitNodeOffer)
	mux.HandleFunc("/api/exitnode/jumpto", s.handleExitNodeJumpTo)
	mux.HandleFunc("/api/exitnode/comeback", s.handleExitNodeComeback)
	mux.HandleFunc("/api/exitnode/toggle", s.handleToggleExitNode)
	mux.HandleFunc("/api/exitnode/use", s.handleSetExitNode)
	mux.HandleFunc("/api/ping", s.handlePing)

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
	portFile := ipcPortFile()
	if err := writePortFile(portFile, []byte(fmt.Sprintf("%d", port))); err != nil {
		log.Printf("IPC API: could not write port file %s: %v", portFile, err)
	}

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
	LocalAccess   bool              `json:"local_access"`
	IPs           []string          `json:"ips"`
	PubKey        string            `json:"pubkey"`
	RxBytes       uint64            `json:"rx_bytes"`
	TxBytes       uint64            `json:"tx_bytes"`
	Peers         []device.PeerInfo `json:"peers"`
	// ExitNodeState details exit-node mode (both directions); ExitNode above
	// stays the "this device offers itself as exit" flag.
	ExitNodeState *device.ExitNodeStatus `json:"exit_node_state,omitempty"`

	Version        string `json:"version,omitempty"`
	Commit         string `json:"commit,omitempty"`
	ServerEndpoint string `json:"server_endpoint,omitempty"`
	StartedAt      int64  `json:"started_at,omitempty"`
	UptimeSec      int64  `json:"uptime_sec,omitempty"`
	AutoUpdate     bool   `json:"auto_update"`
}

// processStart approximates daemon start for uptime reporting.
var processStart = time.Now()

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
		LocalAccess:   s.agent.config.AllowLocalAccess,
		IPs:           ips,
		PubKey:        s.agent.device.GetPublicKey(),
		RxBytes:       rx,
		TxBytes:       tx,
		Peers:         s.agent.device.GetDetailedPeers(),

		Version:    version.Version,
		Commit:     version.Commit,
		StartedAt:  processStart.Unix(),
		UptimeSec:  int64(time.Since(processStart).Seconds()),
		AutoUpdate: s.agent.config.AutoUpdate,
	}
	exitState := s.agent.device.ExitStatus()
	status.ExitNode = exitState.Offering
	status.ExitNodeState = &exitState
	if srv := s.agent.config.Server; srv.Endpoint != "" {
		status.ServerEndpoint = srv.Endpoint
		if srv.Port > 0 {
			status.ServerEndpoint = net.JoinHostPort(srv.Endpoint, strconv.Itoa(srv.Port))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ConnectionResponse is returned by /api/connect, /api/disconnect and
// /api/state/toggle.
type ConnectionResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Connected bool   `json:"connected"`
}

func (s *APIServer) connectionReply(w http.ResponseWriter, err error) {
	resp := ConnectionResponse{OK: err == nil, Connected: s.agent.device.IsRunning()}
	code := http.StatusOK
	if err != nil {
		resp.Error = err.Error()
		code = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (s *APIServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.connectionReply(w, s.agent.Connect())
}

func (s *APIServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.connectionReply(w, s.agent.Disconnect())
}

// handleToggleState is the older tray's single button. It now requires the
// control header like every other state change, so a web page cannot drop
// the tunnel with a plain cross-site POST.
func (s *APIServer) handleToggleState(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if s.agent.device.IsRunning() {
		s.connectionReply(w, s.agent.Disconnect())
		return
	}
	s.connectionReply(w, s.agent.Connect())
}
