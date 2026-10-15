package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/device"
)

// APIServer represents the local IPC server for the systray and CLI
type APIServer struct {
	agent      *Agent
	server     *http.Server
	token      string
	tokenError error
}

// NewAPIServer creates a new API Server instance
func NewAPIServer(a *Agent) *APIServer {
	mux := http.NewServeMux()
	s := &APIServer{
		agent: a,
	}
	s.token, s.tokenError = readConfiguredIPCToken()
	if s.tokenError == nil && s.token == "" {
		var tokenBytes [32]byte
		if _, err := rand.Read(tokenBytes[:]); err != nil {
			s.tokenError = fmt.Errorf("generate IPC credential: %w", err)
		} else {
			s.token = hex.EncodeToString(tokenBytes[:])
			if err := os.Setenv("WTC_IPC_TOKEN", s.token); err != nil {
				s.tokenError = fmt.Errorf("publish process IPC credential: %w", err)
			}
		}
	}

	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/state/toggle", s.handleToggleState)
	mux.HandleFunc("/api/shutdown", s.handleShutdown)
	mux.HandleFunc("/api/exitnode/toggle", s.handleToggleExitNode)
	mux.HandleFunc("/api/exitnode/offer", s.handleSetExitNodeOffer)
	mux.HandleFunc("/api/exitnode/offer/runtime", s.handleSetExitNodeOfferRuntime)
	mux.HandleFunc("/api/exitnode/use", s.handleSetExitNode)

	s.server = &http.Server{
		Addr:              "127.0.0.1:9034",
		Handler:           s.authorize(mux),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	return s
}

// Start begins serving the local IPC API
func (s *APIServer) Start() error {
	if s.tokenError != nil {
		return fmt.Errorf("configure IPC authentication: %w", s.tokenError)
	}
	port := 9034
	customPort := strings.TrimSpace(os.Getenv("WTC_IPC_PORT"))

	// Support dynamic IPC ports via WTC_IPC_PORT env to avoid conflicts in localized e2e
	if customPort != "" {
		parsed, ok := validIPCPort(customPort)
		if !ok {
			return fmt.Errorf("invalid WTC_IPC_PORT %q", customPort)
		}
		port, _ = strconv.Atoi(parsed)
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
		return fmt.Errorf("IPC API: failed to bind a loopback port: %w", err)
	}

	// Share selected port for local tray & cli clients
	os.Setenv("WTC_IPC_PORT", fmt.Sprintf("%d", port))
	if customPort == "" {
		if err := writeIPCPortFile(port, s.token); err != nil {
			log.Printf("IPC API Warning: could not publish discovery port: %v", err)
		}
	}

	log.Printf("Starting local IPC API on %s", s.server.Addr)

	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("IPC API HTTP Error: %v", err)
		}
	}()
	return nil
}

func (s *APIServer) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || host != "127.0.0.1" {
			http.Error(w, "loopback host required", http.StatusForbidden)
			return
		}
		if s.token != "" {
			authorization := r.Header.Get("Authorization")
			if !strings.HasPrefix(authorization, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			provided := strings.TrimPrefix(authorization, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeIPCPortFile(port int, token string) error {
	path := ipcPortFile()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink at %s", path)
	}
	payload, err := json.Marshal(ipcDiscovery{Port: port, Token: token})
	if err != nil {
		return err
	}
	payload, err = protectIPCDiscovery(payload)
	if err != nil {
		return fmt.Errorf("protect IPC discovery: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".ipc-port-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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
	MagicDNS      bool              `json:"magic_dns"`
	ExitNode      bool              `json:"exit_node"`
	LocalAccess   bool              `json:"local_access"`
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
		MagicDNS:      s.agent.MagicDNSActive(),
		ExitNode:      s.agent.config.ExitNode.Enabled,
		LocalAccess:   s.agent.config.AllowLocalAccess,
		IPs:           ips,
		PubKey:        s.agent.device.GetPublicKey(),
		RxBytes:       rx,
		TxBytes:       tx,
		Peers:         s.agent.device.GetDetailedPeers(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *APIServer) handleToggleState(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
		return
	}

	log.Println("[API] VPN State toggle requested via IPC")
	var err error
	if s.agent.device.IsRunning() {
		err = s.agent.device.Stop()
	} else {
		err = s.agent.device.Start()
	}
	if err != nil {
		http.Error(w, "could not toggle VPN state", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "{\"status\":\"toggled\"}")
}

func (s *APIServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, "{\"status\":\"stopping\"}")
	s.agent.requestShutdown()
}

func (s *APIServer) handleToggleExitNode(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
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

func (s *APIServer) handleSetExitNodeOffer(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
		return
	}
	enabled, err := strconv.ParseBool(r.URL.Query().Get("enabled"))
	if err != nil {
		http.Error(w, "enabled must be true or false", http.StatusBadRequest)
		return
	}
	if err := s.agent.SetOfferExitNode(enabled); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"enabled\":%t}", enabled)
}

func (s *APIServer) handleSetExitNodeOfferRuntime(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
		return
	}
	enabled, err := strconv.ParseBool(r.URL.Query().Get("enabled"))
	if err != nil {
		http.Error(w, "enabled must be true or false", http.StatusBadRequest)
		return
	}
	s.agent.SetOfferExitNodeRuntime(enabled)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"enabled\":%t}", enabled)
}

func (s *APIServer) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	if !allowLocalMutation(w, r) {
		return
	}

	peerPubKey := r.URL.Query().Get("peer")
	log.Printf("[API] Exit Node set requested via IPC to peer: %s", peerPubKey)

	if err := s.agent.SetExitNode(peerPubKey); err != nil {
		log.Printf("[API] Failed to set exit node routing: %v", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"status\":\"requested\"}")
}

func allowLocalMutation(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	// Native clients do not send Origin. Reject browser-originated requests so
	// an arbitrary website cannot toggle a loopback-bound VPN service via CSRF.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "browser-originated IPC is not allowed", http.StatusForbidden)
		return false
	}
	return true
}
