package agent

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/device"
)

// ControlHeader must accompany every state-changing exit-node request. A
// browser page cannot add it to a cross-origin request without a CORS
// preflight this server never answers, so websites cannot drive the daemon.
const ControlHeader = "X-Wantastic-Control"

// ExitNodeResponse is returned by the exit-node endpoints.
type ExitNodeResponse struct {
	OK     bool                  `json:"ok"`
	Error  string                `json:"error,omitempty"`
	Notice string                `json:"notice,omitempty"`
	State  device.ExitNodeStatus `json:"state"`
}

func controlAllowed(r *http.Request) bool {
	return r.Method == http.MethodPost && r.Header.Get(ControlHeader) == "1" && r.Header.Get("Origin") == ""
}

func (s *APIServer) exitReply(w http.ResponseWriter, code int, err error, notice string) {
	resp := ExitNodeResponse{OK: err == nil, Notice: notice, State: s.agent.device.ExitStatus()}
	if err != nil {
		resp.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (s *APIServer) guard(w http.ResponseWriter, r *http.Request) bool {
	if !controlAllowed(r) {
		http.Error(w, "forbidden: POST with "+ControlHeader+": 1 required", http.StatusForbidden)
		return false
	}
	return true
}

func (s *APIServer) handleExitNodeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.exitReply(w, http.StatusOK, nil, "")
}

func parseBool(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true, true
	case "0", "off", "false", "no":
		return false, true
	}
	return false, false
}

func (s *APIServer) handleExitNodeOffer(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	on, ok := parseBool(r.URL.Query().Get("enabled"))
	if !ok {
		http.Error(w, "enabled=on|off required", http.StatusBadRequest)
		return
	}
	log.Printf("[API] Exit-node sharing %v requested via IPC", on)
	err := s.agent.device.SetExitOffer(on)
	code := http.StatusOK
	if err != nil {
		code = http.StatusConflict
	}
	s.exitReply(w, code, err, "")
}

func (s *APIServer) handleExitNodeJumpTo(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	target := r.URL.Query().Get("ip")
	wait := 12 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 && ms <= 30000 {
			wait = time.Duration(ms) * time.Millisecond
		}
	}
	log.Printf("[API] Exit node %q requested via IPC", target)
	use, err := s.agent.device.UseExitNode(target, wait)
	if err != nil {
		s.exitReply(w, http.StatusConflict, err, "")
		return
	}
	notice := ""
	if use != nil && use.State != "active" && use.Reason != "" {
		notice = use.Reason
	}
	s.exitReply(w, http.StatusOK, nil, notice)
}

func (s *APIServer) handleExitNodeComeback(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	log.Printf("[API] Exit node release requested via IPC")
	err := s.agent.device.ClearExitNode()
	code := http.StatusOK
	if err != nil {
		code = http.StatusConflict
	}
	s.exitReply(w, code, err, "")
}

// Legacy tray endpoints, kept for older menus.

func (s *APIServer) handleToggleExitNode(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	on := !s.agent.device.ExitStatus().Offering
	err := s.agent.device.SetExitOffer(on)
	code := http.StatusOK
	if err != nil {
		code = http.StatusConflict
	}
	s.exitReply(w, code, err, "")
}

func (s *APIServer) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	peer := strings.TrimSpace(r.URL.Query().Get("peer"))
	if peer == "" || strings.EqualFold(peer, "none") {
		s.handleExitNodeComeback(w, r)
		return
	}
	for _, c := range s.agent.device.ExitStatus().Candidates {
		if strings.EqualFold(c.PublicKey, peer) {
			_, err := s.agent.device.UseExitNode(c.IP, 0)
			code := http.StatusOK
			if err != nil {
				code = http.StatusConflict
			}
			s.exitReply(w, code, err, "")
			return
		}
	}
	http.Error(w, "unknown peer", http.StatusNotFound)
}
