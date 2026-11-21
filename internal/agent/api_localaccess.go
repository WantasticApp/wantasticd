package agent

import (
	"log"
	"net/http"
)

// handleLocalAccess turns sharing this device's LANs on or off:
// POST /api/localaccess?enabled=on|off.
func (s *APIServer) handleLocalAccess(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	on, ok := parseBool(r.URL.Query().Get("enabled"))
	if !ok {
		http.Error(w, "enabled=on|off required", http.StatusBadRequest)
		return
	}
	log.Printf("[API] Local access %v requested via IPC", on)
	code := http.StatusOK
	err := s.agent.SetLocalAccess(on)
	if err != nil {
		code = http.StatusConflict
	}
	s.exitReply(w, code, err, "")
}
