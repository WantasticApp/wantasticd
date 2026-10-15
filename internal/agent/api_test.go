package agent

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/config"
)

func TestHandleSetExitNodeOfferRuntime(t *testing.T) {
	t.Parallel()
	agt := &Agent{config: &config.Config{}}
	server := &APIServer{agent: agt}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/exitnode/offer/runtime?enabled=true", nil)
	response := httptest.NewRecorder()

	server.handleSetExitNodeOfferRuntime(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !agt.config.ExitNode.Enabled {
		t.Fatal("runtime exit-node offer was not applied")
	}
}

func TestHandleSetLocalAccessRuntimeRejectsOverlayRoute(t *testing.T) {
	t.Parallel()
	agt := &Agent{
		config: &config.Config{
			Server: config.Server{AllowedIPs: []string{"10.255.255.32/27"}},
		},
		localAccessWake: make(chan struct{}, 1),
	}
	server := &APIServer{agent: agt}
	req := httptest.NewRequest(
		http.MethodPost,
		"http://127.0.0.1/api/local-access/runtime?enabled=true&route=10.255.255.36%2F32",
		nil,
	)
	response := httptest.NewRecorder()

	server.handleSetLocalAccessRuntime(response, req)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusConflict)
	}
	if body := response.Body.String(); !strings.Contains(body, "overlaps tenant overlay") {
		t.Fatalf("response = %q, want overlay separation error", body)
	}
}

func TestAllowLocalMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		origin string
		want   bool
		code   int
	}{
		{name: "native post", method: http.MethodPost, want: true, code: http.StatusOK},
		{name: "browser post", method: http.MethodPost, origin: "https://example.com", want: false, code: http.StatusForbidden},
		{name: "get", method: http.MethodGet, want: false, code: http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tt.method, "http://127.0.0.1/api/state/toggle", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			response := httptest.NewRecorder()
			if got := allowLocalMutation(response, req); got != tt.want {
				t.Fatalf("allowLocalMutation() = %v, want %v", got, tt.want)
			}
			if response.Code != tt.code {
				t.Fatalf("status = %d, want %d", response.Code, tt.code)
			}
		})
	}
}

func TestHandleShutdown(t *testing.T) {
	t.Parallel()
	agt := &Agent{shutdownCh: make(chan struct{})}
	server := &APIServer{agent: agt}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/shutdown", nil)
	response := httptest.NewRecorder()

	server.handleShutdown(response, req)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	select {
	case <-agt.ShutdownRequested():
	default:
		t.Fatal("shutdown request was not delivered")
	}
}

func TestIPCAuthorization(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	s := &APIServer{token: token}
	handler := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name string
		host string
		auth string
		code int
	}{
		{name: "valid", host: "127.0.0.1:9034", auth: "Bearer " + token, code: http.StatusNoContent},
		{name: "missing token", host: "127.0.0.1:9034", code: http.StatusUnauthorized},
		{name: "wrong scheme", host: "127.0.0.1:9034", auth: "Basic " + token, code: http.StatusUnauthorized},
		{name: "wrong host", host: "attacker.example:9034", auth: "Bearer " + token, code: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9034/api/status", nil)
			req.Host = tt.host
			req.Header.Set("Authorization", tt.auth)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tt.code {
				t.Fatalf("status = %d, want %d", response.Code, tt.code)
			}
		})
	}
}

func TestNewAPIServerGeneratesProcessCredential(t *testing.T) {
	t.Setenv("WTC_IPC_TOKEN", "")
	t.Setenv("WTC_IPC_TOKEN_FILE", "")
	s := NewAPIServer(nil)
	if s.tokenError != nil {
		t.Fatalf("NewAPIServer() token error = %v", s.tokenError)
	}
	if len(s.token) != 64 {
		t.Fatalf("generated token length = %d, want 64", len(s.token))
	}
	if os.Getenv("WTC_IPC_TOKEN") != s.token {
		t.Fatal("generated token was not scoped to the current process")
	}
}

func TestReadIPCTokenRejectsLoosePermissions(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permission test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WTC_IPC_TOKEN", "")
	t.Setenv("WTC_IPC_TOKEN_FILE", path)
	if _, err := readIPCToken(); err == nil {
		t.Fatal("readIPCToken() accepted a group/world-readable token file")
	}
}

func TestValidIPCPort(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: " 9091\n", want: "9091", ok: true},
		{raw: "1023", ok: false},
		{raw: "65536", ok: false},
		{raw: "9091/path", ok: false},
	}
	for _, tt := range tests {
		got, ok := validIPCPort(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("validIPCPort(%q) = %q, %t; want %q, %t", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

func TestIPCDiscoveryRoundTrip(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	path := filepath.Join(t.TempDir(), "ipc-discovery")
	t.Setenv("WTC_IPC_PORT", "")
	t.Setenv("WTC_IPC_PORT_FILE", path)
	t.Setenv("WTC_IPC_TOKEN", "")
	t.Setenv("WTC_IPC_TOKEN_FILE", "")
	if err := writeIPCPortFile(9091, token); err != nil {
		t.Fatalf("writeIPCPortFile() error = %v", err)
	}
	if got := GetIPCPort(); got != "9091" {
		t.Fatalf("GetIPCPort() = %q, want 9091", got)
	}
	got, err := readIPCToken()
	if err != nil {
		t.Fatalf("readIPCToken() error = %v", err)
	}
	if got != token {
		t.Fatal("readIPCToken() did not return the discovery credential")
	}
}
