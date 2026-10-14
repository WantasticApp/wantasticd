package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
