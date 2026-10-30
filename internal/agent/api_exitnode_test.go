package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExitNodeEndpointsRequireControlHeader(t *testing.T) {
	s := &APIServer{}
	for _, h := range []func(http.ResponseWriter, *http.Request){s.handleExitNodeOffer, s.handleExitNodeJumpTo, s.handleExitNodeComeback, s.handleToggleExitNode, s.handleSetExitNode, s.handleToggleState, s.handleConnect, s.handleDisconnect} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodPost, "/x?enabled=on", nil),              // no header (CSRF)
			withHeader(httptest.NewRequest(http.MethodGet, "/x?enabled=on", nil)),   // GET
			withOrigin(withHeader(httptest.NewRequest(http.MethodPost, "/x", nil))), // browser origin
		} {
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %v: code %d", req.Method, req.Header, rec.Code)
			}
		}
	}
	if !controlAllowed(withHeader(httptest.NewRequest(http.MethodPost, "/x", nil))) {
		t.Fatal("CLI request refused")
	}
}

func withHeader(r *http.Request) *http.Request { r.Header.Set(ControlHeader, "1"); return r }
func withOrigin(r *http.Request) *http.Request {
	r.Header.Set("Origin", "https://evil.example")
	return r
}
