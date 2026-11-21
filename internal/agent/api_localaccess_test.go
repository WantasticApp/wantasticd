package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalAccessEndpointNeedsOnOrOff(t *testing.T) {
	s := &APIServer{}
	for _, q := range []string{"", "?enabled=maybe"} {
		rec := httptest.NewRecorder()
		s.handleLocalAccess(rec, withHeader(httptest.NewRequest(http.MethodPost, "/api/localaccess"+q, nil)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: code %d, want 400", q, rec.Code)
		}
	}
}
