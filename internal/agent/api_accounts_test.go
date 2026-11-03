package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"wantastic-agent/internal/config"
)

func TestAccountEndpointsRequireControlHeader(t *testing.T) {
	s := &APIServer{agent: &Agent{}}
	for _, h := range []func(http.ResponseWriter, *http.Request){s.handleAccountAdd, s.handleAccountUse, s.handleAccountRemove, s.handleAccountRename} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/x?id=a", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code %d without the control header", rec.Code)
		}
	}
}

func TestAccountAddAndSwitchRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	// Keys are made per run: none is stored in the repository.
	randKey := func() string {
		b := make([]byte, 32)
		rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	data := `{"private_key":"` + randKey() + `","server":{"endpoint":"192.0.2.1","public_key":"` + randKey() + `"},"interface":{"addresses":["10.0.0.5/32"]}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &APIServer{agent: &Agent{config: cfg}}

	rec := httptest.NewRecorder()
	s.handleAccountAdd(rec, withHeader(httptest.NewRequest(http.MethodPost, "/api/accounts/add?name=Work", nil)))
	var resp AccountsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.OK || resp.Added == nil || len(resp.Accounts) != 2 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if !resp.Accounts[0].Active || resp.Accounts[0].Address != "10.0.0.5" || !resp.Accounts[1].Pending || resp.Added.ClaimURL == "" {
		t.Fatalf("accounts after add: %+v", resp.Accounts)
	}

	// A pending account cannot be switched to; the active one is a no-op.
	for _, id := range []string{"Work", resp.Accounts[0].ID} {
		rec = httptest.NewRecorder()
		s.handleAccountUse(rec, withHeader(httptest.NewRequest(http.MethodPost, "/api/accounts/use?id="+id, nil)))
		select {
		case got := <-accountSwitches:
			t.Fatalf("switch to %s requested for %q", got, id)
		default:
		}
	}
}
