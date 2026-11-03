package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"wantastic-agent/internal/accounts"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/config"
)

// AccountsResponse answers /api/accounts and its actions.
type AccountsResponse struct {
	OK       bool               `json:"ok"`
	Error    string             `json:"error,omitempty"`
	Notice   string             `json:"notice,omitempty"`
	Accounts []accounts.Account `json:"accounts"`
	// Added is the account an add created, with the claim link to open.
	Added *accounts.Account `json:"added,omitempty"`
}

// accountSwitches carries the id of the account to switch to. The daemon's
// run loop stops the agent, makes that account active and starts again, so
// the running agent can never write its config over the new one.
var accountSwitches = make(chan string, 1)

// AccountSwitches delivers switch requests to the daemon's run loop.
func AccountSwitches() <-chan string { return accountSwitches }

// accountClaimWake starts the claim watcher after an add.
var accountClaimWake = make(chan struct{}, 1)

// accountClaimPoll is how often a pending account's claim is checked.
const accountClaimPoll = 10 * time.Second

func (a *Agent) accountStore() (*accounts.Store, error) {
	path := ""
	if a.config != nil {
		path = a.config.FilePath()
	}
	if path == "" {
		return nil, errors.New("accounts need a configuration file; this device has none")
	}
	return accounts.Open(path), nil
}

func (s *APIServer) accountsReply(w http.ResponseWriter, err error, notice string, added *accounts.Account) {
	resp := AccountsResponse{OK: err == nil, Notice: notice, Added: added, Accounts: []accounts.Account{}}
	if store, serr := s.agent.accountStore(); serr == nil {
		if list, lerr := store.List(); lerr == nil {
			resp.Accounts = list
		} else if err == nil {
			err = lerr
		}
	} else if err == nil {
		err = serr
	}
	code := http.StatusOK
	if err != nil {
		resp.OK, resp.Error = false, err.Error()
		code = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (s *APIServer) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.accountsReply(w, nil, "", nil)
}

// handleAccountAdd creates a key for another account and returns its claim
// link; the claim watcher finishes the account once it is claimed.
func (s *APIServer) handleAccountAdd(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	store, err := s.agent.accountStore()
	if err != nil {
		s.accountsReply(w, err, "", nil)
		return
	}
	server := auth.NormalizeServerURL(r.URL.Query().Get("server"))
	host, _ := os.Hostname()
	acct, _, err := store.Add(r.URL.Query().Get("name"), server, func(pub string) string {
		return auth.BuildClaimURL(server, pub, host)
	})
	if err != nil {
		s.accountsReply(w, err, "", nil)
		return
	}
	select {
	case accountClaimWake <- struct{}{}:
	default:
	}
	s.accountsReply(w, nil, "Open the link in the account to add this device to", &acct)
}

func (s *APIServer) handleAccountUse(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	store, err := s.agent.accountStore()
	if err != nil {
		s.accountsReply(w, err, "", nil)
		return
	}
	want := r.URL.Query().Get("id")
	list, err := store.List()
	if err != nil {
		s.accountsReply(w, err, "", nil)
		return
	}
	for _, acct := range list {
		if acct.ID != want && !strings.EqualFold(acct.Name, want) {
			continue
		}
		switch {
		case acct.Active:
			s.accountsReply(w, nil, acct.Name+" is already active", nil)
		case acct.Pending:
			s.accountsReply(w, errors.New(acct.Name+" is not claimed yet: open its claim link first"), "", nil)
		default:
			select {
			case accountSwitches <- acct.ID:
				s.accountsReply(w, nil, "Switching to "+acct.Name+"…", nil)
			default:
				s.accountsReply(w, errors.New("a switch is already running"), "", nil)
			}
		}
		return
	}
	s.accountsReply(w, accounts.ErrNotFound, "", nil)
}

func (s *APIServer) handleAccountRemove(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	store, err := s.agent.accountStore()
	if err == nil {
		err = store.Remove(r.URL.Query().Get("id"))
	}
	s.accountsReply(w, err, "Account removed from this device; remove the device in that account's console too", nil)
}

func (s *APIServer) handleAccountRename(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	store, err := s.agent.accountStore()
	if err == nil {
		err = store.Rename(r.URL.Query().Get("id"), r.URL.Query().Get("name"))
	}
	s.accountsReply(w, err, "Account renamed", nil)
}

// runAccountClaims finishes accounts added on this device once they are
// claimed. It sleeps until an add (or a pending account left from before a
// restart) gives it something to wait for.
func (a *Agent) runAccountClaims(ctx context.Context) {
	defer a.wg.Done()
	store, err := a.accountStore()
	if err != nil {
		return
	}
	for {
		pending, _ := store.Pending()
		if len(pending) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-accountClaimWake:
				continue
			}
		}
		for _, key := range pending {
			a.checkAccountClaim(ctx, store, key)
		}
		select {
		case <-ctx.Done():
			return
		case <-accountClaimWake:
		case <-time.After(accountClaimPoll):
		}
	}
}

func (a *Agent) checkAccountClaim(ctx context.Context, store *accounts.Store, key accounts.PendingKey) {
	deviceID, err := auth.HashedDeviceID()
	if err != nil {
		return
	}
	pollCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	claim, err := auth.FetchClaimConfig(pollCtx, key.ServerURL, deviceID, key.PublicKey)
	if err != nil || claim == nil || !claim.Claimed {
		return
	}
	cfg, err := config.LoadFromClaimConfig(key.ServerURL, key.PrivateKey, key.PublicKey, claim)
	if err != nil {
		log.Printf("Accounts: claim of %s found but its config is not ready: %v", key.ID, err)
		return
	}
	// The new account connects the way this device does today.
	cfg.Interface.TUNMode = a.config.Interface.TUNMode
	cfg.Interface.TUNName = a.config.Interface.TUNName
	cfg.AutoUpdate = a.config.AutoUpdate
	if err := store.Complete(key.ID, cfg); err != nil {
		log.Printf("Accounts: save claimed account %s: %v", key.ID, err)
		return
	}
	log.Printf("Accounts: account %s claimed; switch to it from the menu or with: wantasticd account use %s", key.ID, key.ID)
}
