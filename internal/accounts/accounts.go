// Package accounts keeps one device in several Wantastic accounts. The hub
// knows a device by its WireGuard public key only, so each account gets its
// own key and its own claimed configuration; switching makes another one
// the active configuration the daemon connects with.
//
// Layout, next to the active config (config.conf):
//
//	accounts/index.json   names and order
//	accounts/<id>.conf    each account's configuration
//	accounts/<id>.key     a pending account's key, until it is claimed
package accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"wantastic-agent/internal/config"
)

// Account is one entry as the CLI and the tray show it.
type Account struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Address string `json:"address,omitempty"`
	// Pending accounts wait to be claimed with ClaimURL.
	Pending  bool   `json:"pending,omitempty"`
	ClaimURL string `json:"claim_url,omitempty"`
}

type entry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	ServerURL string `json:"server_url,omitempty"`
	ClaimURL  string `json:"claim_url,omitempty"`
	Pending   bool   `json:"pending,omitempty"`
	AddedAt   string `json:"added_at,omitempty"`
}

type index struct {
	Accounts []entry `json:"accounts"`
}

// PendingKey is a pending account's key pair and server.
type PendingKey struct {
	ID         string `json:"id"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ServerURL  string `json:"server_url"`
}

// ErrNotFound is returned for an unknown account id or name.
var ErrNotFound = errors.New("no such account")

// Store is the account list for the config at ConfigPath. Methods are safe
// for concurrent use within one process.
type Store struct {
	ConfigPath string
	dir        string
	mu         sync.Mutex
}

// Open returns the store kept beside configPath.
func Open(configPath string) *Store {
	return &Store{ConfigPath: configPath, dir: filepath.Join(filepath.Dir(configPath), "accounts")}
}

// ID is the account id for a public key: short, stable, not secret.
func ID(publicKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return hex.EncodeToString(sum[:])[:8]
}

// List returns every account, the active one marked. The active config is
// added to the list the first time it is seen.
func (s *Store) List() ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, active, err := s.syncActiveLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(idx.Accounts))
	for _, e := range idx.Accounts {
		a := Account{ID: e.ID, Name: e.Name, Active: active != nil && e.PublicKey == active.publicKey, Pending: e.Pending}
		switch {
		case e.Pending:
			a.ClaimURL = e.ClaimURL
		case a.Active:
			a.Address = active.address
		default:
			if data, err := os.ReadFile(s.confPath(e.ID)); err == nil {
				a.Address = inspect(data).address
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// Add creates a key for a new account and returns its pending entry; the
// caller shows ClaimURL, waits for the claim and calls Complete.
func (s *Store) Add(name, serverURL string, claimURL func(publicKey string) string) (Account, PendingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, _, err := s.syncActiveLocked()
	if err != nil {
		return Account{}, PendingKey{}, err
	}
	priv, pub, err := newKeyPair()
	if err != nil {
		return Account{}, PendingKey{}, err
	}
	key := PendingKey{ID: ID(pub), PrivateKey: priv, PublicKey: pub, ServerURL: serverURL}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("Account %d", len(idx.Accounts)+1)
	}
	e := entry{ID: key.ID, Name: cleanName(name), PublicKey: pub, ServerURL: serverURL, ClaimURL: claimURL(pub), Pending: true, AddedAt: time.Now().UTC().Format(time.RFC3339)}
	data, err := json.Marshal(key)
	if err != nil {
		return Account{}, PendingKey{}, err
	}
	if err := writeAtomic(s.keyPath(key.ID), data); err != nil {
		return Account{}, PendingKey{}, err
	}
	idx.Accounts = append(idx.Accounts, e)
	if err := s.saveIndexLocked(idx); err != nil {
		return Account{}, PendingKey{}, err
	}
	return Account{ID: e.ID, Name: e.Name, Pending: true, ClaimURL: e.ClaimURL}, key, nil
}

// Pending returns the keys of accounts still waiting for their claim.
func (s *Store) Pending() ([]PendingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, err := s.loadIndexLocked()
	if err != nil {
		return nil, err
	}
	var out []PendingKey
	for _, e := range idx.Accounts {
		if !e.Pending {
			continue
		}
		data, err := os.ReadFile(s.keyPath(e.ID))
		if err != nil {
			continue
		}
		var k PendingKey
		if json.Unmarshal(data, &k) == nil && k.PrivateKey != "" {
			out = append(out, k)
		}
	}
	return out, nil
}

// Complete stores the claimed configuration of a pending account.
func (s *Store) Complete(id string, cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, err := s.loadIndexLocked()
	if err != nil {
		return err
	}
	i := findLocked(idx, id)
	if i < 0 || !idx.Accounts[i].Pending {
		return ErrNotFound
	}
	if err := saveConfig(cfg, s.confPath(id)); err != nil {
		return err
	}
	idx.Accounts[i].Pending = false
	idx.Accounts[i].ClaimURL = ""
	if err := s.saveIndexLocked(idx); err != nil {
		return err
	}
	_ = os.Remove(s.keyPath(id))
	return nil
}

// Use makes the account id (or name) the active configuration. The current
// active configuration is saved back to its own entry first, so settings
// changed while it was active are kept. It returns the account switched to.
func (s *Store) Use(idOrName string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, active, err := s.syncActiveLocked()
	if err != nil {
		return Account{}, err
	}
	i := findLocked(idx, idOrName)
	if i < 0 {
		return Account{}, ErrNotFound
	}
	target := idx.Accounts[i]
	if target.Pending {
		return Account{}, errors.New("that account is not claimed yet: open its claim link first")
	}
	if active != nil && active.publicKey == target.PublicKey {
		return Account{ID: target.ID, Name: target.Name, Active: true}, nil
	}
	next, err := os.ReadFile(s.confPath(target.ID))
	if err != nil {
		return Account{}, fmt.Errorf("read %s: %w", target.Name, err)
	}
	if inspect(next).publicKey != target.PublicKey {
		return Account{}, fmt.Errorf("the saved configuration of %s is damaged", target.Name)
	}
	if active != nil {
		if err := writeAtomic(s.confPath(ID(active.publicKey)), active.data); err != nil {
			return Account{}, fmt.Errorf("save the current account: %w", err)
		}
	}
	if err := writeAtomic(s.ConfigPath, next); err != nil {
		return Account{}, err
	}
	return Account{ID: target.ID, Name: target.Name, Active: true}, nil
}

// Rename changes an account's name.
func (s *Store) Rename(idOrName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, _, err := s.syncActiveLocked()
	if err != nil {
		return err
	}
	i := findLocked(idx, idOrName)
	if i < 0 {
		return ErrNotFound
	}
	if name = cleanName(name); name == "" {
		return errors.New("the name is empty")
	}
	idx.Accounts[i].Name = name
	return s.saveIndexLocked(idx)
}

// Remove forgets an account on this device. The active account cannot be
// removed; switch first. The device stays listed in that account's console
// until it is removed there.
func (s *Store) Remove(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, active, err := s.syncActiveLocked()
	if err != nil {
		return err
	}
	i := findLocked(idx, idOrName)
	if i < 0 {
		return ErrNotFound
	}
	e := idx.Accounts[i]
	if active != nil && e.PublicKey == active.publicKey {
		return errors.New("that is the active account: switch to another one first")
	}
	idx.Accounts = append(idx.Accounts[:i], idx.Accounts[i+1:]...)
	if err := s.saveIndexLocked(idx); err != nil {
		return err
	}
	_ = os.Remove(s.confPath(e.ID))
	_ = os.Remove(s.keyPath(e.ID))
	return nil
}

// syncActiveLocked loads the index and makes sure the active config has an
// entry (the first account, from before accounts existed, gets one here).
func (s *Store) syncActiveLocked() (*index, *activeConfig, error) {
	idx, err := s.loadIndexLocked()
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		return idx, nil, nil
	}
	parsed := inspect(data)
	active := &parsed
	if active.publicKey == "" {
		return idx, nil, nil
	}
	active.data = data
	id := ID(active.publicKey)
	if findLocked(idx, id) >= 0 {
		return idx, active, nil
	}
	name := "Account 1"
	if len(idx.Accounts) > 0 {
		name = fmt.Sprintf("Account %d", len(idx.Accounts)+1)
	}
	idx.Accounts = append([]entry{{ID: id, Name: name, PublicKey: active.publicKey, AddedAt: time.Now().UTC().Format(time.RFC3339)}}, idx.Accounts...)
	if err := writeAtomic(s.confPath(id), data); err != nil {
		return nil, nil, err
	}
	if err := s.saveIndexLocked(idx); err != nil {
		return nil, nil, err
	}
	return idx, active, nil
}

func findLocked(idx *index, idOrName string) int {
	key := strings.TrimSpace(idOrName)
	for i, e := range idx.Accounts {
		if e.ID == key {
			return i
		}
	}
	for i, e := range idx.Accounts {
		if strings.EqualFold(e.Name, key) {
			return i
		}
	}
	return -1
}

func (s *Store) loadIndexLocked() (*index, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &index{}, nil
	}
	if err != nil {
		return nil, err
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Join(s.dir, "index.json"), err)
	}
	return &idx, nil
}

func (s *Store) saveIndexLocked(idx *index) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, "index.json"), data)
}

func (s *Store) confPath(id string) string { return filepath.Join(s.dir, id+".conf") }
func (s *Store) keyPath(id string) string  { return filepath.Join(s.dir, id+".key") }

// activeConfig is a configuration file as read, never re-encoded: copies
// stay byte for byte what the agent wrote.
type activeConfig struct {
	data      []byte
	publicKey string
	address   string
}

// inspect finds a config's identity without loading it: config.LoadFromFile
// resolves and rewrites the server endpoint. Both the JSON config and the
// WireGuard INI form are read; the public key comes from the private key.
func inspect(data []byte) activeConfig {
	var c activeConfig
	var js struct {
		PrivateKey string `json:"private_key"`
		Interface  struct {
			Addresses []string `json:"addresses"`
		} `json:"interface"`
	}
	priv := ""
	if json.Unmarshal(data, &js) == nil {
		priv = js.PrivateKey
		if len(js.Interface.Addresses) > 0 {
			c.address = strings.SplitN(js.Interface.Addresses[0], "/", 2)[0]
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "privatekey":
				priv = strings.TrimSpace(v)
			case "address":
				if c.address == "" {
					c.address = strings.SplitN(strings.TrimSpace(strings.Split(v, ",")[0]), "/", 2)[0]
				}
			}
		}
	}
	c.publicKey = publicKeyOf(priv)
	return c
}

func publicKeyOf(privateKey string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func saveConfig(cfg *config.Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// writeAtomic writes data (mode 0600: configs hold private keys) so a crash
// never leaves a half-written file.
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

func cleanName(name string) string {
	name = strings.Join(strings.Fields(strings.ToValidUTF8(name, "")), " ")
	if len(name) > 48 {
		name = strings.ToValidUTF8(name[:48], "")
	}
	return name
}

func newKeyPair() (privateKey, publicKey string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}
