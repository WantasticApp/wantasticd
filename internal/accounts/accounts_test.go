package accounts

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"wantastic-agent/internal/config"
)

// keys maps a test name to a real key pair: accounts are told apart by the
// public key derived from the private key.
var keys = map[string][2]string{}

func key(t *testing.T, name string) (priv, pub string) {
	t.Helper()
	if k, ok := keys[name]; ok {
		return k[0], k[1]
	}
	priv, pub, err := newKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys[name] = [2]string{priv, pub}
	return priv, pub
}

func writeActive(t *testing.T, path, name, addr string) {
	t.Helper()
	priv, pub := key(t, name)
	cfg := &config.Config{PublicKey: pub, PrivateKey: priv}
	cfg.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix(addr + "/32")}
	if err := saveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
}

func TestAddClaimSwitchRemove(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "config.conf")
	writeActive(t, active, "keyA", "10.0.0.1")
	s := Open(active)

	list, err := s.List()
	if err != nil || len(list) != 1 || !list[0].Active || list[0].Name != "Account 1" || list[0].Address != "10.0.0.1" {
		t.Fatalf("first list = %+v, %v", list, err)
	}

	acct, pk, err := s.Add("Work", "https://console.wantastic.app", func(pub string) string { return "https://claim/" + pub })
	if err != nil || !acct.Pending || acct.ClaimURL != "https://claim/"+pk.PublicKey || acct.Name != "Work" {
		t.Fatalf("add = %+v, %v", acct, err)
	}
	if _, err := s.Use("Work"); err == nil {
		t.Fatal("switched to an unclaimed account")
	}
	pending, _ := s.Pending()
	if len(pending) != 1 || pending[0].PublicKey != pk.PublicKey {
		t.Fatalf("pending = %+v", pending)
	}

	claimed := &config.Config{PublicKey: pk.PublicKey, PrivateKey: pk.PrivateKey}
	claimed.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix("10.9.0.7/32")}
	if err := s.Complete(acct.ID, claimed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.keyPath(acct.ID)); !os.IsNotExist(err) {
		t.Fatal("pending key left behind after the claim")
	}

	// Settings changed on the active account survive a switch away and back.
	writeActive(t, active, "keyA", "10.0.0.2")
	if got, err := s.Use("work"); err != nil || got.ID != acct.ID {
		t.Fatalf("use = %+v, %v", got, err)
	}
	if data, _ := os.ReadFile(active); inspect(data).publicKey != pk.PublicKey {
		t.Fatal("the switch did not make Work active")
	}
	if err := s.Remove(acct.ID); err == nil {
		t.Fatal("removed the active account")
	}
	if _, err := s.Use("Account 1"); err != nil {
		t.Fatal(err)
	}
	_, pubA := key(t, "keyA")
	if data, _ := os.ReadFile(active); inspect(data).publicKey != pubA || inspect(data).address != "10.0.0.2" {
		t.Fatalf("back on account 1: %s", data)
	}
	if err := s.Rename("Work", "  Office   VPN "); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("Office VPN"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(); len(list) != 1 || list[0].ID != ID(pubA) {
		t.Fatalf("after remove: %+v", list)
	}
	if fi, err := os.Stat(s.confPath(ID(pubA))); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("account file mode: %v %v", fi, err)
	}
}

func TestUseUnknown(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "config.conf"))
	if _, err := s.Use("nope"); err != ErrNotFound {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectINI(t *testing.T) {
	priv, pub := key(t, "ini")
	got := inspect([]byte("[Interface]\nPrivateKey = " + priv + "\nAddress = 10.1.2.3/32, fd00::1/128\n"))
	if got.publicKey != pub || got.address != "10.1.2.3" {
		t.Fatalf("inspect = %+v", got)
	}
}
