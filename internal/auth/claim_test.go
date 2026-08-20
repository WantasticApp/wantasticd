package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestClaimWaitURLUsesWebsocketScheme(t *testing.T) {
	got, err := claimWaitURL("https://console.wantastic.app/base/", "pub key+1")
	if err != nil {
		t.Fatalf("claimWaitURL returned error: %v", err)
	}
	want := "wss://console.wantastic.app/api/agent/claim-wait?public_key=pub+key%2B1"
	if got != want {
		t.Fatalf("claimWaitURL=%q want %q", got, want)
	}
}

func TestClaimWaitMessageAcceptsNestedAndFlatClaim(t *testing.T) {
	nested := claimWaitMessage{
		Claim: &ClaimConfig{
			Claimed:    true,
			PublicKey:  "nested-key",
			AssignedIP: "10.255.255.40",
		},
	}
	if claim := nested.claimConfig(); claim == nil || claim.PublicKey != "nested-key" || claim.AssignedIP != "10.255.255.40" {
		t.Fatalf("nested claimConfig=%#v", claim)
	}

	flat := claimWaitMessage{
		Claimed:    true,
		PublicKey:  "flat-key",
		AssignedIP: "10.255.255.41",
		Endpoint:   "hub.example:51820",
	}
	if claim := flat.claimConfig(); claim == nil || claim.PublicKey != "flat-key" || claim.Endpoint != "hub.example:51820" {
		t.Fatalf("flat claimConfig=%#v", claim)
	}

	if claim := (claimWaitMessage{Type: "waiting"}).claimConfig(); claim != nil {
		t.Fatalf("waiting claimConfig=%#v want nil", claim)
	}
}

func validSignedClaimRequest(r *http.Request, deviceID string) bool {
	ts := r.Header.Get(HeaderTimestamp)
	if ts == "" || r.Header.Get(HeaderDevice) != deviceID {
		return false
	}
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	_, _ = mac.Write([]byte(ts + ":" + deviceID))
	return hmac.Equal([]byte(r.Header.Get(HeaderSig)), []byte(hex.EncodeToString(mac.Sum(nil))))
}

func TestFetchClaimConfigSendsSignedIdentityAndDecodesClaim(t *testing.T) {
	const (
		deviceID  = "device-hash"
		publicKey = "gTkybMRi4b1wgAmCo6DjZZFUEOsPNVq1ccDGLTG0IE0="
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ClaimConfigPath || r.URL.Query().Get("public_key") != publicKey {
			http.NotFound(w, r)
			return
		}
		if !validSignedClaimRequest(r, deviceID) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClaimConfig{
			Claimed:    true,
			PublicKey:  publicKey,
			AssignedIP: "10.255.255.40",
			Endpoint:   "hub.example:51820",
		})
	}))
	defer server.Close()

	claim, err := FetchClaimConfig(context.Background(), server.URL, deviceID, publicKey)
	if err != nil {
		t.Fatalf("FetchClaimConfig: %v", err)
	}
	if claim == nil || !claim.Claimed || claim.PublicKey != publicKey || claim.AssignedIP != "10.255.255.40" {
		t.Fatalf("claim = %#v", claim)
	}
}

func TestWaitClaimConfigReceivesEventAndHonorsCancellation(t *testing.T) {
	const (
		deviceID  = "device-hash"
		publicKey = "gTkybMRi4b1wgAmCo6DjZZFUEOsPNVq1ccDGLTG0IE0="
	)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	t.Run("claimed event", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validSignedClaimRequest(r, deviceID) || r.URL.Query().Get("public_key") != publicKey {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.WriteJSON(claimWaitMessage{Type: "waiting"})
			_ = conn.WriteJSON(claimWaitMessage{
				Type:       "claimed",
				Claimed:    true,
				PublicKey:  publicKey,
				AssignedIP: "10.255.255.41",
			})
		}))
		defer server.Close()

		claim, err := WaitClaimConfig(context.Background(), server.URL, deviceID, publicKey)
		if err != nil {
			t.Fatalf("WaitClaimConfig: %v", err)
		}
		if claim == nil || claim.PublicKey != publicKey || claim.AssignedIP != "10.255.255.41" {
			t.Fatalf("claim = %#v", claim)
		}
	})

	t.Run("cancel closes active read", func(t *testing.T) {
		connected := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			close(connected)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := WaitClaimConfig(ctx, server.URL, deviceID, publicKey)
			done <- err
		}()
		select {
		case <-connected:
		case <-time.After(2 * time.Second):
			t.Fatal("claim websocket did not connect")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "claim wait websocket read") {
				t.Fatalf("cancellation error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("claim websocket did not stop promptly after cancellation")
		}
	})
}
