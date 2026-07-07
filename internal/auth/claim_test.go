package auth

import "testing"

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
