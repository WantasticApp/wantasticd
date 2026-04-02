package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GeneratePKCE creates a cryptographically random PKCE code verifier and its
// S256 challenge as specified in RFC 7636 §4.1–4.2.
//
// Verifier: BASE64URL(32 random bytes), 43 characters, no padding.
// Challenge: BASE64URL(SHA256(verifier)), no padding.
func GeneratePKCE() (*PKCEPair, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate pkce verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	return &PKCEPair{Verifier: verifier, Challenge: challenge}, nil
}

// generateState returns a URL-safe random string for CSRF protection.
func generateState() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// exchangeCodeForToken POSTs to /oauth/token with the authorization code and
// code verifier, returning the access token on success.
func exchangeCodeForToken(ctx context.Context, portalBaseURL, clientID, code, verifier, redirectURI string) (string, error) {
	endpoint := strings.TrimRight(portalBaseURL, "/") + TokenPath

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := limitDecode(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("decode token exchange response: %w", err)
	}

	if resp.StatusCode == http.StatusOK && tr.AccessToken != "" {
		return tr.AccessToken, nil
	}

	// Surface peer-limit error clearly.
	if tr.Error == "access_denied" && tr.ErrorDescription == "peer_limit_exceeded" {
		return "", ErrPeerLimitExceeded
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token exchange error %q: %s", tr.Error, tr.ErrorDescription)
	}
	return "", fmt.Errorf("token exchange returned %d", resp.StatusCode)
}

// RunPKCEFlow runs the full PKCE authorization code flow:
//  1. Generates a PKCE pair and random state
//  2. Opens the browser to /oauth/authorize
//  3. Starts a local HTTP server on PKCECallbackPort to receive the redirect
//  4. Exchanges the authorization code for an access token
//
// Returns the access token on success.
func RunPKCEFlow(ctx context.Context, portalBaseURL, clientID string) (string, error) {
	pkce, err := GeneratePKCE()
	if err != nil {
		return "", err
	}
	state, err := generateState()
	if err != nil {
		return "", err
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", PKCECallbackPort)

	authURL := fmt.Sprintf("%s/oauth/authorize?%s",
		strings.TrimRight(portalBaseURL, "/"),
		url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {pkce.Challenge},
			"code_challenge_method": {"S256"},
			"state":                 {state},
			"scope":                 {"org:create_api_key user:profile"},
		}.Encode(),
	)

	// Start the local callback server before opening the browser.
	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", PKCECallbackPort))
	if err != nil {
		return "", fmt.Errorf("open callback listener on :%d: %w", PKCECallbackPort, err)
	}

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Check for error from the portal.
		if errVal := q.Get("error"); errVal != "" {
			desc := q.Get("error_description")
			switch {
			case errVal == "access_denied" && desc == "peer_limit_exceeded":
				http.Error(w, "Device limit reached. Upgrade your plan or remove a device.", http.StatusForbidden)
				resultCh <- callbackResult{err: ErrPeerLimitExceeded}
			case errVal == "access_denied":
				http.Error(w, "Authorization was denied.", http.StatusForbidden)
				resultCh <- callbackResult{err: ErrUserDenied}
			default:
				http.Error(w, fmt.Sprintf("Authorization error: %s", desc), http.StatusBadRequest)
				resultCh <- callbackResult{err: fmt.Errorf("oauth2 error %q: %s", errVal, desc)}
			}
			return
		}

		// Verify state to prevent CSRF.
		if q.Get("state") != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("state mismatch: possible CSRF")}
			return
		}

		code := q.Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("callback missing code parameter")}
			return
		}

		fmt.Fprintln(w, "Authorization successful — you can close this tab.")
		select {
		case resultCh <- callbackResult{code: code}:
		default:
			// A second callback arrived after the first was already consumed;
			// ignore it — the auth code is single-use anyway.
		}
	})

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("callback server: %w", err)}:
			default:
			}
		}
	}()

	// Shut down the callback server once we have a result or the context expires.
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	printDeviceAuthUI(authURL, "")

	// Wait for the callback or context cancellation.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return "", res.err
		}
		return exchangeCodeForToken(ctx, portalBaseURL, clientID, res.code, pkce.Verifier, redirectURI)
	}
}

// HandoffURL builds the console auto-login URL for the given portal domain and
// session token returned by RegisterDevice.
func HandoffURL(portalBaseURL, sessionToken string) string {
	return fmt.Sprintf("%s%s?t=%s",
		strings.TrimRight(portalBaseURL, "/"),
		HandoffPath,
		url.QueryEscape(sessionToken),
	)
}
