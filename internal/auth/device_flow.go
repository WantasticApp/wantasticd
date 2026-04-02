package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
)

// StartHTTPDeviceFlow initiates RFC 8628 device authorization by POSTing to
// /oauth/device/code and returning the device code + user instructions.
func StartHTTPDeviceFlow(ctx context.Context, portalBaseURL, clientID string) (*DeviceCode, error) {
	endpoint := strings.TrimRight(portalBaseURL, "/") + DeviceCodePath

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "openid profile email")

	const maxAttempts = 5
	var lastStatus int
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
			strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("build device code request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("device code request: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()

			var dc DeviceCode
			if err := limitDecode(resp.Body, &dc); err != nil {
				return nil, fmt.Errorf("decode device code response: %w", err)
			}
			if dc.DeviceCode == "" || dc.UserCode == "" {
				return nil, fmt.Errorf("invalid device code response (missing fields)")
			}
			if dc.Interval == 0 {
				dc.Interval = 5
			}
			if dc.ExpiresIn == 0 {
				dc.ExpiresIn = 300
			}
			return &dc, nil
		}

		lastStatus = resp.StatusCode
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()

		// Retry on 5xx (gateway/service unavailable); fail fast on 4xx.
		if resp.StatusCode < 500 {
			return nil, fmt.Errorf("device code endpoint returned %d: %s", resp.StatusCode, bytes.TrimSpace(body))
		}

		backoff := time.Duration(attempt*attempt) * time.Second
		log.Printf("Portal not ready (%d): %s — retrying in %s (attempt %d/%d)",
			resp.StatusCode, bytes.TrimSpace(body), backoff, attempt, maxAttempts)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, fmt.Errorf("device code endpoint returned %d after %d attempts", lastStatus, maxAttempts)
}

// ErrSlowDown is a sentinel returned by PollHTTPDeviceFlow when the server
// requests the client slow down.  RunDeviceFlow handles it by increasing the
// interval; callers that call PollHTTPDeviceFlow directly should do the same.
var ErrSlowDown = fmt.Errorf("slow_down: reduce poll frequency")

// PollHTTPDeviceFlow polls POST /oauth/token once for the device access token.
//
// Returns:
//   - (token, nil)          on success
//   - ("", nil)             when authorization is still pending
//   - ("", ErrSlowDown)     when the server requests back-off (caller must increase interval)
//   - ("", ErrPeerLimitExceeded) when the user has hit their plan limit
//   - ("", ErrUserDenied)   when the user explicitly denied
//   - ("", err)             on any other terminal error
func PollHTTPDeviceFlow(ctx context.Context, portalBaseURL, clientID, deviceCode string) (string, error) {
	endpoint := strings.TrimRight(portalBaseURL, "/") + TokenPath

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token poll request: %w", err)
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := limitDecode(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if resp.StatusCode == http.StatusOK && tr.AccessToken != "" {
		return tr.AccessToken, nil
	}

	// RFC 8628 error handling
	switch tr.Error {
	case "authorization_pending":
		return "", nil // still waiting — caller should keep polling
	case "slow_down":
		return "", ErrSlowDown // caller must increase interval by ≥5 s (RFC 8628 §3.5)
	case "expired_token":
		return "", fmt.Errorf("device code expired — please start a new login")
	case "access_denied":
		switch tr.ErrorDescription {
		case "peer_limit_exceeded":
			return "", ErrPeerLimitExceeded
		case "user_denied":
			return "", ErrUserDenied
		default:
			return "", fmt.Errorf("access denied: %s", tr.ErrorDescription)
		}
	case "":
		return "", fmt.Errorf("token endpoint returned %d with no error field", resp.StatusCode)
	default:
		return "", fmt.Errorf("token error %q: %s", tr.Error, tr.ErrorDescription)
	}
}

// printDeviceAuthUI renders a QR code and authorization instructions to stderr.
// Width is measured in runes (display columns), not bytes, so Unicode box-drawing
// characters render correctly regardless of their UTF-8 byte length.
func printDeviceAuthUI(verifyURL, userCode string) {
	const (
		borderRune  = '━'
		borderWidth = 54 // display columns inside the box
	)
	border := strings.Repeat(string(borderRune), borderWidth)
	row := func(content string) {
		fmt.Fprintf(os.Stderr, "  ┃%s┃\n", centerPad(content, borderWidth))
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  ┏%s┓\n", border)
	row("  Wantastic Device Authorization  ")
	fmt.Fprintf(os.Stderr, "  ┣%s┫\n", border)
	row("")
	row("Scan the QR code or open the URL below:")
	row("")
	row(verifyURL)
	if userCode != "" {
		row("")
		row("Your device code:")
		row("")
		row("  " + userCode + "  ")
	}
	row("")
	fmt.Fprintf(os.Stderr, "  ┗%s┛\n", border)
	fmt.Fprintln(os.Stderr, "")

	// Render QR code to stderr so it doesn't pollute stdout piping.
	qrterminal.GenerateWithConfig(verifyURL, qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stderr,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 2,
	})
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  URL: %s\n", verifyURL)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Waiting for authorization…")
	fmt.Fprintln(os.Stderr, "")
}

// centerPad returns s padded with spaces to width display columns, centered.
// Width and string length are measured in runes, not bytes.
func centerPad(s string, width int) string {
	runes := []rune(s)
	sLen := len(runes)
	if sLen >= width {
		return string(runes[:width])
	}
	total := width - sLen
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// testPollInterval overrides the per-poll sleep in RunDeviceFlow when non-zero.
// Tests set this to 0 to avoid 5-second waits between polls.
var testPollInterval time.Duration = -1 // -1 means "use dc.Interval"

// RunDeviceFlow orchestrates the full RFC 8628 device authorization flow and
// returns the access token on success. It prints the user code and verification
// URI to stdout so the operator knows where to go.
func RunDeviceFlow(ctx context.Context, portalBaseURL, clientID string) (string, error) {
	dc, err := StartHTTPDeviceFlow(ctx, portalBaseURL, clientID)
	if err != nil {
		return "", fmt.Errorf("start device flow: %w", err)
	}

	verifyURL := dc.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = dc.VerificationURI
	}

	printDeviceAuthUI(verifyURL, dc.UserCode)

	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	interval := time.Duration(dc.Interval) * time.Second
	if testPollInterval >= 0 {
		interval = testPollInterval
	}

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("device code expired — please try again")
		}

		token, err := PollHTTPDeviceFlow(ctx, portalBaseURL, clientID, dc.DeviceCode)
		if err == ErrSlowDown {
			// RFC 8628 §3.5: increase interval by at least 5 seconds.
			interval += 5 * time.Second
		} else if err != nil {
			return "", err // terminal error
		} else if token != "" {
			return token, nil // success
		}

		// Still pending — wait before next poll.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}
