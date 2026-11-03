package auth

import (
	"net/url"
	"strings"
)

// NormalizeServerURL is the scheme://host of a server URL or bare domain;
// empty means the default Wantastic server.
func NormalizeServerURL(serverURL string) string {
	base := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if base == "" {
		return "https://" + DefaultOAuth2Domain
	}
	if !strings.HasPrefix(strings.ToLower(base), "http://") &&
		!strings.HasPrefix(strings.ToLower(base), "https://") {
		base = "https://" + base
	}
	if parsed, err := url.Parse(base); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host
	}
	return base
}

// BuildClaimURL is the genkey claim link for publicKey: the console's claim
// form, the console's Scan QR and the phone app all read it. hostname only
// pre-fills the device name.
func BuildClaimURL(serverURL, publicKey, hostname string) string {
	base := NormalizeServerURL(serverURL)
	claimURL := base + "/#desktop?claim_public_key=" + url.QueryEscape(strings.TrimSpace(publicKey)) + "&wantastic_server=" + url.QueryEscape(base)
	if host := ClaimHostname(hostname); host != "" {
		claimURL += "&hostname=" + url.QueryEscape(host)
	}
	return claimURL
}

// ClaimHostname is the device hostname as the claim link carries it:
// network suffixes and stock defaults that say nothing about the device are
// dropped.
func ClaimHostname(host string) string {
	host = strings.TrimSpace(host)
	lower := strings.ToLower(host)
	for _, suffix := range []string{".local", ".lan", ".home", ".localdomain"} {
		if strings.HasSuffix(lower, suffix) {
			host = host[:len(host)-len(suffix)]
			break
		}
	}
	switch strings.ToLower(host) {
	case "", "localhost", "openwrt":
		return ""
	}
	if len(host) > 64 {
		host = strings.ToValidUTF8(host[:64], "")
	}
	return host
}
