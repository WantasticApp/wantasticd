// Command wantasticd-olt is the on-device Wantastic onboarding helper for
// FOS-based GPON OLTs (Photon PTF3708 / GP8X2G6 family).
//
// The OLT's vendor kernel has no epoll, so modern Go cannot use os.Open or
// any file I/O (every os file is registered with the epoll-based poller and
// the first open kills the runtime). This helper therefore uses ONLY stdio
// and argv: the shell wrapper performs all file placement.
//
// Modes:
//
//	wantasticd-olt genkey              reads a 32-byte seed from stdin,
//	                                   prints PRIVATE= PUBLIC= CLAIMURL=
//	wantasticd-olt pubkey <priv-b64>   prints PUBLIC= CLAIMURL=
//
// The claim URL embeds the device public key and points at the Wantastic
// console claim form; the vendor web UI shows it as a QR code rendered
// client-side by the onboarding page.
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const defaultServerURL = "https://console.wantastic.app"

func main() {
	// No file I/O happens in this process; disabling the GC also keeps the
	// scavenger from ever creating a timer (which would touch netpoll).
	debug.SetGCPercent(-1)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		seed := make([]byte, 32)
		if _, err := io.ReadFull(os.Stdin, seed); err != nil {
			fmt.Fprintf(os.Stderr, "wantasticd-olt: read seed: %v\n", err)
			os.Exit(1)
		}
		private, public, err := keypair(seed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wantasticd-olt: keypair: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PRIVATE=%s\n", private)
		fmt.Printf("PUBLIC=%s\n", public)
		fmt.Printf("CLAIMURL=%s\n", claimURL(defaultServerURL, public))
	case "pubkey":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		private := os.Args[2]
		public, err := publicKey(private)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wantasticd-olt: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PUBLIC=%s\n", public)
		fmt.Printf("CLAIMURL=%s\n", claimURL(defaultServerURL, public))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wantasticd-olt genkey | pubkey <private-key-b64>")
}

func keypair(seed []byte) (private, public string, err error) {
	seed[0] &= 248
	seed[31] = (seed[31] & 127) | 64
	pub, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(seed), base64.StdEncoding.EncodeToString(pub), nil
}

func publicKey(privateB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// claimURL mirrors the agent's auth.BuildClaimURL (no hostname part: the
// console shows the device name once claimed).
func claimURL(serverURL, publicKey string) string {
	base := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if base == "" {
		base = defaultServerURL
	}
	return base + "/#desktop?claim_public_key=" + urlEscape(publicKey) + "&wantastic_server=" + urlEscape(base)
}

// urlEscape is a minimal QueryEscape (no net/url import: this binary must
// not touch anything that could reach the runtime netpoll).
func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}
