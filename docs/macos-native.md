# Native macOS implementation

Branch: `macos-native`. The Swift client and native networking implementation
live in the repository-root `Sources/`, `Tests/`, `Config/`, and Swift package;
this note summarizes what is verified and what still needs an Apple-enabled machine.

## Verified locally

- `make test-swift`: passes the Swift tests and type-checks the conditional
  Xcode host-app and system-extension source sets.
- `make macos-build`: optimized Swift package build succeeds.
- `make macos-xcode-test`: full Xcode project gate is provided and used by CI;
  it cannot run here because this Mac has only Command Line Tools.
- `make macos-local-app`: builds and verifies a menu-bar UI shell with an
  ad-hoc signature; `make macos-run-local` launches it successfully.
- Root `make test-cli`: Go protocol/reference test suite passes.
- The local app bundle fails when explicitly signed with
  `Wantastic Local Code Signing (kimo)` (`errSecInternalComponent`). The login
  Keychain contains that self-signed certificate, but `security verify-cert`
  reports `CSSMERR_TP_NOT_TRUSTED` and macOS reports zero valid Code Signing
  identities. The fallback ad-hoc bundle has no Team ID or
  certificate and cannot authenticate the pinned helper.

The tests establish protocol and loopback behavior, not production network
reliability. Current code includes Swift WUSP framing/dispatch, Go-compatible
WireGuard handshake and transport code, P2P punch/session promotion, split
route and DNS policy, device authorization, Keychain credential storage,
localized UI, and a constrained PF/XPC helper design. The detailed feature
matrix and gaps are in [`implementation-status.md`](implementation-status.md).

## Not verified / release gates

- This Mac has Command Line Tools, not full Xcode; `xcodebuild` is unavailable.
  Native app/extension targets have not been built and signed by Xcode here.
- No Apple-granted Network Extension entitlement or matching provisioning
  profile is installed. The packet tunnel has not been activated, and the UI
  shell cannot establish a system tunnel.
- Cross-target shared Keychain access, system-extension approval, helper XPC,
  actual PF/sysctl mutation and recovery, and device reboot/reset execution have
  not been tested on the operating system.
- Production Go-peer/WUSP interoperability, tenant MagicDNS resolution, and
  P2P traversal across independent NATs remain unverified. Loopback tests do
  not prove these deployment behaviors.
- The installed local self-signed identity was attempted, but macOS rejected
  signing with it. Do not weaken Keychain trust, trust the local root globally,
  or bypass system-extension security to make this build appear functional.

Before retiring the Go implementation, complete the full-Xcode build, Apple entitlement/provisioning,
matching signature and shared-Keychain tests, signed helper installation and
recovery checks, and live tunnel/WUSP/P2P tests on approved hardware. Follow
[`apple-signing.md`](apple-signing.md) for the
Apple-side prerequisites. Keep profiles, certificates, private keys, and
tenant credentials out of the public repository.
