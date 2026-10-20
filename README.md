# Wantastic for macOS

This branch (`macos-native`) contains the native Swift/SwiftUI macOS client,
WireGuard protocol implementation, Network Extension source, and constrained
privileged helper. Swift sources, tests, configuration, and package metadata
now live at the repository root alongside the Go daemon and shared protocol tests.

The Swift package, unit/integration tests, and a locally ad-hoc-signed menu-bar
UI shell build and launch on macOS. The shell is not a working VPN: this
development Mac has Command Line Tools but not full Xcode, has no valid signing
identities, and has no Apple-granted Network Extension entitlement or
provisioning profile.
Consequently, the system extension, shared Keychain access, privileged XPC
helper, real PF/sysctl changes, and live tunnel have not been activated here.
Do not enable local-network forwarding from an ad-hoc build.

## Build and test

```sh
make test             # Full Go suite plus Swift tests and source type-checks
make macos-build      # optimized Swift package build
make macos-xcode-test # full Xcode app/extension target tests (requires Xcode)
make macos-local-app  # local, ad-hoc-signed UI shell only
make macos-run-local  # open that UI shell
```

The Swift test suite covers Go-compatible protocol fixtures, WireGuard
loopback handshakes and rekey, P2P punch promotion, WUSP request/replay and
transfer behavior, route/DNS policy, firewall plan safety, and UI localization.
Run only the narrower Go CLI suite from the repository root with `make test-cli`.

For feature scope, current verification, and known limitations, see
[`docs/macos-native.md`](docs/macos-native.md),
[`docs/implementation-status.md`](docs/implementation-status.md),
[`docs/architecture.md`](docs/architecture.md), and
[`docs/security.md`](docs/security.md).
Apple signing, entitlement, and provisioning prerequisites are tracked in
[`docs/apple-signing.md`](docs/apple-signing.md).
