# Apple signing and Network Extension work still required

The local app is a UI shell and does not activate the Network Extension.
An ad-hoc signature is not an Apple Developer ID identity or provisioning
profile. Three local self-signed identities (`Wantastic Local Signing Root
(kimo)`, `Wantastic Local Development (kimo)`, and `Wantastic Local Code
Signing (kimo)`) are in the current user's login Keychain. The newest identity
is a non-CA Code Signing leaf whose private key was imported as non-exportable
and authorized only for `/usr/bin/codesign`. macOS reports all three
identities as untrusted and `security find-identity -p codesigning -v` reports
zero valid identities. `security verify-cert -p codeSign` reports
`CSSMERR_TP_NOT_TRUSTED`; signing the helper inside a disposable copy of the
app with the exact leaf certificate fails with `errSecInternalComponent`, and
the active app bundle remains unchanged. Adding a user-Keychain trust setting
for only the new leaf and Code Signing policy was denied by macOS
authorization, so the app remains ad-hoc signed. The local build script is configured to use
`Wantastic Local Code Signing (kimo)` once macOS reports it as valid. To retry,
approve that leaf's Code Signing trust in Keychain Access, then run
`make macos-local-app` from the repository root. Do not trust the self-signed root
globally, export or commit a private key. Even if local signing works, these
self-signed identities cannot grant Network Extension entitlements.

## Choose the distribution model first

The XcodeGen project now describes a macOS Packet Tunnel system extension with
the `packet-tunnel-provider-systemextension` entitlement, the host installation
entitlement, an `NEProviderClasses` mapping, and an `OSSystemExtensionRequest`
approval flow. Apple lists the macOS app-extension form of a Packet Tunnel
Provider as App Store only; direct distribution requires this system-extension
model and Apple-granted signing/provisioning. See Apple's
[provider deployment matrix](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
and [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).

The local ad-hoc app shell does not embed the extension, so it cannot activate
the system tunnel. XcodeGen successfully generated the project, but the native
targets have not been built on this machine because full Xcode is not installed.
The provider source fails closed unless shared credentials exist and a fresh
authenticated handshake completes before routes are installed.

The Xcode project declares one team-prefixed Keychain access group for the app
and extension. The registered WireGuard private key stays in Keychain; the
extension must load it from that shared group rather than receiving private
configuration in `providerConfiguration`. Both targets need matching signed
entitlements and provisioning. The ad-hoc local shell does not test this shared
access path.

## Separate privilege required for LAN forwarding

The packet-tunnel entitlement does not authorize host-wide PF or IP-forwarding
changes. The local app bundle now contains the helper executable and an
`SMAppService` LaunchDaemon manifest; the registration API, constrained XPC
interface, root-side PF/sysctl operations, and validation tests are present.
The Network screen provides an explicit route selection; the provider
revalidates the selections, applies the helper plan, and advertises only after
forwarding succeeds. The helper persists Wantastic-owned state and performs
scoped recovery before serving. These paths are not yet verified against real
macOS PF/sysctl or signed XPC runtime. This Mac's local app remains ad-hoc
signed, so it cannot satisfy the certificate-pinned XPC requirement. Each
process derives its signing leaf certificate and requires the peer's expected
bundle identifier and exact same certificate, allowing a self-signed local
developer identity without trusting all system-trusted signers. Ad-hoc
binaries have no certificate and fail closed. Do not enable LAN forwarding
until app, extension, and helper use matching trusted signing, helper approval
works, recovery/rollback succeeds, and activation/cleanup is tested on a real
host. The XPC API accepts validated Wantastic plans rather than shell commands
or arbitrary PF rules. See Apple's
[SMAppService helper guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)
and [`SMAppService.daemon(plistName:)`](https://developer.apple.com/documentation/servicemanagement/smappservice/daemon(plistname:)).

An ad-hoc signature is not sufficient to authenticate the XPC peer. A local
self-signed identity can be pinned for development but does not grant Network
Extension entitlements, and the bundled helper still requires user
authorization. XPC transport and helper operations are not runtime-tested in
this branch.

## Direct distribution checklist

Before producing a downloadable VPN build:

1. Use an Apple Developer team and register explicit App IDs for the containing
   app (`app.wantastic.desktop`) and packet-tunnel system extension
   (`app.wantastic.desktop.network-extension`). Enable the Network Extension
   capability for the relevant identifiers.
2. Generate and review the Xcode project from `project.yml`; it now declares the
   system-extension target, entry point (`NEProvider.startSystemExtensionMode()`),
   provider-class mapping, and approval flow using `OSSystemExtensionRequest`.
   Confirm Apple's granted entitlements: the containing app needs system-extension
   installation permission and the extension needs the packet-tunnel system
   extension entitlement.
3. Create and install the matching Developer ID provisioning profiles and
   certificates. Sign the app and extension with the same Team ID and verify the
   signed entitlements against each embedded profile. Keep profiles and private
   keys out of the repository.
4. Build and test on a machine with full Xcode; install from `/Applications` and
   approve the system extension through macOS. Verify activation, tunnel start,
   stop, reconnect, and route/DNS cleanup on supported macOS versions.
5. Harden, notarize, and staple the final app package before publishing it.

If the product is instead distributed only through the Mac App Store, retain the
app-extension model and use the `packet-tunnel-provider` entitlement with the
matching App Store provisioning/signing setup. The App Store and direct-download
models are not interchangeable signing configurations.

Apple's [`NEProvider.startSystemExtensionMode()` reference](https://developer.apple.com/documentation/networkextension/neprovider/startsystemextensionmode())
describes how a system extension starts servicing Network Extension requests.
