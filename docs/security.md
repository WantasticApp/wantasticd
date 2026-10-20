# Security

- Store tenant credentials and WireGuard private keys in Keychain. Keep tokens
  out of logs, URLs, QR codes, crash reports, and `UserDefaults`.
- Accept only HTTPS console URLs, restrict authorization requests and redirects
  to the configured console host, and never treat an OAuth token as a completed
  device claim or tunnel connection.
- The embedded console uses WKWebView's persistent app-local website store. It
  accepts only HTTPS top-level navigation and rejects URLs containing embedded
  credentials. It has no JavaScript-to-native bridge and does not share Safari
  cookies; device authorization remains a separate, configured-origin flow.
- Configure tunnel addresses, routes, and DNS through Network Extension APIs.
  Restore them through the operating system when the tunnel disconnects.
- Apply TUN-control route changes only after WireGuard authentication and replay
  validation from the configured hub peer. Route updates are bounded, private
  IPv4 only, scoped by advertiser, and rejected when they overlap configured
  overlay routes. Exit-node changes and subnet forwarding are not enabled yet.
- The Swift BLAKE2s/HMAC/KDF, Noise transcript, packet MACs, cookie decryption,
  and transport AEAD are hand-ported cryptographic code verified against
  RFC/Go/public vectors, but have not received an independent security audit.
  Transport framing is not UDP/Network Extension integration. The replay
  filter is ported against bundled Go RFC 6479 fixtures, but surrounding
  lifecycle and concurrency remain unaudited. Do not enable production traffic
  before interoperability testing and independent security review.
- Treat endpoint discovery, peer lists, device names, and service scan results
  as untrusted input. Never launch a service automatically.
- Require a user-selected device and explicit action before scanning ports.
  Show the target and scan scope; bound port count, concurrency, and timeout.
  ICMP probes use native sockets and never launch shell commands.
- A packet-tunnel entitlement does not grant unrestricted firewall access.
  The separate helper only accepts a structured plan, regenerates the PF rules
  for a fixed Wantastic-owned anchor, and exposes fixed IP-forwarding/PF
  operations. Its only additional system-control operation is a fixed delayed
  reboot syscall with no caller-controlled command or arguments; it is reached
  only through the existing pinned app/extension XPC identities after an
  authenticated WUSP operation request. The UI/provider/helper path and persisted rollback are unit-tested
  but not runtime-verified on macOS. Ad-hoc signing cannot satisfy the XPC peer
  pin; do not enable local routes until matching trusted signing, helper
  approval, real PF/sysctl activation, and restart/withdrawal tests pass.
- Local UI runs use the local self-signed code-signing identity only after the
  user trusts it for Code Signing in Keychain Access; until then the build
  falls back to an ad-hoc signature. Signing with both installed local
  identities has failed with `errSecInternalComponent`, so verify private-key
  access before relying on either. These identities are not Apple Developer
  IDs. Before
  enabling a tunnel, choose
  App Store app-extension packaging or direct-distribution system-extension
  packaging, then provision and sign every target with the matching Apple team.
  Do not disable SIP or system-extension checks to bypass installation approval.
- The tunnel controller may select only a packet-tunnel profile whose provider
  bundle identifier is `app.wantastic.desktop.network-extension`; it must not
  start, stop, or modify another VPN profile installed on the Mac.
- WUSP `Device.FactoryReset()` deletes only the registered/manual configuration
  and two WUSP preference entries scoped to the configured console host. It
  stops this provider after the success response; it deliberately leaves the
  non-secret Network Extension profile installed and never enumerates or wipes
  unrelated Keychain entries.
