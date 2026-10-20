# Architecture

The app uses SwiftUI and `MenuBarExtra`. `WantasticCore` holds shared models
and interfaces; `WantasticTunnel` owns Network Extension lifecycle and the
packet provider. The host app configures and starts the signed packet-tunnel
extension through `NETunnelProviderManager`.

The provider selects either an account-registered or manually imported
WireGuard configuration from separate shared-Keychain records, establishes the
Wantastic WireGuard peer, and only then installs the configured
split routes and DNS before pumping packets through `NEPacketTunnelFlow`. No
packet may be accepted as connected before a fresh authenticated handshake
completes. This source path is unit-tested but is not yet installed or runtime-
verified through an Apple-entitled extension on this machine.

The provider implements the encrypted packet path and a WUSP request transport
over the deployed encrypted type-8 control framing. Method IDs, WU message
encoding, compact selectors, fragmentation/reassembly, request correlation,
timeouts, and error mapping have tests against Go fixtures and local loopback
responders. Mutating control requests are deduplicated per authenticated peer
using request ID and sequence for two minutes; the exact response is replayed,
concurrent duplicates share one execution, and changed payloads under a reused
identity are rejected. The negotiated `+request-replay-v1` capability matches
the Go runtime. The only installed Operate command is `Device.Reboot()`: it
crosses a fixed, certificate-pinned helper API and invokes Darwin's reboot
syscall after a two-second response window. Arbitrary commands and command-line
arguments are not accepted. `Device.FactoryReset()` removes the four
Wantastic Keychain accounts scoped to the current console and stops this tunnel
after returning success, while preserving the non-secret Network Extension
profile. Other operations fail as unsupported. The
app-provider RPC exposes this channel to the UI. TUN-control
messages are a separate authenticated control path: only the provider's pinned
hub transport handles them, and route state is applied through native tunnel
settings. Other privileged control actions remain disabled.

P2P uses the deployed authenticated punch envelope, bounded candidate sets,
shared-port UDP flows, fresh WireGuard handshake confirmation, and hub transport
fallback on setup failure or direct-session closure. A successful UDP punch
alone does not prove a direct encrypted path. NAT and carrier policies can
prevent direct paths entirely; live multi-network validation and recovery from
silent stale NAT mappings remain open, so the UI must never promise every NAT
can be traversed.

The version-1 WUSP envelope and inline-path WU frame have bounded binary
encoders/decoders, including typed values, compact selectors, and Go-compatible
LZ4 blocks. WUSP type-8 fragments have Go-compatible framing and bounded
reassembly. Deployed Go fixtures, authenticated loopback sessions, and
fragmented-control tests cover the current paths; transfer-stream frames,
including LZ4-compressed chunks, have byte-for-byte Go/Swift fixture coverage.
The Go control-fragment sender currently disables compression, so compressed
control fragments are not part of the active interoperability contract. Live
tenant sessions remain unverified. Upload/Download sessions now run over the
authenticated type-8 stream with ACK retries and private, bounded staging;
general user-selected file access is intentionally not exposed yet. The Go P2P
header, WPC1 candidates, and peer-list records are ported and tested. The
coordinator authenticates punch responses, then the provider attempts a fresh
WireGuard session over that socket and routes packets for that peer directly;
the loopback promotion test covers the punch-socket handshake, while
Network-Extension route switching and real NAT remain unverified. TUN-control
codecs cover exit-node commands and bounded private IPv4 local-access routes,
including /32s. Authenticated type-7 route apply/remove/snapshot actions from
the configured hub are installed through Network Extension settings with
per-advertiser ownership and overlay-overlap rejection. Exit-node selection is
advertisement-gated in the UI and provider RPC, then server-issued select/revoke
controls add/remove Go-compatible address-family default routes. Providing exit
node forwarding and client-side subnet advertisement/forwarding remain
unimplemented. Native LAN
discovery now retains each route's physical egress interface, and a pure Swift
plan builder emits PF NAT/pass rules matching the Go Darwin contract while
rejecting interface injection, conflicting egress, excessive routes, and
overlay overlap. The provider's opt-in local-access RPC is connected to the
coordinator; it enforces helper/firewall activation before subnet advertisement
and route withdrawal before cleanup, including rollback and retry paths. A
separate, narrowly authorized LaunchDaemon helper owns the fixed Wantastic PF
anchor and forwarding sysctl, persists its owned state, and recovers it at
startup. Unit tests cover these plans and lifecycle paths with fakes, but real
macOS PF/sysctl and signed XPC behavior remain unverified. Activation stays
gated on matching trusted app/helper/extension signatures and helper approval.
Native ICMP
ping and bounded service probes work as explicit actions. Configured DNS and
routes are applied by the provider after the hub handshake. The `wantastic`
suffix is split-routed to configured resolvers and explicitly added to the
search domains for single-label MagicDNS names, matching Go's Darwin `domain
wantastic` resolver. Tenant MagicDNS records, live WUSP collector behavior,
and entitled extension runtime remain unverified.

The host's manual-import flow parses the same bounded WireGuard format as the
registered flow, stores configuration separately from login tokens, and
persists an explicit source selector in the non-secret VPN profile. Provider
startup fails closed if the selected Keychain record is missing; it never
silently substitutes credentials from the other setup method.

The core has native CryptoKit X25519, Swift BLAKE2s-256/HMAC/KDF1-3, a partial
Noise IKpsk2 transcript, fixed handshake packet layouts, MAC1/MAC2, cookie
reply decryption, encrypted type-4/7/8 framing, Go-compatible padding/IP
trimming, and an initiator peer-session
state machine. Native UDP drives the session, retries initiations, performs
overlapping 120-second rekeys with a 300-second reject-after window, maintains
configured idle keepalive, and integrates with the packet provider; route and
DNS settings are built from the configuration with endpoint exclusions. Tests
cover RFC 7748/RFC 7693, Go KDF/MAC fixtures, a public XChaCha vector, matched
session keys, tamper rejection, cookie retry, replay windows, bidirectional
packets, and authenticated UDP loopback handshake and rekey. Live Go
interoperability and entitled provider runtime remain unverified; this is not
yet a production-ready tunnel.
