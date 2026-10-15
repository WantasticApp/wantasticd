<div align="center">

# Wantastic

**A secure WireGuard-based tenant network for desktop, servers, routers, and embedded devices.**

[![Release](https://img.shields.io/github/v/release/WantasticApp/wantasticd?style=flat-square)](https://github.com/WantasticApp/wantasticd/releases)
[![Desktop](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml/badge.svg?branch=Desktop)](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml)
[![Platforms](https://img.shields.io/badge/Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20OpenWrt-supported-258bd2?style=flat-square)](#platform-support)

</div>

`wantasticd` is the Wantastic networking agent. It joins a device to its tenant
overlay, keeps traffic encrypted with WireGuard, tries authenticated direct P2P
paths, and retains the tenant relay as the availability fallback when a NAT or
firewall prevents direct UDP connectivity.

The `Desktop` branch also contains the compact Wails v3 tray application used
on macOS, Windows, and Linux. The CLI and desktop app share the same agent,
configuration, identity, MagicDNS, P2P, exit-node, and local-access logic.

## Features

- WireGuard-encrypted tenant overlay
- Direct P2P path discovery with automatic relay fallback
- Stable device claim links and automatic post-claim connection
- Manual Wantastic JSON and WireGuard configuration import
- MagicDNS status and tenant device discovery
- Six-sample overlay ping chart
- Exit-node advertisement and selection safeguards
- Opt-in private LAN advertisement, including `/32` host routes
- System service installers for Linux, OpenWrt, macOS, and Windows
- Frameless Wantastic tray UI with native platform packaging

Direct P2P cannot be guaranteed through every NAT or a network that blocks UDP.
Wantastic keeps the encrypted relay path available so connectivity does not
depend on successful hole punching.

## Install the CLI and service

Linux, OpenWrt, and macOS:

```sh
curl -fsSL https://get.wantastic.app/install.sh | sh
```

Windows PowerShell, run as Administrator:

```powershell
irm https://get.wantastic.app/install.ps1 | iex
```

The installer detects the operating system and architecture, installs the
matching release archive, and configures the native service manager. It does
not overwrite an existing configuration.

## Join a tenant

### Claim link

Generate a stable device key and wait for the signed-in user to claim it:

```sh
wantasticd genkey \
  --out /etc/wantastic/device-claim-key.json \
  --server-url https://console.wantastic.app
```

The private key remains on the device. The command prints a claim URL containing
only the public key, waits for approval, writes the resulting configuration,
and connects automatically. Use `--no-wait` only for a factory workflow that
will complete the claim later.

### Browser or token login

```sh
wantasticd login
wantasticd login --token '<ENROLLMENT_TOKEN>'
```

Use browser login for an interactive workstation. Use a scoped enrollment token
for headless provisioning and automation; do not place tokens in source files,
shell history, or images.

### Manual WireGuard configuration

Wantastic accepts a standard WireGuard client configuration:

```ini
[Interface]
PrivateKey = <DEVICE_PRIVATE_KEY>
Address = 10.x.x.x/32
DNS = <TENANT_DNS>, <FALLBACK_DNS>

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = wg.wantastic.app:51820
AllowedIPs = <TENANT_PREFIX>
PersistentKeepalive = 25
```

```sh
wantasticd connect --config /etc/wantastic
```

Configuration and claim-key files are written as private files. Never publish
a real WireGuard private key or enrollment token in an issue, commit, or CI log.

## CLI usage

```sh
# Connect and inspect the local agent
wantasticd connect --config /etc/wantastic
wantasticd status
wantasticd peers

# Ping by MagicDNS name, overlay address, or public key
wantasticd ping node-10-20-0-4.wantastic

# Offer this device as an exit node or select an advertised exit node
wantasticd exit-node --offer=true
wantasticd exit-node --use=<PEER_PUBLIC_KEY>

# Stop using an exit node
wantasticd exit-node --use=none
```

An exit node can be selected only when that peer is actively advertising
exit-node capability.

## Allow tenant access to a local network

Local access turns the device into an opt-in subnet router for other devices in
the same tenant. Automatic discovery advertises directly connected RFC 1918
IPv4 LANs:

```sh
sudo wantasticd connect --config /etc/wantastic --allow-local-access
```

Explicit private routes are comma-separated. `/32` is supported when only one
LAN host should be exposed:

```sh
sudo wantasticd connect --config /etc/wantastic \
  --advertise-routes=192.168.50.0/24,172.16.4.25/32
```

The route validator rejects public prefixes, default routes, malformed input,
more than 16 routes, and routes that overlap the Wantastic overlay source. The
feature is disabled by default.

On Linux and OpenWrt, Wantastic installs narrowly scoped forwarding, packet
marking, and source-NAT rules. On macOS, the privileged desktop helper enables
IPv4 forwarding and loads NAT/pass rules only into the dedicated
`com.apple/wantastic` PF anchor; it does not flush or replace the system ruleset.
The helper removes its anchor and restores the previous forwarding/PF state
when local access stops. Windows can consume advertised tenant routes, while
offering a Windows LAN remains disabled until the native service owns its
forwarding and Firewall policy.

## Desktop application

The desktop app is a fixed-size, frameless tray application with the Wantastic
logo and explicit Online/Offline status. It provides:

- connect and disconnect control
- tenant device list and direct/relay path status
- MagicDNS and traffic status
- six-sample device ping visualization
- claim-link creation and automatic claim connection
- manual Wantastic JSON or WireGuard import
- exit-node controls gated by peer advertisement
- local-access subnet and `/32` assignment

macOS runs the tunnel in an administrator-authorized helper while the Wails UI
remains unprivileged. Windows also keeps the UI manifest at `asInvoker`; native
system changes belong to the service boundary rather than the webview process.

CI creates ad-hoc/self-signed desktop artifacts. Those signatures provide build
integrity but are not a substitute for Apple notarization or a publicly trusted
Windows Authenticode certificate.

## Build and test

Requirements:

- Go 1.27.2 or newer compatible toolchain
- Node.js 22 and pnpm 11
- Wails v3 platform dependencies
- Linux desktop builds: GTK 3/4, WebKitGTK 4.1/6.0, and Ayatana AppIndicator

The Makefile is the supported developer entrypoint:

```sh
make help
make test
make test-desktop
make frontend-build
make desktop-dev
make desktop-build
make desktop-package
```

Build the universal, ad-hoc-signed macOS bundle on a Mac:

```sh
make desktop-macos-universal
```

Build every CLI release architecture:

```sh
make cli-all
```

Run the release gates and the binary vulnerability scan:

```sh
make check
make audit
```

The P2P container test remains available as a purpose-built end-to-end check:

```sh
./e2e/run_p2p_test.sh
```

## Platform support

| Platform | CLI/service | Desktop | Offer local LAN |
|---|---:|---:|---:|
| Linux amd64/arm64/arm/386 | Yes | Yes | Yes |
| OpenWrt mips/arm families | Yes | No | Yes |
| macOS amd64/arm64 | Yes | Universal app | Yes, privileged PF helper |
| Windows amd64 | Yes | Yes | Not yet |
| Linux loong64/ppc64/riscv64/s390x | CLI release | No | Platform-dependent |

The Desktop workflow builds and verifies native artifacts on macOS, Ubuntu, and
Windows. Release tags publish the CLI archive matrix separately.

## Service management

```sh
# systemd
systemctl status wantasticd
systemctl restart wantasticd

# OpenWrt/procd
/etc/init.d/wantasticd status
/etc/init.d/wantasticd restart

# macOS launchd
launchctl list | grep wantastic
```
