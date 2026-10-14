<div align="center">

# wantasticd

**Wantastic Networking Daemon** — a lightweight, cross-platform WireGuard-based mesh networking agent.

[![Stars](https://img.shields.io/github/stars/kmoz000/wantasticd?style=flat-square&logo=github&label=Stars)](https://github.com/kmoz000/wantasticd/stargazers)
[![Release](https://img.shields.io/github/v/release/kmoz000/wantasticd?style=flat-square)](https://github.com/kmoz000/wantasticd/releases)
[![License](https://img.shields.io/github/license/kmoz000/wantasticd?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20OpenWrt-blue?style=flat-square)](#installation)

</div>

---

## What is wantasticd?

`wantasticd` is the agent daemon for the [Wantastic](https://wantastic.app) overlay network. It uses a WireGuard-based protocol to create secure, high-performance peer-to-peer tunnels between devices — across NAT, firewalls, and heterogeneous networks.

It runs as a system service on Linux (systemd, procd/OpenWrt, OpenRC, SysV, BusyBox), macOS (launchd), and Windows.

---

## Performance

Wantasticd uses a **Userspace Hybrid Netstack** — combining a Go userspace WireGuard implementation with kernel-bypass techniques for maximum throughput.

| Scenario | Throughput |
|---|---|
| Local loopback (P2P) | ~10 Gbps |
| LAN peer-to-peer | ~2–5 Gbps |
| WAN / cloud relay | Limited by ISP uplink |

> See the full [P2P Performance Benchmarks](./p2pbenchmark.md) for detailed results.

---

## P2P

Wantasticd establishes **direct peer-to-peer tunnels** whenever a validated
WireGuard path can be punched through the current NAT/firewall. Traffic keeps
using the authenticated tenant hub relay until that direct handshake succeeds,
and automatically returns to the relay if the direct path becomes stale. No
mesh VPN can guarantee a direct path through every NAT or UDP-blocking firewall;
the relay is the availability fallback.

- **ICE-like hole punching** through NAT
- **WireGuard encryption** end-to-end
- **Persistent keepalive** for connection stability on embedded/mobile networks
- **Automatic reconnect** managed by the system service

To run the P2P end-to-end test suite:

```bash
./e2e/run_p2p_test.sh
```

---

## Installation

### Linux & macOS — one-liner

```sh
curl -sSL https://get.wantastic.app/install.sh | sh
```

The installer automatically:
- Detects your OS and architecture (`linux/amd64`, `arm64`, `arm`, `mips`, `riscv64`, `ppc64le`, ...)
- Remounts read-only filesystems (OpenWrt)
- Adds reliable DNS if needed
- Installs the binary to `/usr/bin/wantasticd` or `/usr/local/bin/wantasticd`
- Registers and starts a system service (systemd / procd / OpenRC / SysV / BusyBox / launchd)

### Windows

Open PowerShell as Administrator:

```powershell
irm https://get.wantastic.app/install.ps1 | iex
```

---

## Authentication

After installation the agent needs credentials in `/etc/wantastic` to connect. There are three ways to authenticate:

### Factory claim QR

For sold devices, generate a stable WireGuard key and claim QR. By default this
command keeps running forever, waits for the customer claim, writes the final
config, and connects automatically:

```sh
wantasticd genkey --out /etc/wantastic/device-claim-key.json --server-url https://console.wantastic.app
```

The command saves the private key locally, prints the public key, and renders a QR code for:

```text
https://console.wantastic.app/#desktop?claim_public_key=<PUBLIC_KEY>
```

For a self-hosted Wantastic server, pass your own domain:

```sh
wantasticd genkey --out /etc/wantastic/device-claim-key.json --server-url https://wantastic.example.com
```

Anyone with that QR can claim the device into their signed-in Wantastic team on that server. Keep the generated JSON file on the device image and do not print the private key unless you are in a secure factory workflow.

To generate the key and exit without waiting, pass `--no-wait`:

```sh
wantasticd genkey --no-wait --out /etc/wantastic/device-claim-key.json --server-url https://console.wantastic.app
```

If a config has not been claimed yet, `connect` also enters claim-waiting mode automatically when the claim key exists:

```sh
wantasticd connect --claim-key /etc/wantastic/device-claim-key.json --server-url https://wantastic.example.com
```

---

### 1. Interactive browser login

```sh
curl -sSL https://get.wantastic.app/install.sh | sh -s -- --login
```

Or after install:

```sh
wantasticd login
```

Opens `console.wantastic.app` in your browser. After you approve, the config is written to `/etc/wantastic` automatically.

---

### 2. Token login (headless / automated)

Ideal for CI pipelines, bulk installs, and embedded devices with no browser.

**Where to get a token:** Go to **My Account → Secrets** in the console and click **+ New Secret**.

![Enrollment Secrets](docs/secrets.png)

```sh
# Install + authenticate in one command
curl -sSL https://get.wantastic.app/install.sh | sh -s -- --token <YOUR_TOKEN>
```

Or after install:

```sh
wantasticd login --token <YOUR_TOKEN>
```

---

### 3. Manual config file (SD card / provisioning / offline)

Copy the WireGuard config directly from the console: open your device, go to **Device Configuration → WireGuard** tab, and copy the config block.

![Device Configuration WireGuard](docs/device-config.png)

Write it to `/etc/wantastic` on the device:

```ini
[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address    = 10.x.x.x/32

[Peer]
PublicKey           = <YOUR_SERVER_PUBLIC_KEY>
Endpoint            = wg.wantastic.app:51820
AllowedIPs          = 10.0.0.0/8
PersistentKeepalive = 25
```

```sh
vi /etc/wantastic
wantasticd connect --config /etc/wantastic
```

You can pre-write this file to an SD card before first boot — the installer **never overwrites** an existing `/etc/wantastic`.

---

## Usage

```sh
# Connect using config file
wantasticd connect --config /etc/wantastic

# Check connection status
wantasticd status

# List devices and their direct/relay state
wantasticd peers

# Ping by device name, overlay IP, or public key
wantasticd ping node-10-20-0-4.wantastic

# Offer this device or select another device as an exit node
wantasticd exit-node --offer=true
wantasticd exit-node --use=<PEER_PUBLIC_KEY>

# Login interactively
wantasticd login

# Login with token
wantasticd login --token <TOKEN>
```

### Allow tenant access to this device's local LAN

On Linux and OpenWrt, opt this device into subnet-router mode with:

```sh
sudo wantasticd connect --config /etc/wantastic --allow-local-access
```

`--allow-local-access` discovers directly connected private IPv4 subnets (for
example, `192.168.1.0/24`), enables forwarding with source NAT, and advertises
those routes to devices connected to the same Wantastic tenant. It does not
advertise public, default, loopback, point-to-point, or Wantastic tunnel routes.
The feature is off by default.

Use an explicit comma-separated route list when automatic discovery is too
broad. Private `/32` host routes are accepted:

```sh
sudo wantasticd connect --config /etc/wantastic \
  --advertise-routes=192.168.1.0/24,10.20.30.40/32
```

The same flag is accepted by `login` and by the claim-waiting `genkey` flow.
When used during login or claim, the setting is saved in the generated JSON
configuration. To explicitly disable a saved setting, reconnect with:

```sh
wantasticd connect --config /etc/wantastic --allow-local-access=false
```

Automatic forwarding/NAT for this feature is currently supported on Linux and
OpenWrt. Overlapping LAN advertisements from different devices in one tenant
are rejected by the coordinator to avoid ambiguous or hijacked routes.

## Desktop app

The `Desktop` branch includes a Wails v2 tray application for macOS, Windows,
and Linux. It embeds the same agent and exposes peer status, overlay ping,
claim-link generation, manual configuration, exit-node controls, tenant DNS
status, and local-network route assignment. Build it with:

```sh
make desktop
```

The dedicated `.github/workflows/desktop.yml` workflow builds native artifacts
on macOS, Windows, and Linux runners. The app and tray use the Wantastic shield;
left-clicking the tray opens the compact Wails window, while right-clicking
opens connection status and actions. On macOS it runs as a menu-bar-only app.

CI ad-hoc signs and verifies the macOS bundle and signs the Windows executable
with an ephemeral self-signed code-signing certificate. These signatures prove
artifact integrity inside the build but are not publicly trusted, so a clean
machine can still show Gatekeeper or SmartScreen warnings. Public distribution
requires an Apple Developer ID plus notarization and a trusted Authenticode
certificate. Linux artifacts are not code-signed.

Linux/OpenWrt currently provide automatic kernel forwarding and source NAT for
advertised LAN routes; macOS and Windows can consume those routes, but offering
a local subnet there still requires an administrator-managed forwarding/NAT
setup.

---

## Service Management

The installer registers wantasticd as a system service automatically. You can manage it with the standard init tools for your platform:

**systemd**
```sh
systemctl status wantasticd
systemctl restart wantasticd
systemctl stop wantasticd
```

**OpenWrt (procd)**
```sh
/etc/init.d/wantasticd status
/etc/init.d/wantasticd restart
/etc/init.d/wantasticd stop
```

**macOS (launchd)**
```sh
launchctl list | grep wantastic
launchctl stop com.wantastic.wantasticd
```

---

## Supported Platforms

| OS | Init System | Architectures |
|---|---|---|
| Linux | systemd | amd64, arm64, arm, 386 |
| OpenWrt | procd | mips, mipsle, mips64, mips64le, arm, arm64 |
| Alpine Linux | OpenRC | amd64, arm64, arm |
| Debian/Ubuntu (legacy) | SysV | amd64, arm64 |
| Embedded Linux | BusyBox | arm, mipsle |
| macOS | launchd | amd64, arm64 |
| Windows | SCM | amd64 |
| Linux | any | riscv64, ppc64le |

---

## License

See [LICENSE](LICENSE).
