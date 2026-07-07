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

Wantasticd establishes **direct peer-to-peer tunnels** whenever possible, falling back to relay only when both peers are behind symmetric NAT. The P2P path uses:

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

# Login interactively
wantasticd login

# Login with token
wantasticd login --token <TOKEN>
```

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
