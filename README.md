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
curl -sSL https://get.wantastic.app/install.sh | sh          # Linux
curl -fsSL https://get.wantastic.app/install.sh | sudo sh    # macOS (Intel and Apple silicon)
```

On macOS the daemon runs as a LaunchDaemon and the menu-bar app starts for
every user at login (LaunchAgent `com.wantastic.tray`). Pass `--no-tray` to skip
the menu-bar app. The installer picks the native build on Apple silicon even
from a Rosetta shell, and logs go to `/Library/Logs/Wantastic/wantasticd.log`.

To uninstall (keeps the configuration unless `--purge` is given):

```sh
curl -fsSL https://get.wantastic.app/install.sh | sudo sh -s -- --uninstall [--purge]
```

### macOS code signing

Until it is set up, macOS warns that it "could not verify `wantastic-macos.pkg`
is free of malware" when the package comes from a browser and offers only
**Done** or **Move to Trash**. Click **Done**, then open **System Settings →
Privacy & Security**, scroll to Security and click **Open Anyway** next to
`wantastic-macos.pkg`; confirm **Open Anyway** again with your password and
the installer starts. (macOS 15 removed the right-click → Open shortcut.) The
`curl | sudo sh` install is not affected. To remove the warning, with an Apple Developer Program
membership (Wantastic LLC):

1. Create a **Developer ID Application** and a **Developer ID Installer**
   certificate; export each with its private key as `.p12` (same password).
2. Create an App Store Connect API key (Users and Access → Integrations →
   Keys, role Developer) for notarization; download the `.p8`.
3. Repository secrets: `MACOS_APP_CERT_P12`, `MACOS_INSTALLER_CERT_P12`,
   `MACOS_NOTARY_KEY_P8` (base64 of each file), `MACOS_CERT_PASSWORD`,
   `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER`.
4. Repository variable `MACOS_SIGNING` = `apple`.

Releases then sign the binary (hardened runtime) and the package, have Apple
notarize the package and staple the ticket, so it opens with no warning.

Prefer an installer? Download `wantastic-macos.pkg` from
https://get.wantastic.app/latest/ (one package for Intel and Apple silicon, macOS 12+)
and open it; then click **Log in** in the menu bar. It installs exactly what the
script above installs, and upgrades in place.

On macOS the same is built in: `sudo wantasticd uninstall [--purge]`. The
service alone is managed with `sudo wantasticd service install | uninstall |
reinstall | start | stop | restart | status`.

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

Works from any folder (nothing is saved next to you; `C:\Windows\System32`
is read-only even for Administrators). With a login token:

```powershell
& ([scriptblock]::Create((irm https://get.wantastic.app/install.ps1))) -Token <TOKEN>
```

By default the installer shows a **claim QR code** and link. Approve the device
in the console and it connects by itself; the service is already running and
waiting, so the installer never blocks on sign-in. It also opens Windows
Firewall: inbound UDP for direct peer connections, plus traffic from peers over
the tunnel, so they can ping and reach this PC. The agent re-applies both
firewall rules whenever it connects.

The Windows package includes [Wintun](https://www.wintun.net) 0.14.1, the
tunnel driver, for the matching architecture (x64, ARM64 or x86). It is the
official build signed by WireGuard LLC, and the installer checks that signature
before copying it next to `wantasticd.exe`. Self-update adds it to older
installs that lack it.

Options go after the scriptblock, as with `-Token` above:

| Option | Effect |
| --- | --- |
| *(none)* | claim with the QR code; connects once approved |
| `-Token <TOKEN>` | log in with a token instead |
| `-NoLogin` | install only; add the device later (`wantasticd genkey --no-wait`, then `wantasticd service start`) |
| `-NoTray` | do not start the tray app at logon |
| `-Version v1.0.59` | install that release instead of the latest |
| `-ZipPath <file>` | install from a downloaded `wantasticd-windows-*.zip` (offline) |
| `-Uninstall` | remove the service, tray, firewall rules, PATH entry and program files; add `-Purge` to also remove the login and claim key |

The service is managed by `wantasticd` itself (Administrator):

```powershell
wantasticd service install     # register or repair: automatic start, restart on failure, firewall, tray (--no-tray to skip)
wantasticd service status      # state, startup type, command line
wantasticd service start | stop | restart
wantasticd service uninstall   # remove the service, its firewall rules and the tray logon entry
wantasticd uninstall [--purge] # remove everything the installer added; --purge also the login
```

The tray app is on by default: every time the service starts it starts the tray
for the signed-in users and keeps its logon entry, unless it was turned off with
`-NoTray` / `--no-tray`. The service reports Running only once the agent is up,
so `wantasticd status` answers as soon as `service start` returns.

Prefer a setup wizard? Download `wantastic-setup-windows-amd64.exe` (or `-arm64.exe`)
from https://get.wantastic.app/latest/ and run it; it installs the same service and
tray, then click **Log in** to add the PC. Silent install: `/VERYSILENT /SUPPRESSMSGBOXES`.

Requires Windows 10, Windows 11 or Windows Server 2016+ (x64, ARM64 or x86).
Windows 7, 8 and 8.1 are not supported: the Go runtime does not run there.
Works in Windows PowerShell 5.1 and PowerShell 7. Re-running the installer
upgrades in place and keeps the existing login.

The installer does not elevate itself; from a normal prompt it stops and asks
you to re-run it as Administrator. It checks `wantasticd.exe`'s signature
before installing: a release signed by anyone other than Wantastic LLC, or
with a broken signature, is refused.

#### Windows code signing (maintainers)

Release builds of `wantasticd.exe` and `install.ps1` are Authenticode-signed
as **Wantastic LLC** through [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/)
once it is enabled. Until then, Windows builds ship unsigned. They are no
longer UPX-packed, a common cause of antivirus false positives, and they carry
Wantastic LLC version information.

1. Create an Artifact Signing account and complete **Public Trust** identity
   validation for the organization *Wantastic LLC*. Then create a **Public
   Trust** certificate profile.
2. Register an app in Microsoft Entra ID, add a client secret, and on the
   signing account grant it the **Artifact Signing Certificate Profile Signer**
   role.
3. In the GitHub repository settings, add these:
   - Secrets: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
   - Variables: `AZURE_SIGNING_ENDPOINT` (e.g. `https://eus.codesigning.azure.net/`),
     `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE`, and `WINDOWS_SIGNING=azure`
     to turn signing on.

Windows has its own workflow (`.github/workflows/windows.yml`). It runs the Go
tests on Windows, builds amd64/arm64/x86 with Wintun, signs them, and then runs `install.ps1`
for real on Windows Server 2022, Windows Server 2025 and Windows 11 ARM64,
in both Windows PowerShell 5.1 and PowerShell 7: fresh install, the service
bringing a real tunnel up, upgrade and uninstall. It runs on every push or pull request that
touches Windows code, and the release calls it for each tag. With signing on,
it signs and verifies every Windows executable and `install.ps1`. If signing
or the installer test fails, nothing is published.

If a build has already been flagged, submit it as a false positive at
<https://www.microsoft.com/wdsi/filesubmission>.

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

# Connection status (version, addresses, server, traffic, peers)
wantasticd status [--json]

# Peers with path (direct/relay), endpoint, last handshake and traffic;
# --ping adds a latency column
wantasticd peers [--ping] [--json]

# Ping peers over the tunnel (all peers when no target is given)
wantasticd ping [-c 4] [-i 250ms] [-W 1s] [hostname|vpn-ip|pubkey-prefix ...]

# Disconnect / reconnect the tunnel; the service keeps running
wantasticd down
wantasticd up

# Login interactively
wantasticd login

# Login with token
wantasticd login --token <TOKEN>
```

### Tray menu

The tray (menu bar on macOS, notification area on Windows) shows a coloured
icon: green when connected, blue when using an exit node, grey when
disconnected, red when the service is not running. From the menu you can:

- see the VPN IP (click to copy), total traffic, live speed, uptime and server;
- disconnect and reconnect, while the service keeps running;
- list peers with their path (direct/relay), and click one to copy its IP;
- **Ping all peers**: latency for every peer, shown next to each one;
- under **Exit node**, allow this device as an exit node, pick a peer to send
  all internet traffic through, or return to normal routing.

Each action's result or error is shown in the menu for 20 seconds.

### Allow tenant access to this device's local LAN

On Linux and OpenWrt, opt this device into subnet-router mode with:

```sh
sudo wantasticd connect --config /etc/wantastic --allow-local-access
```

`--allow-local-access` discovers directly connected private IPv4 subnets (for
example, `192.168.1.0/24`), enables forwarding with source NAT, and advertises
those routes to devices connected to the same Wantastic tenant. It does not
advertise public, default, loopback, point-to-point, or Wantastic tunnel routes.
Explicit private host routes (`/32`) are accepted by the authenticated route
protocol. The feature is off by default.

The same flag is accepted by `login` and by the claim-waiting `genkey` flow.
When used during login or claim, the setting is saved in the generated JSON
configuration. To explicitly disable a saved setting, reconnect with:

```sh
wantasticd connect --config /etc/wantastic --allow-local-access=false
```

Automatic forwarding/NAT for this feature is currently supported on Linux and
OpenWrt. Overlapping LAN advertisements from different devices in one tenant
are rejected by the coordinator to avoid ambiguous or hijacked routes.

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
sudo launchctl print system/com.wantastic.wantasticd
sudo launchctl kickstart -k system/com.wantastic.wantasticd   # restart
```

To stop and remove the service while keeping the generated key and
configuration, run the installer with `--uninstall` (see Installation).

**Updates** are applied by the daemon itself (or `sudo wantasticd update`):
the new build is verified before it replaces the old one, the service is
restarted, and if it does not come back healthy the previous build is
restored. The previous build is kept as `wantasticd.previous` next to the
binary.

### macOS connectivity troubleshooting

Seeing a laptop in the device list confirms that it registered with the service;
it does not confirm that its tunnel or routes are working. On the Mac that
cannot reach a peer, check the daemon, tunnel, logs, and route:

```sh
/usr/local/bin/wantasticd status
sudo launchctl print system/com.wantastic.wantasticd
sudo tail -n 100 /Library/Logs/Wantastic/wantasticd.log   # installs before 1.0.50: /var/log/wantasticd.log
route -n get <peer-overlay-ip>
```

The status should report `Running` and `TUN (utun...)`. The route to the peer
should use a `utun` interface. Look in the log for a recent WireGuard handshake
and route errors. To restart the service and retry:

```sh
sudo launchctl kickstart -k system/com.wantastic.wantasticd
ping <peer-overlay-ip>
```

If connectivity still fails, collect the command output from both Macs and
check the peer's firewall and tunnel status. Redact private keys and tokens
before sharing logs or configuration. Advertising and forwarding this Mac's
local LAN to tenant peers is currently supported on Linux and OpenWrt, not
macOS.

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
