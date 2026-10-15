<div align="center">

<img src="build/appicon.png" alt="Wantastic logo" width="96">

# Wantastic Desktop

**A compact system-tray app for joining and managing your Wantastic tenant network.**

[![Desktop](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml/badge.svg?branch=Desktop)](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml?query=branch%3ADesktop)
[![Wails](https://img.shields.io/badge/Wails-v3-DA202A?style=flat-square)](https://v3.wails.io/)
[![Platforms](https://img.shields.io/badge/macOS%20%7C%20Windows%20%7C%20Linux-desktop-258bd2?style=flat-square)](#download)

[Download the latest successful Desktop build](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml?query=branch%3ADesktop+is%3Asuccess)

</div>

The `Desktop` branch is dedicated to the Wantastic Wails v3 desktop app. It
contains the frameless tray window, native platform packaging, desktop tests,
and the shared networking agent used by the app.

For the headless `wantasticd` daemon and router installation workflow, use the
[`main` branch](https://github.com/WantasticApp/wantasticd/tree/main).

## Screenshots

<p align="center">
  <img src="screenshots/devices.png" alt="Wantastic tenant device list" width="270">
  <img src="screenshots/device-detail.png" alt="Wantastic device details and actions" width="270">
  <img src="screenshots/network.png" alt="Wantastic network controls" width="270">
</p>

<p align="center">
  <img src="screenshots/settings.png" alt="Wantastic sign-in and advanced setup" width="270">
  <img src="screenshots/settings-ar.png" alt="Wantastic settings in Arabic with right-to-left layout" width="270">
  <img src="screenshots/loading.png" alt="Wantastic branded loading screen" width="270">
</p>

## What the desktop app provides

- Wantastic status beside the native system-tray icon
- connect and disconnect control
- device list with direct, protected-relay, and offline status
- device details, traffic, connection history, private names, and IP addresses
- a short visual connection check instead of a single ping result
- one-step browser sign-in followed by automatic connection
- English, French, Spanish, German, and Arabic with full RTL layout
- advanced Wantastic JSON or WireGuard configuration import
- friendly device names backed by MagicDNS
- internet sharing, available only when the selected device offers it
- opt-in local-network sharing with private subnet or `/32` host routes

A direct device-to-device path is attempted automatically. When NAT or a
firewall prevents a safe direct UDP path, the encrypted Wantastic relay remains
the availability fallback.

## Download

Desktop builds are currently published as artifacts by the
[`Desktop` GitHub Actions workflow](https://github.com/WantasticApp/wantasticd/actions/workflows/desktop.yml?query=branch%3ADesktop+is%3Asuccess).

1. Open the latest successful workflow run.
2. Scroll to **Artifacts**.
3. Download the artifact for your operating system.
4. Extract the downloaded ZIP before launching the application.

| Operating system | Artifact | Package contents |
|---|---|---|
| macOS 13+ | `wantastic-desktop-macos-universal` | Universal Intel and Apple silicon app ZIP |
| Windows 10/11 x64 | `wantastic-desktop-windows-amd64` | `wantastic.exe` |
| Linux x86_64 | `wantastic-desktop-linux-amd64` | `wantastic` GTK 3 binary |

GitHub currently requires signing in to download Actions artifacts. These are
development builds: macOS is ad-hoc signed and Windows uses an ephemeral
self-signed CI certificate. Publicly trusted notarized/Authenticode installers
are not published yet.

### macOS

1. Extract the downloaded artifact.
2. Extract `wantastic-macos-universal.zip` inside it.
3. Move `Wantastic.app` to `/Applications`.
4. On first launch, Control-click the app, choose **Open**, and confirm macOS.
5. Approve the administrator prompt when Wantastic starts its tunnel helper.

The Wails window remains unprivileged. Only the native tunnel helper receives
administrator rights. Local-network access uses a dedicated
`com.apple/wantastic` PF anchor and restores the previous forwarding state when
it stops.

### Windows

1. Extract the downloaded artifact.
2. Run `wantastic.exe`.
3. If SmartScreen warns about the CI certificate, verify that the file came
   from the official Wantastic workflow before choosing **Run anyway**.

The desktop UI is built with an `asInvoker` manifest and does not request
process-wide administrator rights. Native tunnel or firewall operations still
depend on the permissions and service policy configured on the machine.

### Linux

Install the GTK/WebKit/AppIndicator runtime libraries. On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y libgtk-3-0 libwebkit2gtk-4.1-0 libayatana-appindicator3-1
```

Then extract and launch the artifact:

```sh
chmod +x wantastic
./wantastic
```

Creating a native TUN requires an administrator-managed service or suitable
network capabilities. Do not run the desktop webview itself as root.

## First-time setup

### Sign in and connect

1. Open Wantastic from the tray.
2. Select the settings button in the upper-right corner.
3. Select **Sign in**.
4. Finish signing in on the Wantastic Console page that opens in your browser.

The app opens the correct console page directly, keeps the private device key on
the computer, waits for browser approval, saves the returned configuration with
private permissions, and connects automatically. No link or key needs to be
copied between the app and the browser.

### Language

Open **Settings → Language** and choose English, French, Spanish, German, or
Arabic. Wantastic remembers the selection, updates the native tray menu, and
switches the complete window to right-to-left layout for Arabic.

### Manual configuration

Open **Settings → Advanced setup**, paste either a Wantastic JSON configuration
or a standard WireGuard client configuration, then select **Import and connect**.

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

Never publish a real private key, enrollment token, or complete configuration
in an issue, screenshot, commit, or CI log.

## Daily usage

### Tray controls

- The tray label shows **Online**, **Offline**, **Connecting**, or **Setup**.
- Selecting the tray icon opens the compact Wantastic window.
- The tray menu follows the selected language and provides connect/disconnect,
  Devices, Network, Sign in, Settings, and Quit actions.

### Devices and ping

The **Devices** view shows all available devices and whether each connection is
direct, protected by the relay, or offline. Select a device to view its address,
private name, last activity, traffic, and actions. **Check connection** records a
short series of reachability samples rather than reporting only one packet.

### Exit nodes

Open **Network** to share this computer's internet connection. On another
device, **Use internet through this device** is enabled only when that device is
actively offering the capability. Turning sharing off removes the offer.

### Local-network access

**Share local network access** makes a private local route available to devices
in the same Wantastic network. Enter a private subnet or one host:

```text
192.168.50.0/24
192.168.50.25/32
```

Use `/32` to expose only one LAN host. Do not enter a Wantastic overlay address
such as `10.255.255.x`; overlay peers are already reachable. The app rejects
public prefixes, default routes, malformed routes, and routes overlapping the
tenant overlay before changing the tunnel or firewall.

## Build from source

Requirements:

- Go 1.27.2 or a compatible newer toolchain
- Node.js 22
- pnpm 11
- Wails v3 platform dependencies

```sh
# Inspect supported commands
make help

# Test Go, frontend dependencies, and installer syntax
make check
make test-desktop

# Regenerate bindings and build the frontend
make frontend-build

# Run development mode or build for the current platform
make desktop-dev
make desktop-build
```

Build and ad-hoc sign the universal macOS application on a Mac:

```sh
make desktop-macos-universal
```

The dedicated Desktop workflow tests the app and builds native Linux, macOS,
and Windows artifacts for every push to this branch.

## Security model

- the desktop webview remains unprivileged
- IPC listens only on loopback and requires a generated bearer credential
- browser-originated mutation requests are rejected
- configuration and device-identity files use private permissions and no-follow checks
- local-access routes are bounded, normalized, private IPv4 prefixes
- macOS PF changes are limited to Wantastic's dedicated anchor
- Windows UI packaging retains the non-elevated `asInvoker` manifest

Report security issues privately rather than including keys, configurations, or
tenant details in a public GitHub issue.

## License

See [LICENSE](LICENSE).
