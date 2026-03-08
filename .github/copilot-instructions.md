# Copilot Instructions — wantasticd

## Architecture Overview

`wantasticd` is a cross-platform WireGuard-inspired VPN daemon written in Go. Key layers:

| Layer | Package | Role |
|---|---|---|
| CLI entry | `cmd/wantasticd` | Subcommand dispatch (`login`, `connect`, `status`, `tray`, `update`, `version`, `gui`) |
| Agent core | `internal/agent` | Owns WireGuard device + gRPC client + IPC HTTP server + stats |
| Device | `internal/device` | Dual-mode: system TUN (`TUNMode=true`) or embedded gVisor netstack |
| Config / Auth | `internal/config` | JSON or WireGuard INI config; device-flow or token-based gRPC auth |
| IPC API | `internal/agent/api.go` | Local HTTP on `127.0.0.1:9034` (auto-increments to 9100 if occupied) |
| Systray | `pkg/runner/tray.go` | `getlantern/systray`; build-tagged; talks to IPC endpoints only |
| Stats / Dashboard | `internal/stats` | `go:embed` HTML dashboard; SSE events; optional verbose mode |
| GUI (WIP) | `internal/web` | Wails v2 + React + Vite + D3; See `internal/web/README.md` |
| gRPC | `internal/grpc` + `proto/` | Auth service: `StartDeviceFlow`, `RegisterDevice`, `GetConfiguration` |

Data flows inward: CLI → Agent.Start() → Device.Start() → WireGuard loop. The tray/GUI only ever calls IPC endpoints — they never import `internal/agent` directly.

## Module Name

```
module wantastic-agent  // go.mod
```
All internal imports use this module name, e.g. `"wantastic-agent/internal/config"`.

## Build Commands

```bash
make build              # bin/wantasticd (current platform)
make build-all          # all TARGETS in Makefile, compressed with upx
make build-iwinfo       # CGO_ENABLED=1, -tags iwinfo (OpenWrt libiwinfo)
make genproto           # regenerate internal/grpc/proto/ from proto/auth.proto
make build-demo         # bin/demoserver
```

Version is injected via ldflags from `git describe` — always build with `make`, not bare `go build`, to get accurate version strings.

## IPC Port Discovery

The daemon binds to `127.0.0.1:9034` (or next free port up to 9100) and writes the actual port to:
- env `WTC_IPC_PORT`
- `$TMPDIR/wantasticd_ipc_port`

Any CLI or GUI code that calls the daemon **must** use `agent.GetIPCPort()` (`internal/agent/api_port.go`) — never hardcode `9034`.

IPC endpoints: `GET /api/status`, `POST /api/state/toggle`, `POST /api/exitnode/toggle`, `POST /api/exitnode/use?peer=<pubkey>`.

## Systray Build Tag

```go
//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray
```
Release CI cross-builds use `TAGS="nosystray"` to skip systray. Never add systray code to files without this exact build tag. The headless stub is in `pkg/runner/tray_headless.go`.

## Config Loading

`config.LoadFromFile` tries JSON first, then WireGuard INI (`[Interface]`/`[Peer]`). Config is saved to `/etc/wantastic/config.conf` (root) or falls back to `./wantastic.conf`. The `Auth.Token` field persists the session token; the `/__auth` IPC endpoint in `internal/web/server.go` reads it for the GUI.

## Authentication Flow

- **Device flow** (interactive): `config.LoadFromDeviceFlow` → gRPC `StartDeviceFlow`/`PollDeviceFlow` → prints a URL code, polls until approved.  
- **Token flow**: `config.LoadFromToken` → gRPC `RegisterDevice` → decrypts `EncryptedConfig` (ChaCha20-Poly1305, key = SHA256(token), nonce = 12-byte little-endian random int64).

## GUI (Wails v2 + React)

Work in progress under `internal/web/`. Structure:
```
internal/web/
  server.go          # lightweight static server + /__auth endpoint (dev only)
  frontend/
    package.json     # React 18 + Vite 4 + D3 v7
    src/             # React app: Topology tab (D3 force graph), Account tab (Auth0 OIDC)
```

- The production build will use `wails build` — see `internal/web/README.md` for init steps.
- The Account tab initiates Auth0 PKCE flow against `console.wantastic.app` and stores the token via `/__auth` / `internal/config`.
- The Topology tab polls `/api/status` (via `agent.GetIPCPort()`) and renders the peer graph with D3.

## TUN Name Conventions

| OS | Default |
|---|---|
| macOS | `utun` (kernel assigns number) |
| Linux | `wantastic0`…`wantastic99` (first free) |
| Windows | `wantastic0` |

Override with `WANTASTIC_TUN_NAME` env.

## Testing

```bash
go test ./...                   # unit tests (no root required)
./e2e/run_p2p_test.sh           # P2P end-to-end via Docker Compose
```

`internal/device/protocol_test.go` and `internal/device/wireguard-go/` contain WireGuard-level tests. No mock injection pattern — tests use real loopback networking where possible.

## Key Patterns

- **Retry on port conflict**: `startAgentWithRetry` in `cmd/wantasticd/main.go` increments `cfg.Interface.ListenPort` up to 10 times on `"address already in use"`.
- **Stats provider injection**: `dev.SetStatsProvider(statsServer.GetSerializedMetrics)` links the WireGuard device to the stats server for P2P metric push.
- **Dual-mode graceful start**: `runAgent()` blocks the main thread via `runner.RunSystray()` on macOS/Windows (required by Cocoa); headless mode uses `<-ctx.Done()`.
- **Context propagation**: all long-lived goroutines accept `context.Context`; cancellation flows from signal handler `→` context cancel `→` component Stop() methods.
