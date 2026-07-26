# Wantastic Agent — Windows Install Script
# Registers wantasticd as a Windows Service via sc.exe (no extra dependencies).
# Usage:
#   irm https://get.wantastic.app/install.ps1 | iex
#   .\install.ps1 -Token <TOKEN>

param(
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"
$BaseUrl    = "https://get.wantastic.app"
$ServiceName = "wantasticd"
$InstallDir  = Join-Path $env:ProgramFiles "Wantastic"
$InstallPath = Join-Path $InstallDir "wantasticd.exe"
$ConfigDir   = "C:\ProgramData\Wantastic"
$ConfigFile  = Join-Path $ConfigDir "config.conf"

function Invoke-ScChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Action
    )

    & sc.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to $Action (sc.exe exit code $LASTEXITCODE)."
    }
}

Write-Host "Wantastic Agent — Windows Installer" -ForegroundColor Cyan
Write-Host "====================================`n"

# ── require admin ─────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Administrator privileges required. Re-launching elevated…"
    $args = if ($Token) { "-Token `"$Token`"" } else { "" }
    Start-Process powershell -Verb RunAs `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $args"
    exit 0
}

# ── architecture ──────────────────────────────────────────────────────────────
$GoArch = switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
    "ARM64"                                          { "arm64" }
    "x86" { if (-not $env:PROCESSOR_ARCHITEW6432) { "386" } else { "amd64" } }
    default                                          { "amd64" }
}
Write-Host "Architecture: windows/$GoArch"

# ── latest version ────────────────────────────────────────────────────────────
Write-Host "Fetching latest version…"
$Version = (Invoke-RestMethod -Uri "$BaseUrl/latest" -UseBasicParsing).Trim()
if (-not $Version) { Write-Error "Could not determine latest version."; exit 1 }
Write-Host "Version: $Version"

# ── download ──────────────────────────────────────────────────────────────────
$BinaryUrl = "$BaseUrl/latest/wantasticd-windows-${GoArch}.zip"
$TempDir   = Join-Path $env:TEMP "wantasticd_install_$(Get-Random)"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
$ZipPath = Join-Path $TempDir "wantasticd.zip"

Write-Host "Downloading $BinaryUrl…"
Invoke-WebRequest -Uri $BinaryUrl -OutFile $ZipPath -UseBasicParsing

Write-Host "Extracting…"
Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

$ExtractedBin = Get-ChildItem -Path $TempDir -Filter "wantasticd.exe" -Recurse | Select-Object -First 1
if (-not $ExtractedBin) {
    Write-Error "wantasticd.exe not found in archive."
    Remove-Item -Recurse -Force $TempDir
    exit 1
}

# ── install binary ────────────────────────────────────────────────────────────
# Stop existing service/process before replacing the binary
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "Stopping existing service…"
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force -Path $InstallDir  | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir   | Out-Null
Copy-Item -Path $ExtractedBin.FullName -Destination $InstallPath -Force
Remove-Item -Recurse -Force $TempDir
Write-Host "Installed to $InstallPath"

# ── PATH ──────────────────────────────────────────────────────────────────────
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -inotmatch [regex]::Escape($InstallDir)) {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    Write-Host "Added $InstallDir to system PATH."
}
$env:PATH = "$env:PATH;$InstallDir"

# ── login ─────────────────────────────────────────────────────────────────────
Write-Host "`n=== Logging in ==="
$loginArgs = @("login")
if ($Token) { $loginArgs += @("--token", $Token) }

$loginResult = Start-Process -FilePath $InstallPath -ArgumentList $loginArgs `
    -NoNewWindow -Wait -PassThru
if ($loginResult.ExitCode -ne 0) {
    Write-Warning "Login failed (exit $($loginResult.ExitCode))."
    Write-Host "Edit $ConfigFile and re-run: wantasticd login"
    # Write placeholder config
    @"
[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address    = 10.x.x.x/32

[Peer]
PublicKey           = <YOUR_SERVER_PUBLIC_KEY>
Endpoint            = wg.wantastic.app:51820
AllowedIPs          = 10.0.0.0/8
PersistentKeepalive = 25
"@ | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Host "Placeholder config written to $ConfigFile"
}

# ── register Windows Service via sc.exe ───────────────────────────────────────
Write-Host "`n=== Installing Windows Service ==="

# Remove stale service if present
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing service…"
    Invoke-ScChecked -Arguments @("delete", $ServiceName) -Action "remove the existing service"
    Start-Sleep -Seconds 1
}

# sc.exe create — binPath must include all arguments quoted as a single string
$binPath = "`"$InstallPath`" connect --config `"$ConfigFile`""
Invoke-ScChecked `
    -Arguments @("create", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Wantastic Overlay Networking") `
    -Action "create the Windows service"

# Description
Invoke-ScChecked `
    -Arguments @("description", $ServiceName, "Wantastic secure overlay networking agent.") `
    -Action "set the service description"

# Recovery: restart on failure (1st: 5s, 2nd: 10s, subsequent: 30s)
Invoke-ScChecked `
    -Arguments @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000") `
    -Action "configure service recovery"

Write-Host "Starting service…"
Invoke-ScChecked -Arguments @("start", $ServiceName) -Action "start the Windows service"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    throw "The wantasticd service was not found after installation."
}
$svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
$svc.Refresh()
if ($svc.Status -ne "Running") {
    throw "The wantasticd service did not reach the Running state."
}

$serviceConfig = sc.exe qc $ServiceName
if ($LASTEXITCODE -ne 0 -or $serviceConfig -notmatch "AUTO_START") {
    throw "The wantasticd service was not configured for automatic startup."
}

Write-Host "`nwantasticd $Version is installed and running as a Windows Service." -ForegroundColor Green

Write-Host "`nUseful commands:"
Write-Host "  sc.exe query   $ServiceName   — check status"
Write-Host "  sc.exe stop    $ServiceName   — stop"
Write-Host "  sc.exe start   $ServiceName   — start"
Write-Host "  sc.exe delete  $ServiceName   — uninstall"

Start-Sleep -Seconds 3
