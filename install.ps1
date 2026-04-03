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
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# sc.exe create — binPath must include all arguments quoted as a single string
$binPath = "`"$InstallPath`" connect --config `"$ConfigFile`""
sc.exe create $ServiceName `
    binPath= $binPath `
    start=   auto `
    DisplayName= "Wantastic Overlay Networking" | Out-Null

# Description
sc.exe description $ServiceName "Wantastic secure overlay networking agent." | Out-Null

# Recovery: restart on failure (1st: 5s, 2nd: 10s, subsequent: 30s)
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host "Starting service…"
sc.exe start $ServiceName | Out-Null

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "`nwantasticd $Version is installed and running as a Windows Service." -ForegroundColor Green
} else {
    Write-Warning "Service may not have started. Check: sc.exe query $ServiceName"
}

Write-Host "`nUseful commands:"
Write-Host "  sc.exe query   $ServiceName   — check status"
Write-Host "  sc.exe stop    $ServiceName   — stop"
Write-Host "  sc.exe start   $ServiceName   — start"
Write-Host "  sc.exe delete  $ServiceName   — uninstall"

Start-Sleep -Seconds 3
