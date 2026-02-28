# Wantasticd Installation Script for Windows
# https://wantastic.app

$ErrorActionPreference = "Stop"
$BaseUrl = "https://get.wantastic.app"

Write-Host "Wantasticd Installation Script for Windows" -ForegroundColor Cyan
Write-Host "========================================`n"

# 1. Detect Architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
$GoArch = "amd64"

if ($Arch -match "ARM64") {
    $GoArch = "arm64"
} elseif ($Arch -match "x86" -and (-not $env:PROCESSOR_ARCHITEW6432)) {
    $GoArch = "386"
}

Write-Host "Detected Architecture: Windows $GoArch"

# 2. Fetch Latest Version
Write-Host "Checking for latest version..."
try {
    $Version = Invoke-RestMethod -Uri "$BaseUrl/latest" -UseBasicParsing
    $Version = $Version.Trim()
} catch {
    Write-Error "Could not determine the latest version from $BaseUrl/latest"
    exit 1
}

if (-not $Version) {
    Write-Error "Empty version returned from server."
    exit 1
}

Write-Host "Latest version: $Version"

# 3. Download Binary
$BinaryUrl = "$BaseUrl/latest/wantasticd-windows-${GoArch}.zip"
$TempDir = Join-Path $env:TEMP "wantasticd_install_$(Get-Random)"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
$ZipPath = Join-Path $TempDir "wantasticd.zip"

Write-Host "Downloading $BinaryUrl..."
try {
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $ZipPath -UseBasicParsing
} catch {
    Write-Error "Failed to download the release from $BinaryUrl. HTTP Error."
    Remove-Item -Recurse -Force $TempDir
    exit 1
}

# 4. Extract
Write-Host "Extracting..."
try {
    Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
} catch {
    Write-Error "Failed to extract $ZipPath"
    Remove-Item -Recurse -Force $TempDir
    exit 1
}

# 5. Locate binary and Install
$ExtractedBin = Get-ChildItem -Path $TempDir -Filter "wantasticd.exe" -Recurse | Select-Object -First 1

if (-not $ExtractedBin) {
    Write-Error "Could not find 'wantasticd.exe' inside the downloaded archive."
    Remove-Item -Recurse -Force $TempDir
    exit 1
}

# Install Directory: C:\Program Files\Wantastic
$InstallDir = Join-Path $env:ProgramFiles "Wantastic"
$InstallPath = Join-Path $InstallDir "wantasticd.exe"

# Require Admin for Program Files
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Administrator privileges are required to install to $InstallDir!"
    Write-Host "Attempting to restart script as Administrator..."
    
    # Relaunch script with elevation
    $ScriptArgs = $args -join " "
    $MyProcess = New-Object System.Diagnostics.ProcessStartInfo
    $MyProcess.FileName = "powershell.exe"
    $MyProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $ScriptArgs"
    $MyProcess.Verb = "RunAs"
    try {
        [System.Diagnostics.Process]::Start($MyProcess) | Out-Null
    } catch {
        Write-Error "Elevation failed or was cancelled by user. Cannot continue."
    }
    exit 0
}

Write-Host "Installing to $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

try {
    # If upgrading, stop existing process first
    $Process = Get-Process -Name wantasticd -ErrorAction SilentlyContinue
    if ($Process) {
        Write-Host "Stopping existing wantasticd process..."
        Stop-Process -Name wantasticd -Force
        Start-Sleep -Seconds 2
    }

    Copy-Item -Path $ExtractedBin.FullName -Destination $InstallPath -Force
} catch {
    Write-Error "Failed to copy wantasticd.exe to $InstallDir. Is the file in use?"
    exit 1
}

# Add to system PATH if not present
$CurrentMachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($CurrentMachinePath -inotmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding $InstallDir to System PATH..."
    [Environment]::SetEnvironmentVariable("Path", $CurrentMachinePath + ";" + $InstallDir, "Machine")
}

# Cleanup
Remove-Item -Recurse -Force $TempDir

Write-Host "`nSuccess! wantasticd ($Version) has been installed to $InstallPath" -ForegroundColor Green

# 6. Desktop Shortcut / Execution
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Wantastic VPN.lnk"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $InstallPath
$Shortcut.Arguments = "connect"
$Shortcut.IconLocation = "$InstallPath, 0"
$Shortcut.Description = "Wantastic VPN Client"
$Shortcut.Save()

Write-Host "A shortcut has been placed on your Desktop."

Write-Host "`nTo connect immediately, run:" -ForegroundColor Yellow
Write-Host "wantasticd connect" -ForegroundColor Cyan

# Wait before closing if run via double click
Start-Sleep -Seconds 5
