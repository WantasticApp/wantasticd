# Wantastic Agent - Windows Install Script
# Installs wantasticd as a Windows Service, opens Windows Firewall for it, and
# starts the notification-area (tray) app for every user at logon.
#
# Run in PowerShell opened with "Run as administrator", from any folder:
#   irm https://get.wantastic.app/install.ps1 | iex
# With options (any combination):
#   & ([scriptblock]::Create((irm https://get.wantastic.app/install.ps1))) -Token <TOKEN>
#
# Options:
#   (default)          claim: shows a QR code; the device connects once you
#                      approve it in the console. Nothing waits here.
#   -Token <TOKEN>     log in with a token instead
#   -Login             sign in through the browser (device code) instead
#   -NoLogin           install only; add the device later
#   -NoTray            do not start the tray app at logon
#   -Version <vX.Y.Z>  install that release instead of the latest
#   -ZipPath <file>    install from a downloaded wantasticd-windows-*.zip
#   -Uninstall         remove wantasticd (keeps the login; add -Purge to drop it)
#
# Requires Windows 10 / Windows Server 2016 or newer (the Go runtime that
# builds wantasticd does not run on Windows 7, 8 or 8.1). Works in Windows
# PowerShell 5.1 and PowerShell 7.
#
# Keep this file ASCII-only: Windows PowerShell 5.1 reads scripts without a
# BOM, and `irm` responses without a charset, as the ANSI code page.

param(
    [string]$Token = $env:WANTASTIC_TOKEN,
    [switch]$NoTray,
    [switch]$NoLogin,
    [switch]$Login,
    [string]$Version,
    [string]$ZipPath,
    [switch]$Uninstall,
    [switch]$Purge
)

$Wantastic = @{
    BaseUrl      = "https://get.wantastic.app"
    ServiceName  = "wantasticd"
    DisplayName  = "Wantastic Overlay Networking"
    Description  = "Wantastic secure overlay networking agent."
    InstallDir   = Join-Path $env:ProgramFiles "Wantastic"
    ConfigDir    = Join-Path $env:ProgramData "Wantastic"
    RunKey       = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    TrayValue    = "Wantastic"
    FirewallRule = "Wantastic-wantasticd"
}
$Wantastic.InstallPath = Join-Path $Wantastic.InstallDir "wantasticd.exe"
$Wantastic.ConfigFile  = Join-Path $Wantastic.ConfigDir "config.conf"

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "   $Text" }

function Test-Administrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NativeArch {
    # The registry holds the native architecture even when this PowerShell is
    # a 32-bit or x64-emulated process (WOW64, Windows on ARM).
    $arch = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch -Regex ($arch) {
        "ARM64" { return "arm64" }
        "AMD64" { return "amd64" }
        "x86"   { return "386" }
        default { return "amd64" }
    }
}

function Invoke-Download([string]$Url, [string]$OutFile) {
    for ($attempt = 1; ; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
            return
        } catch {
            if ($attempt -ge 3) { throw "Download of $Url failed: $($_.Exception.Message)" }
            Write-Info "Download failed, retrying ($attempt/3)..."
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

function Get-LatestVersion {
    $v = Invoke-RestMethod -Uri "$($Wantastic.BaseUrl)/latest" -UseBasicParsing
    if ($v -is [byte[]]) { $v = [Text.Encoding]::UTF8.GetString($v) }
    $v = ([string]$v).Trim()
    if (-not $v) { throw "Could not determine the latest version." }
    return $v
}

# Signed releases must be signed by Wantastic LLC; a broken or foreign
# signature means the file was tampered with. Unsigned builds predate release
# signing and are still accepted.
function Assert-Publisher([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    switch ($sig.Status) {
        "Valid" {
            if ($sig.SignerCertificate.Subject -notmatch "Wantastic LLC") {
                throw "$(Split-Path $Path -Leaf) is signed by an unexpected publisher: $($sig.SignerCertificate.Subject)"
            }
            Write-Ok "Signature: valid (Wantastic LLC)"
        }
        "NotSigned" { Write-Info "Signature: none (this release predates code signing)" }
        default     { throw "$(Split-Path $Path -Leaf) signature check failed: $($sig.Status) $($sig.StatusMessage)" }
    }
}

function Stop-Wantasticd {
    $svc = Get-Service -Name $Wantastic.ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Stopped") {
        Write-Info "Stopping the service..."
        Stop-Service -Name $Wantastic.ServiceName -Force -ErrorAction SilentlyContinue
        try { $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20)) } catch {}
    }
    # Tray apps run the same .exe; Windows will not replace an image in use.
    Get-Process -Name "wantasticd" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# Registers or reconfigures the service through the Service Control Manager
# API (New-Service, Win32_Service.Change). sc.exe is avoided: Windows
# PowerShell 5.1 strips the quotes inside binPath when calling native
# programs, and sc.exe then rejects the whole command line.
function Register-WantasticService([string]$BinPath) {
    $name = $Wantastic.ServiceName
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    if ($cim) {
        # Reconfigure in place: delete + create fails with "marked for
        # deletion" while anything (services.msc, Task Manager) holds a handle.
        $r = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{
            DisplayName = $Wantastic.DisplayName
            PathName    = $BinPath
            StartMode   = "Automatic"
        }
        if ($r.ReturnValue -ne 0) {
            throw "Could not update the Windows service (Win32_Service.Change returned $($r.ReturnValue)). Close the Services window and Task Manager, then run the installer again."
        }
        Set-Service -Name $name -Description $Wantastic.Description
        Write-Ok "Service updated."
    } else {
        try {
            New-Service -Name $name -BinaryPathName $BinPath -DisplayName $Wantastic.DisplayName `
                -Description $Wantastic.Description -StartupType Automatic | Out-Null
        } catch {
            throw "Could not create the Windows service: $($_.Exception.Message)"
        }
        Write-Ok "Service created."
    }

    # Restart on failure (1st: 5s, 2nd: 10s, later: 30s). No quoted values, so
    # sc.exe is safe here.
    $out = & sc.exe failure $name reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not set service recovery actions: $($out.Trim())" }

    $check = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if (-not $check -or $check.PathName -ne $BinPath -or $check.StartMode -ne "Auto") {
        throw "The Windows service was not registered as expected (path: $($check.PathName), start: $($check.StartMode))."
    }
}

function Set-MachinePath([switch]$Remove) {
    $dir = $Wantastic.InstallDir.TrimEnd('\')
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries = @($machinePath -split ';' | Where-Object { $_.Trim() })
    $present = @($entries | Where-Object { $_.Trim().TrimEnd('\') -ieq $dir }).Count -gt 0
    if ($Remove) {
        if ($present) {
            $kept = $entries | Where-Object { $_.Trim().TrimEnd('\') -ine $dir }
            [Environment]::SetEnvironmentVariable("Path", ($kept -join ';'), "Machine")
            Write-Ok "Removed $dir from the system PATH."
        }
        return
    }
    if (-not $present) {
        [Environment]::SetEnvironmentVariable("Path", ($machinePath.TrimEnd(';') + ";$dir"), "Machine")
        Write-Ok "Added $dir to the system PATH."
    }
    if (($env:Path -split ';') -notcontains $dir) { $env:Path = "$env:Path;$dir" }
}

# Runs a native program and returns its exit code and combined output.
# Windows PowerShell 5.1 turns redirected stderr into errors, which
# $ErrorActionPreference = "Stop" would make fatal.
function Invoke-Exe([string]$Exe, [string[]]$Arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    return [pscustomobject]@{ Code = $code; Output = (@($out) -join "`n") }
}

# Fallback for releases before 1.0.59; newer ones add their own rules.
function Set-FirewallRule {
    # Direct peer-to-peer paths need inbound UDP to the service; without a rule
    # Windows Firewall drops it silently and every peer stays on relay.
    try {
        Get-NetFirewallRule -Name $Wantastic.FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name $Wantastic.FirewallRule -DisplayName "Wantastic (wantasticd)" -Direction Inbound `
            -Action Allow -Program $Wantastic.InstallPath -Protocol UDP -Profile Any | Out-Null
        Write-Ok "Windows Firewall: inbound UDP allowed for wantasticd."
    } catch {
        Write-Warning "Could not add the Windows Firewall rule; peers may connect through the relay only."
    }
}

function Install-Tray([bool]$Skip) {
    if ($Skip) {
        Remove-ItemProperty -Path $Wantastic.RunKey -Name $Wantastic.TrayValue -ErrorAction SilentlyContinue
        Write-Info "Tray app disabled (-NoTray)."
        return
    }
    Set-ItemProperty -Path $Wantastic.RunKey -Name $Wantastic.TrayValue -Value "`"$($Wantastic.InstallPath)`" tray"
    try {
        Start-Process -FilePath $Wantastic.InstallPath -ArgumentList "tray" -WindowStyle Hidden
        Write-Ok "Tray app started; it also starts at every logon."
    } catch {
        Write-Info "Tray app registered; it starts at the next logon."
    }
}

# The config is JSON ("private_key"); older releases wrote "PrivateKey = ...".
function Test-LoggedIn {
    (Test-Path $Wantastic.ConfigFile) -and
        (Select-String -Path $Wantastic.ConfigFile -Quiet `
            -Pattern '"private_key"\s*:\s*"[A-Za-z0-9+/]{43}="', '^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=')
}

function Install-Wantasticd {
    param([string]$Token, [bool]$NoTray, [bool]$NoLogin, [bool]$Login, [string]$Version, [string]$ZipPath)

    $os = [Environment]::OSVersion.Version
    if ($os.Major -lt 10) {
        throw "Windows $($os.Major).$($os.Minor) is not supported. wantasticd needs Windows 10, Windows 11 or Windows Server 2016 or newer."
    }
    $arch = Get-NativeArch
    Write-Info "Windows $($os.Major).$($os.Minor) build $($os.Build), windows/$arch, PowerShell $($PSVersionTable.PSVersion)"

    $TempDir = Join-Path ([IO.Path]::GetTempPath()) "wantasticd_install_$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    $expected = $null
    try {
        # -- download ----------------------------------------------------------
        if ($ZipPath) {
            Write-Step "Using $ZipPath"
            $ZipPath = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
        } else {
            Write-Step "Downloading"
            if (-not $Version) { $Version = Get-LatestVersion }
            # Immutable per-release path: /latest/ can stay cached at the edge
            # after the version marker has moved on.
            $tag = ($Version -split '\+')[0]
            if ($tag -notmatch '^v?[0-9][A-Za-z0-9._-]*$') { throw "Invalid release version: $Version" }
            if ($tag -notmatch '^v') { $tag = "v$tag" }
            # ?v= carries the full version (with commit) so a CDN copy cached
            # before a tag was rebuilt is never used.
            $url = "$($Wantastic.BaseUrl)/$tag/wantasticd-windows-$arch.zip?v=$([uri]::EscapeDataString($Version))"
            $expected = $Version
            Write-Info "Version $Version"
            Write-Info $url
            $ZipPath = Join-Path $TempDir "wantasticd.zip"
            Invoke-Download $url $ZipPath
        }

        $extractDir = Join-Path $TempDir "files"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $extractDir)
        $bin = Get-ChildItem -Path $extractDir -Filter "wantasticd.exe" -Recurse | Select-Object -First 1
        if (-not $bin) { throw "wantasticd.exe not found in the archive." }
        Assert-Publisher $bin.FullName

        # Refuse an archive for another architecture or a broken binary before
        # touching the installed copy.
        $reported = (& $bin.FullName version | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $reported -notmatch '(?m)^wantasticd version (\S+)') {
            throw "The downloaded wantasticd.exe does not run on this computer (windows/$arch): $reported"
        }
        $Version = $Matches[1]
        if ($expected -and $expected.Contains("+") -and $Version -ne $expected) {
            throw "The download server returned wantasticd $Version instead of $expected (an outdated cached copy). Wait a few minutes and run the installer again."
        }

        # -- install binary ----------------------------------------------------
        Write-Step "Installing wantasticd $Version"
        Stop-Wantasticd
        New-Item -ItemType Directory -Force -Path $Wantastic.InstallDir | Out-Null
        New-Item -ItemType Directory -Force -Path $Wantastic.ConfigDir  | Out-Null
        $target = $Wantastic.InstallPath
        # Keep the previous build for manual rollback, like self-update does.
        if (Test-Path $target) { Copy-Item -Path $target -Destination "$target.previous" -Force }
        Remove-Item -Force -ErrorAction SilentlyContinue "$target.new", "$target.failed"
        for ($attempt = 1; ; $attempt++) {
            try {
                Copy-Item -Path $bin.FullName -Destination $target -Force
                break
            } catch {
                # A process that was just stopped can hold the image briefly.
                if ($attempt -ge 10) { throw "Could not replace ${target}: $($_.Exception.Message)" }
                Start-Sleep -Seconds 1
            }
        }
        # Downloaded files carry a "from the internet" mark; this copy was verified.
        Unblock-File -Path $target -ErrorAction SilentlyContinue
        Write-Ok "Installed to $target"

        # Wintun: the tunnel driver wantasticd loads from its own folder. The
        # release ships the build for this architecture, signed by WireGuard LLC.
        $dll = Get-ChildItem -Path $extractDir -Filter "wintun.dll" -Recurse | Select-Object -First 1
        $dllTarget = Join-Path $Wantastic.InstallDir "wintun.dll"
        if ($dll) {
            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName
            if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "WireGuard LLC") {
                throw "wintun.dll in the archive is not validly signed by WireGuard LLC ($($sig.Status))."
            }
            for ($attempt = 1; ; $attempt++) {
                try {
                    Copy-Item -Path $dll.FullName -Destination $dllTarget -Force
                    break
                } catch {
                    if ($attempt -ge 10) { throw "Could not replace ${dllTarget}: $($_.Exception.Message)" }
                    Start-Sleep -Seconds 1
                }
            }
            Unblock-File -Path $dllTarget -ErrorAction SilentlyContinue
            Write-Ok "Tunnel driver: wintun.dll ($($dll.VersionInfo.FileVersion), $arch)"
        } elseif (-not (Test-Path $dllTarget)) {
            Write-Warning "This release does not include wintun.dll; the tunnel cannot start until it is installed."
        }
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
    }

    Set-MachinePath
    $exe = $Wantastic.InstallPath
    # Releases from 1.0.59 register the service and firewall rules themselves
    # through the Service Control Manager API; older ones (-Version) cannot.
    $native = (Invoke-Exe $exe @("service")).Output -notmatch 'Unknown command'

    # -- sign-in ---------------------------------------------------------------
    # Default: claim. The service waits for this device's claim key to be
    # claimed in the console and connects on its own, so nothing here blocks.
    Write-Step "Sign-in"
    $mode = "none"
    $claimUrl = $null
    if (-not $Token -and (Test-LoggedIn)) {
        Write-Ok "Keeping the existing login (run 'wantasticd login' to switch accounts)."
        $mode = "loggedin"
    } elseif ($Token -or $Login) {
        # --no-connect: save the configuration and exit; the service connects.
        $loginArgs = @("login", "--no-connect")
        if ($Token) { $loginArgs += @("--token", $Token) }
        # Start-Process -Wait shares this console and waits, also for older
        # GUI-subsystem builds that `&` would not wait for.
        $login = Start-Process -FilePath $exe -ArgumentList $loginArgs -NoNewWindow -Wait -PassThru
        if ($login.ExitCode -eq 0 -and (Test-LoggedIn)) {
            $mode = "loggedin"
        } else {
            Write-Warning "Login did not complete (exit $($login.ExitCode))."
        }
    } elseif ($NoLogin) {
        Write-Info "Skipped (-NoLogin)."
    } else {
        $gen = Invoke-Exe $exe @("genkey", "--no-wait")
        Write-Host $gen.Output
        if ($gen.Code -ne 0) { throw "Could not create the device claim key (exit $($gen.Code))." }
        if ($gen.Output -match '(?m)^Claim URL: (\S+)') { $claimUrl = $Matches[1] }
        $mode = "claim"
    }
    $start = $mode -ne "none"

    # -- service ---------------------------------------------------------------
    Write-Step "Windows Service"
    if ($native) {
        $svcArgs = @("service", "install", "--config", $Wantastic.ConfigFile)
        if (-not $start) { $svcArgs += "--no-start" }
        $r = Invoke-Exe $exe $svcArgs
        $r.Output -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Info $_ }
        if ($r.Code -ne 0) { throw "Service setup failed (exit $($r.Code)). Check Event Viewer > Windows Logs > Application." }
    } else {
        # The service runs in session 0 with no desktop; the tray is a per-user app.
        $binPath = "`"$exe`" connect --config `"$($Wantastic.ConfigFile)`" --tray=false"
        Register-WantasticService $binPath
        Set-FirewallRule
        if ($start) {
            Start-Service -Name $Wantastic.ServiceName
            try {
                (Get-Service -Name $Wantastic.ServiceName).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
            } catch {
                throw "The service did not reach the Running state within 30 seconds. Check Event Viewer > Windows Logs > Application."
            }
            Write-Ok "Service running."
        }
    }

    Write-Step "Tray"
    Install-Tray $NoTray

    switch ($mode) {
        "loggedin" {
            Write-Host "`nwantasticd $Version is installed and connecting; it starts with Windows." -ForegroundColor Green
        }
        "claim" {
            Write-Host "`nwantasticd $Version is installed and waiting to be added to your account." -ForegroundColor Green
            Write-Host "Scan the QR code above, or open this link, and approve the device:"
            if ($claimUrl) { Write-Host "  $claimUrl" -ForegroundColor Cyan }
            Write-Host "It connects by itself as soon as it is claimed (the tray icon turns green)."
            Write-Host "Prefer signing in here instead? Run: wantasticd login --no-connect; wantasticd service restart"
        }
        default {
            Write-Host "`nwantasticd $Version is installed but not connected yet." -ForegroundColor Yellow
            Write-Host "Add this device, then start the service (PowerShell as administrator):"
            Write-Host "  wantasticd genkey --no-wait     (claim with the QR code)   or   wantasticd login --no-connect"
            Write-Host "  wantasticd service start"
        }
    }
    Write-Host "`nUseful commands:"
    Write-Host "  wantasticd status            connection and peers"
    Write-Host "  wantasticd down / up         disconnect / reconnect"
    Write-Host "  wantasticd service status    Windows service state"
    Write-Host "  wantasticd update            install the newest release"
}

function Uninstall-Wantasticd([bool]$Purge) {
    Write-Step "Removing wantasticd"
    $exe = $Wantastic.InstallPath
    $removed = $false
    if (Test-Path $exe) {
        $r = Invoke-Exe $exe @("service", "uninstall")
        $r.Output -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Info $_ }
        $removed = $r.Code -eq 0
    }
    Stop-Wantasticd
    if (-not $removed -and (Get-Service -Name $Wantastic.ServiceName -ErrorAction SilentlyContinue)) {
        $out = & sc.exe delete $Wantastic.ServiceName | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Could not remove the Windows service: $($out.Trim())" }
        Write-Ok "Service removed."
    }
    # Rules from any installer version: netsh ones carry only a display name.
    Get-NetFirewallRule -Name $Wantastic.FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "Wantastic*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-ItemProperty -Path $Wantastic.RunKey -Name $Wantastic.TrayValue -ErrorAction SilentlyContinue
    Set-MachinePath -Remove
    for ($attempt = 1; Test-Path $Wantastic.InstallDir; $attempt++) {
        try {
            Remove-Item -Recurse -Force $Wantastic.InstallDir
            Write-Ok "Removed $($Wantastic.InstallDir)."
        } catch {
            # A process that was just stopped can hold the image briefly.
            if ($attempt -ge 10) { throw "Could not remove $($Wantastic.InstallDir): $($_.Exception.Message)" }
            Start-Sleep -Seconds 1
        }
    }
    if ($Purge) {
        for ($attempt = 1; Test-Path $Wantastic.ConfigDir; $attempt++) {
            try {
                Remove-Item -Recurse -Force $Wantastic.ConfigDir
            } catch {
                if ($attempt -ge 10) { throw "Could not remove $($Wantastic.ConfigDir): $($_.Exception.Message)" }
                Start-Sleep -Seconds 1
            }
        }
        Write-Ok "Removed the login, claim key and settings ($($Wantastic.ConfigDir))."
    } elseif (Test-Path $Wantastic.ConfigDir) {
        Write-Info "Kept the login in $($Wantastic.ConfigDir) (add -Purge to remove it)."
    }
    Write-Host "`nwantasticd is uninstalled." -ForegroundColor Green
}

function Invoke-WantasticInstaller {
    $ErrorActionPreference = "Stop"
    # Invoke-WebRequest's progress bar slows downloads tenfold on 5.1.
    $ProgressPreference = "SilentlyContinue"

    Write-Host "Wantastic for Windows" -ForegroundColor Cyan
    # No self-elevation: relaunching PowerShell elevated is a pattern antivirus
    # flags, and under `irm | iex` there is no script file to relaunch anyway.
    if (-not (Test-Administrator)) {
        Write-Host "Administrator privileges are required." -ForegroundColor Yellow
        Write-Host "Right-click PowerShell, choose 'Run as administrator', and run again:"
        Write-Host "  irm $($Wantastic.BaseUrl)/install.ps1 | iex"
        return $false
    }
    # Windows PowerShell 5.1 on older Windows 10 builds offers only SSL3/TLS1.0
    # by default; the download host requires TLS 1.2 or newer. Add it without
    # removing anything the system already enables (TLS 1.3 where present).
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    if ($Uninstall) {
        Uninstall-Wantasticd $Purge
    } else {
        Install-Wantasticd -Token $Token -NoTray $NoTray -NoLogin $NoLogin -Login $Login -Version $Version -ZipPath $ZipPath
    }
    return $true
}

# Errors are printed, never `exit`: under `irm | iex` exit closes the window
# before the message can be read. WANTASTIC_INSTALL_STRICT=1 (CI) exits 1.
$wantasticOk = $false
try {
    $wantasticOk = (Invoke-WantasticInstaller | Select-Object -Last 1) -eq $true
} catch {
    Write-Host "`nInstallation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Report it at https://github.com/WantasticApp/wantasticd/issues with the output above."
}
if (-not $wantasticOk -and $env:WANTASTIC_INSTALL_STRICT -eq "1") { exit 1 }
