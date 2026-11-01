# Wantastic Agent - Windows Install Script
# Registers wantasticd as a Windows Service via sc.exe (no extra dependencies).
# The notification-area (tray) app starts for every user at logon; pass
# -NoTray to skip it.
#
# Run in PowerShell opened with "Run as administrator", from any folder:
#   irm https://get.wantastic.app/install.ps1 | iex
# With a login token (no browser step):
#   & ([scriptblock]::Create((irm https://get.wantastic.app/install.ps1))) -Token <TOKEN>
# From a saved copy (save it to a writable folder such as $env:TEMP):
#   powershell -ExecutionPolicy Bypass -File "$env:TEMP\install.ps1" [-Token <TOKEN>] [-NoTray]
#
# Requires Windows 10 / Windows Server 2016 or newer (the Go runtime that
# builds wantasticd does not run on Windows 7, 8 or 8.1).
#
# Keep this file ASCII-only: Windows PowerShell 5.1 reads scripts without a
# BOM, and `irm` responses without a charset, as the ANSI code page.

param(
    [string]$Token = $env:WANTASTIC_TOKEN,
    [switch]$NoTray
)

function Install-Wantasticd {
    param([string]$Token, [switch]$NoTray)

    $ErrorActionPreference = "Stop"
    # Invoke-WebRequest's progress bar slows downloads tenfold on 5.1.
    $ProgressPreference = "SilentlyContinue"

    $BaseUrl     = "https://get.wantastic.app"
    $ServiceName = "wantasticd"
    $InstallDir  = Join-Path $env:ProgramFiles "Wantastic"
    $InstallPath = Join-Path $InstallDir "wantasticd.exe"
    $ConfigDir   = Join-Path $env:ProgramData "Wantastic"
    $ConfigFile  = Join-Path $ConfigDir "config.conf"
    $RunKey      = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $TrayValue   = "Wantastic"
    $FirewallRule = "Wantastic-wantasticd"

    Write-Host "Wantastic Agent - Windows Installer" -ForegroundColor Cyan
    Write-Host "===================================`n"

    # -- require admin ---------------------------------------------------------
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    # No self-elevation: relaunching PowerShell elevated is a pattern antivirus
    # flags, and under `irm | iex` there is no script file to relaunch anyway.
    if (-not $isAdmin) {
        Write-Host "Administrator privileges are required." -ForegroundColor Yellow
        Write-Host "Right-click PowerShell, choose 'Run as administrator', and run again:"
        Write-Host "  irm $BaseUrl/install.ps1 | iex"
        return
    }

    # -- Windows version -------------------------------------------------------
    $os = [Environment]::OSVersion.Version
    if ($os.Major -lt 10) {
        throw "Windows $($os.Major).$($os.Minor) is not supported. wantasticd needs Windows 10, Windows 11 or Windows Server 2016 or newer."
    }

    # -- TLS 1.2 ---------------------------------------------------------------
    # Windows PowerShell 5.1 on older Windows 10 builds offers only SSL3/TLS1.0
    # by default; the download host requires TLS 1.2 or newer. Add it without
    # removing anything the system already enables (TLS 1.3 where present).
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    # -- architecture ----------------------------------------------------------
    # The registry holds the native architecture even when this PowerShell is
    # a 32-bit or x64-emulated process (WOW64, Windows on ARM).
    $nativeArch = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    if (-not $nativeArch) { $nativeArch = $env:PROCESSOR_ARCHITECTURE }
    $GoArch = switch -Regex ($nativeArch) {
        "ARM64" { "arm64" }
        "AMD64" { "amd64" }
        "x86"   { "386" }
        default { "amd64" }
    }
    Write-Host "Windows $($os.Major).$($os.Minor) build $($os.Build), architecture windows/$GoArch"

    # -- latest version --------------------------------------------------------
    Write-Host "Fetching latest version..."
    $Version = Invoke-RestMethod -Uri "$BaseUrl/latest" -UseBasicParsing
    if ($Version -is [byte[]]) { $Version = [Text.Encoding]::UTF8.GetString($Version) }
    $Version = ([string]$Version).Trim()
    if (-not $Version) { throw "Could not determine the latest version." }
    Write-Host "Version: $Version"

    # -- download --------------------------------------------------------------
    # Immutable per-release path: /latest/ can stay cached at the edge after the
    # version marker has moved on.
    $ReleaseTag = ($Version -split '\+')[0]
    if ($ReleaseTag -notmatch '^[A-Za-z0-9._-]+$') { throw "Invalid release version: $Version" }
    $BinaryUrl = "$BaseUrl/$ReleaseTag/wantasticd-windows-${GoArch}.zip"
    $TempDir   = Join-Path ([IO.Path]::GetTempPath()) "wantasticd_install_$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    try {
        $ZipPath = Join-Path $TempDir "wantasticd.zip"
        Write-Host "Downloading $BinaryUrl..."
        for ($attempt = 1; ; $attempt++) {
            try {
                Invoke-WebRequest -Uri $BinaryUrl -OutFile $ZipPath -UseBasicParsing
                break
            } catch {
                if ($attempt -ge 3) { throw "Download failed: $($_.Exception.Message)" }
                Write-Host "  Download failed, retrying ($attempt/3)..."
                Start-Sleep -Seconds (2 * $attempt)
            }
        }

        Write-Host "Extracting..."
        $ExtractDir = Join-Path $TempDir "files"
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
        } else {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractDir)
        }
        $ExtractedBin = Get-ChildItem -Path $ExtractDir -Filter "wantasticd.exe" -Recurse | Select-Object -First 1
        if (-not $ExtractedBin) { throw "wantasticd.exe not found in the downloaded archive." }

        # -- verify publisher --------------------------------------------------
        # Signed releases must be signed by Wantastic LLC; a broken or foreign
        # signature means the download was tampered with. Unsigned builds
        # predate release signing and are still accepted.
        $Signature = Get-AuthenticodeSignature -FilePath $ExtractedBin.FullName
        switch ($Signature.Status) {
            "Valid" {
                if ($Signature.SignerCertificate.Subject -notmatch "Wantastic LLC") {
                    throw "wantasticd.exe is signed by an unexpected publisher: $($Signature.SignerCertificate.Subject)"
                }
                Write-Host "Signature: valid (Wantastic LLC)"
            }
            "NotSigned" {
                Write-Warning "wantasticd.exe is not code-signed (release predates signing)."
            }
            default {
                throw "wantasticd.exe signature check failed: $($Signature.Status) $($Signature.StatusMessage)"
            }
        }

        # -- install binary ----------------------------------------------------
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "Stopping existing service..."
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            try { $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20)) } catch {}
        }
        # Tray apps run the same .exe; Windows will not replace an image in use.
        Get-Process -Name "wantasticd" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        New-Item -ItemType Directory -Force -Path $ConfigDir  | Out-Null
        # Keep the previous build for manual rollback, like self-update does.
        if (Test-Path $InstallPath) {
            Copy-Item -Path $InstallPath -Destination "$InstallPath.previous" -Force
        }
        Remove-Item -Force -ErrorAction SilentlyContinue "$InstallPath.new", "$InstallPath.failed"
        for ($attempt = 1; ; $attempt++) {
            try {
                Copy-Item -Path $ExtractedBin.FullName -Destination $InstallPath -Force
                break
            } catch {
                # A process that was just stopped can hold the image briefly.
                if ($attempt -ge 5) { throw "Could not replace ${InstallPath}: $($_.Exception.Message)" }
                Start-Sleep -Seconds 1
            }
        }
        # Downloaded files carry a "from the internet" mark; this copy was verified.
        Unblock-File -Path $InstallPath -ErrorAction SilentlyContinue
        Write-Host "Installed to $InstallPath"
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
    }

    # -- PATH ------------------------------------------------------------------
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries = @($machinePath -split ';' | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('\') })
    if ($entries -notcontains $InstallDir.TrimEnd('\')) {
        [Environment]::SetEnvironmentVariable("Path", ($machinePath.TrimEnd(';') + ";$InstallDir"), "Machine")
        Write-Host "Added $InstallDir to the system PATH."
    }
    if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path = "$env:Path;$InstallDir" }

    # -- firewall --------------------------------------------------------------
    # Direct peer-to-peer paths need inbound UDP to the service; without a rule
    # Windows Firewall drops it silently and every peer stays on relay.
    try {
        Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name $FirewallRule -DisplayName "Wantastic (wantasticd)" -Direction Inbound `
            -Action Allow -Program $InstallPath -Protocol UDP -Profile Any | Out-Null
        Write-Host "Windows Firewall: inbound UDP allowed for wantasticd."
    } catch {
        Write-Warning "Could not add the Windows Firewall rule; peers may connect through the relay only."
    }

    # -- login -----------------------------------------------------------------
    $loggedIn = $false
    if (-not $Token -and (Test-Path $ConfigFile) -and
        (Select-String -Path $ConfigFile -Pattern '^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=' -Quiet)) {
        Write-Host "`nKeeping the existing login in $ConfigFile (run 'wantasticd login' to switch accounts)."
        $loggedIn = $true
    } else {
        Write-Host "`n=== Logging in ==="
        # --no-connect: save the configuration and exit; the service connects.
        $loginArgs = @("login", "--no-connect")
        if ($Token) { $loginArgs += @("--token", $Token) }
        # Start-Process -Wait shares this console and waits, also for older
        # GUI-subsystem builds that `&` would not wait for.
        $login = Start-Process -FilePath $InstallPath -ArgumentList $loginArgs -NoNewWindow -Wait -PassThru
        if ($login.ExitCode -eq 0) {
            $loggedIn = $true
        } else {
            Write-Warning "Login did not complete (exit $($login.ExitCode))."
        }
    }

    # -- register Windows Service via sc.exe -----------------------------------
    Write-Host "`n=== Installing Windows Service ==="
    # The service runs in session 0 with no desktop; the tray is a per-user app.
    # binPath is one string holding the quoted executable and its arguments.
    $binPath = "`"$InstallPath`" connect --config `"$ConfigFile`" --tray=false"
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        # Reconfigure in place: delete + create fails with "marked for
        # deletion" while anything (services.msc, Task Manager) holds a handle.
        Invoke-ScChecked @("config", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Wantastic Overlay Networking") "update the Windows service"
    } else {
        Invoke-ScChecked @("create", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Wantastic Overlay Networking") "create the Windows service"
    }
    Invoke-ScChecked @("description", $ServiceName, "Wantastic secure overlay networking agent.") "set the service description"
    # Recovery: restart on failure (1st: 5s, 2nd: 10s, subsequent: 30s).
    Invoke-ScChecked @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000") "configure service recovery"

    if (-not $loggedIn) {
        Write-Host "`nThe service is installed but not started because this device is not logged in yet." -ForegroundColor Yellow
        Write-Host "Log in, then start it:"
        Write-Host "  wantasticd login --no-connect"
        Write-Host "  sc.exe start $ServiceName"
        Install-Tray $InstallPath $RunKey $TrayValue $NoTray
        return
    }

    Write-Host "Starting service..."
    Invoke-ScChecked @("start", $ServiceName) "start the Windows service"
    $svc = Get-Service -Name $ServiceName
    try {
        $svc.WaitForStatus("Running", [TimeSpan]::FromSeconds(20))
    } catch {
        throw "The wantasticd service did not reach the Running state within 20 seconds. Check Event Viewer > Windows Logs > Application."
    }
    $serviceConfig = (& sc.exe qc $ServiceName) | Out-String
    if ($serviceConfig -notmatch "AUTO_START") {
        throw "The wantasticd service was not configured for automatic startup."
    }

    Write-Host "`nwantasticd $Version is installed and running as a Windows Service." -ForegroundColor Green
    Install-Tray $InstallPath $RunKey $TrayValue $NoTray

    Write-Host "`nUseful commands:"
    Write-Host "  wantasticd status            - connection and peers"
    Write-Host "  sc.exe stop    $ServiceName   - stop"
    Write-Host "  sc.exe start   $ServiceName   - start"
}

function Invoke-ScChecked {
    param([string[]]$Arguments, [string]$Action)
    $output = & sc.exe @Arguments | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to $Action (sc.exe exit code $LASTEXITCODE): $($output.Trim())"
    }
}

function Install-Tray {
    param([string]$InstallPath, [string]$RunKey, [string]$TrayValue, [bool]$NoTray)
    if ($NoTray) {
        Remove-ItemProperty -Path $RunKey -Name $TrayValue -ErrorAction SilentlyContinue
        Write-Host "Tray app disabled (-NoTray)."
        return
    }
    Set-ItemProperty -Path $RunKey -Name $TrayValue -Value "`"$InstallPath`" tray"
    try {
        Start-Process -FilePath $InstallPath -ArgumentList "tray" -WindowStyle Hidden
        Write-Host "Tray app started; it also starts at every logon."
    } catch {
        Write-Host "Tray app registered; it starts at the next logon."
    }
}

# Errors are printed, never `exit`: under `irm | iex` exit closes the window
# before the message can be read.
try {
    Install-Wantasticd -Token $Token -NoTray:$NoTray
} catch {
    Write-Host "`nInstallation failed: $($_.Exception.Message)" -ForegroundColor Red
}
