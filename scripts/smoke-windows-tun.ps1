param(
    [string]$RustleBin = $(if ($env:RUSTLE_BIN) { $env:RUSTLE_BIN } else { Join-Path (Get-Location) "target\debug\rustle.exe" }),
    [string]$TargetCidr = $(if ($env:RUSTLE_WINDOWS_SMOKE_TARGET_CIDR) { $env:RUSTLE_WINDOWS_SMOKE_TARGET_CIDR } else { "203.0.113.77/32" }),
    [string]$TunIp = $(if ($env:RUSTLE_WINDOWS_SMOKE_TUN_IP) { $env:RUSTLE_WINDOWS_SMOKE_TUN_IP } else { "10.255.255.1" }),
    [int]$TimeoutSeconds = $(if ($env:RUSTLE_WINDOWS_SMOKE_TIMEOUT_SECONDS) { [int]$env:RUSTLE_WINDOWS_SMOKE_TIMEOUT_SECONDS } else { 20 })
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Smoke-Info([string]$Message) {
    Write-Host "smoke: $Message"
}

function Smoke-Die([string]$Message) {
    throw "smoke: $Message"
}

function Get-RouteSnapshot([string]$DestinationPrefix) {
    @(Get-NetRoute -DestinationPrefix $DestinationPrefix -ErrorAction SilentlyContinue |
        Sort-Object InterfaceIndex, NextHop, RouteMetric |
        ForEach-Object {
            "$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.InterfaceAlias)"
        })
}

function Join-Lines([string[]]$Lines) {
    return ($Lines -join "`n")
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Smoke-Die "administrator privileges are required for the Windows TUN smoke"
}

if (-not (Test-Path -LiteralPath $RustleBin -PathType Leaf)) {
    Smoke-Die "Rustle binary not found: $RustleBin"
}

$cidrParts = $TargetCidr.Split("/")
if ($cidrParts.Count -ne 2 -or $cidrParts[1] -ne "32") {
    Smoke-Die "Windows TUN smoke currently requires a /32 target CIDR, got $TargetCidr"
}
$targetIp = $cidrParts[0]

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rustle-windows-tun-smoke." + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$stderrLines = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$stdoutLines = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$process = $null
$routeBefore = @(Get-RouteSnapshot $TargetCidr)
$routeDeleteNeeded = $false

try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = (Resolve-Path -LiteralPath $RustleBin).Path
    foreach ($arg in @(
            "tun-capture",
            "--target", $TargetCidr,
            "--tun-ip", $TunIp,
            "--exit-after-packets", "1"
        )) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $process.add_ErrorDataReceived({
            param($sender, $event)
            if ($null -ne $event.Data) {
                $stderrLines.Enqueue($event.Data)
            }
        })
    $process.add_OutputDataReceived({
            param($sender, $event)
            if ($null -ne $event.Data) {
                $stdoutLines.Enqueue($event.Data)
            }
        })

    Smoke-Info "starting Windows TUN capture smoke for $TargetCidr"
    [void]$process.Start()
    $process.BeginErrorReadLine()
    $process.BeginOutputReadLine()

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $sawRoute = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $log = Join-Lines -Lines @($stderrLines.ToArray())
        if ($log -match "route: added $([regex]::Escape($TargetCidr))") {
            $sawRoute = $true
            $routeDeleteNeeded = $true
            break
        }
        if ($process.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $sawRoute) {
        Smoke-Die "Rustle did not add the target route before timeout"
    }

    Smoke-Info "opening one TCP connection toward $targetIp to generate TUN traffic"
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($targetIp, 443)
        [void]$connect.Wait([TimeSpan]::FromSeconds(3))
    } catch {
        # A connection reset is acceptable; this smoke only needs a packet to hit TUN.
    } finally {
        $client.Dispose()
    }

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Smoke-Die "Rustle did not exit after capturing one packet"
    }
    $process.WaitForExit()

    $stderr = Join-Lines -Lines @($stderrLines.ToArray())
    if ($process.ExitCode -ne 0) {
        Write-Host $stderr
        Smoke-Die "Rustle exited with status $($process.ExitCode)"
    }

    foreach ($pattern in @(
            "tun: created",
            "route: added $([regex]::Escape($TargetCidr))",
            "packet:",
            "capture: exit-after-packets reached",
            "route: deleted $([regex]::Escape($TargetCidr))"
        )) {
        if ($stderr -notmatch $pattern) {
            Write-Host $stderr
            Smoke-Die "Rustle log did not contain expected pattern: $pattern"
        }
    }
    $routeDeleteNeeded = $false

    $routeAfter = @(Get-RouteSnapshot $TargetCidr)
    if ((Join-Lines -Lines $routeAfter) -ne (Join-Lines -Lines $routeBefore)) {
        Write-Host "before route snapshot:`n$(Join-Lines -Lines $routeBefore)"
        Write-Host "after route snapshot:`n$(Join-Lines -Lines $routeAfter)"
        Smoke-Die "target route table did not return to its original state"
    }

    Smoke-Info "Windows TUN capture smoke passed"
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit()
    }
    if ($routeDeleteNeeded) {
        route.exe DELETE $targetIp MASK 255.255.255.255 $TunIp *> $null
    }
    if ($env:RUSTLE_SMOKE_KEEP_LOGS -eq "1") {
        Set-Content -LiteralPath (Join-Path $tmpDir "rustle-stderr.log") -Value (Join-Lines -Lines @($stderrLines.ToArray()))
        Set-Content -LiteralPath (Join-Path $tmpDir "rustle-stdout.log") -Value (Join-Lines -Lines @($stdoutLines.ToArray()))
        Smoke-Info "kept Windows smoke logs in $tmpDir"
    } else {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
