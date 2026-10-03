<#
    ProcWatch end-to-end check.

    Runs the freshly built injector against the freshly built test target, then
    reads the events back out of the injected process's own WebUI and fails if
    anything the target deliberately does is missing.

    This is not a "does it compile" check, on purpose. The failure this exists
    to catch is the one where the import tables are patched correctly but the
    hooks are never called - the build is clean, the process starts and runs
    normally, and the event log stays empty. Nothing short of driving the real
    thing and reading the events back catches that.

    Two things that would otherwise make this flaky are disabled here:
    --gui=0 keeps the run independent of whether the runner has a usable
    desktop, and a fixed --port makes the WebUI address predictable.
#>
[CmdletBinding()]
param(
    [string]$Dist = "dist",
    [int]$Port = 18710,
    [int]$TimeoutSeconds = 150
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# The event data and the injector's own output are UTF-8. Without this, the
# Chinese text in the sample below turns into mojibake in the CI log.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$injector   = Join-Path $Dist "injector.exe"
$target     = Join-Path $Dist "testtarget.exe"
$monitorDll = Join-Path $Dist "ProcWatch.dll"
$base       = "http://127.0.0.1:$Port"

function Fail([string]$msg) {
    Write-Host ""
    Write-Host "FAIL: $msg" -ForegroundColor Red
    if (Test-Path "injector.out.log") {
        Write-Host "--- injector output ---" -ForegroundColor Yellow
        Get-Content "injector.out.log" -Encoding UTF8 | Write-Host
    }
    exit 1
}

function Get-Json([string]$path) {
    try { return Invoke-RestMethod -Uri "$base$path" -TimeoutSec 3 }
    catch { return $null }
}

foreach ($f in @($injector, $target, $monitorDll)) {
    if (-not (Test-Path $f)) { Fail "missing build output: $f" }
}

# Any leftovers from an earlier step would hold the port or confuse the count.
Get-Process testtarget, injector -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "starting: $injector --exe $target --gui=0 --port=$Port"
$proc = Start-Process -FilePath $injector `
                      -ArgumentList @("--exe", $target, "--gui=0", "--port=$Port") `
                      -PassThru -NoNewWindow `
                      -RedirectStandardOutput "injector.out.log" `
                      -RedirectStandardError "injector.err.log"

try {
    # --- wait for the monitor to come up -------------------------------------
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $meta = $null
    while ((Get-Date) -lt $deadline) {
        $meta = Get-Json "/api/meta"
        if ($meta -and $meta.pid) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $meta) { Fail "the monitor never answered on $base/api/meta" }

    Write-Host ("monitor attached: pid={0} exe={1} hooks={2} patches={3} gui={4}" -f `
                $meta.pid, $meta.exe, $meta.hooks, $meta.patches, $meta.gui)

    if ($meta.patches -lt 50) { Fail "only $($meta.patches) import entries were patched" }
    if ($meta.hooks   -lt 60) { Fail "only $($meta.hooks) hooks resolved" }

    # --- let the target work through its phases ------------------------------
    Write-Host "waiting for the target to exercise every behaviour..."
    $stats = $null
    while ((Get-Date) -lt $deadline) {
        $stats = Get-Json "/api/stats"
        if ($stats -and $stats.cat.mem -ge 2) { break }   # memory phase is last
        Start-Sleep -Seconds 2
    }
    if (-not $stats) { Fail "the monitor stopped answering /api/stats" }

    Write-Host ""
    Write-Host "captured:"
    $stats | ConvertTo-Json -Depth 4

    # --- assertions ----------------------------------------------------------
    # Thresholds are well below what a healthy run produces (locally ~250 events
    # across all eight categories) so this fails on a real regression rather
    # than on timing jitter.
    $checks = @(
        @{ name = "total events";   pass = $stats.total  -ge 30 },
        @{ name = "file activity";  pass = $stats.cat.file -ge 5 },
        @{ name = "registry";       pass = $stats.cat.reg  -ge 3 },
        @{ name = "network";        pass = $stats.cat.net  -ge 2 },
        @{ name = "http";           pass = $stats.cat.http -ge 2 },
        @{ name = "process";        pass = $stats.cat.proc -ge 1 },
        @{ name = "modules";        pass = $stats.cat.mod  -ge 1 },
        @{ name = "memory";         pass = $stats.cat.mem  -ge 2 },
        @{ name = "rule hits";      pass = $stats.lvl.suspect -ge 3 }
    )
    $failed = @($checks | Where-Object { -not $_.pass })
    foreach ($c in $checks) {
        $mark = if ($c.pass) { "ok  " } else { "MISS" }
        Write-Host ("  [{0}] {1}" -f $mark, $c.name)
    }

    # A sample of what the rule engine flagged, so a failure is diagnosable
    # from the log alone. Falls back to whatever came first if no rule fired.
    $events = Get-Json "/api/events?after=0&limit=400"
    if ($events -and $events.events) {
        $interesting = @($events.events | Where-Object { $_.lvl -ge 1 })
        if ($interesting.Count -eq 0) { $interesting = @($events.events) }
        Write-Host ""
        Write-Host ("sample of what was flagged ({0} of {1} events shown):" -f `
                    [Math]::Min(8, $interesting.Count), $events.events.Count)
        foreach ($e in ($interesting | Select-Object -First 8)) {
            Write-Host ("  [{0}] {1,-20} {2}" -f $e.lvlName, $e.api, $e.target)
            if ($e.detail) { Write-Host ("         " + $e.detail) }
        }
    }

    if ($failed.Count -gt 0) {
        Fail ("did not observe: " + (($failed | ForEach-Object { $_.name }) -join ", "))
    }

    Write-Host ""
    Write-Host "PASS: every monitored category produced events" -ForegroundColor Green
}
finally {
    Get-Process testtarget -ErrorAction SilentlyContinue | Stop-Process -Force
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    Write-Host ""
    Write-Host "--- injector stdout ---"
    # -Encoding UTF8 explicitly: Windows PowerShell 5.1 otherwise reads a file
    # without a BOM as ANSI and mangles the Chinese output.
    if (Test-Path "injector.out.log") { Get-Content "injector.out.log" -Encoding UTF8 }
    Write-Host "--- injector stderr ---"
    if (Test-Path "injector.err.log") { Get-Content "injector.err.log" -Encoding UTF8 }
}
