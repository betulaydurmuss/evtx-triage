<#
.SYNOPSIS
  C2: prove that a full triage runs with the network off (ADR-0003 E13, ADR-0001 section 9).

.DESCRIPTION
  Run from the repository root in a normal (non-admin) PowerShell. No admin rights needed.

  Before the run, while the network is still ON, start the server cleanly:

      foundry server stop
      while ([int](nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits) -gt 300) { Start-Sleep -Milliseconds 500 }
      foundry server start --port 5273 --idle-timeout 0

  `server start` needs the network: Foundry contacts Azure when the server starts
  (ADR-0001 section 9). Loading models and inference do not, which is what this proves.
  Then turn airplane mode ON and run this script; turn it off afterwards and paste
  out\c2\<timestamp>\c2_summary.txt into the review. The other files in that folder hold
  event data, so they stay local.

  If the run stops with a warm-up or out-of-memory error, restart the server with the three
  commands above (airplane mode can stay on) and run the script again.

  The script:
    1. checks that the network is really off (no reachable internet address, no DNS);
    2. runs `doctor` and `kb check`;
    3. runs `triage` on five eval samples from five different event channels, letting the
       tool load the models and warm up by itself;
    4. samples the TCP connections of foundrylocald and python once a second throughout and
       records every connection whose remote address is not loopback;
    5. writes out\c2\<timestamp>\c2_summary.txt: statuses, counts and hashes only, no log
       content, safe to paste into the conversation.

  -ColdStart additionally stops the server, waits for GPU memory to drain and starts it
  again while offline, to learn whether `foundry server start` works without a network.

  -AllowOnline skips the offline assertion. Only for testing this script; the summary is
  then marked NOT A C2 RUN.
#>
param(
    [switch]$ColdStart,
    [switch]$AllowOnline
)

$ErrorActionPreference = "Stop"
$repo = (Get-Location).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "run from the repository root: $python not found" }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outRoot = Join-Path $repo "out\c2\$stamp"
New-Item -ItemType Directory -Force $outRoot | Out-Null
$summaryPath = Join-Path $outRoot "c2_summary.txt"
$summary = New-Object System.Collections.Generic.List[string]
function Note([string]$line) { $summary.Add($line); Write-Host $line }

$samples = @(
    @{ csv = "sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.csv"; channel = "Sysmon" },
    @{ csv = "dacl_dcsync_right_powerview_add_domainobjectacl.csv"; channel = "Security" },
    @{ csv = "dc_applog_ntdsutil_dfir_325_326_327.csv"; channel = "Application" },
    @{ csv = "lm_remote_service02_7045.csv"; channel = "System" },
    @{ csv = "powershell_4104_minidumpwritedump_lsass.csv"; channel = "PowerShell" }
)

Note "evtx-triage C2 offline check, $stamp"
Note ("git commit: " + (git rev-parse --short HEAD))
Note ("foundry: " + ((Get-Command foundry -ErrorAction SilentlyContinue).Source))

# --- 1. is the network really off? ---------------------------------------------------
function Test-Online {
    $reachable = $false
    foreach ($target in @("1.1.1.1", "8.8.8.8", "13.107.4.52")) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $task = $client.ConnectAsync($target, 443)
            if ($task.Wait(3000) -and $client.Connected) { $reachable = $true }
        } catch { } finally { $client.Dispose() }
    }
    $dns = $false
    try { [System.Net.Dns]::GetHostAddresses("www.microsoft.com") | Out-Null; $dns = $true } catch { }
    return @{ tcp = $reachable; dns = $dns }
}

$online = Test-Online
Note "network: internet tcp reachable=$($online.tcp), dns resolves=$($online.dns)"
if ($online.tcp -or $online.dns) {
    if ($AllowOnline) {
        Note "*** NOT A C2 RUN: the network is on (-AllowOnline was given) ***"
    } else {
        Note "ABORT: the network is on. Turn airplane mode on and run again."
        $summary | Out-File -Encoding utf8 $summaryPath
        exit 2
    }
}

# --- connection sampler: foundrylocald and python, non-loopback remotes --------------
$connectionsLog = Join-Path $outRoot "connections.csv"
$stopFile = Join-Path $outRoot "stop.flag"
$sampler = Start-Job -ArgumentList $connectionsLog, $stopFile -ScriptBlock {
    param($log, $stop)
    "time,process,local,remote,state" | Out-File -Encoding utf8 $log
    while (-not (Test-Path $stop)) {
        $ids = @{}
        Get-Process foundrylocald, python -ErrorAction SilentlyContinue | ForEach-Object { $ids[$_.Id] = $_.Name }
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $ids.ContainsKey([int]$_.OwningProcess) -and
            $_.RemoteAddress -notin @("127.0.0.1", "::1", "0.0.0.0", "::") -and
            $_.State -ne "Listen"
        } | ForEach-Object {
            "$(Get-Date -Format o),$($ids[[int]$_.OwningProcess]),$($_.LocalAddress):$($_.LocalPort),$($_.RemoteAddress):$($_.RemotePort),$($_.State)" |
                Out-File -Append -Encoding utf8 $log
        }
        Start-Sleep -Milliseconds 1000
    }
}

function Invoke-Tool([string[]]$arguments, [string]$logName) {
    # Start-Process, not the call operator: in Windows PowerShell 5.1 a native program's
    # stderr lines become error records, and the CLI writes its console output to stderr.
    $log = Join-Path $outRoot $logName
    $errLog = "$log.stderr"
    $env:PYTHONIOENCODING = "utf-8"
    $quoted = @("-m", "evtx_triage.cli") + ($arguments | ForEach-Object { if ($_ -match "\s") { "`"$_`"" } else { $_ } })
    $started = Get-Date
    $process = Start-Process -FilePath $python -ArgumentList $quoted -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError $errLog
    Get-Content $errLog | Add-Content -Encoding utf8 $log
    Remove-Item $errLog
    return @{ code = $process.ExitCode; seconds = [int]((Get-Date) - $started).TotalSeconds; log = $log }
}

function Invoke-Foundry([string[]]$arguments, [string]$logPath) {
    $process = Start-Process -FilePath "foundry" -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.stderr"
    return $process.ExitCode
}

try {
    # --- optional: start the server while offline ------------------------------------
    if ($ColdStart) {
        Invoke-Foundry @("server", "stop") (Join-Path $outRoot "server_stop.log") | Out-Null
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while ([int](nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits) -gt 300 -and $watch.Elapsed.TotalSeconds -lt 120) {
            Start-Sleep -Milliseconds 500
        }
        $startCode = Invoke-Foundry @("server", "start", "--port", "5273", "--idle-timeout", "0") (Join-Path $outRoot "server_start.log")
        Note "cold start while offline: foundry server start exit=$startCode (log: server_start.log)"
    }

    # --- 2. doctor and kb check ------------------------------------------------------
    $doctor = Invoke-Tool @("doctor") "doctor.log"
    Note "doctor: exit=$($doctor.code) ($($doctor.seconds)s)"
    Get-Content $doctor.log | Where-Object { $_ -match "fail|warn|ready" } | ForEach-Object { Note "  $_" }

    $kb = Invoke-Tool @("kb", "check") "kb_check.log"
    Note "kb check: exit=$($kb.code) ($($kb.seconds)s)"

    # --- 3. triage on five samples ---------------------------------------------------
    $accepted = 0
    $completed = 0
    foreach ($sample in $samples) {
        $csv = Join-Path $repo "data\hayabusa_csv\eval\$($sample.csv)"
        $name = [IO.Path]::GetFileNameWithoutExtension($sample.csv)
        if (-not (Test-Path $csv)) { Note "MISSING $($sample.csv)"; continue }
        $dir = Join-Path $outRoot $name
        $run = Invoke-Tool @("triage", $csv, "--out", $dir, "--format", "json") "triage_$name.log"
        $report = Join-Path $dir "report.json"
        if ($run.code -eq 0 -and (Test-Path $report)) {
            $json = Get-Content $report -Raw -Encoding utf8 | ConvertFrom-Json
            $statuses = @($json.model.interpretations | ForEach-Object { $_.status })
            $ok = @($statuses | Where-Object { $_ -eq "accepted" }).Count
            $accepted += $ok
            $completed += 1
            $hash = (Get-FileHash $report -Algorithm SHA256).Hash.Substring(0, 12)
            Note ("triage $($sample.channel) ${name}: exit=0 $($run.seconds)s groups_to_model=$($statuses.Count) " +
                "accepted=$ok statuses=[$($statuses -join ',')] report_sha256=$hash")
        } else {
            Note "triage $($sample.channel) ${name}: exit=$($run.code) $($run.seconds)s (see triage_$name.log)"
        }
        Get-Content $run.log | Where-Object { $_ -match "loading|warm-up|not ready|out of memory" } | ForEach-Object { Note "  $_" }
    }
    Note "samples completed: $completed / $($samples.Count), accepted model groups: $accepted"
}
finally {
    New-Item -ItemType File -Force $stopFile | Out-Null
    Wait-Job $sampler -Timeout 10 | Out-Null
    Remove-Job $sampler -Force
}

# --- 4. connections seen ---------------------------------------------------------------
$rows = @(Import-Csv $connectionsLog)
Note "non-loopback TCP connections of foundrylocald/python during the run: $($rows.Count)"
$rows | Group-Object remote | ForEach-Object { Note "  $($_.Name) x$($_.Count) ($(($_.Group | Select-Object -First 1).process))" }

$after = Test-Online
Note "network after the run: internet tcp reachable=$($after.tcp), dns resolves=$($after.dns)"
if (-not $AllowOnline -and ($after.tcp -or $after.dns)) { Note "WARNING: the network came back during the run" }

$verdict = if (($online.tcp -or $online.dns) -and $AllowOnline) { "NOT A C2 RUN (online)" }
    elseif ($completed -eq $samples.Count -and $rows.Count -eq 0) { "C2 PASSED" }
    else { "C2 NOT PASSED" }
Note "verdict: $verdict"
$summary | Out-File -Encoding utf8 $summaryPath
Write-Host ""
Write-Host "summary written: $summaryPath"
