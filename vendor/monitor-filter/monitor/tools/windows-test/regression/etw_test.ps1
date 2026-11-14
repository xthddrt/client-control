$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$agentExe = Join-Path $root 'build\Release\agent\msmon-agent.exe'
$fixtureExe = Join-Path $root 'build\fixtures\etw_probe.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) 'msmon-etw-regression'
$scope = Join-Path $work 'scope'
$extra = Join-Path $work 'extra'
$sessions = Join-Path $work 'sessions'
$testId = 'etw-' + (Get-Date -Format 'HHmmss')
$stop = Join-Path $work 'STOP'
$agent = $null

New-Item -ItemType Directory -Force -Path $scope, $extra, $sessions | Out-Null
Copy-Item $fixtureExe (Join-Path $scope 'MapleStory.exe') -Force
Copy-Item $fixtureExe (Join-Path $extra 'etw_probe.exe') -Force
Remove-Item $stop -ErrorAction SilentlyContinue

try {
    $agent = Start-Process $agentExe -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $work 'agent.out') `
        -RedirectStandardError (Join-Path $work 'agent.err') `
        -ArgumentList @('--client', $scope, '--scope-root', $scope, '--extra-root', $extra,
                        '--log-dir', $sessions, '--test-id', $testId, '--scenario', 'mixed', '--stop-file', $stop)
    Start-Sleep 4
    if ($agent.HasExited) { throw "agent exited early: $($agent.ExitCode)" }

    $dnsName = "msmon-$testId.invalid"
    $actor = Start-Process (Join-Path $extra 'etw_probe.exe') -WindowStyle Hidden -PassThru -ArgumentList $dnsName
    if (-not $actor.WaitForExit(30000)) { Stop-Process -Id $actor.Id -Force; throw 'ETW actor timed out' }
    Start-Sleep 3
    New-Item -ItemType File -Path $stop -Force | Out-Null
    if (-not $agent.WaitForExit(120000)) { Stop-Process -Id $agent.Id -Force; throw 'agent did not stop' }
    if ($agent.ExitCode -ne 0) { throw "agent failed: $($agent.ExitCode)" }

    $bundle = Join-Path $sessions $testId
    $eventFiles = Get-ChildItem (Join-Path $bundle 'events.jsonl*') | Sort-Object Name
    $events = $eventFiles | Get-Content | ForEach-Object { $_ | ConvertFrom-Json }
    $actorPid = $actor.Id
    $rpc = @($events | Where-Object { $_.type -eq 'etw_rpc' -and $_.process_id -eq $actorPid -and
        $_.detail -match 'interface=Wkssvc' -and $_.detail -match 'operation=NetrWkstaGetInfo' })
    $wmi = @($events | Where-Object { $_.type -eq 'etw_wmi' -and $_.process_id -eq $actorPid -and
        $_.detail -match 'Win32_BIOS' })
    $dns = @($events | Where-Object { $_.type -eq 'etw_dns' -and $_.process_id -eq $actorPid -and $_.text -eq $dnsName })
    if ($rpc.Count -eq 0) { throw 'no attributed Wkssvc/NetrWkstaGetInfo RPC event' }
    if ($wmi.Count -eq 0) { throw 'no attributed Win32_BIOS WMI event' }
    if ($dns.Count -eq 0) { throw 'no attributed DNS event' }
    if (@($events | Where-Object { $_.type -eq 'etw_unattributed' -and $_.process_id -eq $actorPid }).Count -ne 0) {
        throw 'actor produced an unattributed ETW event'
    }

    $coverage = Get-Content (Join-Path $bundle 'coverage.json') -Raw | ConvertFrom-Json
    foreach ($name in 'rpc', 'wmi', 'dns') {
        $provider = $coverage.agent.etw_providers | Where-Object name -eq $name
        if ($null -eq $provider -or $provider.received -le 0 -or $provider.emitted -le 0) {
            throw "provider $name has no received/emitted events"
        }
    }
    $python = (Get-Command python -ErrorAction Stop).Source
    & $python (Join-Path $root 'tools\verify_log.py') @($eventFiles.FullName)
    if ($LASTEXITCODE -ne 0) { throw 'verify_log failed' }
    Write-Host "ETW regression passed: RPC, WMI and DNS attributed to pid $actorPid"
} finally {
    if ($null -ne $agent -and -not $agent.HasExited) {
        New-Item -ItemType File -Path $stop -Force | Out-Null
        if (-not $agent.WaitForExit(10000)) { Stop-Process -Id $agent.Id -Force }
    }
}
