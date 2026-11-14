# Starts a tracked parent that launches $Workers burst children (inherited tracking), runs the agent, reports drops.
param([int]$Workers = 4, [int]$Count = 250000, [string]$Label = 'pburst')
$agentExe = Join-Path (Resolve-Path "$PSScriptRoot\..\..\..").Path 'build\Release\agent\msmon-agent.exe'
$scratch = $PSScriptRoot
$work = 'C:\msmon-sessions\burst-work'; New-Item -ItemType Directory -Force -Path $work | Out-Null
$target = Join-Path $work 'target.bin'; [IO.File]::WriteAllBytes($target, [byte[]](1..16))
$go = Join-Path $work 'GO'; Remove-Item "$go*" -ErrorAction SilentlyContinue
$burst = Join-Path $scratch 'burst.ps1'
# Parent waits for the agent, then starts the workers so they inherit tracking.
$parentScript = @"
while (-not (Test-Path '$go.ready')) { Start-Sleep -Milliseconds 50 }
`$procs = 1..$Workers | ForEach-Object { Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','$burst','-Go','$go','-Target','$target','-Count','$Count') }
Start-Sleep 3
New-Item -ItemType File -Path '$go' | Out-Null
`$procs | Wait-Process
"@
$parent = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-Command',$parentScript)
$testId = $Label + '-' + (Get-Date -Format 'HHmmss'); $stop = 'C:\msmon-sessions\STOP'; Remove-Item $stop -ErrorAction SilentlyContinue
$agent = Start-Process $agentExe -WindowStyle Hidden -PassThru -RedirectStandardOutput "$work\agent.txt" -RedirectStandardError "$work\agent.err" -ArgumentList @('--client','C:\Nexon\Library\maplestorycw','--log-dir','C:\msmon-sessions','--test-id',$testId,'--scenario','file_io','--pid',$parent.Id,'--stop-file',$stop)
$null = $agent.Handle
Start-Sleep 3
New-Item -ItemType File -Path "$go.ready" | Out-Null
$watch = [Diagnostics.Stopwatch]::StartNew()
$parent.WaitForExit(600000) | Out-Null
"workers finished in {0:N1} s (including 3 s start delay)" -f $watch.Elapsed.TotalSeconds
Start-Sleep 3; New-Item -ItemType File -Path $stop -Force | Out-Null
if (-not $agent.WaitForExit(300000)) { Stop-Process -Id $agent.Id -Force; "agent killed" }
Remove-Item $stop -ErrorAction SilentlyContinue
"agent exit=$($agent.ExitCode)"
Get-Content "$work\agent.txt" | Select-String 'Events written'
$s = Get-Content "C:\msmon-sessions\$testId\summary.json" -Raw | ConvertFrom-Json
"tracked_process_starts=$($s.tracked_process_starts) driver_dropped=$($s.driver_dropped_events)"
Select-String -Path "C:\msmon-sessions\$testId\events.jsonl*" -Pattern 'driver_pump' -SimpleMatch | Select-Object -Last 1 | ForEach-Object { ($_.Line | ConvertFrom-Json).detail }
"testId=$testId"
