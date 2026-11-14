# Tracks a parent, which starts a child after the agent is running (so the child's module map is complete).
# The child opens other processes, reads and writes the registry, and writes a file; then we check that
# those events carry resolved modules.
$agentExe = Join-Path (Resolve-Path "$PSScriptRoot\..\..\..").Path 'build\Release\agent\msmon-agent.exe'
$work = 'C:\msmon-sessions\attr-work'; New-Item -ItemType Directory -Force -Path $work | Out-Null
$ready = Join-Path $work 'READY'; $done = Join-Path $work 'DONE'; Remove-Item $ready, $done -ErrorAction SilentlyContinue
$childScript = @"
Get-Process | ForEach-Object { try { `$null = `$_.Handle } catch {} }
`$null = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid
New-Item -Path 'HKCU:\Software\msmon-attribution-test' -Force | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\msmon-attribution-test' -Name probe -Value 1
Remove-Item -Path 'HKCU:\Software\msmon-attribution-test' -Recurse -Force
Set-Content -Path '$work\probe.txt' -Value 'probe'
New-Item -ItemType File -Path '$done' -Force | Out-Null
"@
$parentScript = @"
while (-not (Test-Path '$ready')) { Start-Sleep -Milliseconds 50 }
Start-Process powershell -WindowStyle Hidden -Wait -ArgumentList @('-NoProfile','-Command',@'
$childScript
'@)
"@
$parent = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-Command',$parentScript)
$testId = 'attr-' + (Get-Date -Format 'HHmmss'); $stop = 'C:\msmon-sessions\STOP'; Remove-Item $stop -ErrorAction SilentlyContinue
$agent = Start-Process $agentExe -WindowStyle Hidden -PassThru -RedirectStandardOutput "$work\agent.txt" -RedirectStandardError "$work\agent.err" -ArgumentList @('--client','C:\Nexon\Library\maplestorycw','--log-dir','C:\msmon-sessions','--test-id',$testId,'--pid',$parent.Id,'--stop-file',$stop)
$null = $agent.Handle
Start-Sleep 3
New-Item -ItemType File -Path $ready | Out-Null
$deadline = (Get-Date).AddSeconds(120); while (-not (Test-Path $done) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
Start-Sleep 2; New-Item -ItemType File -Path $stop -Force | Out-Null
if (-not $agent.WaitForExit(120000)) { Stop-Process -Id $agent.Id -Force; "agent killed" }
Remove-Item $stop -ErrorAction SilentlyContinue
"agent exit=$($agent.ExitCode) child finished=$(Test-Path $done)"
Get-Content "$work\agent.txt" | Select-String 'Events written'
"testId=$testId"
