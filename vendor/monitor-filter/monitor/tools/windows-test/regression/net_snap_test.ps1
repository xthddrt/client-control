# Tracked child: loopback connections closed three ways, plus a short-lived .ini report file.
$agentExe = Join-Path (Resolve-Path "$PSScriptRoot\..\..\..").Path 'build\Release\agent\msmon-agent.exe'
$work = 'C:\msmon-sessions\netsnap-work'; New-Item -ItemType Directory -Force -Path $work | Out-Null
$ready = Join-Path $work 'READY'; $done = Join-Path $work 'DONE'; Remove-Item $ready, $done -ErrorAction SilentlyContinue
$reportDir = Join-Path $env:LOCALAPPDATA 'Nexon\msmon-snapshot-test'
$childScript = @"
function Pair([int]`$Port) {
    `$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, `$Port); `$l.Start()
    `$c = [System.Net.Sockets.TcpClient]::new(); `$c.Connect('127.0.0.1', `$Port)
    `$s = `$l.AcceptTcpClient(); `$l.Stop(); return @(`$c, `$s)
}
`$c, `$s = Pair 47911; `$s.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send); Start-Sleep -Milliseconds 400; `$c.Close(); `$s.Close()
Start-Sleep -Milliseconds 300
`$c, `$s = Pair 47912; `$s.Client.LingerState = [System.Net.Sockets.LingerOption]::new(`$true, 0); `$s.Client.Close(); Start-Sleep -Milliseconds 400; `$c.Close()
Start-Sleep -Milliseconds 300
try { [System.Net.Sockets.TcpClient]::new().Connect('127.0.0.1', 47913) } catch {}
New-Item -ItemType Directory -Force -Path '$reportDir' | Out-Null
Set-Content -Path '$reportDir\_test_report.ini' -Value "[report]``r``nreason=server_closed``r``ncode=42"
Start-Sleep -Milliseconds 500
Remove-Item '$reportDir\_test_report.ini'
New-Item -ItemType File -Path '$done' -Force | Out-Null
"@
$parentScript = @"
while (-not (Test-Path '$ready')) { Start-Sleep -Milliseconds 50 }
Start-Process powershell -WindowStyle Hidden -Wait -ArgumentList @('-NoProfile','-Command',@'
$childScript
'@)
"@
$parent = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-Command',$parentScript)
$testId = 'netsnap-' + (Get-Date -Format 'HHmmss'); $stop = 'C:\msmon-sessions\STOP'; Remove-Item $stop -ErrorAction SilentlyContinue
$agent = Start-Process $agentExe -WindowStyle Hidden -PassThru -RedirectStandardOutput "$work\agent.txt" -RedirectStandardError "$work\agent.err" -ArgumentList @('--client','C:\Nexon\Library\maplestorycw','--log-dir','C:\msmon-sessions','--test-id',$testId,'--pid',$parent.Id,'--stop-file',$stop)
$null = $agent.Handle
Start-Sleep 4
New-Item -ItemType File -Path $ready | Out-Null
$deadline = (Get-Date).AddSeconds(120); while (-not (Test-Path $done) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
Start-Sleep 3; New-Item -ItemType File -Path $stop -Force | Out-Null
if (-not $agent.WaitForExit(120000)) { Stop-Process -Id $agent.Id -Force; "agent killed" }
Remove-Item $stop -ErrorAction SilentlyContinue
Remove-Item $reportDir -Recurse -Force -ErrorAction SilentlyContinue
"agent exit=$($agent.ExitCode) child finished=$(Test-Path $done)"; Get-Content "$work\agent.err" -ErrorAction SilentlyContinue
$b = "C:\msmon-sessions\$testId"
"--- etw_tcp events"
Select-String -Path "$b\events.jsonl*" -Pattern '"type":"etw_tcp"' -SimpleMatch | ForEach-Object { $e = $_.Line | ConvertFrom-Json; "{0} pid={1} {2,-22} {3,-34} {4}" -f $e.timestamp.Substring(11,12), $e.process_id, ($e.detail -replace '^event=',''), $e.text, $e.status_name }
"--- snapshot records"
Select-String -Path "$b\events.jsonl*" -Pattern 'file_snapshot' -SimpleMatch | ForEach-Object { ($_.Line | ConvertFrom-Json) | ForEach-Object { "$($_.text): $($_.detail)" } }
Get-ChildItem "$b\snapshots" -ErrorAction SilentlyContinue | ForEach-Object { "--- $($_.Name)"; Get-Content $_.FullName }
"--- tcp provider stats"; (Get-Content "$b\coverage.json" -Raw | ConvertFrom-Json).agent.etw_providers | Where-Object name -eq 'tcp' | ConvertTo-Json -Compress
