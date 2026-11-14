# Elevated: start the collector detached, stop it later by creating the stop file.
param(
  [string]$Label = ("live-" + (Get-Date -Format 'MMdd-HHmm')),
  [string]$Scenario = 'login',
  [string]$Client = 'C:\Nexon\Library\maplestorycw',
  [string]$LogDir = 'C:\msmon-sessions',
  [string]$StopFile = 'C:\msmon-sessions\STOP'
)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$agent = Join-Path $repo 'build\Release\agent\msmon-agent.exe'
Remove-Item $StopFile -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$console = Join-Path $LogDir 'agent-console.txt'
$p = Start-Process -FilePath $agent -WindowStyle Hidden -PassThru `
     -RedirectStandardOutput $console -RedirectStandardError ($console + '.err') `
     -ArgumentList @('--client', $Client, '--log-dir', $LogDir, '--session-label', $Label,
                     '--scenario', $Scenario, '--phase', 'steady', '--iteration', '1',
                     '--machine-label', $env:COMPUTERNAME.ToLower(), '--stop-file', $StopFile)
Start-Sleep -Seconds 4
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
"agent pid=$($p.Id) alive=$alive label=$Label"
"console: $console"
if (Test-Path $console) { Get-Content $console -Tail 25 }
if (-not $alive) { "RESULT: agent_exited"; if (Test-Path ($console+'.err')) { Get-Content ($console+'.err') } } else { "RESULT: agent_running" }
