# Elevated: gracefully stop the collector, verify the chain, leave the driver loaded.
$ErrorActionPreference = 'Continue'
$stop = 'C:\msmon-sessions\STOP'
$logDir = 'C:\msmon-sessions'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

"stopping via $stop"
New-Item -ItemType File -Path $stop -Force | Out-Null
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Process msmon-agent -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
if (Get-Process msmon-agent -ErrorAction SilentlyContinue) { "agent still running after 60s" } else { "agent exited" }
Remove-Item $stop -ErrorAction SilentlyContinue

$bundle = Get-ChildItem $logDir -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
"bundle: $($bundle.FullName)"
Get-ChildItem $bundle.FullName -File | Select-Object Name, Length | Format-Table -AutoSize

$summary = Join-Path $bundle.FullName 'summary.json'
if (Test-Path $summary) { "--- summary ---"; Get-Content $summary }
"--- driver state (left loaded; reboot to unload) ---"
(& sc.exe query msmon) -join "`n"
"--- chain verify ---"
# @() keeps a single part an array; splatting a lone string passes it one character at a time.
$parts = @(Get-ChildItem $bundle.FullName -Filter 'events.jsonl*' | Sort-Object Name | ForEach-Object { $_.FullName })
if ($parts) { & python "$repo\tools\verify_log.py" @parts }
