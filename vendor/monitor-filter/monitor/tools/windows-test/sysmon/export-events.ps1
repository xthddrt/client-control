# Elevated: export Sysmon events for the client path as NDJSON for later analysis.
param(
  [string]$Out = 'C:\msmon-sessions\sysmon-events.jsonl',
  [int]$Minutes = 120
)
$start = (Get-Date).AddMinutes(-$Minutes)
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start} -ErrorAction SilentlyContinue
$rows = foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $d = [ordered]@{}
    foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    [pscustomobject]@{
        time   = $e.TimeCreated.ToUniversalTime().ToString('o')
        id     = $e.Id
        type   = switch ($e.Id) { 1 {'process_create'} 3 {'network_connect'} 10 {'process_access'} 11 {'file_create'} 12 {'registry_create'} 13 {'registry_set'} 14 {'registry_rename'} 22 {'dns_query'} 5 {'process_terminate'} default {"event_$($e.Id)"} }
        fields = $d
    }
}
# One object per line, UTF-8 without BOM so line-oriented JSON readers accept the first line.
$lines = [string[]]@(foreach ($row in $rows) { $row | ConvertTo-Json -Depth 4 -Compress })
[System.IO.File]::WriteAllLines($Out, $lines, (New-Object System.Text.UTF8Encoding($false)))
"wrote $($lines.Length) events to $Out"
$rows | Group-Object type | Sort-Object Count -Descending | Select-Object Count,Name | Format-Table -AutoSize
