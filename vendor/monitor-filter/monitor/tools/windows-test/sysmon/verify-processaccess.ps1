# Elevated: prove Sysmon's ObRegisterCallbacks path actually emits ProcessAccess, then restore the tight config.
$ErrorActionPreference = 'Continue'
function Say($m) { Write-Host $m }
$dir = 'C:\Nexon\ms-test\sysmon'
$tight = Join-Path $dir 'msmon-sysmon.xml'
$temp  = Join-Path $dir 'verify-temp.xml'

@'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="verify" groupRelation="or">
      <ProcessAccess onmatch="include">
        <SourceImage condition="contains">powershell</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content $temp -Encoding UTF8

& "$dir\Sysmon64.exe" -c $temp | Out-Null
Start-Sleep 2
$victim = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
Say "opening handle to $($victim.ProcessName)#$($victim.Id) from powershell"
$h = $victim.Handle
$null = $victim.Modules.Count
Start-Sleep 3

$ev = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -eq 10 } | Select-Object -First 2
if ($ev) {
    Say "PROOF: $($ev.Count) ProcessAccess events"
    foreach ($e in $ev) {
        $x = [xml]$e.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        Say ("  {0} -> {1}  granted={2}" -f $d['SourceImage'], $d['TargetImage'], $d['GrantedAccess'])
    }
} else { Say "NO ProcessAccess events found" }

& "$dir\Sysmon64.exe" -c $tight | Out-Null
Say "restored tight config"
Get-Service Sysmon64 | Select-Object Name,Status | Format-Table -AutoSize
