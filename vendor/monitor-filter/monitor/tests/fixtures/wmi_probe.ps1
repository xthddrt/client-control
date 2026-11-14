# Controlled WMI/DNS fixture. Run while the monitor is collecting with --scenario wmi or dns.
$ErrorActionPreference = 'Continue'
try {
    Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -First 1 | Out-Null
    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -First 1 | Out-Null
} catch {
    Write-Host "WMI probe: $($_.Exception.Message)"
}
try {
    Resolve-DnsName -Name example.com -ErrorAction Stop | Select-Object -First 1 | Out-Null
} catch {
    Write-Host "DNS probe: $($_.Exception.Message)"
}
Write-Host "wmi_probe complete"
