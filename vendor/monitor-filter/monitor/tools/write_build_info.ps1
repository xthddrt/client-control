param([string]$Root)
$ErrorActionPreference = 'Stop'
$Root = $Root.TrimEnd('\')
$driver = Join-Path $Root 'build\Release\driver\msmon.sys'
$agent = Join-Path $Root 'build\Release\agent\msmon-agent.exe'
$commit = 'unknown'
$gitPath = $null
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git) { $gitPath = $git.Source }
if (-not $gitPath) {
    $candidate = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
    if (Test-Path $candidate) { $gitPath = $candidate }
}
if ($gitPath) {
    try {
        $value = (& $gitPath -C $Root rev-parse HEAD 2>$null)
        if ($value) { $commit = "$value".Trim() }
    } catch { $commit = 'unknown' }
}
function Hash-File([string]$Path) {
    if (Test-Path $Path) { return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() }
    return ''
}
# IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (set by /INTEGRITYCHECK); ObRegisterCallbacks denies images without it.
function Test-ForceIntegrity([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $dllCharacteristics = [BitConverter]::ToUInt16($bytes, $pe + 24 + 70)
    return ($dllCharacteristics -band 0x0080) -ne 0
}
$record = [ordered]@{
    schema_version = 1
    commit = "$commit".Trim()
    built_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    driver_sha256 = Hash-File $driver
    driver_force_integrity = Test-ForceIntegrity $driver
    agent_sha256 = Hash-File $agent
}
$json = $record | ConvertTo-Json
$path = Join-Path $Root 'build\build-info.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($path, $json, $utf8)
Write-Host "build-info: $path"
