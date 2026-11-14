# Elevated: replace the running driver with the current build and restart it.
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host $m }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$build = Join-Path $repo 'build\Release\driver\msmon.sys'
$info = Get-Content (Join-Path $repo 'build\build-info.json') -Raw | ConvertFrom-Json
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon.sys'
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq 'CN=msmon test signing' | Sort-Object NotAfter -Descending | Select-Object -First 1
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $cert) { throw 'Test-signing certificate not found.' }
if (-not $signtool) { throw 'x64 signtool.exe not found.' }

Say "== verify build matches build-info =="
$h = (Get-FileHash $build -Algorithm SHA256).Hash.ToLower()
Say "build sha256 : $h"
Say "build-info   : $($info.driver_sha256)"
Say "commit: $($info.commit)"
if ($h -ne ([string]$info.driver_sha256).ToLower()) { throw 'Build hash does not match build-info.json.' }

Say "== sign current build =="
$work = Join-Path $env:TEMP 'msmon-sign'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$signed = Join-Path $work 'msmon.sys'
Copy-Item $build $signed -Force
& $signtool.FullName sign /sm /s My /sha1 $cert.Thumbprint /fd sha256 $signed | Out-Host
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
$signature = Get-AuthenticodeSignature $signed
if ($signature.Status -ne 'Valid') { throw "Signed build signature status is $($signature.Status)." }
$signedHash = (Get-FileHash $signed -Algorithm SHA256).Hash.ToLower()
Say "signed: $signedHash"

Say "== stop collector + driver =="
$stop = 'C:\msmon-sessions\STOP'
New-Item -ItemType File -Path $stop -Force | Out-Null
try {
    for ($i = 0; $i -lt 120; $i++) {
        if (-not (Get-Process msmon-agent -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }
    if (Get-Process msmon-agent -ErrorAction SilentlyContinue) { throw 'Collector did not stop within 60 seconds.' }
} finally {
    Remove-Item $stop -Force -ErrorAction SilentlyContinue
}
& sc.exe stop msmon | Out-Host
# 1062 = ERROR_SERVICE_NOT_ACTIVE: already stopped is fine.
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) { throw "sc stop failed with exit code $LASTEXITCODE." }
for ($i = 0; $i -lt 30; $i++) {
    if ((& sc.exe query msmon) -notmatch 'RUNNING') { break }
    Start-Sleep -Milliseconds 500
}
if ((& sc.exe query msmon) -match 'RUNNING') { throw 'Driver did not stop.' }

Say "== take ownership + replace =="
& takeown /f $target | Out-Host
if ($LASTEXITCODE -ne 0) { throw "takeown failed with exit code $LASTEXITCODE." }
& icacls $target /grant 'Administrators:F' | Out-Host
if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE." }
Copy-Item $signed $target -Force
$deployedHash = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
if ($deployedHash -ne $signedHash) { throw 'Deployed driver hash does not match the signed build.' }
Say "deployed: $deployedHash"

Say "== start =="
& sc.exe start msmon | Out-Host
if ($LASTEXITCODE -ne 0) { throw "sc start failed with exit code $LASTEXITCODE." }
Start-Sleep -Seconds 3
$q = (& sc.exe query msmon) -join "`n"
Say $q
if ($q -notmatch 'RUNNING') { throw 'Driver is not running after deployment.' }
(& fltmc.exe filters 2>&1) | Select-String 'msmon' | ForEach-Object { Say "  $_" }
Say "RESULT: driver_running_new_build sha256=$deployedHash"
