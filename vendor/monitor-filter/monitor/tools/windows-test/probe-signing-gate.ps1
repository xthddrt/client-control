# Elevated: probe object-callback and WFP registration with a verified /INTEGRITYCHECK build.
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host $m }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$build = Join-Path $repo 'build\Release\driver\msmon.sys'
$info = Get-Content (Join-Path $repo 'build\build-info.json') -Raw | ConvertFrom-Json
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon.sys'
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'x64 signtool.exe not found.' }
if (Get-Process msmon-agent -ErrorAction SilentlyContinue) { throw 'Stop the collector before running this probe.' }
$buildHash = (Get-FileHash $build -Algorithm SHA256).Hash.ToLower()
if ($buildHash -ne ([string]$info.driver_sha256).ToLower()) { throw 'Build hash does not match build-info.json.' }
if ($info.driver_force_integrity -ne $true) { throw 'Build was not linked with /INTEGRITYCHECK (build-info.json driver_force_integrity is not true); rebuild with build.cmd.' }

Say "== cert with code-signing + kernel-mode EKU =="
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq 'CN=msmon kernel test' | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=msmon kernel test' `
        -KeyUsage DigitalSignature -KeyUsageProperty Sign -KeyAlgorithm RSA -KeyLength 2048 `
        -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.61.1.1') `
        -CertStoreLocation Cert:\LocalMachine\My
}
Say "thumbprint $($cert.Thumbprint)"
$eku = ($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }).Format($false)
Say "EKU: $eku"
$cer = Join-Path $env:TEMP 'msmon-kernel.cer'
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
foreach ($s in 'Root','TrustedPublisher') { Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$s" | Out-Null }

Say "== sign + deploy =="
$work = Join-Path $env:TEMP 'msmon-sign2'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$signed = Join-Path $work 'msmon.sys'
Copy-Item $build $signed -Force
& $signtool.FullName sign /sm /s My /sha1 $cert.Thumbprint /fd sha256 $signed | Out-Host
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
$signature = Get-AuthenticodeSignature $signed
if ($signature.Status -ne 'Valid') { throw "Signed build signature status is $($signature.Status)." }
& sc.exe stop msmon | Out-Host
# 1062 = ERROR_SERVICE_NOT_ACTIVE: already stopped is fine.
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) { throw "sc stop failed with exit code $LASTEXITCODE." }
Start-Sleep 1
Copy-Item $signed $target -Force
$signedHash = (Get-FileHash $signed -Algorithm SHA256).Hash.ToLower()
$deployedHash = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
if ($deployedHash -ne $signedHash) { throw 'Deployed driver hash does not match the signed build.' }
Say "deployed sha256=$deployedHash commit=$($info.commit)"
& sc.exe start msmon | Out-Host
if ($LASTEXITCODE -ne 0) { throw "sc start failed with exit code $LASTEXITCODE." }
Start-Sleep 2

Say "== probe: short agent session, read registration statuses =="
$logDir = 'C:\msmon-sessions'
$stop = Join-Path $logDir 'STOP'
$testId = 'probe-eku-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$agent = Join-Path $repo 'build\Release\agent\msmon-agent.exe'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Remove-Item $stop -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $agent -WindowStyle Hidden -PassThru -ArgumentList @(
  '--client','C:\Nexon\Library\maplestorycw','--log-dir',$logDir,
  '--session-label','probe-eku','--test-id',$testId,
  '--scenario','mixed','--stop-file',$stop)
$null = $p.Handle  # cache the handle so ExitCode is readable after Wait-Process
try {
    Start-Sleep 8
    New-Item -ItemType File -Path $stop -Force | Out-Null
    Wait-Process -Id $p.Id -Timeout 60 -ErrorAction Stop
    if ($p.ExitCode -ne 0) { throw "Agent exited with code $($p.ExitCode)." }
} finally {
    Remove-Item $stop -Force -ErrorAction SilentlyContinue
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
}

$b = Join-Path $logDir $testId
$cov = Get-Content (Join-Path $b 'coverage.json') -Raw | ConvertFrom-Json
if ($cov.session_uuid.Length -eq 0) { throw 'Coverage session UUID is missing.' }
$rs = $cov.driver.registration_status
Say "session: $testId uuid=$($cov.session_uuid)"
Say ("object_process(23)=0x{0:X8}  object_thread(24)=0x{1:X8}" -f ($rs[23] -band 0xFFFFFFFF), ($rs[24] -band 0xFFFFFFFF))
foreach ($i in 28..34) { Say ("wfp slot {0} = 0x{1:X8}" -f $i, ($rs[$i] -band 0xFFFFFFFF)) }
Say ("registered_ok={0} failed={1}" -f $cov.driver.registration_ok, $cov.driver.registration_failed)
