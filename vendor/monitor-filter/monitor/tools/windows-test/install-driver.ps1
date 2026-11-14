# Elevated: test-sign the current build, diagnose any write denial, then register the driver (fallback path if needed).
$ErrorActionPreference = 'Continue'
function Say($m) { Write-Host $m }

Say "elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))  user: $env:USERNAME"
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon.sys'
$src = Join-Path $env:TEMP 'msmon-sign\msmon.sys'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$build = Join-Path $repo 'build\Release\driver\msmon.sys'

Say "== sign current build =="
$info = Get-Content (Join-Path $repo 'build\build-info.json') -Raw | ConvertFrom-Json
if ((Get-FileHash $build -Algorithm SHA256).Hash.ToLower() -ne ([string]$info.driver_sha256).ToLower()) { throw 'Build hash does not match build-info.json; rerun build.cmd.' }
if ($info.driver_force_integrity -ne $true) { throw 'Build was not linked with /INTEGRITYCHECK; rerun build.cmd.' }
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'x64 signtool.exe not found.' }
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq 'CN=msmon test signing' | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=msmon test signing' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) `
        -CertStoreLocation Cert:\LocalMachine\My
    $cer = Join-Path $env:TEMP 'msmon-test-signing.cer'
    Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
    foreach ($s in 'Root','TrustedPublisher') { Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$s" | Out-Null }
    Say "created test certificate $($cert.Thumbprint)"
}
New-Item -ItemType Directory -Force -Path (Split-Path $src) | Out-Null
Copy-Item $build $src -Force
& $signtool.FullName sign /sm /s My /sha1 $cert.Thumbprint /fd sha256 $src | Out-Host
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
$signature = Get-AuthenticodeSignature $src
if ($signature.Status -ne 'Valid') { throw "Signed build signature status is $($signature.Status)." }
Say "signed $src"

Say "== current destination state =="
$f = Get-Item $target -ErrorAction SilentlyContinue
if ($f) {
  Say ("attrs={0} len={1}" -f $f.Attributes, $f.Length)
  (Get-Acl $target).Access | ForEach-Object { Say ("  ace {0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights) }
  Say ("owner: {0}" -f (Get-Acl $target).Owner)
} else { Say "destination missing" }

Say "== protection state =="
try {
  $mp = Get-MpPreference
  Say ("ControlledFolderAccess={0} EnableControlledFolderAccess={1}" -f $mp.EnableControlledFolderAccess, $mp.EnableControlledFolderAccess)
} catch { Say "no Defender cmdlets: $_" }
try { Say ("SmartAppControl={0}" -f (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState) } catch {}
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { Say "AV: $($_.displayName) state=$($_.productState)" }

Say "== try delete + copy =="
try { Remove-Item $target -Force -ErrorAction Stop; Say "deleted" } catch { Say "delete failed: $($_.Exception.Message)" }
try { Copy-Item $src $target -Force -ErrorAction Stop; Say "copied to System32\drivers" } catch { Say "copy failed: $($_.Exception.Message)" }

$imagePath = '\SystemRoot\System32\drivers\msmon.sys'
$staged = $target
if (-not (Test-Path $target)) {
  Say "== falling back to a non-System32 driver path =="
  $alt = 'C:\Nexon\ms-test\driver'
  New-Item -ItemType Directory -Force -Path $alt | Out-Null
  $staged = Join-Path $alt 'msmon.sys'
  Copy-Item $src $staged -Force
  $imagePath = '\??\C:\Nexon\ms-test\driver\msmon.sys'
  Say "imagePath=$imagePath"
}
Say ("staged: {0} ({1} bytes, {2})" -f $imagePath, (Get-Item $staged).Length, (Get-AuthenticodeSignature $staged).Status)

Say "== register service =="
& sc.exe stop msmon | Out-Null
& sc.exe delete msmon | Out-Null
Start-Sleep -Milliseconds 500
& sc.exe create msmon type= filesys start= demand error= normal binPath= $imagePath DisplayName= "MapleStory application telemetry monitor" | ForEach-Object { Say "  $_" }
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\msmon'
New-ItemProperty -Path $k -Name Group -PropertyType String -Value 'FSFilter Activity Monitor' -Force | Out-Null
New-ItemProperty -Path $k -Name DependOnService -PropertyType MultiString -Value 'FltMgr' -Force | Out-Null
New-ItemProperty -Path $k -Name Type -PropertyType DWord -Value 2 -Force | Out-Null
New-ItemProperty -Path $k -Name Start -PropertyType DWord -Value 3 -Force | Out-Null
New-Item -Path "$k\Instances\msmon" -Force | Out-Null
New-ItemProperty -Path "$k\Instances" -Name DefaultInstance -PropertyType String -Value 'msmon' -Force | Out-Null
New-ItemProperty -Path "$k\Instances\msmon" -Name Altitude -PropertyType String -Value '370030' -Force | Out-Null
New-ItemProperty -Path "$k\Instances\msmon" -Name Flags -PropertyType DWord -Value 0 -Force | Out-Null
Say "registered"

Say "== start =="
& sc.exe start msmon 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 3
$q = (& sc.exe query msmon 2>&1) -join "`n"
Say $q
Say "-- fltmc --"
(& fltmc.exe filters 2>&1) | ForEach-Object { Say "  $_" }
Say "-- events --"
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 12 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, @{n='m';e={ ($_.Message -split "`n")[0] }} | ForEach-Object { Say ("  {0} {1} {2} :: {3}" -f $_.TimeCreated,$_.Id,$_.ProviderName,$_.m) }
if ($q -match 'RUNNING') { Say "RESULT: driver_running" } else { Say "RESULT: driver_NOT_running" }
