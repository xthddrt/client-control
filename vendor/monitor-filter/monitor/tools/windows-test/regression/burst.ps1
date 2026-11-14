# Waits for a go-file, then performs N unbuffered 1-byte reads so each reaches the file system.
param([string]$Go, [string]$Target, [int]$Count = 250000)
while (-not (Test-Path $Go)) { Start-Sleep -Milliseconds 50 }
$stream = New-Object System.IO.FileStream($Target, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite, 1, [System.IO.FileOptions]::None)
$buffer = New-Object byte[] 1
$watch = [System.Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt $Count; $i++) {
    $stream.Position = 0
    [void]$stream.Read($buffer, 0, 1)
}
$watch.Stop()
$stream.Dispose()
Set-Content -Path ($Go + '.done') -Value ("{0} reads in {1:N0} ms" -f $Count, $watch.ElapsedMilliseconds)
