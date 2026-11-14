<#
.SYNOPSIS
    Build a candidate kfilter policy from an msmon JSONL capture.

.DESCRIPTION
    Thin wrapper over tools/kfilter_policy.py, the one implementation (it parses each
    msmon JSONL record as JSON, so field order and new fields do not matter). Writes a
    markdown report of file and registry prefixes and a candidate policy; review both,
    then merge the interesting lines into policy/default-policy.txt. Needs Python 3, as
    the msmon tools do.

.EXAMPLE
    .\Build-Policy.ps1 -Log C:\logs\session.jsonl -ProcessId 5540 `
        -ClientRoot '\Device\HarddiskVolume3\Nexon\Library\maplestorycw' `
        -Out generated-policy.txt -Report generated-report.md
#>
param(
    [string]$Log = '',
    [int[]]$ProcessId = @(),
    [string]$ClientRoot = '',
    [string]$Out = 'generated-policy.txt',
    [string]$Report = 'generated-report.md',
    [int]$MaxFileRules = 24,
    [int]$MaxRegistryRules = 12
)

$ErrorActionPreference = 'Stop'
$python = Get-Command python, python3 -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $python) { throw 'Python 3 is required (install it and put python on PATH)' }
# Empty strings are not passed: Windows PowerShell drops them from native command lines.
$arguments = @((Join-Path $PSScriptRoot 'kfilter_policy.py'))
if ($Log) { $arguments += @('--log', $Log) }
if ($ClientRoot) { $arguments += @('--client-root', $ClientRoot) }
$arguments += @('--out', $Out, '--report', $Report, '--max-file-rules', $MaxFileRules,
                '--max-registry-rules', $MaxRegistryRules)
foreach ($id in $ProcessId) { $arguments += @('--pid', $id) }
& $python.Source @arguments
if ($LASTEXITCODE -ne 0) { throw "kfilter_policy.py failed with exit code $LASTEXITCODE" }
