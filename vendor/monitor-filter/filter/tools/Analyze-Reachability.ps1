<#
.SYNOPSIS
    Identify every outside program reached by the client family, across one or
    more monitor captures.

.DESCRIPTION
    Thin wrapper over tools/analyze_reachability.py, the one implementation (it parses
    each msmon JSONL record as JSON). Per outside program it reports what the family
    executed, loaded, and touched, whether the policy covers it, and a candidate rule
    when it does not. Needs Python 3, as the msmon tools do.

.EXAMPLE
    .\Analyze-Reachability.ps1 -Log C:\msmon-logs\00-baseline-v2.jsonl,C:\msmon-logs\01-manual-supported.jsonl `
        -Policy ..\policy\default-policy.txt -Out reachability.md -OutPolicy reachability-rules.txt
#>
param(
    [Parameter(Mandatory = $true)][string[]]$Log,
    [string]$Policy = '',
    [string]$Out = 'reachability-report.md',
    [string]$OutPolicy = '',
    [int]$Top = 15
)

$ErrorActionPreference = 'Stop'
$python = Get-Command python, python3 -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $python) { throw 'Python 3 is required (install it and put python on PATH)' }
$arguments = @((Join-Path $PSScriptRoot 'analyze_reachability.py'), '--log', ($Log -join ';'), '--out', $Out, '--top', $Top)
if ($Policy) { $arguments += @('--policy', $Policy) }
if ($OutPolicy) { $arguments += @('--out-policy', $OutPolicy) }
& $python.Source @arguments
if ($LASTEXITCODE -ne 0) { throw "analyze_reachability.py failed with exit code $LASTEXITCODE" }
