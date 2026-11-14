<#
.SYNOPSIS
    Replay a monitor capture through kfilterctl's shared policy matcher.
.DESCRIPTION
    Uses the same parsed rules, rights mapping and OS-free matcher as the driver.
    Optional value_name fields are used for registry value rules; missing value
    names are handled conservatively. This is coverage analysis, not a security proof.
#>
param(
    [Parameter(Mandatory = $true)][string]$Log,
    [Parameter(Mandatory = $true)][string]$Policy,
    [int[]]$ProcessId = @(),
    [int]$Top = 15,
    [int]$MaxEvents = 0
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Log)) { throw "log not found: $Log" }
if (-not (Test-Path $Policy)) { throw "policy not found: $Policy" }
$tool = Join-Path $PSScriptRoot '..\build\Release\tool\kfilterctl.exe'
if (-not (Test-Path $tool)) { $tool = (Get-Command 'kfilterctl.exe' -ErrorAction Stop).Source }
$arguments = @('simulate', $Policy, $Log, '--max', [string]$MaxEvents)
foreach ($pidValue in $ProcessId) { $arguments += @('--pid', [string]$pidValue) }
& $tool @arguments
if ($LASTEXITCODE -ne 0) { throw "kfilterctl simulate failed with exit code $LASTEXITCODE" }
