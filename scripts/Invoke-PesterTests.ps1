#Requires -Version 7.2
<#
.SYNOPSIS
Runs all Pester tests of the PowerShell collectors and exits non-zero on failure.

.EXAMPLE
pwsh -NoProfile -File scripts/Invoke-PesterTests.ps1
#>
[CmdletBinding()]
param(
    [string] $Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'collectors/powershell/tests'),
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')] [string] $Output = 'Normal'
)
$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.5.0' } | Sort-Object -Property Version -Descending | Select-Object -First 1
if (-not $pester) {
    Write-Error 'Pester 5.5 or later is required (Install-Module Pester -Scope CurrentUser -MinimumVersion 5.5.0).'
    exit 2
}
Import-Module $pester.Path -Force

$config = New-PesterConfiguration
$config.Run.Path = $Path
$config.Run.PassThru = $true
$config.Output.Verbosity = $Output
$config.TestResult.Enabled = $false

$result = Invoke-Pester -Configuration $config
Write-Output ("Pester {0}: {1} passed, {2} failed, {3} skipped, {4} not run." -f $pester.Version, $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.NotRunCount)
if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') { exit 1 }
exit 0
