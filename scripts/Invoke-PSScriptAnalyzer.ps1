#Requires -Version 7.2
<#
.SYNOPSIS
Runs PSScriptAnalyzer (Error and Warning severity) over the PowerShell collectors and the repository
PowerShell scripts, using collectors/powershell/PSScriptAnalyzerSettings.psd1. Exits non-zero on any finding.

.EXAMPLE
pwsh -NoProfile -File scripts/Invoke-PSScriptAnalyzer.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$settings = Join-Path $repoRoot 'collectors/powershell/PSScriptAnalyzerSettings.psd1'
$targets = @(
    (Join-Path $repoRoot 'collectors/powershell'),
    (Join-Path $repoRoot 'collectors/onprem'),
    (Join-Path $repoRoot 'scripts')
)

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Error 'PSScriptAnalyzer is required (Install-Module PSScriptAnalyzer -Scope CurrentUser).'
    exit 2
}
Import-Module PSScriptAnalyzer

$findings = [System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    foreach ($f in @(Invoke-ScriptAnalyzer -Path $target -Recurse -Settings $settings)) { $findings.Add($f) }
}

if ($findings.Count -gt 0) {
    $findings | Sort-Object -Property ScriptPath, Line | Format-Table -Property Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Output
    Write-Output "PSScriptAnalyzer: $($findings.Count) finding(s)."
    exit 1
}
$files = @($targets | ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' }).Count
Write-Output "PSScriptAnalyzer $((Get-Module PSScriptAnalyzer).Version): 0 findings in $files file(s) (Error, Warning)."
exit 0
