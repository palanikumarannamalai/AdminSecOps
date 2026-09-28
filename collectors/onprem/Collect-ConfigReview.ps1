#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'evidence'),
    [ValidateSet('AD','ADCS','GPO','Windows')][string[]]$Module = @('AD','ADCS','GPO','Windows'),
    [switch]$IncludeDomainControllerSettings,
    [string]$ReplayPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'powershell/AdminSecOps.Collector.psd1') -Force
$arguments = @{Module=$Module;TenantId=$TenantId.ToString();OutputPath=$OutputPath;Label='On-premises snapshot';SkipConnect=$true;IncludeDomainControllerSettings=$IncludeDomainControllerSettings}
if ($ReplayPath) { $arguments.ReplayPath=$ReplayPath }
Invoke-AdminSecOpsCollection @arguments
