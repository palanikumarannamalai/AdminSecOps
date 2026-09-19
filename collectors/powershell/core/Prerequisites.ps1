# Prerequisite checks per collector module.

function Test-AsoWindowsPlatform {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ($PSVersionTable.Platform -eq 'Win32NT' -or $IsWindows)
}

function Test-AsoElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-AsoWindowsPlatform)) { return $false }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
}

function Test-AsoDomainMember {
    [CmdletBinding()]
    param()
    if (-not (Test-AsoWindowsPlatform)) { return [pscustomobject]@{ Member = $false; Domain = $null } }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return [pscustomobject]@{ Member = [bool]$cs.PartOfDomain; Domain = if ($cs.PartOfDomain) { [string]$cs.Domain } else { $null } }
    }
    catch {
        return [pscustomobject]@{ Member = $false; Domain = $null }
    }
}

function New-AsoPrerequisite {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [bool] $Satisfied, [string] $Detail, [bool] $Blocking = $true)
    [pscustomobject][ordered]@{ Name = $Name; Satisfied = $Satisfied; Detail = $Detail; Blocking = $Blocking }
}

function Test-AsoModuleAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    return ($null -ne (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1))
}

function Get-AsoModulePrerequisite {
    <#
    .SYNOPSIS
    Returns prerequisite checks for one collector module. Blocking checks that are not satisfied
    cause the module to be skipped (its datasets are written with status NotCollected).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Module, [switch] $Replay, [string] $ReplayPath)
    $checks = [System.Collections.Generic.List[object]]::new()
    $psOk = $PSVersionTable.PSVersion -ge [version]'7.2'
    $checks.Add((New-AsoPrerequisite -Name 'PowerShell 7.2 or later' -Satisfied $psOk -Detail "PowerShell $($PSVersionTable.PSVersion)"))

    if ($Replay) {
        $category = switch ($Module) {
            { $_ -in 'Entra', 'M365', 'Intune' } { 'graph' }
            'Exchange' { 'exo' }
            'Azure' { 'arm' }
            { $_ -in 'AD', 'ADCS' } { 'ad' }
            'GPO' { 'gpo' }
            'Windows' { 'windows' }
        }
        $exists = Test-Path -LiteralPath (Join-Path $ReplayPath $category) -PathType Container
        $checks.Add((New-AsoPrerequisite -Name 'Replay data' -Satisfied $exists -Detail "Replay mode: recorded responses are read from the '$category' folder; no service is contacted."))
        return , $checks.ToArray()
    }

    $onWindows = Test-AsoWindowsPlatform
    switch ($Module) {
        { $_ -in 'Entra', 'M365', 'Intune' } {
            $has = Test-AsoModuleAvailable -Name 'Microsoft.Graph.Authentication'
            $checks.Add((New-AsoPrerequisite -Name 'Module Microsoft.Graph.Authentication' -Satisfied $has -Detail $(if ($has) { 'Installed.' } else { 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' })))
            $state = Get-AsoGraphConnectionState
            $checks.Add((New-AsoPrerequisite -Name 'Microsoft Graph connection' -Satisfied $state.Connected -Detail $state.Detail))
        }
        'Exchange' {
            $has = Test-AsoModuleAvailable -Name 'ExchangeOnlineManagement'
            $checks.Add((New-AsoPrerequisite -Name 'Module ExchangeOnlineManagement' -Satisfied $has -Detail $(if ($has) { 'Installed.' } else { 'Install-Module ExchangeOnlineManagement -Scope CurrentUser' })))
            $state = Get-AsoExchangeConnectionState
            $checks.Add((New-AsoPrerequisite -Name 'Exchange Online connection' -Satisfied $state.Connected -Detail $state.Detail))
            $graph = Get-AsoGraphConnectionState
            $checks.Add((New-AsoPrerequisite -Name 'Microsoft Graph connection (licence detection, optional)' -Satisfied $graph.Connected -Detail $graph.Detail -Blocking $false))
        }
        'Azure' {
            $has = Test-AsoModuleAvailable -Name 'Az.Accounts'
            $checks.Add((New-AsoPrerequisite -Name 'Module Az.Accounts' -Satisfied $has -Detail $(if ($has) { 'Installed.' } else { 'Install-Module Az.Accounts -Scope CurrentUser' })))
            $state = Get-AsoAzureConnectionState
            $checks.Add((New-AsoPrerequisite -Name 'Azure connection' -Satisfied $state.Connected -Detail $state.Detail))
            $graph = Get-AsoGraphConnectionState
            $checks.Add((New-AsoPrerequisite -Name 'Microsoft Graph connection (principal names, optional)' -Satisfied $graph.Connected -Detail $graph.Detail -Blocking $false))
        }
        { $_ -in 'AD', 'ADCS', 'GPO' } {
            $checks.Add((New-AsoPrerequisite -Name 'Windows platform' -Satisfied $onWindows -Detail "Platform $($PSVersionTable.Platform)"))
            $hasAd = Test-AsoModuleAvailable -Name 'ActiveDirectory'
            $checks.Add((New-AsoPrerequisite -Name 'Module ActiveDirectory (RSAT)' -Satisfied $hasAd -Detail $(if ($hasAd) { 'Installed.' } else { 'Install RSAT: Active Directory Domain Services tools.' })))
            if ($Module -eq 'GPO') {
                $hasGp = Test-AsoModuleAvailable -Name 'GroupPolicy'
                $checks.Add((New-AsoPrerequisite -Name 'Module GroupPolicy (RSAT)' -Satisfied $hasGp -Detail $(if ($hasGp) { 'Installed.' } else { 'Install RSAT: Group Policy Management tools.' })))
            }
            $member = Test-AsoDomainMember
            $checks.Add((New-AsoPrerequisite -Name 'Computer is joined to an Active Directory domain' -Satisfied $member.Member -Detail $(if ($member.Member) { "Domain $($member.Domain)" } else { 'Run the collector on a domain-joined computer as a domain user.' })))
        }
        'Windows' {
            $checks.Add((New-AsoPrerequisite -Name 'Windows platform' -Satisfied $onWindows -Detail "Platform $($PSVersionTable.Platform)"))
            $elevated = Test-AsoElevated
            $checks.Add((New-AsoPrerequisite -Name 'Running elevated (local administrator)' -Satisfied $elevated -Detail $(if ($elevated) { 'Elevated.' } else { 'Not elevated: some values (e.g. Defender, Device Guard, protected registry keys) may be reported as null.' }) -Blocking $false))
        }
    }
    return , $checks.ToArray()
}

function Test-AdminSecOpsPrerequisite {
    <#
    .SYNOPSIS
    Checks what each collector module needs: PowerShell version, required modules, service
    connections, elevation (Windows) and domain membership (AD, ADCS, GPO).

    .DESCRIPTION
    Read-only. Does not sign in to any service; run Invoke-AdminSecOpsCollection (which signs in
    interactively when needed) or connect yourself first to see connection checks satisfied.

    .PARAMETER Module
    One or more collector modules, or All.

    .EXAMPLE
    Test-AdminSecOpsPrerequisite -Module Entra, AD | Format-Table
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows', 'All')]
        [string[]] $Module = @('All')
    )
    $selected = Resolve-AsoModuleSelection -Module $Module
    foreach ($m in $selected) {
        foreach ($check in (Get-AsoModulePrerequisite -Module $m)) {
            [pscustomobject][ordered]@{
                Module    = $m
                Check     = $check.Name
                Satisfied = $check.Satisfied
                Required  = $check.Blocking
                Detail    = $check.Detail
            }
        }
    }
}

function Resolve-AsoModuleSelection {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([string[]] $Module)
    if (-not $Module -or $Module -contains 'All') { return , [string[]]$script:AsoModuleOrder }
    return , [string[]]@($script:AsoModuleOrder | Where-Object { $Module -contains $_ })
}
