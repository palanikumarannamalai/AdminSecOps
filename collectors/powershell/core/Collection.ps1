# Orchestration: runs modules and datasets, isolates failures, writes the package.

function Invoke-AsoDataset {
    <#
    .SYNOPSIS
    Runs one dataset collector with full failure isolation and writes its envelope.
    A collector sets $State.Data (and optionally $State.Status / errors / warnings); it never returns data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Entry)
    $ctx = Get-AsoContext
    $state = New-AsoDatasetState -Entry $Entry
    Write-AsoLog -Module $Entry.Module -Dataset $Entry.Id -Message 'Collecting.'

    if ($Entry.Optional -and $Entry.Id -eq 'ad.domainControllerSettings' -and -not $ctx.IncludeDomainControllerSettings) {
        $state.Status = 'NotCollected'
        Add-AsoDatasetWarning -State $state -Code 'OPTION_NOT_SELECTED' -Message 'Domain controller registry settings are collected only with -IncludeDomainControllerSettings (requires local administrator on each domain controller).'
    }
    else {
        try {
            $null = & $Entry.Function -State $state
            if (-not $state.Status) {
                $state.Status = if ($state.Partial) { 'Partial' } else { 'Success' }
            }
            elseif ($state.Status -eq 'Success' -and $state.Partial) {
                $state.Status = 'Partial'
            }
            if ($state.Status -in 'Success', 'Partial' -and $null -eq $state.Data) {
                $state.Status = 'Failed'
                $state.Errors.Add((New-AsoMessage -Code 'NO_DATA' -Message 'The collector produced no data.'))
            }
        }
        catch {
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            $state.Status = $mapped.Status
            $state.Data = $null
            if ($mapped.Status -eq 'NotApplicable') {
                $state.Warnings.Add((New-AsoMessage -Code $mapped.Code -Message $mapped.Message -Target $mapped.Target))
            }
            else {
                $state.Errors.Add((New-AsoMessage -Code $mapped.Code -Message $mapped.Message -Target $mapped.Target))
            }
            $position = if ($_.InvocationInfo) { "$($_.InvocationInfo.ScriptName | Split-Path -Leaf):$($_.InvocationInfo.ScriptLineNumber)" } else { '' }
            Write-AsoLog -Level $(if ($mapped.Status -eq 'Failed') { 'Error' } else { 'Warning' }) -Module $Entry.Module -Dataset $Entry.Id -Message "$($mapped.Code): $($mapped.Message) $position"
        }
    }
    $collectedAt = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $status = Write-AsoEnvelope -State $state -CollectedAt $collectedAt
    Write-AsoLog -Module $Entry.Module -Dataset $Entry.Id -Message "Completed with status $status."
    return $status
}

function Invoke-AsoModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    $ctx = Get-AsoContext
    $startedAt = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    Write-AsoLog -Module $Name -Message "Module $Name started."
    $prereqs = Get-AsoModulePrerequisite -Module $Name -Replay:($ctx.Mode -eq 'Replay') -ReplayPath $ctx.ReplayPath
    $moduleErrors = [System.Collections.Generic.List[object]]::new()
    $moduleWarnings = [System.Collections.Generic.List[object]]::new()
    $entries = @(Get-AsoCatalogEntry -Module $Name)
    $statuses = [System.Collections.Generic.List[string]]::new()

    $unmet = @($prereqs | Where-Object { -not $_.Satisfied -and $_.Blocking })
    foreach ($p in @($prereqs | Where-Object { -not $_.Satisfied -and -not $_.Blocking })) {
        $moduleWarnings.Add((New-AsoMessage -Code 'PREREQUISITE_OPTIONAL_NOT_MET' -Message "$($p.Name): $($p.Detail)"))
    }

    $notApplicablePlatform = ($Name -eq 'Windows' -and $ctx.Mode -ne 'Replay' -and -not (Test-AsoWindowsPlatform))
    if ($notApplicablePlatform) {
        foreach ($entry in $entries) {
            $state = New-AsoDatasetState -Entry $entry
            Set-AsoDatasetNotApplicable -State $state -Code 'PLATFORM_NOT_WINDOWS' -Message 'Windows host settings apply only when the collector runs on Windows.'
            $statuses.Add((Write-AsoEnvelope -State $state -CollectedAt ([DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture))))
        }
        $moduleStatus = 'Skipped'
    }
    elseif ($unmet.Count -gt 0) {
        $reason = ($unmet | ForEach-Object { "$($_.Name) ($($_.Detail))" }) -join '; '
        $moduleErrors.Add((New-AsoMessage -Code 'PREREQUISITE_NOT_MET' -Message "Module skipped: $reason"))
        Write-AsoLog -Level Warning -Module $Name -Message "Module skipped: $reason"
        foreach ($entry in $entries) {
            $state = New-AsoDatasetState -Entry $entry
            $state.Status = 'NotCollected'
            $state.Errors.Add((New-AsoMessage -Code 'PREREQUISITE_NOT_MET' -Message "Not collected because a module prerequisite is not met: $reason"))
            $statuses.Add((Write-AsoEnvelope -State $state -CollectedAt ([DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture))))
        }
        $moduleStatus = 'Skipped'
    }
    else {
        foreach ($entry in $entries) {
            try {
                $statuses.Add((Invoke-AsoDataset -Entry $entry))
            }
            catch {
                # Envelope writing itself failed (e.g. disk error). Record and continue with the next dataset.
                $moduleErrors.Add((New-AsoMessage -Code 'DATASET_WRITE_FAILED' -Message $_.Exception.Message -Target $entry.Id))
                Write-AsoLog -Level Error -Module $Name -Dataset $entry.Id -Message "Evidence file could not be written: $($_.Exception.Message)"
                $statuses.Add('Failed')
            }
        }
        $bad = @($statuses | Where-Object { $_ -in 'Failed', 'Unauthorized', 'Partial' })
        $hard = @($statuses | Where-Object { $_ -in 'Failed', 'Unauthorized' })
        $moduleStatus = if ($statuses.Count -gt 0 -and $hard.Count -eq $statuses.Count) { 'Failed' }
        elseif ($bad.Count -gt 0) { 'CompletedWithErrors' }
        else { 'Completed' }
    }

    $ctx.Modules.Add([ordered]@{
            name          = $Name
            version       = $script:AsoCollectorVersion
            status        = $moduleStatus
            startedAt     = $startedAt
            completedAt   = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            prerequisites = [object[]]@($prereqs | ForEach-Object { [ordered]@{ name = $_.Name; satisfied = [bool]$_.Satisfied; detail = if ($_.Detail) { [string]$_.Detail } else { $null } } })
            errors        = [object[]]$moduleErrors.ToArray()
            warnings      = [object[]]$moduleWarnings.ToArray()
        })
    Write-AsoLog -Module $Name -Message "Module $Name finished with status $moduleStatus."
    return [pscustomobject]@{ Module = $Name; Status = $moduleStatus; Datasets = [string[]]$statuses.ToArray() }
}

function Invoke-AdminSecOpsCollection {
    <#
    .SYNOPSIS
    Collects read-only security configuration evidence and writes an AdminSecOps evidence package.

    .DESCRIPTION
    Produces <OutputPath>/AdminSecOps-Assessment-<yyyyMMdd-HHmmss>/ with evidence-manifest.json,
    evidence/<module>/<dataset>.json and logs/collection-log.json, plus (unless -NoZip) the ZIP
    adminsecops-assessment-<yyyyMMdd-HHmmss>.zip next to it. Every data access is a read operation.
    Secrets (passwords, client secrets and hints, keys, tokens, LAPS passwords, cpassword values,
    message content) are never requested, and every evidence file is scanned before it is written.

    .PARAMETER Module
    Collector modules to run: Entra, M365, Exchange, Intune, Azure, AD, ADCS, GPO, Windows or All.

    .PARAMETER OutputPath
    Directory in which the package folder and ZIP are created. Defaults to the current directory.

    .PARAMETER Label
    Free-text label stored in the manifest (e.g. customer or environment name). Do not put secrets here.

    .PARAMETER TenantId
    Microsoft Entra tenant ID used for interactive sign-in and recorded in the manifest.

    .PARAMETER IncludeDomainControllerSettings
    Also reads LDAP/SMB signing registry settings from each domain controller (remote registry,
    requires local administrator on the domain controllers).

    .PARAMETER ReplayPath
    Offline replay: read recorded, sanitized responses from this folder instead of calling services.

    .PARAMETER NoZip
    Do not create the ZIP file.

    .PARAMETER SkipConnect
    Do not sign in; use existing sessions (Connect-MgGraph / Connect-ExchangeOnline / Connect-AzAccount).

    .EXAMPLE
    Invoke-AdminSecOpsCollection -Module Entra, Exchange -OutputPath C:\Assessments -Label 'Contoso'

    .EXAMPLE
    Invoke-AdminSecOpsCollection -Module All -ReplayPath .\tests\replay\contoso -OutputPath $env:TEMP -SkipConnect
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows', 'All')]
        [string[]] $Module,
        [string] $OutputPath = (Get-Location).ProviderPath,
        [ValidateLength(0, 200)] [string] $Label,
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')] [string] $TenantId,
        [switch] $IncludeDomainControllerSettings,
        [string] $ReplayPath,
        [switch] $NoZip,
        [switch] $SkipConnect
    )
    $selected = Resolve-AsoModuleSelection -Module $Module
    $resolvedReplay = $null
    if ($ReplayPath) {
        if (-not (Test-Path -LiteralPath $ReplayPath -PathType Container)) { throw "Replay folder '$ReplayPath' does not exist." }
        $resolvedReplay = (Resolve-Path -LiteralPath $ReplayPath).ProviderPath
    }
    $timestamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)
    $packagePath = Initialize-AsoPackageDirectory -OutputPath $OutputPath -Timestamp $timestamp
    $ctx = Initialize-AsoContext -ReplayPath $resolvedReplay -PackagePath $packagePath -Label $Label -TenantId $TenantId -IncludeDomainControllerSettings:$IncludeDomainControllerSettings -SkipConnect:$SkipConnect
    Write-AsoLog -Message "Collection started (assessment $($ctx.AssessmentId), mode $($ctx.Mode), modules $($selected -join ', '))."

    if ($ctx.Mode -eq 'Live' -and -not $SkipConnect) {
        Connect-AsoService -Module $selected -TenantId $TenantId
    }
    if ($ctx.Mode -eq 'Live' -and -not $ctx.Environment.tenantId) {
        $graph = Get-AsoGraphConnectionState
        if ($graph.Connected -and $graph.TenantId) { $ctx.Environment.tenantId = $graph.TenantId }
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $selected) {
        try {
            $results.Add((Invoke-AsoModule -Name $m))
        }
        catch {
            Write-AsoLog -Level Error -Module $m -Message "Module failed unexpectedly: $($_.Exception.Message)"
            $ctx.Modules.Add([ordered]@{
                    name = $m; version = $script:AsoCollectorVersion; status = 'Failed'; startedAt = $null; completedAt = $null
                    prerequisites = @(); errors = @((New-AsoMessage -Code 'MODULE_FAILED' -Message $_.Exception.Message)); warnings = @()
                })
            $results.Add([pscustomobject]@{ Module = $m; Status = 'Failed'; Datasets = [string[]]@() })
        }
    }

    $options = @{
        modules                         = [string[]]$selected
        includeDomainControllerSettings = [bool]$IncludeDomainControllerSettings
        replayMode                      = ($ctx.Mode -eq 'Replay')
        skipConnect                     = [bool]$SkipConnect
        zip                             = -not $NoZip
    }
    Write-AsoLog -Message 'Writing manifest.'
    $manifestPath = Write-AsoManifest -Options $options
    Write-AsoLog -Message 'Collection finished.'
    Write-AsoLogFile

    $zipPath = $null
    if (-not $NoZip) {
        $zipPath = Join-Path -Path (Split-Path -Path $packagePath -Parent) -ChildPath ("adminsecops-assessment-$timestamp.zip")
        $n = 1
        while (Test-Path -LiteralPath $zipPath) {
            $zipPath = Join-Path -Path (Split-Path -Path $packagePath -Parent) -ChildPath ("adminsecops-assessment-$timestamp-$n.zip")
            $n++
        }
        Compress-AsoPackage -PackagePath $packagePath -ZipPath $zipPath | Out-Null
    }

    $byStatus = [ordered]@{}
    foreach ($f in $ctx.Files) {
        if (-not $byStatus.Contains($f.status)) { $byStatus[$f.status] = 0 }
        $byStatus[$f.status]++
    }
    [pscustomobject][ordered]@{
        AssessmentId     = $ctx.AssessmentId
        Mode             = $ctx.Mode
        PackagePath      = $packagePath
        ManifestPath     = $manifestPath
        ZipPath          = $zipPath
        Modules          = [object[]]@($results | ForEach-Object { [pscustomobject]@{ Module = $_.Module; Status = $_.Status } })
        DatasetCount     = $ctx.Files.Count
        DatasetsByStatus = [pscustomobject]$byStatus
    }
}

function Get-AdminSecOpsPermission {
    <#
    .SYNOPSIS
    Explains the least-privilege, read-only permissions each collector module and dataset needs,
    and what is (and is never) collected.

    .PARAMETER Module
    One or more collector modules, or All.

    .PARAMETER Summary
    Return one object per module instead of one per dataset.

    .EXAMPLE
    Get-AdminSecOpsPermission -Module Entra | Format-List

    .EXAMPLE
    Get-AdminSecOpsPermission -Summary
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows', 'All')]
        [string[]] $Module = @('All'),
        [switch] $Summary
    )
    $selected = Resolve-AsoModuleSelection -Module $Module
    foreach ($m in $selected) {
        $info = $script:AsoModuleInfo[$m]
        if ($Summary) {
            $scopes = @()
            if ($m -in 'Entra', 'M365', 'Intune', 'Azure', 'Exchange') {
                $scopes = @(Get-AsoCatalogEntry -Module $m | ForEach-Object { $_.Permissions } | Where-Object { $_ -match '^Graph: ' } | ForEach-Object { ($_ -replace '^Graph: ', '') -replace ' \(.*$', '' } | Sort-Object -Unique)
            }
            [pscustomobject][ordered]@{
                Module              = $m
                RoleOrRights        = $info.Role
                GraphDelegatedScope = [string[]]$scopes
                SignIn              = $info.Connection
                RequiredModules     = [string[]]$info.RequiredTools
                Collects            = $info.Collects
                NeverCollects       = $info.NeverCollects
            }
            continue
        }
        foreach ($entry in (Get-AsoCatalogEntry -Module $m)) {
            [pscustomobject][ordered]@{
                Module        = $m
                DatasetId     = $entry.Id
                Title         = $entry.Title
                Source        = $entry.System
                Operations    = [string[]]$entry.Operations
                Permissions   = [string[]]$entry.Permissions
                Prerequisites = [string[]]$entry.Prerequisites
                Optional      = $entry.Optional
                ModuleRole    = $info.Role
                NeverCollects = $info.NeverCollects
            }
        }
    }
}
