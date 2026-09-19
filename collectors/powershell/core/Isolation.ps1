# Process isolation for modules whose authentication libraries conflict.
#
# Live validation showed that ExchangeOnlineManagement and Microsoft.Graph.Authentication / Az.Accounts
# load incompatible MSAL assemblies: whichever loads second fails to sign in ("Method not found ...
# BrokerExtension.WithBroker" for Exchange, or a silent Graph sign-in failure). No load order in one
# process works for both. The Exchange module therefore runs in a child PowerShell process that
# imports this same module, signs in to Exchange Online only, and contributes its evidence files to
# the parent's package (same assessment ID). The parent merges the child's manifest entries and log.

function ConvertTo-AsoRoundTripString {
    <#
    ConvertFrom-Json (PowerShell 7) turns ISO-8601 strings into DateTime values; casting those with
    [string] produces a culture-specific format that the evidence schema rejects (found in live
    validation). Normalise back to the round-trip UTC format.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function Test-AsoIsolationRequired {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string[]] $Module, [Parameter(Mandatory)] [string] $Mode)
    if ($Mode -ne 'Live' -or $Module -notcontains 'Exchange') { return $false }
    return @($Module | Where-Object { $_ -in 'Entra', 'M365', 'Intune', 'Azure' }).Count -gt 0
}

function Start-AsoIsolatedProcess {
    <# Starts a child pwsh (same executable) that imports this module and runs the isolated module. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts the same read-only collector in a child process; it changes no system state.')]
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $InputPath)
    $manifestPath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'AdminSecOps.Collector.psd1'
    $pwshExe = Join-Path -Path $PSHOME -ChildPath $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    $command = "Import-Module -Name '$($manifestPath.Replace("'", "''"))' -Force; & (Get-Module AdminSecOps.Collector) { Invoke-AsoIsolatedModuleChild -InputPath `$args[0] } '$($InputPath.Replace("'", "''"))'"
    & $pwshExe -NoProfile -NoLogo -Command $command | Out-Host
    return [int]$LASTEXITCODE
}

function Invoke-AsoIsolatedModule {
    <#
    .SYNOPSIS
    Parent side: runs one module in a child pwsh process and merges its results into this run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [string] $TenantId, [switch] $UseDeviceCode)
    $ctx = Get-AsoContext
    $inputPath = Join-Path -Path $ctx.PackagePath -ChildPath ".isolated-$Name-input.json"
    $outputPath = Join-Path -Path $ctx.PackagePath -ChildPath ".isolated-$Name-output.json"
    $plans = if ($ctx.ServicePlansResolved -and $null -ne $ctx.ServicePlans) { [string[]]@($ctx.ServicePlans) } else { $null }
    $request = [ordered]@{
        module               = $Name
        assessmentId         = $ctx.AssessmentId
        packagePath          = $ctx.PackagePath
        label                = $ctx.Label
        tenantId             = $TenantId
        useDeviceCode        = [bool]$UseDeviceCode
        servicePlans         = $plans
        servicePlansResolved = [bool]($ctx.ServicePlansResolved -and $null -ne $plans)
        outputPath           = $outputPath
    }
    Write-AsoTextFile -Path $inputPath -Text ($request | ConvertTo-Json -Depth 5)
    Write-AsoLog -Module $Name -Message "Running module $Name in an isolated PowerShell process (authentication library isolation)."

    try {
        $exitCode = Start-AsoIsolatedProcess -InputPath $inputPath
    }
    catch {
        $exitCode = -1
        Write-AsoLog -Level Error -Module $Name -Message "Isolated process could not be started: $($_.Exception.Message)"
    }
    finally {
        Remove-AsoHandoffFile -Path $inputPath
    }

    $moduleRecord = $null
    if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
        try {
            $handoff = Get-Content -LiteralPath $outputPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
            if ([string]$handoff.assessmentId -ne $ctx.AssessmentId) { throw 'The isolated process returned results for a different assessment.' }
            foreach ($f in @($handoff.files)) {
                if ([string]$f.module -ne $Name) { throw "The isolated process returned a file for module $($f.module)." }
                $ctx.Files.Add([ordered]@{
                        path = [string]$f.path; datasetId = [string]$f.datasetId; module = [string]$f.module; sha256 = [string]$f.sha256
                        sizeBytes = [long]$f.sizeBytes; schemaVersion = [string]$f.schemaVersion; status = [string]$f.status; collectedAt = ConvertTo-AsoRoundTripString $f.collectedAt
                    })
            }
            foreach ($l in @($handoff.log)) { if ($null -ne $l) { $ctx.Log.Add($l) } }
            foreach ($key in @('tenantDisplayName', 'primaryDomain')) {
                $value = $handoff.environment.$key
                if ($value -and -not $ctx.Environment[$key]) { $ctx.Environment[$key] = [string]$value }
            }
            $moduleRecord = $handoff.moduleRecord
            if ($null -ne $moduleRecord) {
                $moduleRecord.startedAt = ConvertTo-AsoRoundTripString $moduleRecord.startedAt
                $moduleRecord.completedAt = ConvertTo-AsoRoundTripString $moduleRecord.completedAt
            }
        }
        catch {
            Write-AsoLog -Level Error -Module $Name -Message "Isolated module results could not be merged: $($_.Exception.Message)"
        }
        finally {
            Remove-AsoHandoffFile -Path $outputPath
        }
    }

    # Every dataset of the module must have an envelope, even if the child failed before writing it.
    $present = @($ctx.Files | Where-Object { $_.module -eq $Name } | ForEach-Object { $_.datasetId })
    $missing = @(Get-AsoCatalogEntry -Module $Name | Where-Object { $present -notcontains $_.Id })
    foreach ($entry in $missing) {
        $state = New-AsoDatasetState -Entry $entry
        $state.Status = 'Failed'
        $state.Errors.Add((New-AsoMessage -Code 'ISOLATED_PROCESS_FAILED' -Message "The isolated $Name collection process did not produce this dataset (exit code $exitCode)."))
        [void](Write-AsoEnvelope -State $state -CollectedAt ([DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)))
    }

    if ($null -eq $moduleRecord) {
        $moduleRecord = [ordered]@{
            name = $Name; version = $script:AsoCollectorVersion; status = 'Failed'; startedAt = $null; completedAt = $null; prerequisites = @()
            errors = @((New-AsoMessage -Code 'ISOLATED_PROCESS_FAILED' -Message "The isolated $Name collection process failed (exit code $exitCode).")); warnings = @()
        }
    }
    $ctx.Modules.Add($moduleRecord)
    $statuses = [string[]]@($ctx.Files | Where-Object { $_.module -eq $Name } | ForEach-Object { $_.status })
    return [pscustomobject]@{ Module = $Name; Status = [string]$moduleRecord.status; Datasets = $statuses }
}

function Invoke-AsoIsolatedModuleChild {
    <#
    .SYNOPSIS
    Child side: signs in to the module's service only, runs the module into the parent's package and
    writes a handoff file. Never throws; failures are reported through the handoff file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $InputPath)
    $request = Get-Content -LiteralPath $InputPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 5
    $outputFull = [System.IO.Path]::GetFullPath([string]$request.outputPath)
    $packageFull = [System.IO.Path]::GetFullPath([string]$request.packagePath)
    if ([System.IO.Path]::GetDirectoryName($outputFull) -ne $packageFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) -or [System.IO.Path]::GetFileName($outputFull) -notlike '.isolated-*-output.json') {
        throw 'Invalid isolation request: the handoff file must be inside the package folder.'
    }
    if ([string]$request.module -notin 'Exchange') { throw 'Invalid isolation request: unsupported module.' }
    $ctx = Initialize-AsoContext -PackagePath ([string]$request.packagePath) -Label ([string]$request.label) -TenantId ([string]$request.tenantId) -AssessmentId ([string]$request.assessmentId)
    if ($request.servicePlansResolved) {
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($p in @($request.servicePlans)) { if ($p) { [void]$set.Add([string]$p) } }
        $ctx.ServicePlans = $set
        $ctx.ServicePlansResolved = $true
    }
    $name = [string]$request.module
    $moduleRecord = $null
    try {
        Connect-AsoService -Module $name -TenantId ([string]$request.tenantId) -UseDeviceCode:([bool]$request.useDeviceCode)
        Assert-AsoSessionTenant -Module $name -TenantId ([string]$request.tenantId)
        [void](Invoke-AsoModule -Name $name)
        if ($ctx.Modules.Count -gt 0) { $moduleRecord = $ctx.Modules[$ctx.Modules.Count - 1] }
    }
    catch {
        Write-AsoLog -Level Error -Module $name -Message "Isolated module failed: $($_.Exception.Message)"
        $moduleRecord = [ordered]@{
            name = $name; version = $script:AsoCollectorVersion; status = 'Failed'; startedAt = $null; completedAt = $null; prerequisites = @()
            errors = @((New-AsoMessage -Code 'MODULE_FAILED' -Message $_.Exception.Message)); warnings = @()
        }
    }
    $handoff = [ordered]@{
        assessmentId = $ctx.AssessmentId
        moduleRecord = $moduleRecord
        files        = [object[]]$ctx.Files.ToArray()
        log          = [object[]]$ctx.Log.ToArray()
        environment  = $ctx.Environment
    }
    Write-AsoTextFile -Path ([string]$request.outputPath) -Text ($handoff | ConvertTo-Json -Depth 20)
}
