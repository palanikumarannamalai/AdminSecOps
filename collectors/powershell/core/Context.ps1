# Collection context, conversions and dataset status handling.

$script:AsoCollectorName = 'AdminSecOps.Collector'
$script:AsoCollectorVersion = '0.1.0'
$script:AsoSchemaVersion = '1.0'
$script:AsoManifestVersion = '1.0'
$script:AsoContext = $null

function Initialize-AsoContext {
    <#
    .SYNOPSIS
    Creates the in-memory state for one collection run (one assessmentId).
    #>
    [CmdletBinding()]
    param(
        [string] $ReplayPath,
        [string] $PackagePath,
        [string] $Label,
        [string] $TenantId,
        [switch] $IncludeDomainControllerSettings,
        [switch] $SkipConnect
    )
    $script:AsoContext = [pscustomobject]@{
        AssessmentId                    = [guid]::NewGuid().ToString()
        StartedAt                       = [DateTime]::UtcNow
        Mode                            = if ($ReplayPath) { 'Replay' } else { 'Live' }
        ReplayPath                      = $ReplayPath
        PackagePath                     = $PackagePath
        Label                           = $Label
        TenantId                        = $TenantId
        IncludeDomainControllerSettings = [bool]$IncludeDomainControllerSettings
        SkipConnect                     = [bool]$SkipConnect
        Log                             = [System.Collections.Generic.List[object]]::new()
        Files                           = [System.Collections.Generic.List[object]]::new()
        Modules                         = [System.Collections.Generic.List[object]]::new()
        ServicePlans                    = $null
        ServicePlansResolved            = $false
        Environment                     = [ordered]@{
            label             = if ($Label) { $Label } else { $null }
            tenantId          = if ($TenantId) { $TenantId } else { $null }
            tenantDisplayName = $null
            primaryDomain     = $null
            adForestName      = $null
            adDomainName      = $null
        }
        Cache                           = @{}
    }
    $script:AsoContext
}

function Get-AsoContext {
    [CmdletBinding()]
    param()
    if ($null -eq $script:AsoContext) {
        Initialize-AsoContext | Out-Null
    }
    $script:AsoContext
}

function Test-AsoReplayMode {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $ctx = $script:AsoContext
    return ($null -ne $ctx -and $ctx.Mode -eq 'Replay')
}

function ConvertTo-AsoTimestamp {
    <#
    .SYNOPSIS
    Converts a DateTime, DateTimeOffset or date string into an ISO-8601 UTC round-trip string
    (e.g. 2026-09-01T10:00:00.0000000Z). Returns $null for null, empty, or year-1 values.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(ValueFromPipeline)] $Value)
    process {
        if ($null -eq $Value) { return $null }
        if ($Value -is [DateTimeOffset]) {
            if ($Value.UtcDateTime.Year -le 1) { return $null }
            return $Value.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        if ($Value -is [DateTime]) {
            $dt = $Value
            if ($dt.Kind -eq [DateTimeKind]::Unspecified) { $dt = [DateTime]::SpecifyKind($dt, [DateTimeKind]::Utc) }
            $utc = $dt.ToUniversalTime()
            if ($utc.Year -le 1) { return $null }
            return $utc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        $parsed = [DateTimeOffset]::MinValue
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AllowWhiteSpaces
        if ([DateTimeOffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            if ($parsed.UtcDateTime.Year -le 1) { return $null }
            return $parsed.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        return $null
    }
}

function ConvertFrom-AsoFileTime {
    <#
    .SYNOPSIS
    Converts an Active Directory FILETIME / large integer (e.g. lastLogonTimestamp, pwdLastSet,
    msLAPS-PasswordExpirationTime) into an ISO-8601 UTC string. 0, negative values and
    0x7FFFFFFFFFFFFFFF ("never") return $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(ValueFromPipeline)] $Value)
    process {
        if ($null -eq $Value) { return $null }
        if ($Value -is [DateTime] -or $Value -is [DateTimeOffset]) { return (ConvertTo-AsoTimestamp -Value $Value) }
        [long]$ft = 0
        if ($Value -is [string]) {
            if (-not [long]::TryParse($Value.Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ft)) {
                return (ConvertTo-AsoTimestamp -Value $Value)
            }
        }
        else {
            try { $ft = [long]$Value } catch { return $null }
        }
        if ($ft -le 0 -or $ft -eq [long]::MaxValue) { return $null }
        try {
            return [DateTime]::FromFileTimeUtc($ft).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        catch {
            return $null
        }
    }
}

function ConvertTo-AsoBool {
    <# Converts common boolean representations to [bool] or $null. #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $text = ([string]$Value).Trim()
    switch -Regex ($text) {
        '^(?i:true|1|yes|enabled)$' { return $true }
        '^(?i:false|0|no|disabled)$' { return $false }
    }
    return $null
}

function ConvertTo-AsoNumber {
    <# Converts a value to [long] (integers) or [double]; returns $null when not numeric. #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint16]) { return [long]$Value }
    if ($Value -is [uint64]) { return [double]$Value }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ([Math]::Floor($d) -eq $d -and [Math]::Abs($d) -lt 9e15) { return [long]$d }
        return $d
    }
    [long]$l = 0
    if ([long]::TryParse(([string]$Value).Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$l)) { return $l }
    [double]$dbl = 0
    if ([double]::TryParse(([string]$Value).Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$dbl)) { return $dbl }
    return $null
}

function ConvertTo-AsoString {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ($text.Length -eq 0) { return $null }
    return $text
}

function Get-AsoPropertyValue {
    <#
    .SYNOPSIS
    Safely reads a property (or dictionary key) from an object; returns $null when absent.
    Supports dotted paths such as 'properties.networkAcls.defaultAction'.
    #>
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string] $Name)
    $current = $InputObject
    foreach ($part in $Name.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($part)) { $current = $current[$part] } else { return $null }
            continue
        }
        $prop = $current.PSObject.Properties[$part]
        if ($null -eq $prop) { return $null }
        $current = $prop.Value
    }
    return , $current
}

function Get-AsoList {
    <#
    .SYNOPSIS
    Returns a property value as an [object[]] (never $null, nulls removed). Assign the result
    directly; do not wrap the call in @() (that would nest the array).
    #>
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string] $Name)
    $value = Get-AsoPropertyValue -InputObject $InputObject -Name $Name
    $out = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $value) {
        if ($value -is [string] -or $value -is [System.Collections.IDictionary] -or $value -is [System.Management.Automation.PSCustomObject]) {
            $out.Add($value)
        }
        else {
            foreach ($item in $value) { if ($null -ne $item) { $out.Add($item) } }
        }
    }
    return , [object[]]$out.ToArray()
}

function Get-AsoOdataPropertyValue {
    <# Reads '@odata.type' style property names that contain dots. #>
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string] $Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function ConvertTo-AsoStringArray {
    <# Returns a [string[]] (never $null) from a scalar, array or $null. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param($Value)
    $out = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $Value) {
        foreach ($item in @($Value)) {
            if ($null -ne $item -and ([string]$item).Length -gt 0) { $out.Add([string]$item) }
        }
    }
    return , [string[]]$out.ToArray()
}

function New-AsoMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only; no system state is changed.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $Target
    )
    $safe = Protect-AsoLogText -Text $Message
    [ordered]@{
        code    = $Code
        message = $safe
        target  = if ($Target) { Protect-AsoLogText -Text $Target -MaxLength 1000 } else { $null }
    }
}

function Protect-AsoLogText {
    <#
    .SYNOPSIS
    Truncates free text and redacts anything that looks like a token or secret before it is
    written to a log or an error message.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Text, [int] $MaxLength = 1000)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*', '[REDACTED]'
    $t = $t -replace '(?i)(AccountKey=)[A-Za-z0-9+/=]{8,}', '$1[REDACTED]'
    $t = $t -replace '(?i)([?&]sig=)[A-Za-z0-9%+/=]{8,}', '$1[REDACTED]'
    $t = $t -replace '(?i)cpassword="[^"]*"', 'cpassword=[REDACTED]'
    $t = $t -replace '(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}', '$1[REDACTED]'
    if ($t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength) + '...[truncated]' }
    return $t
}

# ---------------------------------------------------------------------------------------------
# Service exceptions (uniform across live and replay wrappers)
# ---------------------------------------------------------------------------------------------

function New-AsoServiceException {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory exception object only.')]
    [CmdletBinding()]
    param(
        [int] $StatusCode = 0,
        [string] $ErrorCode,
        [string] $Message,
        [string] $Target
    )
    $text = if ($Message) { $Message } else { "Request failed with status $StatusCode." }
    $ex = [System.InvalidOperationException]::new((Protect-AsoLogText -Text $text))
    $ex.Data['AsoService'] = $true
    $ex.Data['AsoStatusCode'] = $StatusCode
    $ex.Data['AsoErrorCode'] = if ($ErrorCode) { $ErrorCode } else { '' }
    $ex.Data['AsoTarget'] = if ($Target) { $Target } else { '' }
    $ex
}

$script:AsoLicencePattern = '(?i)(premium( p?[12])? licen[cs]e|P2 licen[cs]e|Governance licen[cs]e|licen[cs]e is required|requires? (an? )?(Microsoft )?(Entra|Azure AD|AAD).{0,20}(P1|P2|Premium)|AadPremiumLicenseRequired|RequestFromNonPremiumTenant|NonPremiumTenant|does not have (a |an )?(valid )?licen[cs]e|not licensed|tenant is not licensed|Request not applicable to target tenant|LicenseNotFound|MissingLicense|without a valid licen[cs]e)'
$script:AsoUnauthorizedCodes = @('Authorization_RequestDenied', 'AccessDenied', 'Forbidden', 'AuthorizationFailed', 'Unauthorized', 'InsufficientAccountPermissions', 'AccessDeniedException', 'LinkedAuthorizationFailed')

function Resolve-AsoErrorStatus {
    <#
    .SYNOPSIS
    Maps an exception / ErrorRecord to a collection status:
    licence or feature missing -> NotApplicable; 401/403 or access denied -> Unauthorized; otherwise Failed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $ErrorObject)
    $ex = if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { $ErrorObject.Exception } else { $ErrorObject }
    $statusCode = 0
    $errorCode = ''
    $target = $null
    $message = if ($ex) { $ex.Message } else { [string]$ErrorObject }
    if ($ex -and $ex.Data -and $ex.Data.Contains('AsoService')) {
        $statusCode = [int]$ex.Data['AsoStatusCode']
        $errorCode = [string]$ex.Data['AsoErrorCode']
        if ($ex.Data['AsoTarget']) { $target = [string]$ex.Data['AsoTarget'] }
    }
    $typeName = if ($ex) { $ex.GetType().FullName } else { '' }
    $combined = "$errorCode $message"

    if ($combined -match $script:AsoLicencePattern) {
        return [pscustomobject]@{ Status = 'NotApplicable'; Code = 'LICENSE_OR_FEATURE_NOT_AVAILABLE'; Message = "The service reported that the required licence or feature is not available: $message"; Target = $target }
    }
    if ($statusCode -in 401, 403 -or $script:AsoUnauthorizedCodes -contains $errorCode -or
        $typeName -match 'UnauthorizedAccessException' -or
        $message -match '(?i)(access is denied|insufficient (access rights|privileges)|Authorization_RequestDenied|\bForbidden\b|not authorized|AuthorizationFailed)') {
        return [pscustomobject]@{ Status = 'Unauthorized'; Code = 'UNAUTHORIZED'; Message = "The collecting account is not authorised to read this data: $message"; Target = $target }
    }
    if ($typeName -match 'CommandNotFoundException' -or $errorCode -eq 'CommandNotAvailable') {
        return [pscustomobject]@{ Status = 'Failed'; Code = 'COMMAND_NOT_AVAILABLE'; Message = $message; Target = $target }
    }
    if ($errorCode -eq 'ReplayFixtureMissing') {
        return [pscustomobject]@{ Status = 'Failed'; Code = 'REPLAY_FIXTURE_MISSING'; Message = $message; Target = $target }
    }
    $code = if ($statusCode -gt 0) { "HTTP_$statusCode" } else { 'COLLECTION_FAILED' }
    return [pscustomobject]@{ Status = 'Failed'; Code = $code; Message = $message; Target = $target }
}

# ---------------------------------------------------------------------------------------------
# Dataset state used by collectors
# ---------------------------------------------------------------------------------------------

function New-AsoDatasetState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Entry)
    [pscustomobject]@{
        Id       = $Entry.Id
        Module   = $Entry.Module
        Entry    = $Entry
        Data     = $null
        Status   = $null
        Partial  = $false
        Errors   = [System.Collections.Generic.List[object]]::new()
        Warnings = [System.Collections.Generic.List[object]]::new()
    }
}

function Add-AsoDatasetError {
    <# Records a non-fatal error; by default marks the dataset Partial. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [string] $Message,
        [string] $Target,
        [switch] $NoPartial
    )
    $State.Errors.Add((New-AsoMessage -Code $Code -Message $Message -Target $Target))
    if (-not $NoPartial) { $State.Partial = $true }
    Write-AsoLog -Level Warning -Module $State.Module -Dataset $State.Id -Message "$Code $Message" -Target $Target
}

function Add-AsoDatasetWarning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [string] $Message,
        [string] $Target
    )
    $State.Warnings.Add((New-AsoMessage -Code $Code -Message $Message -Target $Target))
    Write-AsoLog -Level Info -Module $State.Module -Dataset $State.Id -Message "$Code $Message" -Target $Target
}

function Set-AsoDatasetNotApplicable {
    <# Marks the dataset NotApplicable (licence / feature absent). Changes only in-memory state. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $Code, [Parameter(Mandatory)] [string] $Message)
    $State.Status = 'NotApplicable'
    $State.Data = $null
    Add-AsoDatasetWarning -State $State -Code $Code -Message $Message
}

function Resolve-AsoSubCollectionFailure {
    <#
    .SYNOPSIS
    Records a failure for one sub-target (e.g. one subscription or one domain) and returns the mapped status.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] $ErrorObject, [Parameter(Mandatory)] [string] $Target)
    $mapped = Resolve-AsoErrorStatus -ErrorObject $ErrorObject
    Add-AsoDatasetError -State $State -Code $mapped.Code -Message $mapped.Message -Target $Target
    return $mapped.Status
}

function Complete-AsoMultiTargetStatus {
    <#
    .SYNOPSIS
    When every sub-target failed, promotes the dataset to Unauthorized / NotApplicable / Failed
    instead of reporting an empty Partial result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [int] $TargetCount, [string[]] $FailureStatuses = @())
    if ($TargetCount -gt 0 -and $FailureStatuses.Count -ge $TargetCount) {
        $distinct = @($FailureStatuses | Select-Object -Unique)
        if ($distinct.Count -eq 1 -and $distinct[0] -in 'Unauthorized', 'NotApplicable') { $State.Status = $distinct[0] }
        else { $State.Status = 'Failed' }
        $State.Data = $null
    }
}

# ---------------------------------------------------------------------------------------------
# Licence detection (entra.subscribedSkus service plans)
# ---------------------------------------------------------------------------------------------

function Get-AsoServicePlanName {
    <#
    .SYNOPSIS
    Returns the set of enabled service plan names in the tenant (e.g. AAD_PREMIUM, AAD_PREMIUM_P2,
    INTUNE_A, ATP_ENTERPRISE, THREAT_INTELLIGENCE), or $null when licences cannot be determined.
    #>
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    if ($ctx.ServicePlansResolved) { return $ctx.ServicePlans }
    $ctx.ServicePlansResolved = $true
    if (-not (Test-AsoGraphAvailable)) { return $null }
    try {
        $skus = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/subscribedSkus")
        $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($sku in $skus) {
            $skuStatus = [string](Get-AsoPropertyValue $sku 'capabilityStatus')
            if ($skuStatus -and $skuStatus -notin 'Enabled', 'Warning', 'LockedOut') { continue }
            foreach ($plan in (Get-AsoList $sku 'servicePlans')) {
                if ($null -eq $plan) { continue }
                $prov = [string](Get-AsoPropertyValue $plan 'provisioningStatus')
                if ($prov -and $prov -eq 'Disabled') { continue }
                [void]$names.Add([string](Get-AsoPropertyValue $plan 'servicePlanName'))
            }
        }
        $ctx.ServicePlans = $names
    }
    catch {
        Write-AsoLog -Level Warning -Module 'Entra' -Dataset 'entra.subscribedSkus' -Message 'Licence information could not be read; licence-dependent datasets rely on service error mapping.'
        $ctx.ServicePlans = $null
    }
    return $ctx.ServicePlans
}

function Test-AsoLicence {
    <#
    .SYNOPSIS
    Returns $true when any of the service plans is present, $false when licences are known and none
    is present, and $null when licence information is unavailable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $ServicePlan)
    $plans = Get-AsoServicePlanName
    if ($null -eq $plans) { return $null }
    foreach ($p in $ServicePlan) { if ($plans.Contains($p)) { return $true } }
    return $false
}

function Assert-AsoLicence {
    <#
    .SYNOPSIS
    Marks the dataset NotApplicable and returns $false when the tenant is known not to have any of the plans.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string[]] $ServicePlan, [Parameter(Mandatory)] [string] $Feature)
    $licensed = Test-AsoLicence -ServicePlan $ServicePlan
    if ($false -eq $licensed) {
        Set-AsoDatasetNotApplicable -State $State -Code 'LICENSE_NOT_PRESENT' -Message "$Feature is not licensed in this tenant (none of the service plans $($ServicePlan -join ', ') is present in subscribedSkus). The dataset does not apply."
        return $false
    }
    if ($null -eq $licensed) {
        Add-AsoDatasetWarning -State $State -Code 'LICENSE_UNKNOWN' -Message "Licence information was not available; $Feature availability is inferred from the service response."
    }
    return $true
}

function Get-AsoCount {
    <# Returns a non-negative [long] count; null or negative values become 0. #>
    [CmdletBinding()]
    [OutputType([long])]
    param($Value)
    $n = ConvertTo-AsoNumber $Value
    if ($null -eq $n -or $n -lt 0) { return [long]0 }
    return [long]$n
}

function Get-AsoFirstPropertyValue {
    <# Returns the value of the first property in -Name that is present and not null. #>
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string[]] $Name)
    foreach ($n in $Name) {
        $v = Get-AsoPropertyValue -InputObject $InputObject -Name $n
        if ($null -ne $v) { return , $v }
    }
    return $null
}
