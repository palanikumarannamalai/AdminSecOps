# Read-only data access wrappers. EVERY call to a Microsoft service, directory or the local host
# goes through a function in this file. In replay mode (-ReplayPath) the wrappers read recorded,
# sanitized responses from JSON/XML files instead of calling services; the transformation code in
# the module collectors is identical in both modes.
#
# Read-only guarantees:
# - Graph: Invoke-MgGraphRequest -Method GET only.
# - ARM:   Invoke-AzRestMethod -Method GET only.
# - Exchange, AD, GPO, Windows: explicit allow-lists of Get-* cmdlets (validated before invocation).
# - Registry: opened read-only (writable = $false).
# - DNS: Resolve-DnsName (query only).
# tests/ReadOnly.Tests.ps1 verifies these rules statically.

$script:AsoExoAllowList = @(
    'Get-OrganizationConfig', 'Get-TransportConfig', 'Get-AdminAuditLogConfig', 'Get-AcceptedDomain',
    'Get-DkimSigningConfig', 'Get-HostedOutboundSpamFilterPolicy', 'Get-RemoteDomain', 'Get-EXOMailbox',
    'Get-EXOCASMailbox', 'Get-AtpPolicyForO365'
)
$script:AsoAdAllowList = @(
    'Get-ADForest', 'Get-ADDomain', 'Get-ADObject', 'Get-ADUser', 'Get-ADComputer', 'Get-ADGroup',
    'Get-ADGroupMember', 'Get-ADTrust', 'Get-ADDomainController', 'Get-ADDefaultDomainPasswordPolicy',
    'Get-ADFineGrainedPasswordPolicy', 'Get-ADOptionalFeature', 'Get-ADRootDSE'
)
$script:AsoGpoAllowList = @('Get-GPO', 'Get-GPOReport')
$script:AsoWindowsAllowList = @('Get-CimInstance', 'Get-NetFirewallProfile', 'Get-SmbServerConfiguration', 'Get-MpComputerStatus')

# Directory attributes that hold secrets. They are never requested, even if a caller asks.
$script:AsoForbiddenAdAttributes = @(
    'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory',
    'msLAPS-EncryptedDSRMPassword', 'msLAPS-EncryptedDSRMPasswordHistory', 'unicodePwd', 'dBCSPwd',
    'supplementalCredentials', 'userPassword', 'ntPwdHistory', 'lmPwdHistory', 'msDS-ManagedPassword',
    'msFVE-RecoveryPassword', 'msFVE-KeyPackage', 'msFVE-VolumeGuid', 'unixUserPassword', 'msTPM-OwnerInformation'
)

# ---------------------------------------------------------------------------------------------
# Replay support
# ---------------------------------------------------------------------------------------------

function Get-AsoReplayKey {
    <#
    .SYNOPSIS
    Converts a request (URL, ARM path or explicit key) into a file-name-safe replay key.
    The scheme and host are removed, the ARM api-version query parameter is dropped, unsafe
    characters become '_' and long keys are shortened with a SHA-256 suffix.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Request)
    $k = $Request -replace '^https?://[^/]+/', ''
    $k = $k -replace '([?&])api-version=[^&]*', '$1'
    $k = $k -replace '[^A-Za-z0-9._-]+', '_'
    $k = $k.Trim('_', '.', '-')
    if ($k.Length -gt 120) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($k)) | Select-Object -First 5 | ForEach-Object { $_.ToString('x2') })
        }
        finally { $sha.Dispose() }
        $k = $k.Substring(0, 100).TrimEnd('_', '.', '-') + '-' + $hash
    }
    return $k
}

function Get-AsoReplayFilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Category, [Parameter(Mandatory)] [string] $Key, [string] $Extension = '.json')
    $ctx = Get-AsoContext
    return (Join-Path -Path (Join-Path -Path $ctx.ReplayPath -ChildPath $Category) -ChildPath "$Key$Extension")
}

function Read-AsoReplayResponse {
    <#
    .SYNOPSIS
    Reads a recorded response. A file containing {"__replayError": {statusCode, errorCode, message}}
    raises the same exception type the live wrapper raises for that service error.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Category, [Parameter(Mandatory)] [string] $Key)
    $path = Get-AsoReplayFilePath -Category $Category -Key $Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw (New-AsoServiceException -ErrorCode 'ReplayFixtureMissing' -Message "No replay fixture was found for $Category/$Key.json.")
    }
    $parsed = ConvertFrom-AsoJson -Json ([System.IO.File]::ReadAllText($path))
    Assert-AsoReplayNotError -Value $parsed -Target "$Category/$Key"
    return , $parsed
}

function Assert-AsoReplayNotError {
    [CmdletBinding()]
    param($Value, [string] $Target)
    if ($null -ne $Value -and $Value -is [System.Management.Automation.PSCustomObject] -and $null -ne $Value.PSObject.Properties['__replayError']) {
        $e = $Value.__replayError
        throw (New-AsoServiceException -StatusCode ([int](Get-AsoPropertyValue $e 'statusCode')) -ErrorCode ([string](Get-AsoPropertyValue $e 'errorCode')) -Message ([string](Get-AsoPropertyValue $e 'message')) -Target $Target)
    }
}

# ---------------------------------------------------------------------------------------------
# Normalisation of cmdlet output (live) and recorded objects (replay) into plain values
# ---------------------------------------------------------------------------------------------

function ConvertTo-AsoAccessRuleList {
    <#
    .SYNOPSIS
    Converts an ActiveDirectorySecurity descriptor into plain access rule objects. The identity is
    translated to a SID where possible (read-only name resolution).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Security)
    $list = [System.Collections.Generic.List[object]]::new()
    $rules = $Security.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    foreach ($rule in $rules) {
        $name = [string]$rule.IdentityReference.Value
        $sid = $null
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = $null }
        $list.Add([pscustomobject][ordered]@{
                IdentityReference     = $name
                SecurityIdentifier    = $sid
                ActiveDirectoryRights = $rule.ActiveDirectoryRights.ToString()
                AccessControlType     = $rule.AccessControlType.ToString()
                ObjectType            = $rule.ObjectType.ToString()
                InheritedObjectType   = $rule.InheritedObjectType.ToString()
                IsInherited           = [bool]$rule.IsInherited
            })
    }
    return , [object[]]$list.ToArray()
}

function ConvertTo-AsoPlainValue {
    [CmdletBinding()]
    param([AllowNull()] $Value, [int] $Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [char]) { return [string]$Value }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [DateTime] -or $Value -is [DateTimeOffset]) { return (ConvertTo-AsoTimestamp -Value $Value) }
    if ($Value -is [TimeSpan]) { return $Value.ToString('c', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [guid]) { return $Value.ToString() }
    if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    if ($Value -is [ValueType]) { return $Value }
    if ($Value.PSObject.Methods['GetAccessRules'] -and $Value.GetType().Name -match 'Security$') {
        return , (ConvertTo-AsoAccessRuleList -Security $Value)
    }
    if ($Depth -gt 5) { return [string]$Value }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) {
            if (Test-AsoForbiddenPropertyName -Name $p.Name) { continue }
            $o[$p.Name] = ConvertTo-AsoPlainValue -Value $p.Value -Depth ($Depth + 1)
        }
        return [pscustomobject]$o
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) {
            if (Test-AsoForbiddenPropertyName -Name ([string]$k)) { continue }
            $o[[string]$k] = ConvertTo-AsoPlainValue -Value $Value[$k] -Depth ($Depth + 1)
        }
        return [pscustomobject]$o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $list.Add((ConvertTo-AsoPlainValue -Value $item -Depth ($Depth + 1))) }
        return , [object[]]$list.ToArray()
    }
    $text = $Value.ToString()
    $nameProp = $Value.PSObject.Properties['Name']
    if ($null -ne $nameProp -and ($text -eq $Value.GetType().FullName -or [string]::IsNullOrEmpty($text))) { return [string]$nameProp.Value }
    return $text
}

function ConvertTo-AsoPlainObject {
    <#
    .SYNOPSIS
    Projects a cmdlet output object (or recorded replay object) onto the requested property names
    with plain JSON-compatible values. Forbidden (secret) property names are never copied.
    #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string[]] $Property)
    if ($null -eq $InputObject) { return $null }
    $o = [ordered]@{}
    foreach ($name in $Property) {
        if (Test-AsoForbiddenPropertyName -Name $name) { continue }
        $value = $null
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($name)) { $value = $InputObject[$name] }
        }
        else {
            $prop = $InputObject.PSObject.Properties[$name]
            if ($null -ne $prop) { $value = $prop.Value }
        }
        $o[$name] = ConvertTo-AsoPlainValue -Value $value
    }
    return [pscustomobject]$o
}

# ---------------------------------------------------------------------------------------------
# HTTP error extraction (live)
# ---------------------------------------------------------------------------------------------

function Get-AsoHttpErrorInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $ErrorRecord)
    $ex = $ErrorRecord.Exception
    $status = 0
    $code = ''
    $message = [string]$ex.Message
    $retryAfter = $null
    $response = $null
    if ($ex.PSObject.Properties['Response']) { $response = $ex.Response }
    if ($null -ne $response) {
        try { $status = [int]$response.StatusCode } catch { $status = 0 }
        try {
            if ($response.Headers -and $response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) {
                $retryAfter = [int][Math]::Ceiling($response.Headers.RetryAfter.Delta.TotalSeconds)
            }
        }
        catch { $retryAfter = $null }
    }
    $details = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails) { $details = $ErrorRecord.ErrorDetails.Message }
    if ($details) {
        try {
            $parsed = ConvertFrom-AsoJson -Json $details
            $err = Get-AsoPropertyValue $parsed 'error'
            if ($err) {
                $code = [string](Get-AsoPropertyValue $err 'code')
                $m = [string](Get-AsoPropertyValue $err 'message')
                if ($m) { $message = $m }
            }
        }
        catch { Write-Verbose 'Error details were not JSON.' }
    }
    if ($status -eq 0) {
        $map = @{ 'BadRequest' = 400; 'Unauthorized' = 401; 'Forbidden' = 403; 'NotFound' = 404; 'TooManyRequests' = 429; 'InternalServerError' = 500; 'ServiceUnavailable' = 503; 'GatewayTimeout' = 504 }
        foreach ($k in $map.Keys) { if ($message -match "\b$k\b") { $status = $map[$k]; break } }
    }
    [pscustomobject]@{ StatusCode = $status; ErrorCode = $code; Message = $message; RetryAfter = $retryAfter }
}

function Wait-AsoRetry {
    [CmdletBinding()]
    param([int] $Attempt, $RetryAfter)
    $delay = if ($RetryAfter -and [int]$RetryAfter -gt 0) { [Math]::Min([int]$RetryAfter, 120) } else { [Math]::Min([Math]::Pow(2, $Attempt), 60) }
    Write-AsoLog -Level Info -Message "Service throttled the request; retrying in $delay second(s) (attempt $Attempt)."
    Start-Sleep -Seconds $delay
}

# ---------------------------------------------------------------------------------------------
# Microsoft Graph (GET only)
# ---------------------------------------------------------------------------------------------

function Resolve-AsoGraphUri {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Uri)
    if ($Uri -match '^https://') { return $Uri }
    return 'https://graph.microsoft.com/' + $Uri.TrimStart('/')
}

function Test-AsoGraphAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $ctx = Get-AsoContext
    if ($ctx.Mode -eq 'Replay') { return (Test-Path -LiteralPath (Join-Path $ctx.ReplayPath 'graph') -PathType Container) }
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) { return $false }
    return ($null -ne (Get-MgContext))
}

function Invoke-AsoGraphGet {
    <#
    .SYNOPSIS
    Performs a single Microsoft Graph GET (live: Invoke-MgGraphRequest -Method GET; replay: recorded file)
    with 429/503 Retry-After handling. Returns the parsed response body.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Uri)
    $full = Resolve-AsoGraphUri -Uri $Uri
    if (Test-AsoReplayMode) {
        return , (Read-AsoReplayResponse -Category 'graph' -Key (Get-AsoReplayKey -Request $full))
    }
    $attempt = 0
    while ($true) {
        try {
            $json = Invoke-MgGraphRequest -Method GET -Uri $full -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType Json -ErrorAction Stop
            return , (ConvertFrom-AsoJson -Json ([string]$json))
        }
        catch {
            $info = Get-AsoHttpErrorInfo -ErrorRecord $_
            if ($info.StatusCode -in 429, 503, 504 -and $attempt -lt 5) {
                $attempt++
                Wait-AsoRetry -Attempt $attempt -RetryAfter $info.RetryAfter
                continue
            }
            throw (New-AsoServiceException -StatusCode $info.StatusCode -ErrorCode $info.ErrorCode -Message $info.Message)
        }
    }
}

function Invoke-AsoGraphGetAll {
    <#
    .SYNOPSIS
    GETs a Graph collection and follows @odata.nextLink. Emits each item. If a page after the first
    fails and a dataset state is supplied, the error is recorded and the dataset marked Partial.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Uri, $State, [int] $MaxPages = 10000)
    $next = Resolve-AsoGraphUri -Uri $Uri
    $page = 0
    while ($next) {
        try {
            $response = Invoke-AsoGraphGet -Uri $next
        }
        catch {
            if ($page -eq 0 -or $null -eq $State) { throw }
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            Add-AsoDatasetError -State $State -Code 'PAGE_FAILED' -Message "A result page could not be read after $page page(s); results are incomplete. $($mapped.Message)"
            break
        }
        $page++
        foreach ($item in (Get-AsoList $response 'value')) { $item }
        $next = Get-AsoOdataPropertyValue -InputObject $response -Name '@odata.nextLink'
        if ($page -ge $MaxPages) {
            if ($State) { Add-AsoDatasetError -State $State -Code 'PAGE_LIMIT' -Message "Stopped after $MaxPages pages; results are incomplete." }
            break
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Azure Resource Manager (GET only)
# ---------------------------------------------------------------------------------------------

function Test-AsoArmAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $ctx = Get-AsoContext
    if ($ctx.Mode -eq 'Replay') { return (Test-Path -LiteralPath (Join-Path $ctx.ReplayPath 'arm') -PathType Container) }
    if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) { return $false }
    return ($null -ne (Get-AzContext -ErrorAction SilentlyContinue))
}

function Invoke-AsoArmGet {
    <#
    .SYNOPSIS
    Performs a single ARM GET (live: Invoke-AzRestMethod -Method GET; replay: recorded file).
    -Path is a management.azure.com path with api-version, or an absolute nextLink URL.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    if (Test-AsoReplayMode) {
        return , (Read-AsoReplayResponse -Category 'arm' -Key (Get-AsoReplayKey -Request $Path))
    }
    $attempt = 0
    while ($true) {
        $params = @{ Method = 'GET'; ErrorAction = 'Stop' }
        if ($Path -match '^https://') { $params['Uri'] = $Path } else { $params['Path'] = $Path }
        $response = Invoke-AzRestMethod @params
        $status = [int]$response.StatusCode
        if ($status -ge 200 -and $status -lt 300) {
            return , (ConvertFrom-AsoJson -Json ([string]$response.Content))
        }
        $code = ''
        $message = "Azure Resource Manager returned HTTP $status."
        try {
            $body = ConvertFrom-AsoJson -Json ([string]$response.Content)
            $err = Get-AsoPropertyValue $body 'error'
            if ($err) {
                $code = [string](Get-AsoPropertyValue $err 'code')
                $m = [string](Get-AsoPropertyValue $err 'message')
                if ($m) { $message = $m }
            }
        }
        catch { Write-Verbose 'ARM error body was not JSON.' }
        if ($status -in 429, 503, 504 -and $attempt -lt 5) {
            $attempt++
            $retry = $null
            try { $retry = [int](@($response.Headers['Retry-After'])[0]) } catch { $retry = $null }
            Wait-AsoRetry -Attempt $attempt -RetryAfter $retry
            continue
        }
        throw (New-AsoServiceException -StatusCode $status -ErrorCode $code -Message $message)
    }
}

function Invoke-AsoArmGetAll {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, $State, [string] $Target, [int] $MaxPages = 1000)
    $next = $Path
    $page = 0
    while ($next) {
        try { $response = Invoke-AsoArmGet -Path $next }
        catch {
            if ($page -eq 0 -or $null -eq $State) { throw }
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            Add-AsoDatasetError -State $State -Code 'PAGE_FAILED' -Message "A result page could not be read; results are incomplete. $($mapped.Message)" -Target $Target
            break
        }
        $page++
        foreach ($item in (Get-AsoList $response 'value')) { $item }
        $next = Get-AsoPropertyValue $response 'nextLink'
        if ($page -ge $MaxPages) { break }
    }
}

# ---------------------------------------------------------------------------------------------
# Allow-listed cmdlet invocation (Exchange Online, Active Directory, Group Policy, Windows)
# ---------------------------------------------------------------------------------------------

function Invoke-AsoAllowListedCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string[]] $AllowList,
        [Parameter(Mandatory)] [string] $Name,
        [hashtable] $Parameters = @{},
        [string[]] $Property,
        [string] $ReplayKey,
        [switch] $Raw
    )
    if ($AllowList -notcontains $Name -or $Name -notmatch '^Get-') {
        throw "The command '$Name' is not on the read-only allow-list for $Category."
    }
    $key = if ($ReplayKey) { $ReplayKey } else { $Name }
    if (Test-AsoReplayMode) {
        $recorded = Read-AsoReplayResponse -Category $Category -Key $key
        $items = if ($null -eq $recorded) { @() } elseif ($recorded -is [array]) { $recorded } else { @($recorded) }
        foreach ($item in $items) {
            if ($Raw -or -not $Property) { $item } else { ConvertTo-AsoPlainObject -InputObject $item -Property $Property }
        }
        return
    }
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw (New-AsoServiceException -ErrorCode 'CommandNotAvailable' -Message "The command '$Name' is not available in this session.")
    }
    $invokeParams = @{} + $Parameters
    $invokeParams['ErrorAction'] = 'Stop'
    foreach ($item in (& $command @invokeParams)) {
        if ($Raw -or -not $Property) { $item } else { ConvertTo-AsoPlainObject -InputObject $item -Property $Property }
    }
}

function Invoke-AsoExoCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [hashtable] $Parameters = @{}, [Parameter(Mandatory)] [string[]] $Property, [string] $ReplayKey)
    Invoke-AsoAllowListedCommand -Category 'exo' -AllowList $script:AsoExoAllowList -Name $Name -Parameters $Parameters -Property $Property -ReplayKey $ReplayKey
}

function Test-AsoExoCommandAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    if (Test-AsoReplayMode) { return (Test-Path -LiteralPath (Get-AsoReplayFilePath -Category 'exo' -Key $Name) -PathType Leaf) }
    return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
}

function Invoke-AsoAdCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [hashtable] $Parameters = @{}, [Parameter(Mandatory)] [string[]] $Property, [string] $ReplayKey)
    if ($Parameters.ContainsKey('Properties')) {
        foreach ($attr in @($Parameters['Properties'])) {
            if ($attr -eq '*' -or $script:AsoForbiddenAdAttributes -contains $attr -or (Test-AsoForbiddenPropertyName -Name $attr)) {
                throw "The directory attribute '$attr' must never be requested by the collector."
            }
        }
    }
    Invoke-AsoAllowListedCommand -Category 'ad' -AllowList $script:AsoAdAllowList -Name $Name -Parameters $Parameters -Property $Property -ReplayKey $ReplayKey
}

function Invoke-AsoGpoCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [hashtable] $Parameters = @{}, [Parameter(Mandatory)] [string[]] $Property, [string] $ReplayKey)
    Invoke-AsoAllowListedCommand -Category 'gpo' -AllowList $script:AsoGpoAllowList -Name $Name -Parameters $Parameters -Property $Property -ReplayKey $ReplayKey
}

function Get-AsoGpoReportXml {
    <# Returns the XML report of one GPO (Get-GPOReport -ReportType Xml) as a string. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Guid, [Parameter(Mandatory)] [string] $Domain)
    if (Test-AsoReplayMode) {
        $path = Get-AsoReplayFilePath -Category 'gpo' -Key "Get-GPOReport_$($Domain)_$($Guid.Trim('{}').ToLowerInvariant())" -Extension '.xml'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw (New-AsoServiceException -ErrorCode 'ReplayFixtureMissing' -Message "No replay fixture was found for the GPO report $Guid.")
        }
        return [System.IO.File]::ReadAllText($path)
    }
    $result = Invoke-AsoAllowListedCommand -Category 'gpo' -AllowList $script:AsoGpoAllowList -Name 'Get-GPOReport' -Parameters @{ Guid = $Guid; ReportType = 'Xml'; Domain = $Domain } -Raw
    return [string]$result
}

function Invoke-AsoWindowsCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [hashtable] $Parameters = @{}, [Parameter(Mandatory)] [string[]] $Property, [string] $ReplayKey)
    Invoke-AsoAllowListedCommand -Category 'windows' -AllowList $script:AsoWindowsAllowList -Name $Name -Parameters $Parameters -Property $Property -ReplayKey $ReplayKey
}

# ---------------------------------------------------------------------------------------------
# Registry (read-only)
# ---------------------------------------------------------------------------------------------

function Get-AsoRegistryValue {
    <#
    .SYNOPSIS
    Reads one HKLM registry value on the local host, read-only. Returns $null when the key or value
    does not exist; throws when access is denied.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SubKey, [Parameter(Mandatory)] [string] $Name)
    $SubKey = $SubKey -replace '^(HKLM:\\|HKEY_LOCAL_MACHINE\\)', ''
    if (Test-AsoReplayMode) {
        $map = Get-AsoReplayCachedFile -Category 'windows' -Key 'registry'
        $prop = $map.PSObject.Properties["HKLM\$SubKey\$Name"]
        if ($null -eq $prop) { return $null }
        Assert-AsoReplayNotError -Value $prop.Value -Target "HKLM\$SubKey\$Name"
        return $prop.Value
    }
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, $false)
    if ($null -eq $key) { return $null }
    try { return $key.GetValue($Name, $null) }
    finally { $key.Dispose() }
}

function Get-AsoRemoteRegistryValue {
    <#
    .SYNOPSIS
    Reads HKLM registry values from a remote host (domain controller) read-only through the Remote
    Registry service. Returns a hashtable name -> value ($null when absent).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ComputerName, [Parameter(Mandatory)] [string] $SubKey, [Parameter(Mandatory)] [string[]] $Name)
    $result = @{}
    if (Test-AsoReplayMode) {
        $map = Get-AsoReplayCachedFile -Category 'ad' -Key 'remote-registry'
        $hostEntry = $map.PSObject.Properties[$ComputerName]
        if ($null -eq $hostEntry) { throw (New-AsoServiceException -ErrorCode 'ReplayFixtureMissing' -Message "No replay remote registry data for $ComputerName.") }
        Assert-AsoReplayNotError -Value $hostEntry.Value -Target $ComputerName
        foreach ($n in $Name) {
            $p = $hostEntry.Value.PSObject.Properties["$SubKey\$n"]
            $result[$n] = if ($null -eq $p) { $null } else { $p.Value }
        }
        return $result
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
    try {
        $key = $base.OpenSubKey($SubKey, $false)
        foreach ($n in $Name) {
            $result[$n] = if ($null -eq $key) { $null } else { $key.GetValue($n, $null) }
        }
        if ($null -ne $key) { $key.Dispose() }
    }
    finally { $base.Dispose() }
    return $result
}

function Get-AsoReplayCachedFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Category, [Parameter(Mandatory)] [string] $Key)
    $ctx = Get-AsoContext
    $cacheKey = "replay:$Category/$Key"
    if (-not $ctx.Cache.ContainsKey($cacheKey)) {
        $ctx.Cache[$cacheKey] = Read-AsoReplayResponse -Category $Category -Key $Key
    }
    return $ctx.Cache[$cacheKey]
}

# ---------------------------------------------------------------------------------------------
# DNS (public TXT queries)
# ---------------------------------------------------------------------------------------------

function Resolve-AsoDnsTxt {
    <#
    .SYNOPSIS
    Queries public TXT records. Returns Status Found | NotFound | Error and the TXT strings
    (multi-string records are concatenated).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    if (Test-AsoReplayMode) {
        try {
            $recorded = Read-AsoReplayResponse -Category 'dns' -Key (Get-AsoReplayKey -Request $Name)
        }
        catch {
            return [pscustomobject]@{ Status = 'Error'; Records = [string[]]@(); Message = $_.Exception.Message }
        }
        $status = [string](Get-AsoPropertyValue $recorded 'status')
        $records = ConvertTo-AsoStringArray -Value (Get-AsoPropertyValue $recorded 'records')
        if (-not $status) { $status = if ($records.Count -gt 0) { 'Found' } else { 'NotFound' } }
        return [pscustomobject]@{ Status = $status; Records = $records; Message = $null }
    }
    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Status = 'Error'; Records = [string[]]@(); Message = 'Resolve-DnsName is not available on this platform.' }
    }
    try {
        $answers = @(Resolve-DnsName -Name $Name -Type TXT -DnsOnly -ErrorAction Stop)
        $records = [System.Collections.Generic.List[string]]::new()
        foreach ($a in $answers) {
            if ([string]$a.Type -ne 'TXT') { continue }
            $records.Add((-join @($a.Strings)))
        }
        $status = if ($records.Count -gt 0) { 'Found' } else { 'NotFound' }
        return [pscustomobject]@{ Status = $status; Records = [string[]]$records.ToArray(); Message = $null }
    }
    catch {
        $native = 0
        try { $native = [int]$_.Exception.NativeErrorCode } catch { $native = 0 }
        if ($native -in 9003, 9501 -or $_.Exception.Message -match '(?i)(does not exist|No records|NXDOMAIN)') {
            return [pscustomobject]@{ Status = 'NotFound'; Records = [string[]]@(); Message = $null }
        }
        return [pscustomobject]@{ Status = 'Error'; Records = [string[]]@(); Message = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------
# SYSVOL (read-only file scan)
# ---------------------------------------------------------------------------------------------

function Get-AsoSysvolPolicyRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Domain)
    $ctx = Get-AsoContext
    if ($ctx.Mode -eq 'Replay') {
        return (Join-Path -Path (Join-Path -Path (Join-Path -Path $ctx.ReplayPath -ChildPath 'gpo') -ChildPath 'sysvol') -ChildPath (Join-Path $Domain 'Policies'))
    }
    return "\\$Domain\SYSVOL\$Domain\Policies"
}

function Get-AsoSysvolPreferenceFile {
    <# Lists Group Policy Preferences XML files that can carry a cpassword attribute. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string[]] $FileName)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw (New-AsoServiceException -ErrorCode 'PathNotFound' -Message "The SYSVOL Policies folder is not reachable.")
    }
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $FileName -contains $_.Name }
}

function Test-AsoFileContainsCpassword {
    <#
    .SYNOPSIS
    Returns $true when the file contains a non-empty cpassword attribute. The file content is only
    held in a local variable inside this function and is never returned, logged or stored.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)
    $text = [System.IO.File]::ReadAllText($Path)
    try {
        return [regex]::IsMatch($text, 'cpassword\s*=\s*"[^"]+"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    finally {
        $text = $null
    }
}
