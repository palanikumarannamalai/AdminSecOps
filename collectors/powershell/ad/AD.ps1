# Active Directory datasets (allow-listed Get-AD* cmdlets from the RSAT ActiveDirectory module).
# Password material is never requested: no unicodePwd, no LAPS passwords, no supplementalCredentials.

# userAccountControl flags
$script:AsoUac = @{
    ACCOUNTDISABLE                 = 0x2
    PASSWD_NOTREQD                 = 0x20
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x80
    DONT_EXPIRE_PASSWORD           = 0x10000
    TRUSTED_FOR_DELEGATION         = 0x80000
    NOT_DELEGATED                  = 0x100000
    DONT_REQ_PREAUTH               = 0x400000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
}

$script:AsoAdUserLdapFilter = '(|(adminCount=1)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=32)(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=524288))'

function Test-AsoFlag {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Value, [Parameter(Mandatory)] [long] $Flag)
    $n = ConvertTo-AsoNumber $Value
    if ($null -eq $n) { return $false }
    return (([long]$n -band $Flag) -ne 0)
}

function Get-AsoAdForestInfo {
    <#
    .SYNOPSIS
    Cached forest topology shared by the AD, ADCS and GPO modules.
    #>
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    if ($ctx.Cache.ContainsKey('ad:forest')) { return $ctx.Cache['ad:forest'] }
    $forest = @(Invoke-AsoAdCommand -Name 'Get-ADForest' -Property @('Name', 'ForestMode', 'RootDomain', 'Domains'))[0]
    if ($null -eq $forest) { throw 'Get-ADForest returned no forest.' }
    $current = @(Invoke-AsoAdCommand -Name 'Get-ADDomain' -Property @('DNSRoot') -ReplayKey 'Get-ADDomain_current')[0]
    $info = [pscustomobject]@{
        Name          = [string]$forest.Name
        ForestMode    = [string]$forest.ForestMode
        RootDomain    = [string]$forest.RootDomain
        Domains       = ConvertTo-AsoStringArray $forest.Domains
        CurrentDomain = if ($current) { [string]$current.DNSRoot } else { [string]$forest.RootDomain }
    }
    $ctx.Cache['ad:forest'] = $info
    $ctx.Environment.adForestName = $info.Name
    $ctx.Environment.adDomainName = $info.CurrentDomain
    return $info
}

function Get-AsoAdDomainInfo {
    <# Cached Get-ADDomain result for one domain. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Domain)
    $ctx = Get-AsoContext
    $key = "ad:domain:$Domain"
    if (-not $ctx.Cache.ContainsKey($key)) {
        $ctx.Cache[$key] = @(Invoke-AsoAdCommand -Name 'Get-ADDomain' -Parameters @{ Identity = $Domain; Server = $Domain } -Property @('DNSRoot', 'NetBIOSName', 'DomainSID', 'DistinguishedName', 'DomainMode', 'PDCEmulator') -ReplayKey "Get-ADDomain_$Domain")[0]
    }
    return $ctx.Cache[$key]
}

function Invoke-AsoAdPerDomain {
    <#
    .SYNOPSIS
    Runs a script block for every domain in the forest, isolating failures per domain.
    Returns the list of per-domain outputs; applies Partial / Unauthorized semantics.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [scriptblock] $ScriptBlock)
    # Variable names are prefixed so they cannot shadow variables the script block reads from its caller.
    $asoPerDomainForest = Get-AsoAdForestInfo
    $asoPerDomainOut = [System.Collections.Generic.List[object]]::new()
    $asoPerDomainFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($asoPerDomainName in $asoPerDomainForest.Domains) {
        try {
            foreach ($asoPerDomainItem in (& $ScriptBlock $asoPerDomainName)) { if ($null -ne $asoPerDomainItem) { $asoPerDomainOut.Add($asoPerDomainItem) } }
        }
        catch {
            $asoPerDomainFailures.Add((Resolve-AsoSubCollectionFailure -State $State -ErrorObject $_ -Target "domain $asoPerDomainName"))
        }
    }
    Complete-AsoMultiTargetStatus -State $State -TargetCount $asoPerDomainForest.Domains.Count -FailureStatuses $asoPerDomainFailures.ToArray()
    return , [object[]]$asoPerDomainOut.ToArray()
}

function Get-AsoAdForest {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $forest = Get-AsoAdForestInfo
    $features = @(Invoke-AsoAdCommand -Name 'Get-ADOptionalFeature' -Parameters @{ Filter = "name -eq 'Recycle Bin Feature'"; Server = $forest.RootDomain } -Property @('Name', 'EnabledScopes') -ReplayKey 'Get-ADOptionalFeature_RecycleBin')
    $enabled = $false
    foreach ($f in $features) { if ((ConvertTo-AsoStringArray $f.EnabledScopes).Count -gt 0) { $enabled = $true } }
    $State.Data = [ordered]@{
        name              = $forest.Name
        forestMode        = $forest.ForestMode
        rootDomain        = $forest.RootDomain
        domains           = [string[]]$forest.Domains
        recycleBinEnabled = $enabled
    }
}

function Get-AsoAdDomain {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $d = Get-AsoAdDomainInfo -Domain $domain
        $maq = $null
        try {
            $obj = @(Invoke-AsoAdCommand -Name 'Get-ADObject' -Parameters @{ Identity = [string]$d.DistinguishedName; Server = $domain; Properties = @('ms-DS-MachineAccountQuota') } -Property @('ms-DS-MachineAccountQuota') -ReplayKey "Get-ADObject_$($domain)_MachineAccountQuota")[0]
            $maq = ConvertTo-AsoNumber $obj.'ms-DS-MachineAccountQuota'
        }
        catch {
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            Add-AsoDatasetError -State $State -Code $mapped.Code -Message "ms-DS-MachineAccountQuota could not be read. $($mapped.Message)" -Target $domain
        }
        [ordered]@{
            dnsRoot             = [string]$d.DNSRoot
            netBIOSName         = [string]$d.NetBIOSName
            domainSid           = [string]$d.DomainSID
            distinguishedName   = [string]$d.DistinguishedName
            domainMode          = [string]$d.DomainMode
            machineAccountQuota = $maq
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function ConvertTo-AsoPasswordPolicyField {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)
    $maxAge = $null
    if ($Policy.MaxPasswordAge) {
        $ts = [TimeSpan]::Zero
        if ([TimeSpan]::TryParse([string]$Policy.MaxPasswordAge, [Globalization.CultureInfo]::InvariantCulture, [ref]$ts) -and $ts.Ticks -gt 0 -and $ts -ne [TimeSpan]::MaxValue) {
            $maxAge = [Math]::Round($ts.TotalDays, 2)
            if ($maxAge -eq [Math]::Floor($maxAge)) { $maxAge = [long]$maxAge }
        }
    }
    $lockMinutes = $null
    if ($null -ne $Policy.LockoutDuration) {
        $ts = [TimeSpan]::Zero
        if ([TimeSpan]::TryParse([string]$Policy.LockoutDuration, [Globalization.CultureInfo]::InvariantCulture, [ref]$ts) -and $ts.Ticks -ge 0 -and $ts -ne [TimeSpan]::MaxValue) {
            $lockMinutes = [Math]::Round($ts.TotalMinutes, 2)
            if ($lockMinutes -eq [Math]::Floor($lockMinutes)) { $lockMinutes = [long]$lockMinutes }
        }
    }
    [ordered]@{
        minPasswordLength           = Get-AsoCount $Policy.MinPasswordLength
        passwordHistoryCount        = Get-AsoCount $Policy.PasswordHistoryCount
        maxPasswordAgeDays          = $maxAge
        complexityEnabled           = [bool](ConvertTo-AsoBool $Policy.ComplexityEnabled)
        reversibleEncryptionEnabled = [bool](ConvertTo-AsoBool $Policy.ReversibleEncryptionEnabled)
        lockoutThreshold            = Get-AsoCount $Policy.LockoutThreshold
        lockoutDurationMinutes      = $lockMinutes
    }
}

function Get-AsoAdPasswordPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $fields = @('MinPasswordLength', 'PasswordHistoryCount', 'MaxPasswordAge', 'ComplexityEnabled', 'ReversibleEncryptionEnabled', 'LockoutThreshold', 'LockoutDuration')
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $default = @(Invoke-AsoAdCommand -Name 'Get-ADDefaultDomainPasswordPolicy' -Parameters @{ Identity = $domain; Server = $domain } -Property $fields -ReplayKey "Get-ADDefaultDomainPasswordPolicy_$domain")[0]
        if ($null -eq $default) { throw "No default domain password policy was returned for $domain." }
        $fine = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($pso in (Invoke-AsoAdCommand -Name 'Get-ADFineGrainedPasswordPolicy' -Parameters @{ Filter = '*'; Server = $domain } -Property (@('Name', 'Precedence', 'AppliesTo') + $fields) -ReplayKey "Get-ADFineGrainedPasswordPolicy_$domain")) {
                $f = ConvertTo-AsoPasswordPolicyField -Policy $pso
                $entry = [ordered]@{
                    name           = [string]$pso.Name
                    precedence     = [long](ConvertTo-AsoNumber $pso.Precedence)
                    appliesToCount = [long](ConvertTo-AsoStringArray $pso.AppliesTo).Count
                }
                foreach ($k in $f.Keys) { $entry[$k] = $f[$k] }
                $fine.Add($entry)
            }
        }
        catch {
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            Add-AsoDatasetError -State $State -Code $mapped.Code -Message "Fine-grained password policies could not be read. $($mapped.Message)" -Target $domain
        }
        [ordered]@{
            domain              = $domain
            defaultPolicy       = ConvertTo-AsoPasswordPolicyField -Policy $default
            fineGrainedPolicies = [object[]]$fine.ToArray()
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdPrivilegedGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $forest = Get-AsoAdForestInfo
    $rootSid = [string](Get-AsoAdDomainInfo -Domain $forest.RootDomain).DomainSID
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $d = Get-AsoAdDomainInfo -Domain $domain
        $sid = [string]$d.DomainSID
        $groupSids = [System.Collections.Generic.List[string]]::new()
        foreach ($rid in 512, 520, 526) { $groupSids.Add("$sid-$rid") }
        if ($domain -eq $forest.RootDomain) { foreach ($rid in 518, 519, 527) { $groupSids.Add("$rootSid-$rid") } }
        foreach ($builtin in 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551') { $groupSids.Add($builtin) }
        foreach ($gs in $groupSids) {
            try {
                $group = @(Invoke-AsoAdCommand -Name 'Get-ADGroup' -Parameters @{ Identity = $gs; Server = $domain } -Property @('Name', 'SID') -ReplayKey "Get-ADGroup_$($domain)_$gs")[0]
                if ($null -eq $group) { continue }
                $members = @(Invoke-AsoAdCommand -Name 'Get-ADGroupMember' -Parameters @{ Identity = $gs; Server = $domain; Recursive = $true } -Property @('SamAccountName', 'SID', 'objectClass') -ReplayKey "Get-ADGroupMember_$($domain)_$gs")
                [ordered]@{
                    domain    = $domain
                    groupName = [string]$group.Name
                    groupSid  = [string]$group.SID
                    members   = [object[]]@($members | ForEach-Object {
                            [ordered]@{
                                samAccountName = [string]$_.SamAccountName
                                sid            = [string]$_.SID
                                objectClass    = [string]$_.objectClass
                            }
                        })
                }
            }
            catch {
                $mapped = Resolve-AsoErrorStatus -ErrorObject $_
                if ($mapped.Status -eq 'Unauthorized') { throw }
                Add-AsoDatasetError -State $State -Code $mapped.Code -Message "Membership of group $gs could not be read. $($mapped.Message)" -Target "$domain $gs"
            }
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdUser {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $domainsOut = [System.Collections.Generic.List[object]]::new()
    $usersOut = [System.Collections.Generic.List[object]]::new()
    $null = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $d = Get-AsoAdDomainInfo -Domain $domain
        $protectedSid = "$([string]$d.DomainSID)-525"
        $all = @(Invoke-AsoAdCommand -Name 'Get-ADUser' -Parameters @{ Filter = '*'; Server = $domain; ResultSetSize = $null } -Property @('Enabled') -ReplayKey "Get-ADUser_$($domain)_all")
        $protectedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($m in (Invoke-AsoAdCommand -Name 'Get-ADGroupMember' -Parameters @{ Identity = $protectedSid; Server = $domain; Recursive = $true } -Property @('SID') -ReplayKey "Get-ADGroupMember_$($domain)_$protectedSid")) {
                [void]$protectedMembers.Add([string]$m.SID)
            }
        }
        catch {
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            Add-AsoDatasetError -State $State -Code $mapped.Code -Message "Protected Users membership could not be read. $($mapped.Message)" -Target $domain
        }
        $domainsOut.Add([ordered]@{
                domain                  = $domain
                totalUsers              = [long]$all.Count
                enabledUsers            = [long]@($all | Where-Object { ConvertTo-AsoBool $_.Enabled }).Count
                protectedUsersGroupSids = [string[]]@($protectedSid)
            })
        $props = @('SamAccountName', 'SID', 'Enabled', 'adminCount', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'userAccountControl', 'servicePrincipalName')
        $risky = @(Invoke-AsoAdCommand -Name 'Get-ADUser' -Parameters @{ LDAPFilter = $script:AsoAdUserLdapFilter; Server = $domain; ResultSetSize = $null; Properties = @('adminCount', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'userAccountControl', 'servicePrincipalName') } -Property $props -ReplayKey "Get-ADUser_$($domain)_securityRelevant")
        foreach ($u in $risky) {
            $uac = $u.userAccountControl
            $usersOut.Add([ordered]@{
                    domain                            = $domain
                    samAccountName                    = [string]$u.SamAccountName
                    sid                               = [string]$u.SID
                    enabled                           = if ($null -ne $u.Enabled) { [bool](ConvertTo-AsoBool $u.Enabled) } else { -not (Test-AsoFlag $uac $script:AsoUac.ACCOUNTDISABLE) }
                    adminCount                        = ((ConvertTo-AsoNumber $u.adminCount) -eq 1)
                    lastLogonTimestamp                = ConvertFrom-AsoFileTime $u.lastLogonTimestamp
                    pwdLastSet                        = ConvertFrom-AsoFileTime $u.pwdLastSet
                    whenCreated                       = ConvertTo-AsoTimestamp $u.whenCreated
                    passwordNeverExpires              = Test-AsoFlag $uac $script:AsoUac.DONT_EXPIRE_PASSWORD
                    passwordNotRequired               = Test-AsoFlag $uac $script:AsoUac.PASSWD_NOTREQD
                    doesNotRequirePreAuth             = Test-AsoFlag $uac $script:AsoUac.DONT_REQ_PREAUTH
                    allowReversiblePasswordEncryption = Test-AsoFlag $uac $script:AsoUac.ENCRYPTED_TEXT_PWD_ALLOWED
                    accountNotDelegated               = Test-AsoFlag $uac $script:AsoUac.NOT_DELEGATED
                    trustedForDelegation              = Test-AsoFlag $uac $script:AsoUac.TRUSTED_FOR_DELEGATION
                    trustedToAuthForDelegation        = Test-AsoFlag $uac $script:AsoUac.TRUSTED_TO_AUTH_FOR_DELEGATION
                    servicePrincipalNameCount         = [long](ConvertTo-AsoStringArray $u.servicePrincipalName).Count
                    memberOfProtectedUsers            = $protectedMembers.Contains([string]$u.SID)
                })
        }
    }
    if (-not $State.Status) {
        $State.Data = [ordered]@{
            domains = [object[]]$domainsOut.ToArray()
            users   = [object[]]$usersOut.ToArray()
        }
    }
}

function Get-AsoAdKrbtgt {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $k = @(Invoke-AsoAdCommand -Name 'Get-ADUser' -Parameters @{ Identity = 'krbtgt'; Server = $domain; Properties = @('pwdLastSet') } -Property @('SamAccountName', 'pwdLastSet') -ReplayKey "Get-ADUser_$($domain)_krbtgt")[0]
        [ordered]@{ domain = $domain; pwdLastSet = ConvertFrom-AsoFileTime $k.pwdLastSet }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdLapsSchemaAttribute {
    <# Returns which LAPS expiration attributes exist in the schema (requesting a missing attribute fails). #>
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    if ($ctx.Cache.ContainsKey('ad:laps')) { return $ctx.Cache['ad:laps'] }
    $forest = Get-AsoAdForestInfo
    $rootDse = @(Invoke-AsoAdCommand -Name 'Get-ADRootDSE' -Parameters @{ Server = $forest.RootDomain } -Property @('schemaNamingContext', 'configurationNamingContext'))[0]
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($attr in 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime') {
        $hit = @(Invoke-AsoAdCommand -Name 'Get-ADObject' -Parameters @{ SearchBase = [string]$rootDse.schemaNamingContext; LDAPFilter = "(lDAPDisplayName=$attr)"; Server = $forest.RootDomain } -Property @('Name') -ReplayKey "Get-ADObject_schema_$attr")
        if ($hit.Count -gt 0) { $found.Add($attr) }
    }
    $ctx.Cache['ad:laps'] = [string[]]$found.ToArray()
    return , $ctx.Cache['ad:laps']
}

function Get-AsoAdComputer {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $laps = Get-AsoAdLapsSchemaAttribute
    if ($laps.Count -eq 0) {
        Add-AsoDatasetWarning -State $State -Code 'LAPS_SCHEMA_NOT_PRESENT' -Message 'Neither legacy LAPS nor Windows LAPS schema attributes exist; LAPS expiration timestamps are null.'
    }
    $adProps = @('OperatingSystem', 'OperatingSystemVersion', 'LastLogonTimestamp', 'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'PrimaryGroupID', 'DNSHostName') + $laps
    $props = @('Name', 'DNSHostName', 'Enabled', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonTimestamp', 'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'PrimaryGroupID') + $laps
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        foreach ($c in (Invoke-AsoAdCommand -Name 'Get-ADComputer' -Parameters @{ Filter = '*'; Server = $domain; ResultSetSize = $null; Properties = $adProps } -Property $props -ReplayKey "Get-ADComputer_$domain")) {
            $pgid = ConvertTo-AsoNumber $c.PrimaryGroupID
            [ordered]@{
                domain                     = $domain
                name                       = [string]$c.Name
                dnsHostName                = ConvertTo-AsoString $c.DNSHostName
                enabled                    = [bool](ConvertTo-AsoBool $c.Enabled)
                operatingSystem            = ConvertTo-AsoString $c.OperatingSystem
                operatingSystemVersion     = ConvertTo-AsoString $c.OperatingSystemVersion
                isDomainController         = ($pgid -eq 516 -or $pgid -eq 521)
                trustedForDelegation       = [bool](ConvertTo-AsoBool $c.TrustedForDelegation)
                trustedToAuthForDelegation = [bool](ConvertTo-AsoBool $c.TrustedToAuthForDelegation)
                allowedToDelegateToCount   = [long](ConvertTo-AsoStringArray $c.'msDS-AllowedToDelegateTo').Count
                lastLogonTimestamp         = ConvertFrom-AsoFileTime $c.LastLogonTimestamp
                legacyLapsExpiration       = if ($laps -contains 'ms-Mcs-AdmPwdExpirationTime') { ConvertFrom-AsoFileTime $c.'ms-Mcs-AdmPwdExpirationTime' } else { $null }
                windowsLapsExpiration      = if ($laps -contains 'msLAPS-PasswordExpirationTime') { ConvertFrom-AsoFileTime $c.'msLAPS-PasswordExpirationTime' } else { $null }
            }
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $props = @('Target', 'Direction', 'TrustType', 'ForestTransitive', 'IntraForest', 'SIDFilteringQuarantined', 'SIDFilteringForestAware', 'SelectiveAuthentication', 'TGTDelegation')
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        foreach ($t in (Invoke-AsoAdCommand -Name 'Get-ADTrust' -Parameters @{ Filter = '*'; Server = $domain } -Property $props -ReplayKey "Get-ADTrust_$domain")) {
            [ordered]@{
                domain                  = $domain
                target                  = [string]$t.Target
                direction               = [string]$t.Direction
                trustType               = [string]$t.TrustType
                forestTransitive        = [bool](ConvertTo-AsoBool $t.ForestTransitive)
                intraForest             = [bool](ConvertTo-AsoBool $t.IntraForest)
                sidFilteringQuarantined = [bool](ConvertTo-AsoBool $t.SIDFilteringQuarantined)
                sidFilteringForestAware = [bool](ConvertTo-AsoBool $t.SIDFilteringForestAware)
                selectiveAuthentication = [bool](ConvertTo-AsoBool $t.SelectiveAuthentication)
                tgtDelegation           = ConvertTo-AsoBool $t.TGTDelegation
            }
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdDomainControllerList {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Domain)
    $ctx = Get-AsoContext
    $key = "ad:dcs:$Domain"
    if (-not $ctx.Cache.ContainsKey($key)) {
        $ctx.Cache[$key] = [object[]]@(Invoke-AsoAdCommand -Name 'Get-ADDomainController' -Parameters @{ Filter = '*'; Server = $Domain } -Property @('HostName', 'Site', 'OperatingSystem', 'OperatingSystemVersion', 'IsGlobalCatalog', 'IsReadOnly') -ReplayKey "Get-ADDomainController_$Domain")
    }
    return , $ctx.Cache[$key]
}

function Get-AsoAdDomainController {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        foreach ($dc in (Get-AsoAdDomainControllerList -Domain $domain)) {
            [ordered]@{
                domain                 = $domain
                hostName               = [string]$dc.HostName
                site                   = ConvertTo-AsoString $dc.Site
                operatingSystem        = ConvertTo-AsoString $dc.OperatingSystem
                operatingSystemVersion = ConvertTo-AsoString $dc.OperatingSystemVersion
                isGlobalCatalog        = [bool](ConvertTo-AsoBool $dc.IsGlobalCatalog)
                isReadOnly             = [bool](ConvertTo-AsoBool $dc.IsReadOnly)
            }
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoAdDomainControllerSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $ntds = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $lanman = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        foreach ($dc in (Get-AsoAdDomainControllerList -Domain $domain)) {
            $hostName = [string]$dc.HostName
            try {
                $a = Get-AsoRemoteRegistryValue -ComputerName $hostName -SubKey $ntds -Name @('LDAPServerIntegrity', 'LdapEnforceChannelBinding')
                $b = Get-AsoRemoteRegistryValue -ComputerName $hostName -SubKey $lanman -Name @('RequireSecuritySignature', 'SMB1')
                [ordered]@{
                    hostName                    = $hostName
                    readStatus                  = 'Success'
                    ldapServerIntegrity         = ConvertTo-AsoNumber $a['LDAPServerIntegrity']
                    ldapEnforceChannelBinding   = ConvertTo-AsoNumber $a['LdapEnforceChannelBinding']
                    smbRequireSecuritySignature = ConvertTo-AsoNumber $b['RequireSecuritySignature']
                    smb1Enabled                 = ConvertTo-AsoNumber $b['SMB1']
                }
            }
            catch {
                $mapped = Resolve-AsoErrorStatus -ErrorObject $_
                Add-AsoDatasetError -State $State -Code $mapped.Code -Message "Registry settings could not be read remotely. $($mapped.Message)" -Target $hostName
                [ordered]@{
                    hostName                    = $hostName
                    readStatus                  = 'Failed'
                    ldapServerIntegrity         = $null
                    ldapEnforceChannelBinding   = $null
                    smbRequireSecuritySignature = $null
                    smb1Enabled                 = $null
                }
            }
        }
    }
    if (-not $State.Status) {
        $State.Data = $items
        if ($items.Count -gt 0 -and @($items | Where-Object { $_.readStatus -eq 'Success' }).Count -eq 0) {
            $State.Status = 'Unauthorized'
            $State.Data = $null
        }
    }
}
