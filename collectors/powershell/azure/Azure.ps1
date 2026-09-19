# Azure datasets via Azure Resource Manager REST (Invoke-AzRestMethod -Method GET only).
# Keys, connection strings, secrets and security contact addresses are never read or stored.

function Get-AsoAzureSubscriptionList {
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    if (-not $ctx.Cache.ContainsKey('arm:subscriptions')) {
        $ctx.Cache['arm:subscriptions'] = [object[]]@(Invoke-AsoArmGetAll -Path '/subscriptions?api-version=2022-12-01')
    }
    return , $ctx.Cache['arm:subscriptions']
}

function Get-AsoAzureActiveSubscriptionId {
    <# Subscriptions that can be read (Enabled, Warned, PastDue). #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $ids = @((Get-AsoAzureSubscriptionList) | Where-Object { [string]$_.state -in 'Enabled', 'Warned', 'PastDue' } | ForEach-Object { [string]$_.subscriptionId })
    return , [string[]]$ids
}

function Get-AsoResourceGroupFromId {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $ResourceId)
    if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
    return ''
}

function Invoke-AsoAzurePerSubscription {
    <#
    .SYNOPSIS
    Runs a per-subscription ARM list, isolating failures per subscription. Returns a hashtable
    subscriptionId -> items for the subscriptions that succeeded and applies Partial / Unauthorized
    semantics to the dataset.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $PathTemplate)
    $subs = Get-AsoAzureActiveSubscriptionId
    $results = [ordered]@{}
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $subs) {
        try {
            $results[$id] = [object[]]@(Invoke-AsoArmGetAll -Path ($PathTemplate -f $id) -State $State -Target $id)
        }
        catch {
            $failures.Add((Resolve-AsoSubCollectionFailure -State $State -ErrorObject $_ -Target "subscription $id"))
        }
    }
    Complete-AsoMultiTargetStatus -State $State -TargetCount $subs.Count -FailureStatuses $failures.ToArray()
    if ($subs.Count -eq 0) {
        Add-AsoDatasetWarning -State $State -Code 'NO_SUBSCRIPTIONS' -Message 'No enabled subscriptions are visible to the collecting account.'
    }
    return $results
}

function Get-AsoAzureSubscription {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $subs = Get-AsoAzureSubscriptionList
    $State.Data = [object[]]@($subs | ForEach-Object {
            [ordered]@{
                subscriptionId = [string]$_.subscriptionId
                displayName    = [string]$_.displayName
                state          = [string]$_.state
                tenantId       = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'tenantId')
            }
        })
}

function Resolve-AsoDirectoryObjectName {
    <#
    .SYNOPSIS
    Resolves principal display names through Graph GET /directoryObjects/{id}. Optional: when Graph
    is unavailable names are left null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [string[]] $PrincipalId, [int] $Max = 500)
    $names = @{}
    if (-not (Test-AsoGraphAvailable)) {
        Add-AsoDatasetWarning -State $State -Code 'PRINCIPAL_NAMES_UNRESOLVED' -Message 'Microsoft Graph is not connected; principal display names were not resolved.'
        return $names
    }
    $unique = @($PrincipalId | Where-Object { $_ } | Sort-Object -Unique)
    if ($unique.Count -gt $Max) {
        Add-AsoDatasetWarning -State $State -Code 'PRINCIPAL_NAMES_TRUNCATED' -Message "Only the first $Max of $($unique.Count) principals were resolved to names."
        $unique = $unique[0..($Max - 1)]
    }
    $failed = 0
    foreach ($id in $unique) {
        try {
            $o = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/directoryObjects/$([uri]::EscapeDataString($id))?`$select=id,displayName,userPrincipalName"
            $names[$id] = [pscustomobject]@{
                DisplayName       = ConvertTo-AsoString (Get-AsoPropertyValue $o 'displayName')
                UserPrincipalName = ConvertTo-AsoString (Get-AsoPropertyValue $o 'userPrincipalName')
            }
        }
        catch { $failed++ }
    }
    if ($failed -gt 0) {
        Add-AsoDatasetWarning -State $State -Code 'PRINCIPAL_NAMES_PARTIAL' -Message "$failed principal(s) could not be resolved to a name (deleted objects or insufficient Graph permissions)."
    }
    return $names
}

function Get-AsoAzureRoleAssignment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01'
    if ($State.Status) { return }
    $roleNames = @{}
    foreach ($subId in $perSub.Keys) {
        try {
            foreach ($def in (Invoke-AsoArmGetAll -Path "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01" -State $State -Target $subId)) {
                $guid = ([string]$def.name).ToLowerInvariant()
                $roleNames[$guid] = [string](Get-AsoPropertyValue $def 'properties.roleName')
            }
        }
        catch {
            [void](Resolve-AsoSubCollectionFailure -State $State -ErrorObject $_ -Target "role definitions of subscription $subId")
        }
    }
    $principalIds = @($perSub.Values | ForEach-Object { $_ } | ForEach-Object { [string](Get-AsoPropertyValue $_ 'properties.principalId') })
    $principalNames = Resolve-AsoDirectoryObjectName -State $State -PrincipalId $principalIds
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        foreach ($ra in $perSub[$subId]) {
            $roleDefId = [string](Get-AsoPropertyValue $ra 'properties.roleDefinitionId')
            $roleGuid = ($roleDefId -split '/')[-1].ToLowerInvariant()
            $principalId = [string](Get-AsoPropertyValue $ra 'properties.principalId')
            $resolved = $principalNames[$principalId]
            $type = [string](Get-AsoPropertyValue $ra 'properties.principalType')
            $out.Add([ordered]@{
                    subscriptionId       = $subId
                    roleAssignmentId     = [string](Get-AsoPropertyValue $ra 'id')
                    scope                = [string](Get-AsoPropertyValue $ra 'properties.scope')
                    roleDefinitionName   = if ($roleNames.ContainsKey($roleGuid)) { $roleNames[$roleGuid] } else { $roleGuid }
                    roleDefinitionId     = ConvertTo-AsoString $roleDefId
                    principalId          = $principalId
                    principalType        = if ($type) { $type } else { 'Unknown' }
                    principalDisplayName = if ($resolved) { $resolved.DisplayName } else { $null }
                    principalSignInName  = if ($resolved) { $resolved.UserPrincipalName } else { $null }
                })
        }
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureDefenderPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Security/pricings?api-version=2024-01-01'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        foreach ($p in $perSub[$subId]) {
            $out.Add([ordered]@{
                    subscriptionId = $subId
                    name           = [string](Get-AsoPropertyValue $p 'name')
                    pricingTier    = [string](Get-AsoPropertyValue $p 'properties.pricingTier')
                    subPlan        = ConvertTo-AsoString (Get-AsoPropertyValue $p 'properties.subPlan')
                })
        }
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureSecurityContact {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        $contacts = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $perSub[$subId]) {
            # Only count addresses; the addresses themselves are never stored.
            $emails = [string](Get-AsoPropertyValue $c 'properties.emails')
            $emailCount = @($emails -split '[;,]' | Where-Object { $_.Trim() }).Count
            $alertSource = @((Get-AsoList (Get-AsoPropertyValue $c 'properties') 'notificationsSources') | Where-Object { [string](Get-AsoPropertyValue $_ 'sourceType') -eq 'Alert' }) | Select-Object -First 1
            $contacts.Add([ordered]@{
                    name                 = [string](Get-AsoPropertyValue $c 'name')
                    emailCount           = [long]$emailCount
                    isEnabled            = ConvertTo-AsoBool (Get-AsoPropertyValue $c 'properties.isEnabled')
                    notifyRoles          = ConvertTo-AsoStringArray (Get-AsoPropertyValue $c 'properties.notificationsByRole.roles')
                    notifyRolesState     = ConvertTo-AsoString (Get-AsoPropertyValue $c 'properties.notificationsByRole.state')
                    alertMinimalSeverity = ConvertTo-AsoString (Get-AsoPropertyValue $alertSource 'minimalSeverity')
                })
        }
        $out.Add([ordered]@{ subscriptionId = $subId; contacts = [object[]]$contacts.ToArray() })
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureStorageAccount {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        foreach ($s in $perSub[$subId]) {
            $id = [string](Get-AsoPropertyValue $s 'id')
            $out.Add([ordered]@{
                    subscriptionId           = $subId
                    id                       = $id
                    name                     = [string](Get-AsoPropertyValue $s 'name')
                    resourceGroup            = Get-AsoResourceGroupFromId -ResourceId $id
                    location                 = ConvertTo-AsoString (Get-AsoPropertyValue $s 'location')
                    kind                     = ConvertTo-AsoString (Get-AsoPropertyValue $s 'kind')
                    allowBlobPublicAccess    = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'properties.allowBlobPublicAccess')
                    supportsHttpsTrafficOnly = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'properties.supportsHttpsTrafficOnly')
                    minimumTlsVersion        = ConvertTo-AsoString (Get-AsoPropertyValue $s 'properties.minimumTlsVersion')
                    allowSharedKeyAccess     = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'properties.allowSharedKeyAccess')
                    publicNetworkAccess      = ConvertTo-AsoString (Get-AsoPropertyValue $s 'properties.publicNetworkAccess')
                    networkDefaultAction     = ConvertTo-AsoString (Get-AsoPropertyValue $s 'properties.networkAcls.defaultAction')
                })
        }
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureKeyVault {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        foreach ($v in $perSub[$subId]) {
            $id = [string](Get-AsoPropertyValue $v 'id')
            $out.Add([ordered]@{
                    subscriptionId            = $subId
                    id                        = $id
                    name                      = [string](Get-AsoPropertyValue $v 'name')
                    resourceGroup             = Get-AsoResourceGroupFromId -ResourceId $id
                    location                  = ConvertTo-AsoString (Get-AsoPropertyValue $v 'location')
                    enableSoftDelete          = ConvertTo-AsoBool (Get-AsoPropertyValue $v 'properties.enableSoftDelete')
                    softDeleteRetentionInDays = ConvertTo-AsoNumber (Get-AsoPropertyValue $v 'properties.softDeleteRetentionInDays')
                    enablePurgeProtection     = ConvertTo-AsoBool (Get-AsoPropertyValue $v 'properties.enablePurgeProtection')
                    enableRbacAuthorization   = ConvertTo-AsoBool (Get-AsoPropertyValue $v 'properties.enableRbacAuthorization')
                    publicNetworkAccess       = ConvertTo-AsoString (Get-AsoPropertyValue $v 'properties.publicNetworkAccess')
                    networkDefaultAction      = ConvertTo-AsoString (Get-AsoPropertyValue $v 'properties.networkAcls.defaultAction')
                })
        }
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureNetworkSecurityGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        foreach ($n in $perSub[$subId]) {
            $id = [string](Get-AsoPropertyValue $n 'id')
            # Custom rules only; defaultSecurityRules are intentionally excluded.
            $rules = [object[]]@((Get-AsoList (Get-AsoPropertyValue $n 'properties') 'securityRules') | ForEach-Object {
                    $priority = ConvertTo-AsoNumber (Get-AsoPropertyValue $_ 'properties.priority')
                    [ordered]@{
                        name                   = [string](Get-AsoPropertyValue $_ 'name')
                        direction              = [string](Get-AsoPropertyValue $_ 'properties.direction')
                        access                 = [string](Get-AsoPropertyValue $_ 'properties.access')
                        priority               = if ($null -eq $priority) { [long]0 } else { [long]$priority }
                        protocol               = [string](Get-AsoPropertyValue $_ 'properties.protocol')
                        sourceAddressPrefix    = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'properties.sourceAddressPrefix')
                        sourceAddressPrefixes  = ConvertTo-AsoStringArray (Get-AsoPropertyValue $_ 'properties.sourceAddressPrefixes')
                        destinationPortRange   = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'properties.destinationPortRange')
                        destinationPortRanges  = ConvertTo-AsoStringArray (Get-AsoPropertyValue $_ 'properties.destinationPortRanges')
                    }
                })
            $out.Add([ordered]@{
                    subscriptionId = $subId
                    id             = $id
                    name           = [string](Get-AsoPropertyValue $n 'name')
                    resourceGroup  = Get-AsoResourceGroupFromId -ResourceId $id
                    securityRules  = $rules
                })
        }
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoAzureActivityLogDiagnostic {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $perSub = Invoke-AsoAzurePerSubscription -State $State -PathTemplate '/subscriptions/{0}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview'
    if ($State.Status) { return }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $perSub.Keys) {
        $settings = [object[]]@($perSub[$subId] | ForEach-Object {
                $props = Get-AsoPropertyValue $_ 'properties'
                $enabled = [string[]]@((Get-AsoList $props 'logs') | Where-Object { ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'enabled') } | ForEach-Object {
                        $cat = Get-AsoPropertyValue $_ 'category'
                        if ($cat) { [string]$cat } else { [string](Get-AsoPropertyValue $_ 'categoryGroup') }
                    } | Where-Object { $_ })
                [ordered]@{
                    name                     = [string](Get-AsoPropertyValue $_ 'name')
                    workspaceConfigured      = [bool](Get-AsoPropertyValue $props 'workspaceId')
                    storageAccountConfigured = [bool](Get-AsoPropertyValue $props 'storageAccountId')
                    eventHubConfigured       = [bool]((Get-AsoPropertyValue $props 'eventHubAuthorizationRuleId') -or (Get-AsoPropertyValue $props 'eventHubName'))
                    enabledCategories        = $enabled
                }
            })
        $out.Add([ordered]@{ subscriptionId = $subId; settings = $settings })
    }
    $State.Data = [object[]]$out.ToArray()
}
