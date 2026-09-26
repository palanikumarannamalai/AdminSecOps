# Microsoft Entra ID datasets (Microsoft Graph v1.0, GET only).

$script:AsoGraphAppId = '00000003-0000-0000-c000-000000000000'
$script:AsoExchangeAppId = '00000002-0000-0ff1-ce00-000000000000'

# Directory setting names that are safe and useful to keep. Everything else (notably
# BannedPasswordList and URL/free-text values) is dropped.
$script:AsoGroupSettingAllowList = @(
    'EnableBannedPasswordCheckOnPremises', 'BannedPasswordCheckOnPremisesMode', 'EnableBannedPasswordCheck',
    'LockoutThreshold', 'LockoutDurationInSeconds',
    'EnableGroupCreation', 'AllowGuestsToAccessGroups', 'AllowGuestsToBeGroupOwner', 'AllowToAddGuests',
    'EnableMIPLabels', 'EnableMSStandardBlockedWords', 'NewUnifiedGroupWritebackDefault',
    'EnableGroupSpecificConsent', 'BlockUserConsentForRiskyApps', 'EnableAdminConsentRequests',
    'ConstrainGroupSpecificConsentToMembersOfGroupId'
)

function ConvertTo-AsoPrincipalType {
    <# Maps '#microsoft.graph.user' -> 'user', '#microsoft.graph.servicePrincipal' -> 'servicePrincipal'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $ODataType)
    if (-not $ODataType) { return 'other' }
    $t = $ODataType -replace '^#?microsoft\.graph\.', ''
    switch ($t) {
        'user' { return 'user' }
        'group' { return 'group' }
        'servicePrincipal' { return 'servicePrincipal' }
        default { return 'other' }
    }
}

function ConvertTo-AsoCredentialSummary {
    <#
    .SYNOPSIS
    Keeps only credential metadata. passwordCredentials.secretText and .hint and keyCredentials.key
    are never copied.
    #>
    [CmdletBinding()]
    param($InputObject, [switch] $Key)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $InputObject) {
        if ($null -eq $c) { continue }
        $o = [ordered]@{
            keyId         = [string](Get-AsoPropertyValue $c 'keyId')
            displayName   = ConvertTo-AsoString (Get-AsoPropertyValue $c 'displayName')
            startDateTime = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $c 'startDateTime')
            endDateTime   = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $c 'endDateTime')
        }
        if ($Key) {
            $o['type'] = ConvertTo-AsoString (Get-AsoPropertyValue $c 'type')
            $o['usage'] = ConvertTo-AsoString (Get-AsoPropertyValue $c 'usage')
        }
        $out.Add($o)
    }
    return , [object[]]$out.ToArray()
}

function Get-AsoEntraOrganization {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $ctx = Get-AsoContext
    $orgs = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/organization" -State $State)
    if ($orgs.Count -eq 0) { throw 'The organization endpoint returned no tenant.' }
    $org = $orgs[0]
    $domains = [System.Collections.Generic.List[object]]::new()
    foreach ($d in (Get-AsoList $org 'verifiedDomains')) {
        $domains.Add([ordered]@{
                name         = [string](Get-AsoPropertyValue $d 'name')
                isDefault    = [bool](Get-AsoPropertyValue $d 'isDefault')
                isInitial    = [bool](Get-AsoPropertyValue $d 'isInitial')
                type         = ConvertTo-AsoString (Get-AsoPropertyValue $d 'type')
                capabilities = ConvertTo-AsoString (Get-AsoPropertyValue $d 'capabilities')
            })
    }
    $State.Data = [ordered]@{
        id                         = [string](Get-AsoPropertyValue $org 'id')
        displayName                = [string](Get-AsoPropertyValue $org 'displayName')
        createdDateTime            = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $org 'createdDateTime')
        onPremisesSyncEnabled      = ConvertTo-AsoBool (Get-AsoPropertyValue $org 'onPremisesSyncEnabled')
        onPremisesLastSyncDateTime = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $org 'onPremisesLastSyncDateTime')
        verifiedDomains            = [object[]]$domains.ToArray()
    }
    if (-not $ctx.Environment.tenantId) { $ctx.Environment.tenantId = $State.Data.id }
    $ctx.Environment.tenantDisplayName = $State.Data.displayName
    $default = @($domains | Where-Object { $_.isDefault }) | Select-Object -First 1
    if ($default) { $ctx.Environment.primaryDomain = $default.name }
}

function Get-AsoEntraSubscribedSku {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $skus = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/subscribedSkus" -State $State)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $skus) {
        $plans = [System.Collections.Generic.List[object]]::new()
        foreach ($p in (Get-AsoList $s 'servicePlans')) {
            $plans.Add([ordered]@{
                    servicePlanId      = [string](Get-AsoPropertyValue $p 'servicePlanId')
                    servicePlanName    = [string](Get-AsoPropertyValue $p 'servicePlanName')
                    provisioningStatus = [string](Get-AsoPropertyValue $p 'provisioningStatus')
                    appliesTo          = ConvertTo-AsoString (Get-AsoPropertyValue $p 'appliesTo')
                })
        }
        $prepaid = Get-AsoPropertyValue $s 'prepaidUnits'
        $consumed = ConvertTo-AsoNumber (Get-AsoPropertyValue $s 'consumedUnits')
        $enabled = ConvertTo-AsoNumber (Get-AsoPropertyValue $prepaid 'enabled')
        $out.Add([ordered]@{
                skuId            = [string](Get-AsoPropertyValue $s 'skuId')
                skuPartNumber    = [string](Get-AsoPropertyValue $s 'skuPartNumber')
                capabilityStatus = [string](Get-AsoPropertyValue $s 'capabilityStatus')
                consumedUnits    = if ($null -eq $consumed) { 0 } else { $consumed }
                prepaidUnits     = [ordered]@{
                    enabled   = if ($null -eq $enabled) { 0 } else { $enabled }
                    suspended = ConvertTo-AsoNumber (Get-AsoPropertyValue $prepaid 'suspended')
                    warning   = ConvertTo-AsoNumber (Get-AsoPropertyValue $prepaid 'warning')
                }
                servicePlans     = [object[]]$plans.ToArray()
            })
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoEntraSecurityDefault {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $policy = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/policies/identitySecurityDefaultsEnforcementPolicy"
    $State.Data = [ordered]@{ isEnabled = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $policy 'isEnabled')) }
}

function Get-AsoEntraAuthorizationPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $response = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/policies/authorizationPolicy"
    # v1.0 returns a single object; tolerate the collection form as well.
    $policy = if ($null -ne (Get-AsoPropertyValue $response 'value')) { (Get-AsoList $response 'value')[0] } else { $response }
    $perms = Get-AsoPropertyValue $policy 'defaultUserRolePermissions'
    $State.Data = [ordered]@{
        allowInvitesFrom                                  = [string](Get-AsoPropertyValue $policy 'allowInvitesFrom')
        allowedToSignUpEmailBasedSubscriptions            = ConvertTo-AsoBool (Get-AsoPropertyValue $policy 'allowedToSignUpEmailBasedSubscriptions')
        allowEmailVerifiedUsersToJoinOrganization         = ConvertTo-AsoBool (Get-AsoPropertyValue $policy 'allowEmailVerifiedUsersToJoinOrganization')
        allowUserConsentForRiskyApps                      = ConvertTo-AsoBool (Get-AsoPropertyValue $policy 'allowUserConsentForRiskyApps')
        blockMsolPowerShell                               = ConvertTo-AsoBool (Get-AsoPropertyValue $policy 'blockMsolPowerShell')
        guestUserRoleId                                   = [string](Get-AsoPropertyValue $policy 'guestUserRoleId')
        permissionGrantPolicyIdsAssignedToDefaultUserRole = ConvertTo-AsoStringArray (Get-AsoPropertyValue $policy 'permissionGrantPolicyIdsAssignedToDefaultUserRole')
        defaultUserRolePermissions                        = [ordered]@{
            allowedToCreateApps                      = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $perms 'allowedToCreateApps'))
            allowedToCreateSecurityGroups            = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $perms 'allowedToCreateSecurityGroups'))
            allowedToCreateTenants                   = ConvertTo-AsoBool (Get-AsoPropertyValue $perms 'allowedToCreateTenants')
            allowedToReadBitlockerKeysForOwnedDevice = ConvertTo-AsoBool (Get-AsoPropertyValue $perms 'allowedToReadBitlockerKeysForOwnedDevice')
            allowedToReadOtherUsers                  = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $perms 'allowedToReadOtherUsers'))
        }
    }
}

function ConvertTo-AsoIncludeExclude {
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string[]] $Name)
    if ($null -eq $InputObject) { return $null }
    $o = [ordered]@{}
    foreach ($n in $Name) { $o[$n] = ConvertTo-AsoStringArray (Get-AsoPropertyValue $InputObject $n) }
    return $o
}

function Get-AsoEntraConditionalAccessPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan @('AAD_PREMIUM', 'AAD_PREMIUM_P2') -Feature 'Conditional Access (Microsoft Entra ID P1)')) { return }
    $policies = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/identity/conditionalAccess/policies" -State $State)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $cond = Get-AsoPropertyValue $p 'conditions'
        $users = Get-AsoPropertyValue $cond 'users'
        $apps = Get-AsoPropertyValue $cond 'applications'
        $grant = Get-AsoPropertyValue $p 'grantControls'
        $session = Get-AsoPropertyValue $p 'sessionControls'

        $usersOut = $null
        if ($null -ne $users) {
            $usersOut = [ordered]@{}
            foreach ($n in 'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles') {
                $usersOut[$n] = ConvertTo-AsoStringArray (Get-AsoPropertyValue $users $n)
            }
            $usersOut['includeGuestsOrExternalUsers'] = ConvertTo-AsoPlainValue (Get-AsoPropertyValue $users 'includeGuestsOrExternalUsers')
            $usersOut['excludeGuestsOrExternalUsers'] = ConvertTo-AsoPlainValue (Get-AsoPropertyValue $users 'excludeGuestsOrExternalUsers')
        }
        $appsOut = ConvertTo-AsoIncludeExclude -InputObject $apps -Name @('includeApplications', 'excludeApplications', 'includeUserActions', 'includeAuthenticationContextClassReferences')
        $flows = Get-AsoPropertyValue $cond 'authenticationFlows'
        $devices = Get-AsoPropertyValue $cond 'devices'
        $devicesOut = $null
        if ($null -ne $devices) {
            $filter = Get-AsoPropertyValue $devices 'deviceFilter'
            $devicesOut = [ordered]@{
                includeDevices = ConvertTo-AsoStringArray (Get-AsoPropertyValue $devices 'includeDevices')
                excludeDevices = ConvertTo-AsoStringArray (Get-AsoPropertyValue $devices 'excludeDevices')
                deviceFilter   = if ($null -ne $filter) { [ordered]@{ mode = ConvertTo-AsoString (Get-AsoPropertyValue $filter 'mode'); rule = ConvertTo-AsoString (Get-AsoPropertyValue $filter 'rule') } } else { $null }
            }
        }

        $grantOut = $null
        if ($null -ne $grant) {
            $strength = Get-AsoPropertyValue $grant 'authenticationStrength'
            $grantOut = [ordered]@{
                operator                    = [string](Get-AsoPropertyValue $grant 'operator')
                builtInControls             = ConvertTo-AsoStringArray (Get-AsoPropertyValue $grant 'builtInControls')
                customAuthenticationFactors = ConvertTo-AsoStringArray (Get-AsoPropertyValue $grant 'customAuthenticationFactors')
                termsOfUse                  = ConvertTo-AsoStringArray (Get-AsoPropertyValue $grant 'termsOfUse')
                authenticationStrength      = if ($null -ne $strength) { [ordered]@{ id = [string](Get-AsoPropertyValue $strength 'id'); displayName = ConvertTo-AsoString (Get-AsoPropertyValue $strength 'displayName'); requirementsSatisfied = ConvertTo-AsoString (Get-AsoPropertyValue $strength 'requirementsSatisfied') } } else { $null }
            }
        }
        $sessionOut = $null
        if ($null -ne $session) {
            $sif = Get-AsoPropertyValue $session 'signInFrequency'
            $pb = Get-AsoPropertyValue $session 'persistentBrowser'
            $sessionOut = [ordered]@{
                signInFrequency   = if ($null -ne $sif) {
                    [ordered]@{
                        isEnabled         = ConvertTo-AsoBool (Get-AsoPropertyValue $sif 'isEnabled')
                        value             = ConvertTo-AsoNumber (Get-AsoPropertyValue $sif 'value')
                        type              = ConvertTo-AsoString (Get-AsoPropertyValue $sif 'type')
                        frequencyInterval = ConvertTo-AsoString (Get-AsoPropertyValue $sif 'frequencyInterval')
                    }
                }
                else { $null }
                persistentBrowser = if ($null -ne $pb) { [ordered]@{ isEnabled = ConvertTo-AsoBool (Get-AsoPropertyValue $pb 'isEnabled'); mode = ConvertTo-AsoString (Get-AsoPropertyValue $pb 'mode') } } else { $null }
            }
        }

        $out.Add([ordered]@{
                id               = [string](Get-AsoPropertyValue $p 'id')
                displayName      = [string](Get-AsoPropertyValue $p 'displayName')
                state            = [string](Get-AsoPropertyValue $p 'state')
                createdDateTime  = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $p 'createdDateTime')
                modifiedDateTime = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $p 'modifiedDateTime')
                conditions       = [ordered]@{
                    users               = $usersOut
                    applications        = $appsOut
                    clientAppTypes      = ConvertTo-AsoStringArray (Get-AsoPropertyValue $cond 'clientAppTypes')
                    signInRiskLevels    = ConvertTo-AsoStringArray (Get-AsoPropertyValue $cond 'signInRiskLevels')
                    userRiskLevels      = ConvertTo-AsoStringArray (Get-AsoPropertyValue $cond 'userRiskLevels')
                    platforms           = ConvertTo-AsoIncludeExclude -InputObject (Get-AsoPropertyValue $cond 'platforms') -Name @('includePlatforms', 'excludePlatforms')
                    locations           = ConvertTo-AsoIncludeExclude -InputObject (Get-AsoPropertyValue $cond 'locations') -Name @('includeLocations', 'excludeLocations')
                    authenticationFlows = if ($null -ne $flows) { [ordered]@{ transferMethods = ConvertTo-AsoString (Get-AsoPropertyValue $flows 'transferMethods') } } else { $null }
                    devices             = $devicesOut
                }
                grantControls    = $grantOut
                sessionControls  = $sessionOut
            })
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoEntraRoleDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $defs = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/roleManagement/directory/roleDefinitions" -State $State)
    $State.Data = [object[]]@($defs | ForEach-Object {
            [ordered]@{
                id           = [string](Get-AsoPropertyValue $_ 'id')
                displayName  = [string](Get-AsoPropertyValue $_ 'displayName')
                templateId   = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'templateId')
                isBuiltIn    = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isBuiltIn'))
                isEnabled    = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isEnabled')
                isPrivileged = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isPrivileged')
            }
        })
}

function Get-AsoEntraRoleAssignment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/roleManagement/directory/roleAssignments?`$expand=principal" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            $principal = Get-AsoPropertyValue $_ 'principal'
            $principalOut = $null
            if ($null -ne $principal) {
                $principalOut = [ordered]@{
                    id                    = [string](Get-AsoPropertyValue $principal 'id')
                    principalType         = ConvertTo-AsoPrincipalType -ODataType (Get-AsoOdataPropertyValue $principal '@odata.type')
                    displayName           = ConvertTo-AsoString (Get-AsoPropertyValue $principal 'displayName')
                    userPrincipalName     = ConvertTo-AsoString (Get-AsoPropertyValue $principal 'userPrincipalName')
                    userType              = ConvertTo-AsoString (Get-AsoPropertyValue $principal 'userType')
                    accountEnabled        = ConvertTo-AsoBool (Get-AsoPropertyValue $principal 'accountEnabled')
                    onPremisesSyncEnabled = ConvertTo-AsoBool (Get-AsoPropertyValue $principal 'onPremisesSyncEnabled')
                }
            }
            [ordered]@{
                id               = [string](Get-AsoPropertyValue $_ 'id')
                roleDefinitionId = [string](Get-AsoPropertyValue $_ 'roleDefinitionId')
                principalId      = [string](Get-AsoPropertyValue $_ 'principalId')
                directoryScopeId = [string](Get-AsoPropertyValue $_ 'directoryScopeId')
                principal        = $principalOut
            }
        })
}

function Get-AsoEntraRoleAssignmentScheduleInstance {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan @('AAD_PREMIUM_P2', 'Entra_Identity_Governance', 'ENTRA_IDENTITY_GOVERNANCE') -Feature 'Privileged Identity Management (Microsoft Entra ID P2 / ID Governance)')) { return }
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/roleManagement/directory/roleAssignmentScheduleInstances" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                id               = [string](Get-AsoPropertyValue $_ 'id')
                roleDefinitionId = [string](Get-AsoPropertyValue $_ 'roleDefinitionId')
                principalId      = [string](Get-AsoPropertyValue $_ 'principalId')
                directoryScopeId = [string](Get-AsoPropertyValue $_ 'directoryScopeId')
                assignmentType   = [string](Get-AsoPropertyValue $_ 'assignmentType')
                memberType       = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'memberType')
                startDateTime    = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $_ 'startDateTime')
                endDateTime      = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $_ 'endDateTime')
            }
        })
}

function Get-AsoEntraRoleEligibilitySchedule {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan @('AAD_PREMIUM_P2', 'Entra_Identity_Governance', 'ENTRA_IDENTITY_GOVERNANCE') -Feature 'Privileged Identity Management (Microsoft Entra ID P2 / ID Governance)')) { return }
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/roleManagement/directory/roleEligibilitySchedules" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            $schedule = Get-AsoPropertyValue $_ 'scheduleInfo'
            $start = Get-AsoPropertyValue $_ 'startDateTime'
            if ($null -eq $start) { $start = Get-AsoPropertyValue $schedule 'startDateTime' }
            $end = Get-AsoPropertyValue $_ 'endDateTime'
            if ($null -eq $end) { $end = Get-AsoPropertyValue $schedule 'expiration.endDateTime' }
            [ordered]@{
                id               = [string](Get-AsoPropertyValue $_ 'id')
                roleDefinitionId = [string](Get-AsoPropertyValue $_ 'roleDefinitionId')
                principalId      = [string](Get-AsoPropertyValue $_ 'principalId')
                directoryScopeId = [string](Get-AsoPropertyValue $_ 'directoryScopeId')
                memberType       = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'memberType')
                startDateTime    = ConvertTo-AsoTimestamp $start
                endDateTime      = ConvertTo-AsoTimestamp $end
            }
        })
}

function Get-AsoEntraUserRegistrationDetail {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan @('AAD_PREMIUM', 'AAD_PREMIUM_P2') -Feature 'Authentication methods activity reports (Microsoft Entra ID P1/P2)')) { return }
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/reports/authenticationMethods/userRegistrationDetails" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                id                    = [string](Get-AsoPropertyValue $_ 'id')
                userPrincipalName     = [string](Get-AsoPropertyValue $_ 'userPrincipalName')
                userType              = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'userType')
                isAdmin               = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isAdmin')
                isMfaRegistered       = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isMfaRegistered'))
                isMfaCapable          = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isMfaCapable')
                isPasswordlessCapable = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isPasswordlessCapable')
                isSsprRegistered      = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'isSsprRegistered')
                methodsRegistered     = ConvertTo-AsoStringArray (Get-AsoPropertyValue $_ 'methodsRegistered')
            }
        })
}

function Get-AsoEntraAuthenticationMethodsPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $policy = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/policies/authenticationMethodsPolicy"
    $configs = [System.Collections.Generic.List[object]]::new()
    foreach ($c in (Get-AsoList $policy 'authenticationMethodConfigurations')) {
        $id = [string](Get-AsoPropertyValue $c 'id')
        $source = $c
        if ($null -eq $c.PSObject.Properties['includeTargets']) {
            # includeTargets is not always returned inline; read the individual configuration.
            try {
                $source = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$([uri]::EscapeDataString($id))"
            }
            catch {
                $mapped = Resolve-AsoErrorStatus -ErrorObject $_
                Add-AsoDatasetError -State $State -Code 'METHOD_CONFIGURATION_UNREADABLE' -Message "Targets of the '$id' method could not be read. $($mapped.Message)" -Target $id
                $source = $c
            }
        }
        $targets = [System.Collections.Generic.List[object]]::new()
        foreach ($t in (Get-AsoList $source 'includeTargets')) {
            $targets.Add([ordered]@{
                    targetType = ConvertTo-AsoString (Get-AsoPropertyValue $t 'targetType')
                    id         = [string](Get-AsoPropertyValue $t 'id')
                })
        }
        $configs.Add([ordered]@{
                id             = $id
                state          = [string](Get-AsoPropertyValue $c 'state')
                includeTargets = [object[]]$targets.ToArray()
            })
    }
    $State.Data = [ordered]@{
        policyMigrationState               = ConvertTo-AsoString (Get-AsoPropertyValue $policy 'policyMigrationState')
        authenticationMethodConfigurations = [object[]]$configs.ToArray()
    }
}

function Get-AsoEntraApplication {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/applications?`$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials&`$top=999" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                id                  = [string](Get-AsoPropertyValue $_ 'id')
                appId               = [string](Get-AsoPropertyValue $_ 'appId')
                displayName         = [string](Get-AsoPropertyValue $_ 'displayName')
                signInAudience      = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'signInAudience')
                createdDateTime     = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $_ 'createdDateTime')
                passwordCredentials = ConvertTo-AsoCredentialSummary -InputObject (Get-AsoList $_ 'passwordCredentials')
                keyCredentials      = ConvertTo-AsoCredentialSummary -InputObject (Get-AsoList $_ 'keyCredentials') -Key
            }
        })
}

function Get-AsoEntraServicePrincipal {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials&`$top=999" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                id                     = [string](Get-AsoPropertyValue $_ 'id')
                appId                  = [string](Get-AsoPropertyValue $_ 'appId')
                displayName            = [string](Get-AsoPropertyValue $_ 'displayName')
                servicePrincipalType   = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'servicePrincipalType')
                appOwnerOrganizationId = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'appOwnerOrganizationId')
                accountEnabled         = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'accountEnabled')
                passwordCredentials    = ConvertTo-AsoCredentialSummary -InputObject (Get-AsoList $_ 'passwordCredentials')
                keyCredentials         = ConvertTo-AsoCredentialSummary -InputObject (Get-AsoList $_ 'keyCredentials') -Key
            }
        })
}

function Get-AsoEntraApiPermissionGrant {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($appId in @($script:AsoGraphAppId, $script:AsoExchangeAppId)) {
        try {
            $resource = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/servicePrincipals(appId='$appId')?`$select=id,appId,displayName,appRoles"
        }
        catch {
            $mapped = Resolve-AsoErrorStatus -ErrorObject $_
            if ($mapped.Status -eq 'Unauthorized') { throw }
            if ($mapped.Code -eq 'HTTP_404') {
                Add-AsoDatasetWarning -State $State -Code 'RESOURCE_NOT_PRESENT' -Message "The resource service principal $appId does not exist in this tenant." -Target $appId
            }
            else {
                Add-AsoDatasetError -State $State -Code $mapped.Code -Message $mapped.Message -Target $appId
            }
            continue
        }
        $resourceId = [string](Get-AsoPropertyValue $resource 'id')
        $roles = [object[]]@((Get-AsoList $resource 'appRoles') | ForEach-Object { [ordered]@{ id = [string](Get-AsoPropertyValue $_ 'id'); value = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'value') } })
        $assignments = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/servicePrincipals/$resourceId/appRoleAssignedTo?`$top=999" -State $State)
        $out.Add([ordered]@{
                resourceAppId       = $appId
                resourceDisplayName = [string](Get-AsoPropertyValue $resource 'displayName')
                appRoles            = $roles
                assignments         = [object[]]@($assignments | ForEach-Object {
                        [ordered]@{
                            id                   = [string](Get-AsoPropertyValue $_ 'id')
                            principalId          = [string](Get-AsoPropertyValue $_ 'principalId')
                            principalType        = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'principalType')
                            principalDisplayName = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'principalDisplayName')
                            appRoleId            = [string](Get-AsoPropertyValue $_ 'appRoleId')
                            createdDateTime      = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $_ 'createdDateTime')
                        }
                    })
            })
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoEntraGroupSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/groupSettings" -State $State)
    $dropped = 0
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $items) {
        $values = [System.Collections.Generic.List[object]]::new()
        foreach ($v in (Get-AsoList $s 'values')) {
            $name = [string](Get-AsoPropertyValue $v 'name')
            if ($script:AsoGroupSettingAllowList -notcontains $name) { $dropped++; continue }
            $values.Add([ordered]@{ name = $name; value = ConvertTo-AsoString (Get-AsoPropertyValue $v 'value') })
        }
        $out.Add([ordered]@{
                id          = [string](Get-AsoPropertyValue $s 'id')
                displayName = ConvertTo-AsoString (Get-AsoPropertyValue $s 'displayName')
                templateId  = ConvertTo-AsoString (Get-AsoPropertyValue $s 'templateId')
                values      = [object[]]$values.ToArray()
            })
    }
    if ($dropped -gt 0) {
        Add-AsoDatasetWarning -State $State -Code 'SETTINGS_FILTERED' -Message "$dropped setting value(s) not on the allow-list (for example custom banned password lists) were not collected."
    }
    $State.Data = [object[]]$out.ToArray()
}

function Get-AsoEntraGuestUser {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $filter = [uri]::EscapeDataString("userType eq 'Guest'")
    $base = "$script:AsoGraphBase/users?`$filter=$filter&`$top=999&`$select="
    $withActivity = $true
    try {
        $items = @(Invoke-AsoGraphGetAll -Uri ($base + 'id,userPrincipalName,accountEnabled,createdDateTime,externalUserState,signInActivity') -State $State)
    }
    catch {
        $mapped = Resolve-AsoErrorStatus -ErrorObject $_
        if ($mapped.Status -ne 'NotApplicable') { throw }
        # signInActivity needs Entra ID P1/P2; collect the rest and flag the gap.
        $withActivity = $false
        $items = @(Invoke-AsoGraphGetAll -Uri ($base + 'id,userPrincipalName,accountEnabled,createdDateTime,externalUserState') -State $State)
        Add-AsoDatasetError -State $State -Code 'SIGNIN_ACTIVITY_UNAVAILABLE' -Message 'Last sign-in times are unavailable (signInActivity requires Microsoft Entra ID P1/P2). Guest accounts were collected without activity data.'
    }
    $State.Data = [object[]]@($items | ForEach-Object {
            $activity = if ($withActivity) { Get-AsoPropertyValue $_ 'signInActivity' } else { $null }
            [ordered]@{
                id                               = [string](Get-AsoPropertyValue $_ 'id')
                userPrincipalName                = [string](Get-AsoPropertyValue $_ 'userPrincipalName')
                accountEnabled                   = ConvertTo-AsoBool (Get-AsoPropertyValue $_ 'accountEnabled')
                createdDateTime                  = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $_ 'createdDateTime')
                externalUserState                = ConvertTo-AsoString (Get-AsoPropertyValue $_ 'externalUserState')
                lastSignInDateTime               = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $activity 'lastSignInDateTime')
                lastNonInteractiveSignInDateTime = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $activity 'lastNonInteractiveSignInDateTime')
            }
        })
}

function Get-AsoEntraOnPremisesSynchronization {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/directory/onPremisesSynchronization" -State $State)
    $names = @('passwordSyncEnabled', 'passwordWritebackEnabled', 'blockSoftMatchEnabled', 'blockCloudObjectTakeoverThroughHardMatchEnabled',
        'softMatchOnUpnEnabled', 'userWritebackEnabled', 'deviceWritebackEnabled', 'passThroughAuthenticationEnabled', 'synchronizeUpnForManagedUsersEnabled')
    $State.Data = [object[]]@($items | ForEach-Object {
            $features = Get-AsoPropertyValue $_ 'features'
            $f = [ordered]@{}
            foreach ($n in $names) { $f[$n] = ConvertTo-AsoBool (Get-AsoPropertyValue $features $n) }
            [ordered]@{ id = [string](Get-AsoPropertyValue $_ 'id'); features = $f }
        })
}
