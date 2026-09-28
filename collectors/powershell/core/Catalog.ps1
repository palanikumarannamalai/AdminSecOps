# Dataset catalogue: the PowerShell view of packages/schemas/src/datasets/*.ts.
# Every dataset the engine knows has exactly one entry here (enforced by tests/Catalog.Tests.ps1).
# Operations are recorded in each envelope's source.operations. They are templates and never
# contain tokens, credentials or query secrets.

$script:AsoGraphBase = 'https://graph.microsoft.com/v1.0'
$script:AsoArmBase = 'https://management.azure.com'

$script:AsoModuleOrder = @('Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows')

$script:AsoGraphScopes = @(
    'Organization.Read.All',
    'Policy.Read.All',
    'RoleManagement.Read.Directory',
    'RoleAssignmentSchedule.Read.Directory',
    'RoleEligibilitySchedule.Read.Directory',
    'AuditLog.Read.All',
    'UserAuthenticationMethod.Read.All',
    'Application.Read.All',
    'Directory.Read.All',
    'User.Read.All',
    'OnPremDirectorySynchronization.Read.All',
    'SharePointTenantSettings.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'TeamworkAppSettings.Read.All',
    'Team.ReadBasic.All'
)

$script:AsoModuleInfo = [ordered]@{
    Entra    = [ordered]@{
        Role          = 'Microsoft Entra role: Global Reader (read-only). Security Reader is sufficient for most datasets; directory/onPremisesSynchronization additionally requires Hybrid Identity Administrator or Global Administrator and is reported Unauthorized without it.'
        Connection    = 'Connect-MgGraph -Scopes <read-only delegated scopes> -NoWelcome'
        RequiredTools = @('Microsoft.Graph.Authentication')
        Collects      = 'Tenant, licences, security defaults, authorization policy, Conditional Access, directory roles and PIM, MFA registration, authentication methods policy, app registrations and service principals (credential metadata only), application permission grants on Microsoft Graph and Exchange Online, allow-listed directory settings, guest users, directory synchronisation feature flags.'
        NeverCollects = 'Client secret values or hints, certificate key material, tokens, user passwords, custom banned password lists, sign-in logs, mail or file content.'
    }
    M365     = [ordered]@{
        Role          = 'Microsoft Entra role: Global Reader (or SharePoint Administrator) for SharePoint settings. Microsoft does not document the role for the Teams app settings; teams the signed-in user cannot read are reported as incomplete.'
        Connection    = 'Connect-MgGraph -Scopes SharePointTenantSettings.Read.All,TeamworkAppSettings.Read.All,Team.ReadBasic.All -NoWelcome'
        RequiredTools = @('Microsoft.Graph.Authentication')
        Collects      = 'SharePoint Online and OneDrive tenant sharing and session settings; Microsoft Teams app settings; member and guest settings of each team (team names and IDs).'
        NeverCollects = 'Sites, files, sharing links, document content, channels, messages or team members. Teams tenant policies are not available through delegated Microsoft Graph.'
    }
    Exchange = [ordered]@{
        Role          = 'Exchange Online role group: View-Only Organization Management (or Microsoft Entra Global Reader).'
        Connection    = 'Connect-ExchangeOnline -ShowBanner:$false'
        RequiredTools = @('ExchangeOnlineManagement')
        Collects      = 'Organization, transport and audit configuration, accepted domains, DKIM, outbound spam policies, remote domains, mailboxes with forwarding configured, per-mailbox SMTP AUTH overrides, Defender for Office 365 global settings, public SPF and DMARC DNS records.'
        NeverCollects = 'Messages, message bodies, inbox rules, mailbox content, message trace data.'
    }
    Intune   = [ordered]@{
        Role          = 'Microsoft Entra role: Global Reader (or Intune read-only role).'
        Connection    = 'Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All,DeviceManagementManagedDevices.Read.All -NoWelcome'
        RequiredTools = @('Microsoft.Graph.Authentication')
        Collects      = 'Tenant compliance settings, device counts per platform, device compliance policies with selected settings and assignment targets.'
        NeverCollects = 'Per-device inventory, users of devices, device logs.'
    }
    Azure    = [ordered]@{
        Role          = 'Azure RBAC: Reader on each subscription (or on a management group). Graph Directory.Read.All is used optionally to resolve principal names.'
        Connection    = 'Connect-AzAccount'
        RequiredTools = @('Az.Accounts')
        Collects      = 'Subscriptions, RBAC role assignments, Defender for Cloud plans, security contact configuration (counts only), storage account, key vault and NSG security properties, activity log diagnostic settings.'
        NeverCollects = 'Storage account keys, connection strings, key vault secrets/keys/certificates, security contact email addresses or phone numbers, resource data.'
    }
    AD       = [ordered]@{
        Role          = 'Active Directory: any authenticated domain user. Optional domain controller registry settings require local administrator on each domain controller.'
        Connection    = 'Runs as the current Windows user against the current forest (Kerberos). No credentials are prompted or stored.'
        RequiredTools = @('ActiveDirectory')
        Collects      = 'Forest, domains, password policies, privileged group membership, security-relevant user and computer accounts (flags and timestamps), KRBTGT password age, trusts, domain controllers, optionally domain controller LDAP/SMB signing settings.'
        NeverCollects = 'Password hashes, LAPS passwords (ms-Mcs-AdmPwd, msLAPS-Password), unicodePwd, supplementalCredentials, BitLocker recovery information.'
    }
    ADCS     = [ordered]@{
        Role          = 'Active Directory: any authenticated domain user (read access to the Configuration partition).'
        Connection    = 'Runs as the current Windows user.'
        RequiredTools = @('ActiveDirectory')
        Collects      = 'Enterprise CAs and published templates, certificate template flags, EKUs and access control entries.'
        NeverCollects = 'Issued certificates, private keys, CA database content.'
    }
    GPO      = [ordered]@{
        Role          = 'Active Directory: any authenticated domain user (GPO and SYSVOL read).'
        Connection    = 'Runs as the current Windows user.'
        RequiredTools = @('GroupPolicy', 'ActiveDirectory')
        Collects      = 'Group Policy objects with links and flattened security settings; locations of Group Policy Preferences files that contain a cpassword attribute.'
        NeverCollects = 'cpassword values (files are scanned in memory, only the path is recorded), registry values whose name suggests a password or key.'
    }
    Windows  = [ordered]@{
        Role          = 'Local administrator on the assessed host (some values are readable only when elevated).'
        Connection    = 'Local host only; no remoting.'
        RequiredTools = @()
        Collects      = 'Local host OS, firewall profiles, SMB, RDP, LSA, WDigest, Credential Guard, PowerShell script block logging and Microsoft Defender status.'
        NeverCollects = 'Files, event logs, user profiles, credentials, BitLocker keys.'
    }
}

function Build-AsoCatalogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $System,
        [Parameter(Mandatory)] [string[]] $Operations,
        [Parameter(Mandatory)] [string[]] $Permissions,
        [string] $ApiVersion,
        [string[]] $Prerequisites = @(),
        [string] $Function,
        [switch] $Optional
    )
    [pscustomobject][ordered]@{
        Id            = $Id
        Module        = $Module
        Name          = $Id.Split('.')[1]
        Title         = $Title
        System        = $System
        Operations    = $Operations
        Permissions   = $Permissions
        ApiVersion    = if ($ApiVersion) { $ApiVersion } else { $null }
        Prerequisites = $Prerequisites
        Function      = $Function
        Optional      = [bool]$Optional
    }
}

$script:AsoCatalog = & {
$g = $script:AsoGraphBase
$a = $script:AsoArmBase
$exoRole = 'Exchange Online: View-Only Organization Management (or Global Reader)'
$reader = 'Azure RBAC: Reader on each assessed subscription (or management group)'
$domainUser = 'Active Directory: authenticated domain user (read access to directory objects)'

@(
    # ---- Entra ----
    Build-AsoCatalogEntry -Id 'entra.organization' -Module Entra -Title 'Tenant organization' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraOrganization' -Operations @("GET $g/organization") -Permissions @('Graph: Organization.Read.All')
    Build-AsoCatalogEntry -Id 'entra.subscribedSkus' -Module Entra -Title 'Licences (subscribed SKUs)' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraSubscribedSku' -Operations @("GET $g/subscribedSkus") -Permissions @('Graph: Organization.Read.All')
    Build-AsoCatalogEntry -Id 'entra.securityDefaults' -Module Entra -Title 'Security defaults' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraSecurityDefault' -Operations @("GET $g/policies/identitySecurityDefaultsEnforcementPolicy") -Permissions @('Graph: Policy.Read.All')
    Build-AsoCatalogEntry -Id 'entra.authorizationPolicy' -Module Entra -Title 'Authorization policy' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraAuthorizationPolicy' -Operations @("GET $g/policies/authorizationPolicy") -Permissions @('Graph: Policy.Read.All')
    Build-AsoCatalogEntry -Id 'entra.conditionalAccessPolicies' -Module Entra -Title 'Conditional Access policies' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraConditionalAccessPolicy' -Operations @("GET $g/identity/conditionalAccess/policies") -Permissions @('Graph: Policy.Read.All', 'Directory role able to read CA policies (e.g. Global Reader or Security Reader)') -Prerequisites @('Microsoft Entra ID P1 (Conditional Access)')
    Build-AsoCatalogEntry -Id 'entra.roleDefinitions' -Module Entra -Title 'Directory role definitions' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraRoleDefinition' -Operations @("GET $g/roleManagement/directory/roleDefinitions") -Permissions @('Graph: RoleManagement.Read.Directory')
    Build-AsoCatalogEntry -Id 'entra.roleAssignments' -Module Entra -Title 'Active directory role assignments' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraRoleAssignment' -Operations @("GET $g/roleManagement/directory/roleAssignments?`$expand=principal") -Permissions @('Graph: RoleManagement.Read.Directory', 'Graph: Directory.Read.All')
    Build-AsoCatalogEntry -Id 'entra.roleAssignmentScheduleInstances' -Module Entra -Title 'PIM active assignment instances' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraRoleAssignmentScheduleInstance' -Operations @("GET $g/roleManagement/directory/roleAssignmentScheduleInstances") -Permissions @('Graph: RoleAssignmentSchedule.Read.Directory') -Prerequisites @('Microsoft Entra ID P2 or Microsoft Entra ID Governance (PIM)')
    Build-AsoCatalogEntry -Id 'entra.roleEligibilitySchedules' -Module Entra -Title 'PIM eligible role assignments' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraRoleEligibilitySchedule' -Operations @("GET $g/roleManagement/directory/roleEligibilitySchedules") -Permissions @('Graph: RoleEligibilitySchedule.Read.Directory') -Prerequisites @('Microsoft Entra ID P2 or Microsoft Entra ID Governance (PIM)')
    Build-AsoCatalogEntry -Id 'entra.userRegistrationDetails' -Module Entra -Title 'Authentication method registration' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraUserRegistrationDetail' -Operations @("GET $g/reports/authenticationMethods/userRegistrationDetails") -Permissions @('Graph: AuditLog.Read.All', 'Graph: UserAuthenticationMethod.Read.All') -Prerequisites @('Microsoft Entra ID P1 or P2')
    Build-AsoCatalogEntry -Id 'entra.authenticationMethodsPolicy' -Module Entra -Title 'Authentication methods policy' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraAuthenticationMethodsPolicy' -Operations @("GET $g/policies/authenticationMethodsPolicy", "GET $g/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{id} (only when includeTargets is not returned inline)") -Permissions @('Graph: Policy.Read.All')
    Build-AsoCatalogEntry -Id 'entra.applications' -Module Entra -Title 'Application registrations' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraApplication' -Operations @("GET $g/applications?`$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials") -Permissions @('Graph: Application.Read.All')
    Build-AsoCatalogEntry -Id 'entra.servicePrincipals' -Module Entra -Title 'Service principals' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraServicePrincipal' -Operations @("GET $g/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials") -Permissions @('Graph: Application.Read.All')
    Build-AsoCatalogEntry -Id 'entra.apiPermissionGrants' -Module Entra -Title 'Application permission grants' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraApiPermissionGrant' -Operations @("GET $g/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')", "GET $g/servicePrincipals(appId='00000002-0000-0ff1-ce00-000000000000')", "GET $g/servicePrincipals/{resourceId}/appRoleAssignedTo") -Permissions @('Graph: Application.Read.All')
    Build-AsoCatalogEntry -Id 'entra.groupSettings' -Module Entra -Title 'Directory settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraGroupSetting' -Operations @("GET $g/groupSettings") -Permissions @('Graph: Directory.Read.All')
    Build-AsoCatalogEntry -Id 'entra.guestUsers' -Module Entra -Title 'Guest users' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraGuestUser' -Operations @("GET $g/users?`$filter=userType eq 'Guest'&`$select=id,userPrincipalName,accountEnabled,createdDateTime,externalUserState,signInActivity") -Permissions @('Graph: User.Read.All', 'Graph: AuditLog.Read.All (signInActivity)') -Prerequisites @('Microsoft Entra ID P1 or P2 for signInActivity')
    Build-AsoCatalogEntry -Id 'entra.onPremisesSynchronization' -Module Entra -Title 'Directory synchronization settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoEntraOnPremisesSynchronization' -Operations @("GET $g/directory/onPremisesSynchronization") -Permissions @('Graph: OnPremDirectorySynchronization.Read.All (delegated only)', 'Directory role: Global Administrator or Hybrid Identity Administrator is required by this API; without it the dataset is reported Unauthorized')

    # ---- M365 ----
    Build-AsoCatalogEntry -Id 'm365.sharePointSettings' -Module M365 -Title 'SharePoint and OneDrive tenant settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoM365SharePointSetting' -Operations @("GET $g/admin/sharepoint/settings") -Permissions @('Graph: SharePointTenantSettings.Read.All', 'Directory role for delegated access: Global Reader or SharePoint Administrator')
    Build-AsoCatalogEntry -Id 'm365.teamsAppSettings' -Module M365 -Title 'Microsoft Teams app settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoM365TeamsAppSetting' -Operations @("GET $g/teamwork/teamsAppSettings") -Permissions @('Graph: TeamworkAppSettings.Read.All (delegated only)') -Prerequisites @('Microsoft Teams')
    Build-AsoCatalogEntry -Id 'm365.teamsTeamSettings' -Module M365 -Title 'Microsoft Teams per-team settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoM365TeamsTeamSetting' -Operations @("GET $g/teams?`$select=id,displayName,visibility", "GET $g/teams/{id}?`$select=id,displayName,visibility,isArchived,memberSettings,guestSettings") -Permissions @('Graph: Team.ReadBasic.All') -Prerequisites @('Microsoft Teams')

    # ---- Exchange ----
    Build-AsoCatalogEntry -Id 'exchange.inboxRules' -Module Exchange -Title 'Inbox forwarding rules (hosted connector)' -System ExchangeOnline -Function 'Get-AsoExchangeHostedRule' -Operations @('Get-InboxRule -IncludeHidden') -Permissions @('Exchange role permitting Get-InboxRule; Global Reader is insufficient')
    Build-AsoCatalogEntry -Id 'exchange.transportRules' -Module Exchange -Title 'Mail-flow recipient actions (hosted connector)' -System ExchangeOnline -Function 'Get-AsoExchangeHostedRule' -Operations @('Get-TransportRule') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.organizationConfig' -Module Exchange -Title 'Exchange Online organization configuration' -System ExchangeOnline -Function 'Get-AsoExchangeOrganizationConfig' -Operations @('Get-OrganizationConfig') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.transportConfig' -Module Exchange -Title 'Exchange Online transport configuration' -System ExchangeOnline -Function 'Get-AsoExchangeTransportConfig' -Operations @('Get-TransportConfig') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.adminAuditLogConfig' -Module Exchange -Title 'Audit log configuration' -System ExchangeOnline -Function 'Get-AsoExchangeAdminAuditLogConfig' -Operations @('Get-AdminAuditLogConfig') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.acceptedDomains' -Module Exchange -Title 'Accepted domains' -System ExchangeOnline -Function 'Get-AsoExchangeAcceptedDomain' -Operations @('Get-AcceptedDomain') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.dkimSigningConfigs' -Module Exchange -Title 'DKIM signing configuration' -System ExchangeOnline -Function 'Get-AsoExchangeDkimSigningConfig' -Operations @('Get-DkimSigningConfig') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.outboundSpamPolicies' -Module Exchange -Title 'Outbound spam filter policies' -System ExchangeOnline -Function 'Get-AsoExchangeOutboundSpamPolicy' -Operations @('Get-HostedOutboundSpamFilterPolicy') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.remoteDomains' -Module Exchange -Title 'Remote domains' -System ExchangeOnline -Function 'Get-AsoExchangeRemoteDomain' -Operations @('Get-RemoteDomain') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.mailboxForwarding' -Module Exchange -Title 'Mailbox-level forwarding' -System ExchangeOnline -Function 'Get-AsoExchangeMailboxForwarding' -Operations @('Get-EXOMailbox -Filter "ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null" -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward -ResultSize Unlimited') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.smtpAuthMailboxes' -Module Exchange -Title 'Per-mailbox SMTP AUTH overrides' -System ExchangeOnline -Function 'Get-AsoExchangeSmtpAuthMailbox' -Operations @('Get-EXOCASMailbox -Properties SmtpClientAuthenticationDisabled -ResultSize Unlimited') -Permissions @($exoRole)
    Build-AsoCatalogEntry -Id 'exchange.atpPolicy' -Module Exchange -Title 'Defender for Office 365 global settings' -System ExchangeOnline -Function 'Get-AsoExchangeAtpPolicy' -Operations @('Get-AtpPolicyForO365') -Permissions @($exoRole) -Prerequisites @('Microsoft Defender for Office 365 Plan 1 or Plan 2')
    Build-AsoCatalogEntry -Id 'exchange.mailDnsRecords' -Module Exchange -Title 'Mail authentication DNS records' -System DNS -Function 'Get-AsoExchangeMailDnsRecord' -Operations @('Get-AcceptedDomain', 'Resolve-DnsName -Type TXT <domain>', 'Resolve-DnsName -Type TXT _dmarc.<domain>') -Permissions @('None (public DNS)')

    # ---- Intune ----
    Build-AsoCatalogEntry -Id 'intune.settings' -Module Intune -Title 'Intune tenant compliance settings' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoIntuneSetting' -Operations @("GET $g/deviceManagement?`$select=settings") -Permissions @('Graph: DeviceManagementConfiguration.Read.All') -Prerequisites @('Microsoft Intune')
    Build-AsoCatalogEntry -Id 'intune.deviceOverview' -Module Intune -Title 'Managed device overview' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoIntuneDeviceOverview' -Operations @("GET $g/deviceManagement/managedDeviceOverview") -Permissions @('Graph: DeviceManagementManagedDevices.Read.All') -Prerequisites @('Microsoft Intune')
    Build-AsoCatalogEntry -Id 'intune.compliancePolicies' -Module Intune -Title 'Device compliance policies' -System MicrosoftGraph -ApiVersion 'v1.0' -Function 'Get-AsoIntuneCompliancePolicy' -Operations @("GET $g/deviceManagement/deviceCompliancePolicies?`$expand=assignments") -Permissions @('Graph: DeviceManagementConfiguration.Read.All') -Prerequisites @('Microsoft Intune')

    # ---- Azure ----
    Build-AsoCatalogEntry -Id 'azure.subscriptions' -Module Azure -Title 'Subscriptions' -System AzureResourceManager -ApiVersion '2022-12-01' -Function 'Get-AsoAzureSubscription' -Operations @("GET $a/subscriptions?api-version=2022-12-01") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.roleAssignments' -Module Azure -Title 'Azure RBAC role assignments' -System AzureResourceManager -ApiVersion '2022-04-01' -Function 'Get-AsoAzureRoleAssignment' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", "GET $a/subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", "GET $g/directoryObjects/{principalId} (principal name resolution, optional)") -Permissions @($reader, 'Graph: Directory.Read.All (principal name resolution)')
    Build-AsoCatalogEntry -Id 'azure.defenderPlans' -Module Azure -Title 'Microsoft Defender for Cloud plans' -System AzureResourceManager -ApiVersion '2024-01-01' -Function 'Get-AsoAzureDefenderPlan' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Security/pricings?api-version=2024-01-01") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.securityContacts' -Module Azure -Title 'Defender for Cloud security contacts' -System AzureResourceManager -ApiVersion '2023-12-01-preview' -Function 'Get-AsoAzureSecurityContact' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.storageAccounts' -Module Azure -Title 'Storage accounts' -System AzureResourceManager -ApiVersion '2023-05-01' -Function 'Get-AsoAzureStorageAccount' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.keyVaults' -Module Azure -Title 'Key vaults' -System AzureResourceManager -ApiVersion '2023-07-01' -Function 'Get-AsoAzureKeyVault' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.networkSecurityGroups' -Module Azure -Title 'Network security groups' -System AzureResourceManager -ApiVersion '2023-09-01' -Function 'Get-AsoAzureNetworkSecurityGroup' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01") -Permissions @($reader)
    Build-AsoCatalogEntry -Id 'azure.activityLogDiagnostics' -Module Azure -Title 'Activity log diagnostic settings' -System AzureResourceManager -ApiVersion '2021-05-01-preview' -Function 'Get-AsoAzureActivityLogDiagnostic' -Operations @("GET $a/subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview") -Permissions @($reader)

    # ---- AD ----
    Build-AsoCatalogEntry -Id 'ad.forest' -Module AD -Title 'Forest' -System ActiveDirectory -Function 'Get-AsoAdForest' -Operations @('Get-ADForest', "Get-ADOptionalFeature -Filter `"name -eq 'Recycle Bin Feature'`"") -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.domains' -Module AD -Title 'Domains' -System ActiveDirectory -Function 'Get-AsoAdDomain' -Operations @('Get-ADDomain', 'Get-ADObject <domain DN> -Properties ms-DS-MachineAccountQuota') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.passwordPolicies' -Module AD -Title 'Password policies' -System ActiveDirectory -Function 'Get-AsoAdPasswordPolicy' -Operations @('Get-ADDefaultDomainPasswordPolicy', 'Get-ADFineGrainedPasswordPolicy -Filter *') -Permissions @($domainUser, 'Reading PSOs may require delegated read on the Password Settings Container')
    Build-AsoCatalogEntry -Id 'ad.privilegedGroups' -Module AD -Title 'Privileged group membership' -System ActiveDirectory -Function 'Get-AsoAdPrivilegedGroup' -Operations @('Get-ADGroup -Identity <well-known SID>', 'Get-ADGroupMember -Recursive') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.users' -Module AD -Title 'Security-relevant user accounts' -System ActiveDirectory -Function 'Get-AsoAdUser' -Operations @('Get-ADUser -Filter * (counts only)', 'Get-ADUser -LDAPFilter "(|(adminCount=1)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=32)(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=524288))"', 'Get-ADGroupMember -Identity <Protected Users SID> -Recursive') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.krbtgt' -Module AD -Title 'KRBTGT account' -System ActiveDirectory -Function 'Get-AsoAdKrbtgt' -Operations @('Get-ADUser krbtgt -Properties pwdLastSet') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.computers' -Module AD -Title 'Computer accounts' -System ActiveDirectory -Function 'Get-AsoAdComputer' -Operations @('Get-ADObject -SearchBase <SchemaNC> (LAPS schema attribute presence)', 'Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,LastLogonTimestamp,TrustedForDelegation,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,PrimaryGroupID,ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.trusts' -Module AD -Title 'Trusts' -System ActiveDirectory -Function 'Get-AsoAdTrust' -Operations @('Get-ADTrust -Filter *') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.domainControllers' -Module AD -Title 'Domain controllers' -System ActiveDirectory -Function 'Get-AsoAdDomainController' -Operations @('Get-ADDomainController -Filter *') -Permissions @($domainUser)
    Build-AsoCatalogEntry -Id 'ad.domainControllerSettings' -Module AD -Title 'Domain controller security settings' -System ActiveDirectory -Function 'Get-AsoAdDomainControllerSetting' -Optional -Operations @('Remote registry read: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters (LDAPServerIntegrity, LdapEnforceChannelBinding)', 'Remote registry read: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters (RequireSecuritySignature, SMB1)') -Permissions @('Local administrator (read-only registry access) on domain controllers')

    # ---- ADCS ----
    Build-AsoCatalogEntry -Id 'adcs.certificateAuthorities' -Module ADCS -Title 'Enterprise certification authorities' -System ActiveDirectory -Function 'Get-AsoAdcsCertificateAuthority' -Operations @('Get-ADRootDSE', 'Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,<ConfigurationNC>" -LDAPFilter "(objectClass=pKIEnrollmentService)"') -Permissions @('Active Directory: authenticated domain user (read access to the Configuration partition)')
    Build-AsoCatalogEntry -Id 'adcs.certificateTemplates' -Module ADCS -Title 'Certificate templates' -System ActiveDirectory -Function 'Get-AsoAdcsCertificateTemplate' -Operations @('Get-ADRootDSE', 'Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,<ConfigurationNC>" -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,msPKI-Certificate-Application-Policy,msPKI-Template-Schema-Version,nTSecurityDescriptor') -Permissions @('Active Directory: authenticated domain user (read access to the Configuration partition)')

    # ---- GPO ----
    Build-AsoCatalogEntry -Id 'gpo.groupPolicyObjects' -Module GPO -Title 'Group Policy objects' -System GroupPolicy -Function 'Get-AsoGpoGroupPolicyObject' -Operations @('Get-GPO -All', 'Get-GPOReport -ReportType Xml') -Permissions @('Active Directory: authenticated domain user (GPO read)')
    Build-AsoCatalogEntry -Id 'gpo.sysvolPasswordArtifacts' -Module GPO -Title 'Group Policy Preferences password artifacts' -System GroupPolicy -Function 'Get-AsoGpoSysvolPasswordArtifact' -Operations @('Get-ChildItem \\<domain>\SYSVOL\<domain>\Policies -Recurse (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml; content scanned in memory)') -Permissions @('Active Directory: authenticated domain user (SYSVOL read)')

    # ---- Windows ----
    Build-AsoCatalogEntry -Id 'windows.hosts' -Module Windows -Title 'Windows host security configuration' -System WindowsHost -Function 'Get-AsoWindowsHost' -Operations @('Get-CimInstance Win32_OperatingSystem', 'Get-CimInstance Win32_ComputerSystem', 'Get-NetFirewallProfile -PolicyStore ActiveStore', 'Get-SmbServerConfiguration', 'Registry reads under HKLM (Terminal Server, Lsa, WDigest, PowerShell policies)', 'Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard', 'Get-MpComputerStatus') -Permissions @('Local administrator on the assessed host (some values are only readable when elevated)')
)
}

function Get-AsoCatalogEntry {
    [CmdletBinding()]
    param([string] $Id, [string[]] $Module)
    $entries = $script:AsoCatalog
    if ($Id) { $entries = @($entries | Where-Object { $_.Id -eq $Id }) }
    if ($Module) { $entries = @($entries | Where-Object { $Module -contains $_.Module }) }
    $entries
}
