#Requires -Modules Pester
# End-to-end replay: runs Invoke-AdminSecOpsCollection against the sanitized Contoso scenario and
# verifies the package and the transformations of every module.

BeforeAll {
    $script:moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:moduleRoot 'AdminSecOps.Collector.psd1') -Force
    $script:replay = Join-Path $PSScriptRoot 'replay/contoso'
    $script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-replay-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][System.IO.Directory]::CreateDirectory($script:tempRoot)
    $script:result = Invoke-AdminSecOpsCollection -Module All -ReplayPath $script:replay -OutputPath $script:tempRoot -SkipConnect -Label 'Contoso replay'
    $script:pkg = $script:result.PackagePath
    $script:manifest = Get-Content -Raw -LiteralPath (Join-Path $script:pkg 'evidence-manifest.json') | ConvertFrom-Json -AsHashtable -DateKind String
    function script:Evidence([string] $Id) {
        $entry = $script:manifest.files | Where-Object { $_.datasetId -eq $Id }
        Get-Content -Raw -LiteralPath (Join-Path $script:pkg $entry.path) | ConvertFrom-Json -AsHashtable -DateKind String
    }
}

AfterAll {
    if ($script:tempRoot -and (Test-Path -LiteralPath $script:tempRoot)) { [System.IO.Directory]::Delete($script:tempRoot, $true) }
}

Describe 'Replay package' {
    It 'returns a summary' {
        $script:result.Mode | Should -Be 'Replay'
        $script:result.DatasetCount | Should -Be 57
        $script:result.AssessmentId | Should -Match '^[0-9a-f]{8}-'
        Split-Path -Leaf $script:pkg | Should -Match '^AdminSecOps-Assessment-\d{8}-\d{6}$'
        Split-Path -Leaf $script:result.ZipPath | Should -Match '^adminsecops-assessment-\d{8}-\d{6}\.zip$'
        (Split-Path -Parent $script:result.ZipPath) | Should -Be (Split-Path -Parent $script:pkg)
    }

    It 'writes manifest, evidence and log' {
        Test-Path -LiteralPath (Join-Path $script:pkg 'evidence-manifest.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:pkg 'logs/collection-log.json') | Should -BeTrue
        @(Get-ChildItem -LiteralPath (Join-Path $script:pkg 'evidence') -Recurse -File).Count | Should -Be 57
    }

    It 'lists every evidence file with a matching hash and size' {
        foreach ($f in $script:manifest.files) {
            $full = Join-Path $script:pkg $f.path
            (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $f.sha256
            (Get-Item -LiteralPath $full).Length | Should -Be $f.sizeBytes
            $f.path | Should -Match '^evidence/[a-z0-9]+/[A-Za-z0-9]+\.json$'
        }
    }

    It 'uses one assessmentId and agrees with the manifest for every envelope' {
        foreach ($f in $script:manifest.files) {
            $e = Get-Content -Raw -LiteralPath (Join-Path $script:pkg $f.path) | ConvertFrom-Json -AsHashtable
            $e.assessmentId | Should -Be $script:manifest.assessmentId
            $e.datasetId | Should -Be $f.datasetId
            $e.status | Should -Be $f.status
            $e.collector.module | Should -Be $f.module
        }
    }

    It 'writes all JSON without a byte order mark' {
        foreach ($file in Get-ChildItem -LiteralPath $script:pkg -Recurse -File -Filter '*.json') {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $bytes[0] | Should -Be ([byte][char]'{') -Because $file.Name
        }
    }

    It 'records environment and modules' {
        $script:manifest.environment.label | Should -Be 'Contoso replay'
        $script:manifest.environment.tenantId | Should -Be '11111111-2222-4333-8444-555555555555'
        $script:manifest.environment.tenantDisplayName | Should -Be 'Contoso'
        $script:manifest.environment.primaryDomain | Should -Be 'contoso.example'
        $script:manifest.environment.adForestName | Should -Be 'corp.contoso.example'
        $script:manifest.environment.adDomainName | Should -Be 'corp.contoso.example'
        @($script:manifest.modules | ForEach-Object { $_.name }) | Should -Be @('Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows')
        ($script:manifest.modules | Where-Object { $_.name -eq 'Entra' }).status | Should -Be 'CompletedWithErrors'
        ($script:manifest.modules | Where-Object { $_.name -eq 'AD' }).status | Should -Be 'Completed'
        $script:manifest.options.replayMode | Should -BeTrue
    }

    It 'produces the intended non-success statuses' {
        $statuses = @{}
        foreach ($f in $script:manifest.files) { $statuses[$f.datasetId] = $f.status }
        $statuses['entra.onPremisesSynchronization'] | Should -Be 'Unauthorized'
        $statuses['entra.roleAssignmentScheduleInstances'] | Should -Be 'NotApplicable'
        $statuses['entra.roleEligibilitySchedules'] | Should -Be 'NotApplicable'
        $statuses['exchange.atpPolicy'] | Should -Be 'NotApplicable'
        $statuses['azure.keyVaults'] | Should -Be 'Partial'
        $statuses['ad.domainControllerSettings'] | Should -Be 'NotCollected'
        @($statuses.Values | Where-Object { $_ -eq 'Success' }).Count | Should -Be 51
    }

    It 'never writes secret material from the recorded responses' {
        $all = (Get-ChildItem -LiteralPath $script:pkg -Recurse -File | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
        $all | Should -Not -Match '"hint"'
        $all | Should -Not -Match 'secretText'
        $all | Should -Not -Match '(?i)cpassword'
        $all | Should -Not -Match 'REPLAYFIXTUREONLY'
        $all | Should -Not -Match 'BannedPasswordList'
        $all | Should -Not -Match 'example-banned-term'
        $all | Should -Not -Match 'secops@contoso.example'
        $all | Should -Not -Match 'replay-fixture-autologon-value'
        $all | Should -Not -Match 'eyJ[A-Za-z0-9_-]{10,}\.'
    }

    It 'creates a ZIP with forward-slash entries identical to the folder' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($script:result.ZipPath)
        try {
            $names = @($zip.Entries | ForEach-Object FullName)
            $names | Should -Contain 'evidence-manifest.json'
            $names | Should -Contain 'logs/collection-log.json'
            $names | Should -Contain 'evidence/entra/conditionalAccessPolicies.json'
            @($names | Where-Object { $_ -match '\\' }).Count | Should -Be 0
            $names.Count | Should -Be 59
        }
        finally { $zip.Dispose() }
    }

    It 'writes a structured log without evidence values' {
        $log = Get-Content -Raw -LiteralPath (Join-Path $script:pkg 'logs/collection-log.json') | ConvertFrom-Json -AsHashtable
        $log.entries.Count | Should -BeGreaterThan 100
        $entry = $log.entries[0]
        @($entry.Keys) | Should -Be @('timestamp', 'level', 'module', 'dataset', 'message', 'target')
        (Get-Content -Raw -LiteralPath (Join-Path $script:pkg 'logs/collection-log.json')) | Should -Not -Match 'adele.admin'
    }
}

Describe 'Entra transformations' {
    It 'follows @odata.nextLink paging (Conditional Access, 2 pages)' {
        $ca = Evidence 'entra.conditionalAccessPolicies'
        $ca.data.Count | Should -Be 5
        ($ca.data | Where-Object { $_.displayName -like 'CA004*' }).conditions.authenticationFlows.transferMethods | Should -Be 'deviceCodeFlow'
        ($ca.data | Where-Object { $_.displayName -like 'CA001*' }).conditions.users.includeRoles.Count | Should -Be 3
        ($ca.data | Where-Object { $_.displayName -like 'CA003*' }).grantControls.authenticationStrength.displayName | Should -Be 'Multifactor authentication'
        ($ca.data | Where-Object { $_.displayName -like 'CA003*' }).grantControls.authenticationStrength.requirementsSatisfied | Should -Be 'mfa'
        ($ca.data | Where-Object { $_.displayName -like 'CA005*' }).conditions.devices.deviceFilter.mode | Should -Be 'exclude'
        ($ca.data | Where-Object { $_.displayName -like 'CA005*' }).conditions.devices.deviceFilter.rule | Should -Be 'device.isCompliant -eq True'
        ($ca.data | Where-Object { $_.displayName -like 'CA001*' }).conditions.devices | Should -BeNullOrEmpty
        ($ca.data | Where-Object { $_.displayName -like 'CA003*' }).sessionControls.signInFrequency.value | Should -Be 12
        ($ca.data | Where-Object { $_.displayName -like 'CA005*' }).conditions.locations.excludeLocations | Should -Be @('AllTrusted')
        ($ca.data | Where-Object { $_.displayName -like 'CA001*' }).conditions.platforms | Should -BeNullOrEmpty
    }

    It 'maps role assignment principal types from @odata.type' {
        $ra = Evidence 'entra.roleAssignments'
        @($ra.data | ForEach-Object { $_.principal.principalType }) | Should -Be @('user', 'user', 'user', 'group', 'servicePrincipal')
        ($ra.data | Where-Object { $_.principalId -eq 'aaaa0001-0000-4000-8000-000000000003' }).principal.onPremisesSyncEnabled | Should -BeTrue
    }

    It 'keeps only credential metadata for applications and service principals (paged)' {
        $apps = Evidence 'entra.applications'
        $apps.data[1].passwordCredentials.Count | Should -Be 2
        @($apps.data[1].passwordCredentials[0].Keys) | Should -Be @('keyId', 'displayName', 'startDateTime', 'endDateTime')
        $apps.data[1].keyCredentials[0].type | Should -Be 'AsymmetricX509Cert'
        $sps = Evidence 'entra.servicePrincipals'
        $sps.data.Count | Should -Be 5
        ($sps.data | Where-Object { $_.servicePrincipalType -eq 'ManagedIdentity' }).appOwnerOrganizationId | Should -BeNullOrEmpty
    }

    It 'collects application permission grants for Microsoft Graph and Exchange Online' {
        $grants = Evidence 'entra.apiPermissionGrants'
        @($grants.data | ForEach-Object resourceAppId) | Should -Be @('00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000')
        $grants.data[0].assignments.Count | Should -Be 2
        ($grants.data[0].appRoles | Where-Object { $_.value -eq 'Mail.ReadWrite' }) | Should -Not -BeNullOrEmpty
        $grants.data[1].assignments.Count | Should -Be 0
    }

    It 'keeps only allow-listed directory settings and warns about dropped values' {
        $gs = Evidence 'entra.groupSettings'
        $names = @($gs.data | ForEach-Object { $_.values } | ForEach-Object { $_.name })
        $names | Should -Contain 'LockoutThreshold'
        $names | Should -Contain 'EnableBannedPasswordCheckOnPremises'
        $names | Should -Not -Contain 'BannedPasswordList'
        $names | Should -Not -Contain 'UsageGuidelinesUrl'
        $gs.warnings[0].code | Should -Be 'SETTINGS_FILTERED'
    }

    It 'maps guest sign-in activity' {
        $g = Evidence 'entra.guestUsers'
        $g.data[0].lastSignInDateTime | Should -Be '2026-08-28T07:15:00.0000000Z'
        $g.data[0].lastNonInteractiveSignInDateTime | Should -Be '2026-08-29T07:15:00.0000000Z'
        $g.data[1].lastSignInDateTime | Should -BeNullOrEmpty
    }

    It 'reads includeTargets that are not returned inline' {
        $amp = Evidence 'entra.authenticationMethodsPolicy'
        ($amp.data.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Email' }).includeTargets[0].id | Should -Be 'all_users'
        ($amp.data.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Sms' }).includeTargets.Count | Should -Be 0
    }

    It 'reports the 403 as Unauthorized with an error and no data' {
        $s = Evidence 'entra.onPremisesSynchronization'
        $s.data | Should -BeNullOrEmpty
        $s.errors[0].code | Should -Be 'UNAUTHORIZED'
    }

    It 'reports missing PIM licence as NotApplicable with a warning' {
        $p = Evidence 'entra.roleEligibilitySchedules'
        $p.warnings[0].code | Should -Be 'LICENSE_NOT_PRESENT'
        $p.errors.Count | Should -Be 0
    }
}

Describe 'Microsoft 365, Exchange and Intune transformations' {
    It 'maps SharePoint settings' {
        (Evidence 'm365.sharePointSettings').data.sharingCapability | Should -Be 'externalUserAndGuestSharing'
        (Evidence 'm365.sharePointSettings').data.idleSessionSignOut.isEnabled | Should -BeFalse
        @((Evidence 'm365.sharePointSettings').data.sharingAllowedDomainList).Count | Should -Be 0
    }

    It 'maps Teams app settings and per-team guest settings' {
        (Evidence 'm365.teamsAppSettings').data.isUserPersonalScopeResourceSpecificConsentEnabled | Should -BeTrue
        $teams = (Evidence 'm365.teamsTeamSettings').data
        $teams.Count | Should -Be 2
        ($teams | Where-Object { $_.displayName -eq 'Partner Project Falcon' }).guestSettings.allowCreateUpdateChannels | Should -BeTrue
        ($teams | Where-Object { $_.displayName -eq 'Contoso Finance' }).guestSettings.allowDeleteChannels | Should -BeFalse
    }

    It 'collects only mailboxes with forwarding and per-mailbox SMTP AUTH overrides' {
        $fw = Evidence 'exchange.mailboxForwarding'
        $fw.data.Count | Should -Be 2
        $fw.data[0].forwardingSmtpAddress | Should -Be 'smtp:cara.personal@mailbox.example'
        $smtp = Evidence 'exchange.smtpAuthMailboxes'
        $smtp.data.Count | Should -Be 2
        @($smtp.data | ForEach-Object smtpClientAuthenticationDisabled) | Should -Be @($false, $true)
    }

    It 'resolves SPF and DMARC for authoritative accepted domains' {
        $dns = Evidence 'exchange.mailDnsRecords'
        @($dns.data | ForEach-Object domain) | Should -Be @('contoso-example.mail.onmicrosoft.com', 'contoso-example.onmicrosoft.com', 'contoso.example')
        $c = $dns.data | Where-Object { $_.domain -eq 'contoso.example' }
        $c.spf.lookupStatus | Should -Be 'Found'
        $c.spf.records | Should -Be @('v=spf1 include:spf.protection.outlook.com -all')
        $c.dmarc.lookupStatus | Should -Be 'Found'
        ($dns.data | Where-Object { $_.domain -eq 'contoso-example.onmicrosoft.com' }).dmarc.lookupStatus | Should -Be 'NotFound'
        ($dns.data | Where-Object { $_.domain -eq 'contoso-example.mail.onmicrosoft.com' }).dmarc.lookupStatus | Should -Be 'Error'
    }

    It 'flattens the Intune device overview' {
        $o = (Evidence 'intune.deviceOverview').data
        $o.enrolledDeviceCount | Should -Be 187
        $o.windowsCount | Should -Be 123
        $o.macOSCount | Should -Be 9
        $o.iosCount | Should -Be 34
        $o.androidCount | Should -Be 21
    }

    It 'maps compliance policy types, assignment targets and platform-specific settings' {
        $p = (Evidence 'intune.compliancePolicies').data
        $p[0].odataType | Should -Be '#microsoft.graph.windows10CompliancePolicy'
        @($p[0].assignments | ForEach-Object targetType) | Should -Be @('#microsoft.graph.allDevicesAssignmentTarget', '#microsoft.graph.exclusionGroupAssignmentTarget')
        $p[0].settings.firewallEnabled | Should -BeTrue
        $p[1].settings.passwordRequired | Should -BeTrue
        $p[1].settings.bitLockerEnabled | Should -BeNullOrEmpty
        $p[2].assignments.Count | Should -Be 0
    }
}

Describe 'Azure transformations' {
    It 'collects enabled subscriptions and resolves role and principal names' {
        (Evidence 'azure.subscriptions').data.Count | Should -Be 3
        $ra = Evidence 'azure.roleAssignments'
        $ra.data.Count | Should -Be 5
        ($ra.data | Where-Object { $_.principalId -eq 'aaaa0001-0000-4000-8000-000000000001' -and $_.subscriptionId -like '*0001' }).roleDefinitionName | Should -Be 'Owner'
        ($ra.data | Where-Object { $_.principalType -eq 'Group' }).principalDisplayName | Should -Be 'Contoso Security Admins'
        ($ra.data | Where-Object { $_.principalId -eq 'aaaa0001-0000-4000-8000-000000000099' }).principalDisplayName | Should -BeNullOrEmpty
        @($ra.warnings | ForEach-Object code) | Should -Contain 'PRINCIPAL_NAMES_PARTIAL'
    }

    It 'counts security contact addresses without storing them' {
        $sc = Evidence 'azure.securityContacts'
        $sc.data[0].contacts[0].emailCount | Should -Be 2
        $sc.data[0].contacts[0].alertMinimalSeverity | Should -Be 'Medium'
        $sc.data[1].contacts.Count | Should -Be 0
    }

    It 'excludes default NSG rules' {
        $nsg = (Evidence 'azure.networkSecurityGroups').data
        @($nsg | ForEach-Object { $_.securityRules } | ForEach-Object name) | Should -Not -Contain 'AllowVnetInBound'
        ($nsg | Where-Object { $_.name -eq 'nsg-prod-mgmt' }).securityRules[0].sourceAddressPrefixes | Should -Be @('198.51.100.0/24', '192.0.2.0/24')
        ($nsg | Where-Object { $_.name -eq 'nsg-dev-empty' }).securityRules.Count | Should -Be 0
    }

    It 'reports one failing subscription as Partial and keeps the others' {
        $kv = Evidence 'azure.keyVaults'
        $kv.data.Count | Should -Be 1
        $kv.errors[0].code | Should -Be 'UNAUTHORIZED'
        $kv.errors[0].target | Should -Match 'a1a1a1a1-0000-4000-8000-000000000002'
    }

    It 'maps storage account and diagnostic settings' {
        $st = (Evidence 'azure.storageAccounts').data
        ($st | Where-Object { $_.name -eq 'stcontosoproddata01' }).minimumTlsVersion | Should -Be 'TLS1_0'
        ($st | Where-Object { $_.name -eq 'stcontosoproddata01' }).resourceGroup | Should -Be 'rg-prod-data'
        $diag = (Evidence 'azure.activityLogDiagnostics').data
        $diag[0].settings[0].workspaceConfigured | Should -BeTrue
        $diag[0].settings[0].enabledCategories | Should -Be @('Administrative', 'Security', 'Alert')
        $diag[1].settings.Count | Should -Be 0
    }
}

Describe 'Active Directory, AD CS and GPO transformations' {
    It 'converts FILETIME values and user account control flags' {
        $u = (Evidence 'ad.users').data
        $u.domains[0].totalUsers | Should -Be 250
        $u.domains[0].enabledUsers | Should -Be 225
        $sql = $u.users | Where-Object { $_.samAccountName -eq 'svc-sql' }
        $sql.servicePrincipalNameCount | Should -Be 2
        $sql.passwordNeverExpires | Should -BeTrue
        $sql.trustedForDelegation | Should -BeTrue
        $sql.adminCount | Should -BeFalse
        $legacy = $u.users | Where-Object { $_.samAccountName -eq 'legacy-app' }
        $legacy.doesNotRequirePreAuth | Should -BeTrue
        $legacy.passwordNotRequired | Should -BeTrue
        $legacy.lastLogonTimestamp | Should -BeNullOrEmpty
        $legacy.pwdLastSet | Should -BeNullOrEmpty
        ($u.users | Where-Object { $_.samAccountName -eq 'adm-adele' }).memberOfProtectedUsers | Should -BeTrue
        ($u.users | Where-Object { $_.samAccountName -eq 'Administrator' }).pwdLastSet | Should -Be '2019-04-17T18:40:00.0000000Z'
    }

    It 'identifies domain controllers from primaryGroupID and keeps LAPS expiry only' {
        $c = (Evidence 'ad.computers').data
        @($c | Where-Object { $_.isDomainController } | ForEach-Object name) | Should -Be @('DC01', 'DC02')
        ($c | Where-Object { $_.name -eq 'WEB01' }).allowedToDelegateToCount | Should -Be 2
        ($c | Where-Object { $_.name -eq 'APP01' }).legacyLapsExpiration | Should -Not -BeNullOrEmpty
        ($c | Where-Object { $_.name -eq 'WS-0001' }).windowsLapsExpiration | Should -Not -BeNullOrEmpty
    }

    It 'converts password policy time spans' {
        $p = (Evidence 'ad.passwordPolicies').data[0]
        $p.defaultPolicy.maxPasswordAgeDays | Should -Be 42
        $p.defaultPolicy.lockoutDurationMinutes | Should -Be 10
        $p.fineGrainedPolicies[0].maxPasswordAgeDays | Should -BeNullOrEmpty
        $p.fineGrainedPolicies[0].appliesToCount | Should -Be 1
    }

    It 'collects privileged groups including forest-root groups' {
        $g = (Evidence 'ad.privilegedGroups').data
        $g.Count | Should -Be 11
        ($g | Where-Object { $_.groupName -eq 'Domain Admins' }).members.Count | Should -Be 3
        ($g | Where-Object { $_.groupName -eq 'Key Admins' }).members.Count | Should -Be 0
    }

    It 'maps certificate template flags, EKUs and ACEs' {
        $t = (Evidence 'adcs.certificateTemplates').data
        $web = $t | Where-Object { $_.name -eq 'ContosoWebServer' }
        $web.certificateNameFlag | Should -Be 1
        $web.extendedKeyUsage | Should -Be @('1.3.6.1.5.5.7.3.1')
        $ace = $web.permissions | Where-Object { $_.principalName -eq 'CORP\Domain Users' }
        $ace.rights | Should -Be @('ExtendedRight')
        $ace.objectType | Should -Be '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $ace.principalSid | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-513'
        ($web.permissions | Where-Object { $_.principalName -eq 'CORP\Domain Admins' }).rights | Should -Contain 'WriteDacl'
        ($t | Where-Object { $_.name -eq 'ContosoUserAuth' }).certificateNameFlag | Should -Be -2113929216
    }

    It 'reads the CA certificate expiry' {
        $ca = (Evidence 'adcs.certificateAuthorities').data[0]
        $ca.caCertificateNotAfter | Should -Be '2031-01-01T00:00:00.0000000Z'
        $ca.certificateTemplates | Should -Contain 'ContosoWebServer'
    }

    It 'flattens GPO settings with the documented naming convention' {
        $gpos = (Evidence 'gpo.groupPolicyObjects').data
        $ddp = $gpos | Where-Object { $_.displayName -eq 'Default Domain Policy' }
        ($ddp.settings | Where-Object { $_.name -eq 'MinimumPasswordLength' }).value | Should -Be 7
        ($ddp.settings | Where-Object { $_.name -eq 'PasswordComplexity' }).value | Should -BeTrue
        ($ddp.settings | Where-Object { $_.name -eq 'LSAAnonymousNameLookup' }).category | Should -Be 'SecurityOptions'
        $ddp.links[0].somPath | Should -Be 'corp.contoso.example'
        $ddcp = $gpos | Where-Object { $_.displayName -eq 'Default Domain Controllers Policy' }
        ($ddcp.settings | Where-Object { $_.name -eq 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' }).value | Should -Be 1
        ($ddcp.settings | Where-Object { $_.name -eq 'SeRemoteInteractiveLogonRight' }).value | Should -Be @('BUILTIN\Administrators', 'S-1-5-21-1111111111-2222222222-3333333333-1140')
        ($ddcp.settings | Where-Object { $_.name -eq 'AuditLogonEvents' }).value | Should -Be 'Success and Failure'
        ($ddcp.settings | Where-Object { $_.name -eq 'Audit Credential Validation' }).value | Should -Be 'Success and Failure'
        ($ddcp.settings | Where-Object { $_.name -eq 'Audit Directory Service Changes' }).value | Should -Be 'No Auditing'
        $wsb = $gpos | Where-Object { $_.displayName -eq 'Contoso Workstation Baseline' }
        $wsb.wmiFilter | Should -Be 'Windows 11 only'
        ($wsb.settings | Where-Object { $_.name -eq 'Turn on PowerShell Script Block Logging' }).value | Should -Be 'Enabled'
        ($wsb.settings | Where-Object { $_.name -eq 'SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL' }).value | Should -Be 1
        ($wsb.settings | Where-Object { $_.name -like '*DefaultPassword' }).value | Should -BeNullOrEmpty
        $wsb.links[0].enforced | Should -BeTrue
        $wsb.links[1].enabled | Should -BeFalse
    }

    It 'records only the location of Group Policy Preferences passwords' {
        $s = (Evidence 'gpo.sysvolPasswordArtifacts').data
        $s.filesScanned | Should -Be 3
        $s.artifacts.Count | Should -Be 1
        $s.artifacts[0].gpoId | Should -Be '4F3A9C21-7B6E-4D2A-9E11-5C0FFEE00001'
        $s.artifacts[0].fileName | Should -Be 'Groups.xml'
        $s.artifacts[0].relativePath | Should -Be '{4F3A9C21-7B6E-4D2A-9E11-5C0FFEE00001}\Machine\Preferences\Groups\Groups.xml'
        @($s.artifacts[0].Keys) | Should -Be @('domain', 'gpoId', 'relativePath', 'fileName')
    }
}

Describe 'Windows host transformation' {
    It 'collects the local host as a one-element array with null for unreadable values' {
        $h = Evidence 'windows.hosts'
        $h.data.GetType().IsArray | Should -BeTrue
        $h.data.Count | Should -Be 1
        $h.data[0].hostName | Should -Be 'app01.corp.contoso.example'
        $h.data[0].isServer | Should -BeTrue
        $h.data[0].rdp.enabled | Should -BeTrue
        $h.data[0].lsa.wdigestUseLogonCredential | Should -BeNullOrEmpty
        $h.data[0].firewallProfiles.Count | Should -Be 3
        $h.data[0].credentialGuard.running | Should -BeFalse
        $h.warnings[0].code | Should -Be 'VALUE_UNREADABLE'
    }
}

Describe 'Replay options' {
    It 'collects domain controller settings with -IncludeDomainControllerSettings (one DC denied -> Partial)' {
        $out = Join-Path $script:tempRoot 'dc'
        $r = Invoke-AdminSecOpsCollection -Module AD -ReplayPath $script:replay -OutputPath $out -SkipConnect -IncludeDomainControllerSettings -NoZip
        $r.ZipPath | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $out -Filter '*.zip').Count | Should -Be 0
        $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/ad/domainControllerSettings.json') | ConvertFrom-Json -AsHashtable
        $e.status | Should -Be 'Partial'
        ($e.data | Where-Object { $_.hostName -eq 'dc01.corp.contoso.example' }).ldapServerIntegrity | Should -Be 2
        ($e.data | Where-Object { $_.hostName -eq 'dc01.corp.contoso.example' }).smb1Enabled | Should -BeNullOrEmpty
        ($e.data | Where-Object { $_.hostName -eq 'dc02.corp.contoso.example' }).readStatus | Should -Be 'Failed'
        $e.errors[0].target | Should -Be 'dc02.corp.contoso.example'
    }

    It 'runs a subset of modules and writes only their datasets' {
        $out = Join-Path $script:tempRoot 'subset'
        $r = Invoke-AdminSecOpsCollection -Module Exchange, Windows -ReplayPath $script:replay -OutputPath $out -SkipConnect -NoZip
        $r.DatasetCount | Should -Be 12
        $m = Get-Content -Raw -LiteralPath $r.ManifestPath | ConvertFrom-Json
        @($m.modules | ForEach-Object name) | Should -Be @('Exchange', 'Windows')
        $m.environment.adForestName | Should -BeNullOrEmpty
    }

    It 'reports a missing replay folder as a skipped module with NotCollected datasets' {
        $empty = Join-Path $script:tempRoot 'empty-replay'
        [void][System.IO.Directory]::CreateDirectory((Join-Path $empty 'graph'))
        $out = Join-Path $script:tempRoot 'skipped'
        $r = Invoke-AdminSecOpsCollection -Module Azure -ReplayPath $empty -OutputPath $out -SkipConnect -NoZip
        $m = Get-Content -Raw -LiteralPath $r.ManifestPath | ConvertFrom-Json
        $m.modules[0].status | Should -Be 'Skipped'
        @($m.files | Where-Object { $_.status -ne 'NotCollected' }).Count | Should -Be 0
        $m.modules[0].errors[0].code | Should -Be 'PREREQUISITE_NOT_MET'
    }

    It 'isolates failures: one broken dataset does not abort the module' {
        $broken = Join-Path $script:tempRoot 'broken-replay'
        Copy-Item -LiteralPath $script:replay -Destination $broken -Recurse
        Remove-Item -LiteralPath (Join-Path $broken 'graph/v1.0_policies_authorizationPolicy.json')
        Set-Content -LiteralPath (Join-Path $broken 'graph/v1.0_groupSettings.json') -Value '{"__replayError":{"statusCode":500,"errorCode":"InternalServerError","message":"Replayed server error."}}'
        $out = Join-Path $script:tempRoot 'broken'
        $r = Invoke-AdminSecOpsCollection -Module Entra -ReplayPath $broken -OutputPath $out -SkipConnect -NoZip
        $m = Get-Content -Raw -LiteralPath $r.ManifestPath | ConvertFrom-Json
        ($m.files | Where-Object datasetId -EQ 'entra.authorizationPolicy').status | Should -Be 'Failed'
        ($m.files | Where-Object datasetId -EQ 'entra.groupSettings').status | Should -Be 'Failed'
        ($m.files | Where-Object datasetId -EQ 'entra.securityDefaults').status | Should -Be 'Success'
        $m.modules[0].status | Should -Be 'CompletedWithErrors'
        $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/entra/groupSettings.json') | ConvertFrom-Json
        $e.errors[0].code | Should -Be 'HTTP_500'
    }

    It 'marks a dataset Partial when a later page fails' {
        $paged = Join-Path $script:tempRoot 'paged-replay'
        Copy-Item -LiteralPath $script:replay -Destination $paged -Recurse
        Set-Content -LiteralPath (Join-Path $paged 'graph/v1.0_identity_conditionalAccess_policies_skiptoken_contoso-replay-page-2.json') -Value '{"__replayError":{"statusCode":503,"errorCode":"ServiceUnavailable","message":"Replayed outage."}}'
        $out = Join-Path $script:tempRoot 'paged'
        $r = Invoke-AdminSecOpsCollection -Module Entra -ReplayPath $paged -OutputPath $out -SkipConnect -NoZip
        $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/entra/conditionalAccessPolicies.json') | ConvertFrom-Json
        $e.status | Should -Be 'Partial'
        $e.data.Count | Should -Be 3
        $e.errors[0].code | Should -Be 'PAGE_FAILED'
    }

    It 'falls back when signInActivity needs a licence the tenant lacks' {
        $nolic = Join-Path $script:tempRoot 'nolicence-replay'
        Copy-Item -LiteralPath $script:replay -Destination $nolic -Recurse
        $guestFile = Get-ChildItem -LiteralPath (Join-Path $nolic 'graph') -Filter 'v1.0_users_filter_userType*' | Select-Object -First 1
        Set-Content -LiteralPath $guestFile.FullName -Value '{"__replayError":{"statusCode":403,"errorCode":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn''t have premium license"}}'
        $fallbackKey = & (Get-Module AdminSecOps.Collector) { Get-AsoReplayKey -Request ('https://graph.microsoft.com/v1.0/users?$filter=' + [uri]::EscapeDataString("userType eq 'Guest'") + '&$top=999&$select=id,userPrincipalName,accountEnabled,createdDateTime,externalUserState') }
        Set-Content -LiteralPath (Join-Path $nolic "graph/$fallbackKey.json") -Value '{"value":[{"id":"aaaa0002-0000-4000-8000-000000000001","userPrincipalName":"pat_partner.example#EXT#@contoso-example.onmicrosoft.com","accountEnabled":true,"createdDateTime":"2022-02-02T10:00:00Z","externalUserState":"Accepted"}]}'
        $out = Join-Path $script:tempRoot 'nolicence'
        $r = Invoke-AdminSecOpsCollection -Module Entra -ReplayPath $nolic -OutputPath $out -SkipConnect -NoZip
        $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/entra/guestUsers.json') | ConvertFrom-Json
        $e.status | Should -Be 'Partial'
        $e.errors[0].code | Should -Be 'SIGNIN_ACTIVITY_UNAVAILABLE'
        $e.data[0].lastSignInDateTime | Should -BeNullOrEmpty
    }

    It 'maps a Graph licence error to NotApplicable when licence data is unavailable' {
        $nosku = Join-Path $script:tempRoot 'nosku-replay'
        Copy-Item -LiteralPath $script:replay -Destination $nosku -Recurse
        Set-Content -LiteralPath (Join-Path $nosku 'graph/v1.0_subscribedSkus.json') -Value '{"__replayError":{"statusCode":403,"errorCode":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}'
        Set-Content -LiteralPath (Join-Path $nosku 'graph/v1.0_deviceManagement_select_settings.json') -Value '{"__replayError":{"statusCode":400,"errorCode":"BadRequest","message":"Request not applicable to target tenant."}}'
        $out = Join-Path $script:tempRoot 'nosku'
        $r = Invoke-AdminSecOpsCollection -Module Intune -ReplayPath $nosku -OutputPath $out -SkipConnect -NoZip
        $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/intune/settings.json') | ConvertFrom-Json
        $e.status | Should -Be 'NotApplicable'
        @($e.warnings | ForEach-Object code) | Should -Contain 'LICENSE_OR_FEATURE_NOT_AVAILABLE'
        @($e.warnings | ForEach-Object code) | Should -Contain 'LICENSE_UNKNOWN'
    }
}
