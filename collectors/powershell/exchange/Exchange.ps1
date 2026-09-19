# Exchange Online datasets (allow-listed Get-* cmdlets from ExchangeOnlineManagement) and public
# mail DNS records. No message content, inbox rules or mailbox data other than forwarding flags.

function Get-AsoExchangeSingle {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string[]] $Property)
    $items = @(Invoke-AsoExoCommand -Name $Name -Property $Property)
    if ($items.Count -eq 0) { throw "$Name returned no configuration object." }
    return $items[0]
}

function Get-AsoExchangeOrganizationConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $o = Get-AsoExchangeSingle -Name 'Get-OrganizationConfig' -Property @('AuditDisabled', 'OAuth2ClientProfileEnabled', 'CustomerLockBoxEnabled', 'MailTipsExternalRecipientsTipsEnabled')
    $State.Data = [ordered]@{
        auditDisabled                         = [bool](ConvertTo-AsoBool $o.AuditDisabled)
        oAuth2ClientProfileEnabled            = [bool](ConvertTo-AsoBool $o.OAuth2ClientProfileEnabled)
        customerLockBoxEnabled                = ConvertTo-AsoBool $o.CustomerLockBoxEnabled
        mailTipsExternalRecipientsTipsEnabled = ConvertTo-AsoBool $o.MailTipsExternalRecipientsTipsEnabled
    }
}

function Get-AsoExchangeTransportConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $o = Get-AsoExchangeSingle -Name 'Get-TransportConfig' -Property @('SmtpClientAuthenticationDisabled')
    $State.Data = [ordered]@{ smtpClientAuthenticationDisabled = [bool](ConvertTo-AsoBool $o.SmtpClientAuthenticationDisabled) }
}

function Get-AsoExchangeAdminAuditLogConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $o = Get-AsoExchangeSingle -Name 'Get-AdminAuditLogConfig' -Property @('UnifiedAuditLogIngestionEnabled')
    $State.Data = [ordered]@{ unifiedAuditLogIngestionEnabled = [bool](ConvertTo-AsoBool $o.UnifiedAuditLogIngestionEnabled) }
}

function Get-AsoExchangeAcceptedDomainList {
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    if (-not $ctx.Cache.ContainsKey('exo:acceptedDomains')) {
        $ctx.Cache['exo:acceptedDomains'] = [object[]]@(Invoke-AsoExoCommand -Name 'Get-AcceptedDomain' -Property @('DomainName', 'DomainType', 'Default', 'IsCoexistenceDomain'))
    }
    return , $ctx.Cache['exo:acceptedDomains']
}

function Get-AsoExchangeAcceptedDomain {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $domains = Get-AsoExchangeAcceptedDomainList
    $State.Data = [object[]]@($domains | ForEach-Object {
            [ordered]@{
                domainName          = [string]$_.DomainName
                domainType          = [string]$_.DomainType
                default             = [bool](ConvertTo-AsoBool $_.Default)
                isCoexistenceDomain = ConvertTo-AsoBool $_.IsCoexistenceDomain
            }
        })
}

function Get-AsoExchangeDkimSigningConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoExoCommand -Name 'Get-DkimSigningConfig' -Property @('Domain', 'Enabled', 'Status'))
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                domain  = [string]$_.Domain
                enabled = [bool](ConvertTo-AsoBool $_.Enabled)
                status  = ConvertTo-AsoString $_.Status
            }
        })
}

function Get-AsoExchangeOutboundSpamPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoExoCommand -Name 'Get-HostedOutboundSpamFilterPolicy' -Property @('Name', 'IsDefault', 'AutoForwardingMode'))
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                name               = [string]$_.Name
                isDefault          = [bool](ConvertTo-AsoBool $_.IsDefault)
                autoForwardingMode = [string]$_.AutoForwardingMode
            }
        })
}

function Get-AsoExchangeRemoteDomain {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = @(Invoke-AsoExoCommand -Name 'Get-RemoteDomain' -Property @('Name', 'DomainName', 'AutoForwardEnabled'))
    $State.Data = [object[]]@($items | ForEach-Object {
            [ordered]@{
                name               = [string]$_.Name
                domainName         = [string]$_.DomainName
                autoForwardEnabled = [bool](ConvertTo-AsoBool $_.AutoForwardEnabled)
            }
        })
}

function Get-AsoExchangeMailboxForwarding {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $params = @{
        Filter     = 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null'
        Properties = @('ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward')
        ResultSize = 'Unlimited'
    }
    $items = @(Invoke-AsoExoCommand -Name 'Get-EXOMailbox' -Parameters $params -Property @('UserPrincipalName', 'RecipientTypeDetails', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward'))
    $State.Data = [object[]]@($items | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | ForEach-Object {
            [ordered]@{
                userPrincipalName          = [string]$_.UserPrincipalName
                recipientTypeDetails       = ConvertTo-AsoString $_.RecipientTypeDetails
                forwardingSmtpAddress      = ConvertTo-AsoString $_.ForwardingSmtpAddress
                forwardingAddress          = ConvertTo-AsoString $_.ForwardingAddress
                deliverToMailboxAndForward = ConvertTo-AsoBool $_.DeliverToMailboxAndForward
            }
        })
}

function Get-AsoExchangeSmtpAuthMailbox {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $params = @{ Properties = @('SmtpClientAuthenticationDisabled'); ResultSize = 'Unlimited' }
    $items = @(Invoke-AsoExoCommand -Name 'Get-EXOCASMailbox' -Parameters $params -Property @('PrimarySmtpAddress', 'SmtpClientAuthenticationDisabled'))
    $overrides = @($items | Where-Object { $null -ne (ConvertTo-AsoBool $_.SmtpClientAuthenticationDisabled) })
    $State.Data = [object[]]@($overrides | ForEach-Object {
            [ordered]@{
                userPrincipalName                = [string]$_.PrimarySmtpAddress
                smtpClientAuthenticationDisabled = [bool](ConvertTo-AsoBool $_.SmtpClientAuthenticationDisabled)
            }
        })
    Add-AsoDatasetWarning -State $State -Code 'IDENTIFIER_PRIMARY_SMTP' -Message 'Get-EXOCASMailbox does not return UserPrincipalName; userPrincipalName contains the primary SMTP address.'
}

function Get-AsoExchangeAtpPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE') -Feature 'Microsoft Defender for Office 365')) { return }
    if (-not (Test-AsoExoCommandAvailable -Name 'Get-AtpPolicyForO365')) {
        Set-AsoDatasetNotApplicable -State $State -Code 'FEATURE_NOT_AVAILABLE' -Message 'Get-AtpPolicyForO365 is not available in this Exchange Online session, which indicates Microsoft Defender for Office 365 is not licensed.'
        return
    }
    $o = Get-AsoExchangeSingle -Name 'Get-AtpPolicyForO365' -Property @('EnableATPForSPOTeamsODB', 'EnableSafeDocs', 'AllowSafeDocsOpen')
    $State.Data = [ordered]@{
        enableATPForSPOTeamsODB = [bool](ConvertTo-AsoBool $o.EnableATPForSPOTeamsODB)
        enableSafeDocs          = ConvertTo-AsoBool $o.EnableSafeDocs
        allowSafeDocsOpen       = ConvertTo-AsoBool $o.AllowSafeDocsOpen
    }
}

function ConvertTo-AsoDnsLookup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)] [string] $Prefix)
    if ($Result.Status -eq 'Error') { return [ordered]@{ lookupStatus = 'Error'; records = [string[]]@() } }
    $matched = [string[]]@($Result.Records | Where-Object { $_ -match "^\s*$([regex]::Escape($Prefix))(\s|;|$)" })
    $status = if ($matched.Count -gt 0) { 'Found' } else { 'NotFound' }
    return [ordered]@{ lookupStatus = $status; records = $matched }
}

function Get-AsoExchangeMailDnsRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $domains = @((Get-AsoExchangeAcceptedDomainList) | Where-Object { [string]$_.DomainType -eq 'Authoritative' } | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() } | Sort-Object -Unique)
    $out = [System.Collections.Generic.List[object]]::new()
    $errors = 0
    foreach ($d in $domains) {
        $spfResult = Resolve-AsoDnsTxt -Name $d
        $dmarcResult = Resolve-AsoDnsTxt -Name "_dmarc.$d"
        foreach ($r in @($spfResult, $dmarcResult)) {
            if ($r.Status -eq 'Error') { $errors++; Add-AsoDatasetWarning -State $State -Code 'DNS_LOOKUP_ERROR' -Message "A TXT lookup failed: $($r.Message)" -Target $d }
        }
        $out.Add([ordered]@{
                domain = $d
                spf    = ConvertTo-AsoDnsLookup -Result $spfResult -Prefix 'v=spf1'
                dmarc  = ConvertTo-AsoDnsLookup -Result $dmarcResult -Prefix 'v=DMARC1'
            })
    }
    if ($domains.Count -gt 0 -and $errors -ge ($domains.Count * 2)) {
        throw 'All DNS lookups failed; check DNS connectivity from the collecting computer.'
    }
    $State.Data = [object[]]$out.ToArray()
}
