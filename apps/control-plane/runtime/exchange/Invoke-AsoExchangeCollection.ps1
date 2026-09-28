<#
.SYNOPSIS
    AdminSecOps hosted Exchange Online collection (read-only, fixed operations).

.DESCRIPTION
    Run only by the AdminSecOps control plane (apps/control-plane/src/collector/exchange-runner.ts)
    with `pwsh -NoLogo -NoProfile -NonInteractive -File <this script>`. The request is read from
    standard input as JSON:

      { "mode": "probe" }
      { "mode": "collect", "tenantId": "<guid>", "userPrincipalName": "<upn>",
        "accessToken": "<delegated Exchange Online token>", "maxItems": 5000, "maxMailboxScan": 20000 }

    Security properties:
    - There is no parameter that selects a command. The operation table below is fixed and every
      entry is a Get-* cmdlet; Connect-ExchangeOnline imports only these cmdlets (-CommandName).
    - The token is used only for Connect-ExchangeOnline and is never written anywhere.
    - Error messages are never returned (they can contain object names); only fixed codes.
    - The result is written once to standard output between fixed markers.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$script:ModuleVersion = '3.10.1'
$script:MinimumPowerShell = [version]'7.6'

# Fixed operation table: id -> cmdlet and the only properties returned.
$script:Operations = [ordered]@{
    organizationConfig   = @{ Cmdlet = 'Get-OrganizationConfig'; Properties = @('AuditDisabled', 'OAuth2ClientProfileEnabled', 'CustomerLockBoxEnabled', 'MailTipsExternalRecipientsTipsEnabled') }
    transportConfig      = @{ Cmdlet = 'Get-TransportConfig'; Properties = @('SmtpClientAuthenticationDisabled') }
    adminAuditLogConfig  = @{ Cmdlet = 'Get-AdminAuditLogConfig'; Properties = @('UnifiedAuditLogIngestionEnabled') }
    acceptedDomains      = @{ Cmdlet = 'Get-AcceptedDomain'; Properties = @('DomainName', 'DomainType', 'Default', 'IsCoexistenceDomain') }
    dkimSigningConfigs   = @{ Cmdlet = 'Get-DkimSigningConfig'; Properties = @('Domain', 'Enabled', 'Status') }
    outboundSpamPolicies = @{ Cmdlet = 'Get-HostedOutboundSpamFilterPolicy'; Properties = @('Name', 'IsDefault', 'AutoForwardingMode') }
    remoteDomains        = @{ Cmdlet = 'Get-RemoteDomain'; Properties = @('Name', 'DomainName', 'AutoForwardEnabled') }
    mailboxForwarding    = @{ Cmdlet = 'Get-EXOMailbox'; Properties = @('UserPrincipalName', 'RecipientTypeDetails', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward') }
    smtpAuthMailboxes    = @{ Cmdlet = 'Get-EXOCASMailbox'; Properties = @('PrimarySmtpAddress', 'SmtpClientAuthenticationDisabled') }
    atpPolicy            = @{ Cmdlet = 'Get-AtpPolicyForO365'; Properties = @('EnableATPForSPOTeamsODB', 'EnableSafeDocs', 'AllowSafeDocsOpen') }
    inboxRules           = @{ Cmdlet = 'Get-InboxRule'; Properties = @('RecordKind','Mailbox','Identity','Name','Enabled','ScannedMailboxes','UnscannedMailboxes','Complete') }
    transportRules       = @{ Cmdlet = 'Get-TransportRule'; Properties = @('Identity','Name','State','Mode','Priority','HasRedirect','HasCopy','HasBlindCopy','HasAddedRecipients') }
}

function Write-AsoResult {
    param([Parameter(Mandatory)] $Value)
    $json = $Value | ConvertTo-Json -Depth 8 -Compress -EnumsAsStrings
    [Console]::Out.Write("@@ADMINSECOPS-RESULT-BEGIN@@$json@@ADMINSECOPS-RESULT-END@@")
}

function ConvertTo-AsoPrimitive {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return $Value }
    $text = [string]$Value
    if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096) }
    return $text
}

function Select-AsoProperty {
    param([Parameter(Mandatory)] $InputObject, [Parameter(Mandatory)] [string[]] $Property)
    $out = [ordered]@{}
    foreach ($name in $Property) {
        $p = $InputObject.PSObject.Properties[$name]
        $out[$name] = if ($null -eq $p) { $null } else { ConvertTo-AsoPrimitive $p.Value }
    }
    return $out
}

function Get-AsoFailureCode {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)
    if ($ErrorRecord.FullyQualifiedErrorId -match 'CommandNotFound') { return 'not-available' }
    $text = "$($ErrorRecord.FullyQualifiedErrorId) $($ErrorRecord.Exception.Message)"
    if ($text -match '(?i)(access ?denied|unauthori[sz]ed|forbidden|not authori[sz]ed|permission|isn''t within your current|does not have the required|\b401\b|\b403\b)') { return 'unauthorized' }
    return 'failed'
}

function Invoke-AsoOperation {
    param([Parameter(Mandatory)] [string] $Id, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [int] $MaxScan)
    $op = $script:Operations[$Id]
    if ($null -eq (Get-Command -Name $op.Cmdlet -ErrorAction SilentlyContinue)) { return @{ status = 'not-available' } }
    try {
        $truncated = $false
        switch ($Id) {
            'inboxRules' {
                # Bound the fan-out. Inbox rules require a role beyond Global Reader.
                $boxes = @(Get-EXOMailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize 26 -ErrorAction Stop)
                $truncated = $boxes.Count -gt 25
                $scope = @($boxes | Select-Object -First 25)
                $rows = [System.Collections.Generic.List[object]]::new()
                $scanned = 0
                $timer = [System.Diagnostics.Stopwatch]::StartNew()
                foreach ($box in $scope) {
                    if ($timer.Elapsed.TotalSeconds -ge 45) { $truncated = $true; break }
                    try {
                        $rules = @(Get-InboxRule -Mailbox $box.PrimarySmtpAddress -IncludeHidden -ResultSize 201 -ErrorAction Stop)
                        if ($rules.Count -gt 200) { $truncated = $true }
                        foreach ($rule in @($rules | Select-Object -First 200)) {
                            foreach ($field in @('ForwardTo','RedirectTo','ForwardAsAttachmentTo')) {
                                if ($null -eq $rule.PSObject.Properties[$field]) { $truncated = $true }
                            }
                            $r = Select-AsoProperty -InputObject $rule -Property @('Identity','Name','Enabled','ForwardTo','RedirectTo','ForwardAsAttachmentTo')
                            if ($r.ForwardTo -or $r.RedirectTo -or $r.ForwardAsAttachmentTo) {
                                $rows.Add([pscustomobject]@{ RecordKind='rule';Mailbox=[string]$box.PrimarySmtpAddress;Identity=$r.Identity;Name=$r.Name;Enabled=$r.Enabled })
                            }
                        }
                        $scanned++
                    } catch { $truncated = $true }
                }
                $raw = @([pscustomobject]@{ RecordKind='coverage';ScannedMailboxes=$scanned;UnscannedMailboxes=($boxes.Count-$scanned);Complete=(-not $truncated) }) + @($rows.ToArray())
            }
            'transportRules' {
                $rules = @(Get-TransportRule -ExcludeConditionActionDetails:$false -ResultSize ($MaxItems + 1) -ErrorAction Stop)
                if ($rules.Count -gt $MaxItems) { $truncated = $true }
                $raw = @(foreach ($rule in @($rules | Select-Object -First $MaxItems)) {
                    $r = Select-AsoProperty -InputObject $rule -Property @('Identity','Name','State','Mode','Priority','RedirectMessageTo','CopyTo','BlindCopyTo','AddToRecipients')
                    [pscustomobject]@{ Identity=$r.Identity;Name=$r.Name;State=$r.State;Mode=$r.Mode;Priority=$r.Priority;HasRedirect=(Test-AsoAction -Object $rule -Name 'RedirectMessageTo');HasCopy=(Test-AsoAction -Object $rule -Name 'CopyTo');HasBlindCopy=(Test-AsoAction -Object $rule -Name 'BlindCopyTo');HasAddedRecipients=(Test-AsoAction -Object $rule -Name 'AddToRecipients') }
                })
            }
            'mailboxForwarding' {
                $raw = @(Get-EXOMailbox -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null' -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward -ResultSize ($MaxItems + 1) -ErrorAction Stop)
                $raw = @($raw | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
            }
            'smtpAuthMailboxes' {
                $scanned = @(Get-EXOCASMailbox -Properties SmtpClientAuthenticationDisabled -ResultSize ($MaxScan + 1) -ErrorAction Stop)
                if ($scanned.Count -gt $MaxScan) { $truncated = $true; $scanned = @($scanned | Select-Object -First $MaxScan) }
                # Only explicit per-mailbox overrides of the organization setting are returned.
                $raw = @($scanned | Where-Object { $null -ne $_.SmtpClientAuthenticationDisabled })
            }
            default {
                $raw = @(& $op.Cmdlet -ErrorAction Stop)
            }
        }
        if ($raw.Count -gt $MaxItems) { $truncated = $true; $raw = @($raw | Select-Object -First $MaxItems) }
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $raw) {
            $item = Select-AsoProperty -InputObject $o -Property $op.Properties
            if ($Id -eq 'mailboxForwarding') {
                $resolved = Resolve-AsoForwardingRecipient -Identity ([string]$item.ForwardingAddress)
                $item['ResolvedForwardingSmtpAddress'] = $resolved.address
                $item['ResolvedForwardingRecipientType'] = $resolved.type
            }
            $items.Add($item)
        }
        return @{ status = 'ok'; items = [object[]]$items.ToArray(); truncated = $truncated }
    }
    catch {
        return @{ status = (Get-AsoFailureCode -ErrorRecord $_) }
    }
}

function Test-AsoAction {
    param($Object, [string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return [bool]$property.Value
}

function Resolve-AsoForwardingRecipient {
    param([string] $Identity)
    $unknown = @{ address = $null; type = $null }
    if (-not $Identity) { return $unknown }
    if (-not $script:RecipientTimer.IsRunning) { $script:RecipientTimer.Start() }
    if ($script:RecipientCache.ContainsKey($Identity)) { return $script:RecipientCache[$Identity] }
    if ($script:RecipientCache.Count -ge 100 -or $script:RecipientTimer.Elapsed.TotalSeconds -ge 60) { return $unknown }
    $script:RecipientCache[$Identity] = $unknown
    try {
        $recipient = @(Get-Recipient -Identity $Identity -ErrorAction Stop)
        if ($recipient.Count -ne 1) { return $unknown }
        $r = Select-AsoProperty -InputObject $recipient[0] -Property @('RecipientTypeDetails','ExternalEmailAddress','PrimarySmtpAddress')
        $address = $null
        if ($r.RecipientTypeDetails -in @('MailContact','MailUser')) { $address = $r.ExternalEmailAddress }
        elseif ($r.RecipientTypeDetails -in @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox')) { $address = $r.PrimarySmtpAddress }
        # Groups and unknown types stay unresolved; a group's primary address does not describe its members.
        $result = @{ address = $address; type = $r.RecipientTypeDetails }
        $script:RecipientCache[$Identity] = $result
        return $result
    } catch { return $unknown }
}

function Get-AsoModuleVersion {
    $m = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Version -eq [version]$script:ModuleVersion } | Select-Object -First 1
    if ($null -eq $m) { return $null }
    return [string]$m.Version
}

$result = [ordered]@{ kind = 'adminsecops.exchange.result'; status = 'invalid-request'; connectedTenantId = $null; operations = [ordered]@{} }
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json -Depth 4 -AsHashtable
    if ($request -isnot [System.Collections.IDictionary]) { Write-AsoResult $result; exit 0 }

    if ($request['mode'] -eq 'probe') {
        $module = Get-AsoModuleVersion
        Write-AsoResult ([ordered]@{
                kind              = 'adminsecops.exchange.probe'
                ok                = ($PSVersionTable.PSVersion -ge $script:MinimumPowerShell -and $null -ne $module)
                powershellVersion = [string]$PSVersionTable.PSVersion
                moduleVersion     = $module
            })
        exit 0
    }

    $tenantId = [string]$request['tenantId']
    $upn = [string]$request['userPrincipalName']
    $token = [string]$request['accessToken']
    $maxItems = $request['maxItems'] -as [int]
    $maxScan = $request['maxMailboxScan'] -as [int]
    if ($request['mode'] -ne 'collect' -or
        $tenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
        $upn -notmatch '^[^@\s]{1,128}@[A-Za-z0-9.-]{1,253}$' -or
        $token -notmatch '^[A-Za-z0-9._-]{20,16384}$' -or
        $null -eq $maxItems -or $maxItems -lt 1 -or $maxItems -gt 100000 -or
        $null -eq $maxScan -or $maxScan -lt 1 -or $maxScan -gt 500000) {
        Write-AsoResult $result
        exit 0
    }

    if ($PSVersionTable.PSVersion -lt $script:MinimumPowerShell -or $null -eq (Get-AsoModuleVersion)) {
        $result.status = 'runtime-unavailable'
        Write-AsoResult $result
        exit 0
    }
    Import-Module -Name ExchangeOnlineManagement -RequiredVersion $script:ModuleVersion -ErrorAction Stop

    $cmdlets = @($script:Operations.Values | ForEach-Object { $_.Cmdlet }) + @('Get-Recipient')
    try {
        Connect-ExchangeOnline -AccessToken $token -UserPrincipalName $upn -CommandName $cmdlets -ShowBanner:$false -SkipLoadingFormatData -ErrorAction Stop | Out-Null
    }
    catch {
        $result.status = if ((Get-AsoFailureCode -ErrorRecord $_) -eq 'unauthorized') { 'connect-unauthorized' } else { 'connect-failed' }
        Write-AsoResult $result
        exit 0
    }
    try {
        $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue) | Select-Object -First 1
        $script:RecipientCache = @{}
        $script:RecipientTimer = [System.Diagnostics.Stopwatch]::new()
        if ($null -ne $info -and $null -ne $info.PSObject.Properties['TenantID']) { $result.connectedTenantId = [string]$info.TenantID }
        # The caller discards everything when the connected tenant is not the verified tenant.
        foreach ($id in $script:Operations.Keys) {
            $result.operations[$id] = Invoke-AsoOperation -Id $id -MaxItems $maxItems -MaxScan $maxScan
        }
        $result.status = 'ok'
    }
    finally {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    Write-AsoResult $result
}
catch {
    $result.status = 'connect-failed'
    $result.operations = [ordered]@{}
    Write-AsoResult $result
}
exit 0
