#Requires -Version 7.2
# Offline tests: load only repository-owned function/table definitions, never the runner entry point.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path (Split-Path -Parent $PSScriptRoot) 'apps/control-plane/runtime/exchange/Invoke-AsoExchangeCollection.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Runner has PowerShell syntax errors.' }
foreach ($definition in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$table = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:Operations' }, $false)[0]
. ([scriptblock]::Create($table.Extent.Text))
function Assert-Result { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
$script:recipientCalls = 0
function Get-Recipient {
    [CmdletBinding()] param([string]$Identity)
    $script:recipientCalls++
    if ($Identity -eq 'denied') { throw 'Access denied' }
    $type = if ($Identity -eq 'group') { 'MailUniversalDistributionGroup' } else { 'MailContact' }
    [pscustomobject]@{ RecipientTypeDetails=$type;ExternalEmailAddress='smtp:external@outside.example';PrimarySmtpAddress='alias@contoso.example' }
}
$script:mode = 'normal'
function Get-EXOMailbox {
    [CmdletBinding()] param([string]$Filter, [string[]]$Properties, [string[]]$RecipientTypeDetails, [int]$ResultSize)
    Assert-Result ($ResultSize -gt 0) 'Mailbox query must be bounded.'
    if ($Filter) {
        Assert-Result ($Properties -contains 'ForwardingAddress') 'Forwarding properties must be requested.'
        return [pscustomobject]@{ UserPrincipalName='source@contoso.example';RecipientTypeDetails='UserMailbox';ForwardingAddress='contact';ForwardingSmtpAddress=$null;DeliverToMailboxAndForward=$true }
    }
    Assert-Result ($RecipientTypeDetails -contains 'UserMailbox') 'Mailbox type must be explicit.'
    $count = if ($script:mode -eq 'limit') { 26 } else { 1 }
    for ($i=0; $i -lt $count; $i++) { [pscustomobject]@{ PrimarySmtpAddress="user$i@contoso.example" } }
}
function Get-InboxRule {
    [CmdletBinding()] param([string]$Mailbox, [switch]$IncludeHidden, [int]$ResultSize)
    Assert-Result ($Mailbox -like '*@contoso.example' -and $ResultSize -eq 201) 'Inbox query must identify a mailbox and cap rules.'
    Assert-Result $IncludeHidden.IsPresent 'Hidden Inbox rules must be included.'
    if ($script:mode -eq 'denied') { throw 'Access denied' }
    [pscustomobject]@{ Identity='rule1';Name='Forward';Enabled=$true;ForwardTo=@('recipient');RedirectTo=@();ForwardAsAttachmentTo=@() }
}
function Get-TransportRule {
    [CmdletBinding()] param([bool]$ExcludeConditionActionDetails, [int]$ResultSize)
    Assert-Result ($ResultSize -eq 101) 'Transport query must use the configured cap plus one.'
    Assert-Result (-not $ExcludeConditionActionDetails) 'Action details must be requested.'
    # Missing CopyTo must remain unknown, not become false.
    [pscustomobject]@{ Identity='transport1';Name='Copy';State='Enabled';Mode='Audit';Priority=0;RedirectMessageTo=@();BlindCopyTo=@('recipient');AddToRecipients=@() }
}
$script:RecipientCache = @{}
$script:RecipientTimer = [Diagnostics.Stopwatch]::new()
$mail = Invoke-AsoOperation -Id mailboxForwarding -MaxItems 100 -MaxScan 100
Assert-Result ($mail.status -eq 'ok' -and $mail.items[0].ResolvedForwardingSmtpAddress -eq 'smtp:external@outside.example') 'Recipient destination was not resolved.'
$null = Resolve-AsoForwardingRecipient -Identity contact
Assert-Result ($script:recipientCalls -eq 1) 'Recipient cache was not reused.'
Assert-Result ($null -eq (Resolve-AsoForwardingRecipient -Identity group).address) 'Group must stay unresolved.'
Assert-Result ($null -eq (Resolve-AsoForwardingRecipient -Identity denied).address) 'Denied lookup must stay unresolved.'
$inbox = Invoke-AsoOperation -Id inboxRules -MaxItems 100 -MaxScan 100
Assert-Result ($inbox.status -eq 'ok' -and -not $inbox.truncated -and $inbox.items[0].Complete -and $inbox.items.Count -eq 2) 'Normal Inbox scan failed.'
$script:mode = 'denied'
$denied = Invoke-AsoOperation -Id inboxRules -MaxItems 100 -MaxScan 100
Assert-Result ($denied.truncated -and -not $denied.items[0].Complete -and $denied.items[0].ScannedMailboxes -eq 0) 'Denied Inbox scan must not report complete coverage.'
$script:mode = 'limit'
$limited = Invoke-AsoOperation -Id inboxRules -MaxItems 100 -MaxScan 100
Assert-Result ($limited.truncated -and $limited.items[0].ScannedMailboxes -eq 25 -and $limited.items[0].UnscannedMailboxes -eq 1) 'Mailbox limit was not enforced.'
$transport = Invoke-AsoOperation -Id transportRules -MaxItems 100 -MaxScan 100
Assert-Result ($transport.status -eq 'ok' -and $transport.items[0].HasBlindCopy -and $null -eq $transport.items[0].HasCopy -and -not $transport.items[0].HasRedirect) 'Transport action presence was not preserved.'
Write-Output 'Offline Exchange forwarding replay passed; no Microsoft connection was opened.'
