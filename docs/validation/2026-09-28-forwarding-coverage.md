# Forwarding collection and evidence gaps

Control library 0.6.0 contains 109 controls. New hosted Exchange operations collect bounded Inbox forwarding-rule metadata and mail-flow recipient-action flags. These are review controls, not proof of external delivery or compromise. No mail content, rule conditions or recipient lists are retained.

Inbox coverage includes hidden rules, at most 25 visible user/shared mailboxes and 200 rules per mailbox, with a time budget. Missing roles, missing properties and scan limits prevent a complete result. Global Reader and View-Only Organization Management cannot run Get-InboxRule. The product does not grant roles automatically. Local PowerShell evidence packages explicitly mark these two hosted-only datasets NotCollected.

Mailbox ForwardingAddress objects use bounded exact Get-Recipient lookups (100 unique objects / 60 seconds). Mail users and contacts use their external address; supported mailbox types use their primary SMTP address. Groups, unsupported recipient types and denied lookups remain unresolved. This classifies the immediate destination only; it does not resolve forwarding chains.

SharePoint invitation-account matching still remains unassessed when Graph omits the property. The control gives an authorised administrator the Get-SPOTenant validation command; the result is not yet imported into cloud evidence. No extra permission or tenant setting is changed.

Validation: 1,483 automated tests passed, one skipped; TypeScript checks and secret scan passed. The standalone PowerShell replay exercises the real runtime functions with synthetic command responses and no Microsoft connection. New live rule collection still needs validation with an authorised account. Live on-premises testing needs an identified domain-joined lab host; no AD/customer scan was run for this release.

References: [Get-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps), [Get-TransportRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-transportrule?view=exchange-ps), [Get-Recipient](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-recipient?view=exchange-ps).
