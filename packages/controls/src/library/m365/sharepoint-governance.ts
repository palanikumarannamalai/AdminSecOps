import { defineControl } from '../../define.js';
import { fact, notAssessed, pass, review } from '../../helpers.js';
import { M365_REF } from './references.js';

const common = {
  version: '1.0.0', lifecycle: 'stable' as const, technology: 'm365' as const, category: 'Data protection',
  subcategory: 'External sharing', severity: 'low' as const, confidence: 'high' as const,
  applicability: { description: 'SharePoint Online tenants with external sharing enabled. Tenant settings only; site overrides and Entra B2B restrictions are not evaluated.' },
  requiredEvidence: ['m365.sharePointSettings'], optionalEvidence: [],
  frameworkMappings: [], tags: ['sharepoint', 'guest-access', 'external-sharing'],
};

export const m365SharePointInvitationIdentity = defineControl({
  ...common,
  version: '1.0.1',
  id: 'M365-SPO-005',
  title: 'SharePoint guest invitations require the invited account',
  description: 'Checks the SharePoint tenant invitation account-matching setting. This does not establish effective Entra B2B redemption behavior or protect anonymous links.',
  rationale: 'Account matching helps keep an invitation tied to its intended recipient. Alternative B2B identity controls and legitimate account aliases need administrator review.',
  evaluation: { logic: 'External sharing disabled: not applicable. True: pass for this setting. False or unrecognized sharing mode: review. Missing setting: not assessed.', parameters: {} },
  expectedState: 'Require the invited account, or document and verify the equivalent Entra B2B redemption controls.',
  remediation: { summary: 'Review invitation redemption and enable account matching where appropriate.', steps: ['Record the current setting and identify Entra B2B integration and partner account aliases.', 'In SharePoint admin center > Policies > Sharing, review the option requiring guests to use the invited account.', 'Test with an approved external account before enabling the setting broadly. If Entra B2B governs redemption, validate that workflow instead.'], effort: 'low' },
  implementationConsiderations: ['This flag alone does not prove how Entra B2B invitations are redeemed.', 'Anyone links do not require the invited account; review M365-SPO-001 separately.'],
  impact: 'Guests using another account or an alias may need a new invitation.',
  rollback: ['Restore the recorded invitation setting after reviewing the reason for rollback.'],
  validation: ['Run a new assessment and verify the collected flag.', 'If Graph omits it, use an authorised SharePoint administrator in SharePoint Online Management Shell: Get-SPOTenant | Select-Object RequireAcceptingAccountMatchInvitedAccount,EnableAzureADB2BIntegration. Do not change either setting to make the test pass.', 'Confirm that an approved guest invitation is redeemed by the intended account.'],
  references: [M365_REF.graphSharePointSettings, M365_REF.manageSharing],
  applies: ctx => ctx.data('m365.sharePointSettings').sharingCapability.trim().toLowerCase() === 'disabled' ? { applicable: false, reason: 'External sharing is disabled.' } : { applicable: true },
  evaluate: ctx => {
    const s = ctx.data('m365.sharePointSettings');
    const mode = s.sharingCapability.trim().toLowerCase();
    if (!['externalusersharingonly', 'externaluserandguestsharing', 'existingexternalusersharingonly'].includes(mode)) return review({ reason: 'The sharing capability is unrecognized; invitation applicability needs review.', summary: 'Invitation scope is uncertain.', confidence: 'low' });
    const enabled = s.isRequireAcceptingUserToMatchInvitedUserEnabled;
    if (enabled === null) return notAssessed({ reason: 'Microsoft Graph did not return the invitation account-matching setting. This is a collection gap, not evidence that matching is disabled.', summary: 'Invitation setting needs administrator verification.', confidence: 'low', notes: ['An authorised SharePoint administrator can read RequireAcceptingAccountMatchInvitedAccount and EnableAzureADB2BIntegration with Get-SPOTenant. This release cannot import that result into the cloud assessment; the control remains unassessed until evidence is collected.'] });
    const facts = [fact('Require invited account', enabled)];
    const notes = ['Tenant flag only: Entra B2B redemption and Anyone links are not validated by this check.'];
    return enabled ? pass({ reason: 'The SharePoint invitation account-matching setting is enabled.', summary: 'Invited-account matching is configured.', facts, notes }) : review({ reason: 'SharePoint does not require the invited account through this setting. Confirm Entra B2B redemption controls and partner requirements before changing it.', summary: 'Guest invitation identity needs review.', facts, notes });
  },
});

export const m365SharePointDomainRestrictions = defineControl({
  ...common,
  id: 'M365-SPO-006',
  title: 'SharePoint external-sharing domain restrictions are configured',
  description: 'Checks the tenant domain restriction mode and its matching domain list. It does not assess the business approval of listed domains or effective Entra B2B/site restrictions.',
  rationale: 'Domain restrictions can limit partner sharing. Organizations needing broad collaboration may instead use other governance controls, so absent restrictions require review rather than automatic failure.',
  evaluation: { logic: 'External sharing disabled: not applicable. Recognized allow/block mode with a nonempty valid domain list: pass for configuration presence only. Missing mode/list: not assessed. None, unknown mode, empty or invalid lists: review.', parameters: {} },
  expectedState: 'A reviewed domain restriction list or a documented alternative external collaboration policy.',
  remediation: { summary: 'Review partner domains and configure appropriate restrictions.', steps: ['Record the current SharePoint mode and domain lists, and review Entra B2B and site restrictions.', 'In SharePoint admin center > Policies > Sharing > More external sharing settings, review Limit external sharing by domain.', 'If required, configure an approved allow list or block list using exact domain names, then test approved partner access.'], effort: 'medium' },
  implementationConsiderations: ['A block list still permits unlisted domains; it is not equivalent to an allow list.', 'Entra B2B and site settings can impose additional restrictions.', 'Domain restrictions do not prevent anonymous Anyone links being forwarded.'],
  impact: 'New restrictions can prevent legitimate partner sharing or access.',
  rollback: ['Restore the recorded mode and lists if testing identifies unintended access changes.'],
  validation: ['Reassess the tenant and inspect the mode and list count.', 'Test sharing with approved and restricted partner domains.'],
  references: [M365_REF.graphSharePointSettings, { title: 'Restrict SharePoint and OneDrive sharing by domain', url: 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing', publisher: 'Microsoft' }],
  applies: ctx => ctx.data('m365.sharePointSettings').sharingCapability.trim().toLowerCase() === 'disabled' ? { applicable: false, reason: 'External sharing is disabled.' } : { applicable: true },
  evaluate: ctx => {
    const s = ctx.data('m365.sharePointSettings');
    if (!['externalusersharingonly', 'externaluserandguestsharing', 'existingexternalusersharingonly'].includes(s.sharingCapability.trim().toLowerCase())) return review({ reason: 'The sharing capability is unrecognized; domain-restriction applicability needs review.', summary: 'Sharing scope is uncertain.', confidence: 'low' });
    if (s.sharingDomainRestrictionMode === null) return notAssessed({ reason: 'Microsoft Graph did not return the sharing domain restriction mode.', summary: 'Domain restriction mode unavailable.' });
    const mode = s.sharingDomainRestrictionMode.trim().toLowerCase();
    const facts = [fact('Domain restriction mode', s.sharingDomainRestrictionMode)];
    const notes = ['Configuration presence only; domain approval, Entra B2B/site restrictions and anonymous link access are not assessed.'];
    if (mode === 'none') return review({ reason: 'No SharePoint tenant domain restriction is configured. Confirm whether partner governance or Entra B2B/site restrictions meet the organization\'s needs.', summary: 'External-sharing domain governance needs review.', facts, notes });
    if (!['allowlist', 'blocklist'].includes(mode)) return review({ reason: 'The sharing domain restriction mode is unrecognized.', summary: 'Unknown domain restriction mode.', confidence: 'low', facts, notes });
    const domains = mode === 'allowlist' ? s.sharingAllowedDomainList : s.sharingBlockedDomainList;
    if (domains === null) return notAssessed({ reason: 'The domain restriction mode was collected but its corresponding domain list was missing.', summary: 'Domain restriction list unavailable.' });
    facts.push(fact('Configured domain count', domains.length));
    const domainName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    if (domains.length === 0 || domains.some(d => !domainName.test(d.trim()))) return review({ reason: 'The configured restriction list is empty or contains invalid domain entries; validate it in SharePoint.', summary: 'Domain restriction list needs validation.', facts, notes });
    if (mode === 'blocklist') notes.push('A block list allows domains not explicitly blocked.');
    return pass({ reason: `SharePoint has a ${mode === 'allowlist' ? 'domain allow list' : 'domain block list'} with ${domains.length} entries. Business approval and effective access need separate validation.`, summary: 'Tenant domain restrictions are configured.', facts, notes });
  },
});
