import { defineControl } from '../../define.js';
import { eqi, fact } from '../../helpers.js';
import { aggregateVerdicts, fail_, pass_, review_, unknown_ } from '../shared/verdicts.js';
import { sameId, subscriptionSubject, subscriptionUniverse } from './common.js';
import { AZ_REF } from './references.js';

/** Friendly names for Defender for Cloud plan identifiers (pricings API "name"). */
const PLAN_LABELS: Readonly<Record<string, string>> = {
  virtualmachines: 'Defender for Servers',
  storageaccounts: 'Defender for Storage',
  keyvaults: 'Defender for Key Vault',
  arm: 'Defender for Resource Manager',
  cloudposture: 'Defender CSPM',
  sqlservers: 'Defender for Azure SQL Databases',
  appservices: 'Defender for App Service',
  containers: 'Defender for Containers',
};

function planLabel(name: string): string {
  return PLAN_LABELS[name.toLowerCase()] ?? name;
}

function parseList(value: string): string[] {
  return value
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

export const azDefenderPlans = defineControl({
  id: 'AZ-DEF-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Microsoft Defender for Cloud plans are enabled for key workloads',
  technology: 'azure',
  category: 'Threat detection',
  subcategory: 'Microsoft Defender for Cloud',
  description:
    'Lists, per subscription, which key Microsoft Defender for Cloud plans (by default Servers, Storage, Key Vault, Resource Manager and Defender CSPM) are on the Free tier, so the administrator can decide which paid protections the subscription needs.',
  rationale:
    'Without the paid Defender plans, Defender for Cloud provides posture recommendations only: there is no threat detection or alerting for attacks against servers, storage accounts, key vaults or the Azure control plane. Many incidents in small Azure estates are discovered late because nothing raised an alert.',
  severity: 'medium',
  confidence: 'medium',
  applicability: { description: 'Every Azure subscription the collector could read.' },
  requiredEvidence: ['azure.defenderPlans'],
  optionalEvidence: ['azure.subscriptions'],
  evaluation: {
    logic:
      'For each subscription the control looks up every plan named in the keyPlans parameter (comma-separated pricings API names). PASS when every key plan is on the Standard tier in every subscription. A subscription where one or more key plans are on the Free tier is marked for REVIEW (never FAIL) because whether a paid plan is warranted depends on which resource types the subscription contains, their business value and cost - a decision AdminSecOps cannot make. A subscription with no plan data, or where a key plan is missing from the evidence, cannot be evaluated and is also reported for review (never PASS).',
    parameters: { keyPlans: 'VirtualMachines,StorageAccounts,KeyVaults,Arm,CloudPosture' },
  },
  expectedState:
    'Each subscription has the Defender plans that match its workloads enabled (Standard tier) - at minimum Defender for Servers where virtual machines run, Defender for Storage where business data is stored, Defender for Key Vault, Defender for Resource Manager and Defender CSPM - or a documented decision not to.',
  remediation: {
    summary: 'Review the Free-tier plans listed for each subscription and enable the plans that match the resources you run there.',
    steps: [
      'In the Azure portal open Microsoft Defender for Cloud > Environment settings and select the subscription.',
      'On the Defender plans page review each plan listed in the finding. Check whether the subscription contains that resource type (for example virtual machines for Defender for Servers).',
      'Use the Defender for Cloud cost calculator / pricing page to estimate cost, then switch the required plans to On and select Save.',
      'For Defender for Servers choose Plan 1 or Plan 2 (Plan 2 adds features such as just-in-time VM access and file integrity monitoring).',
      'Record the decision for plans you intentionally leave off, so future assessments can be reviewed quickly.',
    ],
    scriptExample:
      '# Review, then enable selected plans (Az PowerShell). Enabling plans incurs cost.\nSet-AzContext -Subscription "<subscription-id>"\nGet-AzSecurityPricing | Select-Object Name, PricingTier, SubPlan\n# Set-AzSecurityPricing -Name "Arm" -PricingTier "Standard"\n# Set-AzSecurityPricing -Name "KeyVaults" -PricingTier "Standard"\n# Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard" -SubPlan "P1"',
    effort: 'low',
  },
  implementationConsiderations: [
    'Paid plans are billed per protected resource (for example per server-hour or per storage account); an empty subscription incurs little or no cost, a large one can be significant.',
    'Defender for Servers Plan 1 includes Microsoft Defender for Endpoint licensing for the protected servers; check existing Defender for Endpoint server licences to avoid paying twice.',
    'Enable plans at management group scope with Azure Policy if you have many subscriptions, so new subscriptions are protected automatically.',
    'Alerts are only useful if someone receives them; configure security contacts (AZ-DEF-002).',
  ],
  impact: 'Enabling a plan starts billing and, for some plans, deploys agents or agentless scanning to the protected resources. No workload downtime is expected.',
  rollback: ['In Defender for Cloud > Environment settings > (subscription) > Defender plans, switch the plan to Off and select Save.'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-DEF-001 is PASS or that remaining Free-tier plans are documented decisions.',
    'Open the Defender for Cloud coverage workbook and confirm the expected plans show as enabled.',
  ],
  references: [AZ_REF.defenderIntroduction, AZ_REF.defenderEnablePlans, AZ_REF.mcsb],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-4' },
    { framework: 'NIST-800-53r5', id: 'RA-5' },
    { framework: 'MCSB', id: 'LT-1' },
  ],
  tags: ['defender-for-cloud', 'threat-detection', 'cost-trade-off'],
  evaluate: (ctx) => {
    const plans = ctx.data('azure.defenderPlans');
    const keyPlans = parseList(ctx.str('keyPlans'));
    const subscriptions = subscriptionUniverse(
      ctx,
      plans.map((p) => p.subscriptionId),
    );
    return aggregateVerdicts({
      items: subscriptions,
      subject: subscriptionSubject,
      noun: ['subscription', 'subscriptions'],
      requirement: `the key Defender plans (${keyPlans.map(planLabel).join(', ')}) are enabled`,
      empty: { status: 'NOT_ASSESSED', reason: 'The evidence contains no subscriptions or Defender plan data.' },
      extraFacts: [fact('Key plans (parameter)', keyPlans.join(', '))],
      reviewGuidance:
        'Free-tier plans are listed for review rather than failed: whether each paid plan is warranted depends on the resource types in the subscription, their business value and the cost. Enable plans for workloads you run, and document plans intentionally left off.',
      classify: (sub) => {
        const subPlans = plans.filter((p) => sameId(p.subscriptionId, sub.id));
        if (subPlans.length === 0) return unknown_('No Defender for Cloud plan data was collected for this subscription.');
        const free: string[] = [];
        const missing: string[] = [];
        for (const key of keyPlans) {
          const plan = subPlans.find((p) => eqi(p.name, key));
          if (plan === undefined) missing.push(planLabel(key));
          else if (!eqi(plan.pricingTier, 'Standard')) free.push(planLabel(key));
        }
        if (free.length > 0) {
          return review_(`Free tier: ${free.join(', ')}.${missing.length > 0 ? ` Not reported: ${missing.join(', ')}.` : ''}`);
        }
        if (missing.length > 0) return unknown_(`Plan state not reported for: ${missing.join(', ')}.`);
        return pass_('All key plans are on the Standard tier.');
      },
    });
  },
});

export const azDefenderSecurityContacts = defineControl({
  id: 'AZ-DEF-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Defender for Cloud sends alert notifications to a security contact',
  technology: 'azure',
  category: 'Threat detection',
  subcategory: 'Incident notification',
  description:
    'Checks that each subscription has an enabled Microsoft Defender for Cloud security contact with at least one recipient (an email address or a notified Azure role) and alert notifications turned on.',
  rationale:
    'Defender for Cloud alerts are only useful if a person sees them. Without a security contact, alerts about compromised resources or suspicious control-plane activity sit unread in the portal and incidents are discovered late, if at all.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'Every Azure subscription the collector could read.' },
  requiredEvidence: ['azure.securityContacts'],
  optionalEvidence: ['azure.subscriptions'],
  evaluation: {
    logic:
      'For each subscription: PASS when at least one security contact is explicitly enabled, has one or more email addresses or notifies Azure roles (role notifications On with roles listed), and has alert notifications configured (a minimal alert severity is set). FAIL when the subscription has no security contact, or no contact meets all three conditions. A contact whose enabled state is not reported, or a subscription missing from the evidence, cannot be evaluated and is reported for review (never PASS). A note is added when alerts are only sent for High severity.',
    parameters: {},
  },
  expectedState:
    'Every subscription has an enabled security contact with a monitored mailbox (for example a shared security mailbox) and/or the Owner role notified, with alert notifications for Medium severity and above.',
  remediation: {
    summary: 'Configure Defender for Cloud email notifications for each subscription.',
    steps: [
      'In the Azure portal open Microsoft Defender for Cloud > Environment settings and select the subscription.',
      'Select Email notifications.',
      'Enter one or more monitored email addresses (a shared security mailbox or distribution list is recommended) and/or select the roles to notify, for example Owner.',
      'Under Notification types select "Notify about alerts with the following severity (or higher)" and choose Medium (or Low).',
      'Select Save. Repeat for each subscription, or deploy the built-in Azure Policy that configures security contacts at management group scope.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Use a shared mailbox or distribution list rather than an individual so notifications survive staff changes.',
    'Defender for Cloud limits the number of alert emails per day per severity; also route alerts to your ticketing system or SIEM if you have one.',
    'Security contacts do not replace paid Defender plans; without plans few alerts are generated (see AZ-DEF-001).',
  ],
  impact: 'Recipients start receiving Defender for Cloud alert emails.',
  rollback: ['Remove the email address or turn off the notification type in Defender for Cloud > Environment settings > Email notifications.'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-DEF-002 is PASS.',
    'Create a sample alert in Defender for Cloud (Security alerts > Sample alerts) and confirm the email is received.',
  ],
  references: [AZ_REF.defenderEmailNotifications, AZ_REF.defenderIntroduction, AZ_REF.mcsb],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IR-6' },
    { framework: 'NIST-800-53r5', id: 'SI-4(5)' },
    { framework: 'MCSB', id: 'IR-2' },
  ],
  tags: ['defender-for-cloud', 'incident-response', 'alerting'],
  evaluate: (ctx) => {
    const contacts = ctx.data('azure.securityContacts');
    const subscriptions = subscriptionUniverse(
      ctx,
      contacts.map((c) => c.subscriptionId),
    );
    const highOnly: string[] = [];
    for (const entry of contacts) {
      if (entry.contacts.some((c) => c.isEnabled === true && eqi(c.alertMinimalSeverity, 'High'))) highOnly.push(entry.subscriptionId);
    }
    return aggregateVerdicts({
      items: subscriptions,
      subject: subscriptionSubject,
      noun: ['subscription', 'subscriptions'],
      requirement: 'an enabled security contact with recipients receives alert notifications',
      empty: { status: 'NOT_ASSESSED', reason: 'The evidence contains no subscriptions or security contact data.' },
      notes:
        highOnly.length > 0
          ? [`Alert notifications are limited to High severity in ${highOnly.length} subscription(s); consider Medium so more attacks are reported.`]
          : [],
      classify: (sub) => {
        const entry = contacts.find((c) => sameId(c.subscriptionId, sub.id));
        if (entry === undefined) return unknown_('Security contact configuration was not collected for this subscription.');
        if (entry.contacts.length === 0) return fail_('No security contact is configured.');
        const hasRecipients = (c: (typeof entry.contacts)[number]) =>
          c.emailCount > 0 || (eqi(c.notifyRolesState, 'On') && c.notifyRoles.length > 0);
        const alerts = (c: (typeof entry.contacts)[number]) => c.alertMinimalSeverity !== null && c.alertMinimalSeverity.trim() !== '';
        const good = entry.contacts.find((c) => c.isEnabled === true && hasRecipients(c) && alerts(c));
        if (good !== undefined) {
          return pass_(`Contact "${good.name}" notifies ${good.emailCount} email address(es)${good.notifyRoles.length > 0 ? ` and roles ${good.notifyRoles.join(', ')}` : ''} for alerts of severity ${good.alertMinimalSeverity ?? ''} or higher.`);
        }
        if (entry.contacts.some((c) => c.isEnabled === null && hasRecipients(c) && alerts(c))) {
          return unknown_('A contact with recipients and alert notifications exists but its enabled state was not reported.');
        }
        const problems: string[] = [];
        if (!entry.contacts.some((c) => c.isEnabled === true)) problems.push('no contact is enabled');
        if (!entry.contacts.some(hasRecipients)) problems.push('no email address or notified role');
        if (!entry.contacts.some(alerts)) problems.push('alert notifications are off');
        return fail_(`Security contact incomplete: ${problems.length > 0 ? problems.join('; ') : 'no single contact is enabled, has recipients and sends alert notifications'}.`);
      },
    });
  },
});
