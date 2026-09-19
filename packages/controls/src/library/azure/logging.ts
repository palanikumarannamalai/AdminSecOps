import { defineControl } from '../../define.js';
import { eqi, fact } from '../../helpers.js';
import { aggregateVerdicts, fail_, pass_, unknown_ } from '../shared/verdicts.js';
import { sameId, subscriptionSubject, subscriptionUniverse } from './common.js';
import { AZ_REF } from './references.js';

export const azActivityLogExport = defineControl({
  id: 'AZ-LOG-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Subscription activity log is exported with a diagnostic setting',
  technology: 'azure',
  category: 'Logging and monitoring',
  subcategory: 'Activity log',
  description:
    'Checks that each subscription has a diagnostic setting that sends the Azure activity log - at least the Administrative and Security categories - to a Log Analytics workspace, storage account or event hub.',
  rationale:
    'The activity log records who created, changed or deleted Azure resources and role assignments, and Defender for Cloud security events. Azure keeps it for only 90 days and it cannot be queried together with other logs unless it is exported. Without an export, investigations into older or complex incidents lack the most important control-plane evidence.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Azure subscription the collector could read.' },
  requiredEvidence: ['azure.activityLogDiagnostics'],
  optionalEvidence: ['azure.subscriptions'],
  evaluation: {
    logic:
      'For each subscription (from the dataset plus active subscriptions in azure.subscriptions when available) the control takes the subscription diagnostic settings that have at least one destination (workspace, storage account or event hub) and unions their enabled log categories. PASS when every category in requiredCategories (default Administrative, Security) is exported. FAIL when no diagnostic setting with a destination exists or a required category is missing. A subscription absent from the evidence cannot be evaluated and is reported for review (never PASS).',
    parameters: { requiredCategories: 'Administrative,Security' },
  },
  expectedState:
    'Every subscription exports all activity log categories (at least Administrative and Security, preferably also Policy, Alert and ServiceHealth) to a Log Analytics workspace with retention that meets your investigation needs.',
  remediation: {
    summary: 'Create a subscription diagnostic setting that sends the activity log to a Log Analytics workspace (or storage account for long-term retention).',
    steps: [
      'Create or choose a Log Analytics workspace (or storage account) for security logs, ideally in a dedicated management subscription.',
      'In the Azure portal open Monitor > Activity log > Export Activity Logs, and select the subscription.',
      'Select Add diagnostic setting, tick all categories (at minimum Administrative and Security) and choose the destination.',
      'Select Save. Repeat for each subscription, or assign the built-in Azure Policy that deploys activity log diagnostic settings at management group scope.',
    ],
    scriptExample:
      '# Example (Az PowerShell); review names and destination first\n$sub = "<subscription-id>"\n$ws  = "<log-analytics-workspace-resource-id>"\n$logs = "Administrative","Security","Policy","Alert","ServiceHealth","Recommendation","Autoscale","ResourceHealth" |\n  ForEach-Object { New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category $_ -Enabled $true }\n# New-AzSubscriptionDiagnosticSetting -SubscriptionId $sub -Name "activity-log-export" -WorkspaceId $ws -Log $logs',
    effort: 'low',
  },
  implementationConsiderations: [
    'Log Analytics ingestion of the activity log is free of ingestion charges, but retention beyond the default and data export incur cost; check current pricing.',
    'Use one workspace per organization or region where possible so investigations can correlate subscriptions.',
    'Protect the destination: restrict who can delete the workspace or storage account, and consider an immutability policy for storage.',
  ],
  impact: 'Activity log events are copied to the destination; there is no effect on workloads.',
  rollback: ['Delete the diagnostic setting in Monitor > Activity log > Export Activity Logs.'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-LOG-001 is PASS.',
    'In the workspace run the query "AzureActivity | take 10" and confirm recent events appear.',
  ],
  references: [AZ_REF.activityLog, AZ_REF.diagnosticSettings, AZ_REF.mcsb, AZ_REF.attackDisableCloudLogs],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AU-2' },
    { framework: 'NIST-800-53r5', id: 'AU-6' },
    { framework: 'NIST-800-53r5', id: 'AU-11' },
    { framework: 'MCSB', id: 'LT-3' },
    { framework: 'MCSB', id: 'LT-5' },
    { framework: 'MITRE-ATTACK', id: 'T1562.008' },
  ],
  tags: ['logging', 'activity-log', 'monitoring'],
  evaluate: (ctx) => {
    const diagnostics = ctx.data('azure.activityLogDiagnostics');
    const required = ctx
      .str('requiredCategories')
      .split(',')
      .map((c) => c.trim())
      .filter((c) => c.length > 0);
    const subscriptions = subscriptionUniverse(
      ctx,
      diagnostics.map((d) => d.subscriptionId),
    );
    return aggregateVerdicts({
      items: subscriptions,
      subject: subscriptionSubject,
      noun: ['subscription', 'subscriptions'],
      requirement: `the activity log categories ${required.join(', ')} are exported to a destination`,
      empty: { status: 'NOT_ASSESSED', reason: 'The evidence contains no subscriptions or activity log diagnostic settings data.' },
      extraFacts: [fact('Required categories (parameter)', required.join(', '))],
      classify: (sub) => {
        const entry = diagnostics.find((d) => sameId(d.subscriptionId, sub.id));
        if (entry === undefined) return unknown_('Activity log diagnostic settings were not collected for this subscription.');
        const withDestination = entry.settings.filter((s) => s.workspaceConfigured || s.storageAccountConfigured || s.eventHubConfigured);
        if (withDestination.length === 0) {
          return fail_(entry.settings.length === 0 ? 'No activity log diagnostic setting exists.' : 'Diagnostic settings exist but none has a destination.');
        }
        const enabled = withDestination.flatMap((s) => s.enabledCategories);
        const missing = required.filter((c) => !enabled.some((e) => eqi(e, c)));
        if (missing.length > 0) return fail_(`Not exported: ${missing.join(', ')} (settings: ${withDestination.map((s) => s.name).join(', ')}).`);
        return pass_(`Exported by ${withDestination.map((s) => s.name).join(', ')}.`);
      },
    });
  },
});
