import { allowsInternetInboundToPort, isInternetSource, portExpressionIncludes, ruleSources, rulePorts } from '@adminsecops/inventory';
import type { DatasetData, NsgRule } from '@adminsecops/schemas';
import { defineControl, type ControlDefinition } from '../../define.js';
import { fact } from '../../helpers.js';
import { aggregateVerdicts, fail_, pass_ } from '../shared/verdicts.js';
import { resourceSubject } from './common.js';
import { AZ_REF } from './references.js';

type Nsg = DatasetData<'azure.networkSecurityGroups'>[number];

function protocolIncludesTcp(rule: NsgRule): boolean {
  return ['*', 'tcp', 'any'].includes(rule.protocol.trim().toLowerCase());
}

/**
 * An internet-sourced inbound Deny rule with a higher priority (lower number) that
 * covers the port and TCP makes a later Allow rule ineffective for internet sources.
 */
function shadowedByDeny(nsg: Nsg, allow: NsgRule, port: number): NsgRule | undefined {
  return nsg.securityRules.find(
    (r) =>
      r.direction.toLowerCase() === 'inbound' &&
      r.access.toLowerCase() === 'deny' &&
      r.priority < allow.priority &&
      protocolIncludesTcp(r) &&
      ruleSources(r).some(isInternetSource) &&
      rulePorts(r).some((p) => portExpressionIncludes(p, port)),
  );
}

export interface ExposureFinding {
  rule: NsgRule;
  shadowedBy?: NsgRule;
}

/** Inbound Allow rules that admit internet traffic to the port, with any higher-priority Deny that shadows them. */
export function internetExposureRules(nsg: Nsg, port: number): ExposureFinding[] {
  return nsg.securityRules
    .filter((r) => allowsInternetInboundToPort(r, port))
    .map((rule) => {
      const shadowedBy = shadowedByDeny(nsg, rule, port);
      return shadowedBy === undefined ? { rule } : { rule, shadowedBy };
    });
}

function describeRule(rule: NsgRule): string {
  return `"${rule.name}" (priority ${rule.priority}, source ${ruleSources(rule).join(',')}, ports ${rulePorts(rule).join(',')})`;
}

interface ExposureControlInput {
  id: string;
  service: 'RDP' | 'SSH';
  port: number;
  attack: typeof AZ_REF.attackRdp;
  attackId: string;
}

function managementPortControl(input: ExposureControlInput): ControlDefinition {
  const { service, port } = input;
  return defineControl({
    id: input.id,
    version: '1.0.0',
    lifecycle: 'stable',
    title: `Network security groups do not allow ${service} (port ${port}) from the internet`,
    technology: 'azure',
    category: 'Network security',
    subcategory: 'Network security groups',
    description: `Checks that no network security group has an inbound Allow rule that admits ${service} (TCP ${port}) from any internet source ("*", "Internet", "Any", 0.0.0.0/0 or ::/0), including port ranges and wildcards that contain port ${port}.`,
    rationale: `${service} exposed to the internet is continuously scanned and attacked with password guessing and exploits for remote-access vulnerabilities. It is one of the most common initial access paths into Azure virtual machines. Administrative access should go through Azure Bastion, just-in-time VM access, a VPN or a private connection instead.`,
    severity: 'high',
    confidence: 'high',
    applicability: { description: 'All Azure network security groups (custom rules; default rules are excluded by the collector).' },
    requiredEvidence: ['azure.networkSecurityGroups'],
    optionalEvidence: [],
    evaluation: {
      logic: `For each NSG the control finds inbound Allow rules with protocol TCP, "*" or Any, a source prefix that means the whole internet ("*", "Internet", "Any", 0.0.0.0/0, 0.0.0.0 or ::/0 in sourceAddressPrefix or sourceAddressPrefixes) and a destination port expression that includes ${port} ("${port}", "*" or a range such as "3000-4000"). A rule is ignored when an inbound Deny rule with a higher priority (lower number) from an internet source covers the same port. FAIL when any NSG has an effective rule. PASS otherwise. NSG association (subnet/NIC) and public IP presence are not evaluated, so an affected NSG may currently be unattached - it is still reported because attaching it would expose ${service}.`,
      parameters: { port },
    },
    expectedState: `No NSG allows inbound ${service} from the internet; ${service} is reachable only through Azure Bastion, just-in-time access, VPN or from specific trusted address ranges.`,
    remediation: {
      summary: `Remove or restrict the NSG rules that allow ${service} from the internet and provide administrative access through Azure Bastion or just-in-time VM access.`,
      steps: [
        `Decide how administrators will reach the virtual machines: Azure Bastion (no public ${service} exposure), Defender for Cloud just-in-time VM access (opens ${service} only on request, for a limited time and source IP) or a VPN.`,
        'In the Azure portal open Network security groups > (NSG) > Inbound security rules.',
        `For each rule listed in the finding either delete it or change Source to the specific public IP ranges of your administrators (never Any/Internet).`,
        'Save and confirm administrators can still connect through the chosen method.',
        'Assign the built-in Azure Policy / Defender for Cloud recommendation for management ports so new exposures are flagged.',
      ],
      scriptExample: `# Review only: list inbound Allow rules from internet sources; check DestinationPortRange for ${port}, * or ranges (Az PowerShell)\nGet-AzNetworkSecurityGroup | ForEach-Object {\n  $nsg = $_\n  $nsg.SecurityRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' -and\n    ($_.SourceAddressPrefix -contains '*' -or $_.SourceAddressPrefix -contains 'Internet' -or $_.SourceAddressPrefix -contains '0.0.0.0/0') } |\n    Select-Object @{n='Nsg';e={$nsg.Name}}, Name, Priority, DestinationPortRange\n}\n# Remove after review:\n# Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "<rule>" | Set-AzNetworkSecurityGroup`,
      effort: 'medium',
    },
    implementationConsiderations: [
      `Removing the rule immediately blocks internet ${service} connections; make sure an alternative access path works first.`,
      'Just-in-time access requires Defender for Servers Plan 2; Azure Bastion has an hourly cost per deployment.',
      'Also check Azure Firewall DNAT rules and load balancer inbound NAT rules, which are not covered by this control.',
      'Rules with source "VirtualNetwork" or private ranges are not reported; they are only safe if on-premises networks connected over VPN are trusted.',
    ],
    impact: `${service} connections from the internet to resources behind the NSG are blocked.`,
    rollback: ['Re-create the inbound rule in the NSG with the previous settings (priority, source, port).'],
    validation: [
      `Re-run the AdminSecOps Azure collector and confirm ${input.id} is PASS.`,
      'In Defender for Cloud confirm the recommendation "Management ports should be closed on your virtual machines" is healthy.',
    ],
    references: [AZ_REF.nsgOverview, AZ_REF.justInTimeAccess, AZ_REF.bastionOverview, input.attack, AZ_REF.attackBruteForce],
    frameworkMappings: [
      { framework: 'NIST-800-53r5', id: 'SC-7' },
      { framework: 'NIST-800-53r5', id: 'AC-17' },
      { framework: 'MCSB', id: 'NS-1' },
      { framework: 'MITRE-ATTACK', id: 'T1133' },
      { framework: 'MITRE-ATTACK', id: input.attackId },
      { framework: 'MITRE-ATTACK', id: 'T1110' },
    ],
    tags: ['network', 'internet-exposure', service.toLowerCase(), 'management-ports'],
    evaluate: (ctx) => {
      const nsgs = ctx.data('azure.networkSecurityGroups');
      const configuredPort = ctx.num('port');
      const shadowNotes: string[] = [];
      const findings = new Map(nsgs.map((nsg) => [nsg.id, internetExposureRules(nsg, configuredPort)] as const));
      for (const nsg of nsgs) {
        for (const f of findings.get(nsg.id) ?? []) {
          if (f.shadowedBy !== undefined) {
            shadowNotes.push(
              `NSG "${nsg.name}": rule ${describeRule(f.rule)} would allow ${service} from the internet but is overridden by higher-priority Deny rule "${f.shadowedBy.name}". Remove the redundant Allow rule so a future change to the Deny rule does not expose ${service}.`,
            );
          }
        }
      }
      return aggregateVerdicts({
        items: nsgs,
        subject: (nsg) => resourceSubject('networkSecurityGroup', nsg),
        noun: ['network security group', 'network security groups'],
        requirement: `no inbound rule allows ${service} (TCP ${configuredPort}) from the internet`,
        empty: { status: 'NOT_APPLICABLE', reason: 'No network security groups were found in the assessed subscriptions.' },
        extraFacts: [fact('Port evaluated', configuredPort)],
        notes: shadowNotes,
        classify: (nsg) => {
          const effective = (findings.get(nsg.id) ?? []).filter((f) => f.shadowedBy === undefined);
          if (effective.length === 0) return pass_(`No effective rule allows ${service} from the internet.`);
          return fail_(`Allows ${service} from the internet via ${effective.map((f) => describeRule(f.rule)).join('; ')} (subscription ${nsg.subscriptionId}, resource group ${nsg.resourceGroup}).`);
        },
      });
    },
  });
}

export const azNsgNoInternetRdp = managementPortControl({
  id: 'AZ-NET-001',
  service: 'RDP',
  port: 3389,
  attack: AZ_REF.attackRdp,
  attackId: 'T1021.001',
});

export const azNsgNoInternetSsh = managementPortControl({
  id: 'AZ-NET-002',
  service: 'SSH',
  port: 22,
  attack: AZ_REF.attackSsh,
  attackId: 'T1021.004',
});
