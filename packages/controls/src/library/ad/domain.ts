import { functionalLevelRank } from '@adminsecops/inventory';
import type { DatasetData } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notApplicable, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';

type AdDomain = DatasetData<'ad.domains'>[number];
type AdTrust = DatasetData<'ad.trusts'>[number];

function domainObject(domain: AdDomain, detail: string) {
  return affected('adDomain', domain.distinguishedName, domain.dnsRoot, detail);
}

const NO_DOMAINS = {
  reason: 'The domain dataset was collected but contains no domains, so nothing could be evaluated.',
  summary: 'No domains were returned by the collector.',
};

export const adMachineAccountQuota = defineControl({
  id: 'AD-DOM-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Ordinary users cannot join computers to the domain (MachineAccountQuota is 0)',
  technology: 'ad',
  category: 'Domain configuration',
  subcategory: 'Computer accounts',
  description:
    'Checks that the ms-DS-MachineAccountQuota attribute of every domain is 0, so authenticated users cannot create computer accounts without delegated permission.',
  rationale:
    'By default any authenticated user can create up to 10 computer accounts in the domain. Attacker-controlled computer accounts are a common building block in privilege escalation (for example abusing resource-based constrained delegation or certificate templates enrollable by Domain Computers) and create unmanaged objects. Joining computers should be a delegated task for specific staff or provisioning accounts.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.domains'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain: FAIL when machineAccountQuota is greater than 0; REVIEW when the value could not be read (null), because the effective quota is then unknown; PASS when every domain has 0.',
    parameters: {},
  },
  expectedState: 'ms-DS-MachineAccountQuota is 0 in every domain, and computer joins are delegated to specific groups on specific OUs.',
  remediation: {
    summary: 'Delegate computer-join rights to the people and accounts that need them, then set ms-DS-MachineAccountQuota to 0 on each domain.',
    steps: [
      'Identify who joins computers today (help desk, deployment tools such as MDT/SCCM/Autopilot hybrid join connector) and create a group for them.',
      'In Active Directory Users and Computers, right-click the OU(s) for new computers > Delegate Control, and grant that group "Create Computer objects" (and the related write permissions) on the OU.',
      'Alternatively, pre-stage computer accounts and allow the specified user or group to join them.',
      'Set ms-DS-MachineAccountQuota to 0 on the domain object (ADSI Edit > domain naming context > Properties, or PowerShell below).',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin in each domain. AdminSecOps never runs this.',
      "Get-ADDomain | Get-ADObject -Properties 'ms-DS-MachineAccountQuota' | Select-Object 'ms-DS-MachineAccountQuota'",
      "Set-ADDomain -Identity contoso.com -Replace @{'ms-DS-MachineAccountQuota' = 0}",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Users and tools that join computers without delegated rights will fail with an "exceeded the maximum number of computer accounts" error; set up delegation first.',
    'Delegated join permissions on an OU are not affected by the quota.',
  ],
  impact: 'Only delegated staff and service accounts can add computers to the domain.',
  rollback: ["Restore the previous value with Set-ADDomain -Replace @{'ms-DS-MachineAccountQuota' = 10}."],
  validation: [
    "Read ms-DS-MachineAccountQuota on each domain object and confirm it is 0.",
    'Test a domain join with a delegated account and confirm it succeeds.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-DOM-001 is PASS.',
  ],
  references: [AD_REF.machineAccountQuota, AD_REF.kerberosConstrainedDelegation, AD_REF.securingActiveDirectory],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
  ],
  tags: ['domain-configuration', 'least-privilege', 'active-directory'],
  evaluate: (ctx) => {
    const domains = ctx.data('ad.domains');
    if (domains.length === 0) return notAssessed(NO_DOMAINS);
    const nonZero = domains.filter((d) => d.machineAccountQuota !== null && d.machineAccountQuota > 0);
    const unknown = domains.filter((d) => d.machineAccountQuota === null);
    const facts = [
      fact('Domains evaluated', domains.length),
      fact('Domains allowing users to create computer accounts', nonZero.length),
      fact('Domains with unknown quota', unknown.length),
    ];
    const affectedObjects = [
      ...nonZero.map((d) => domainObject(d, `ms-DS-MachineAccountQuota is ${d.machineAccountQuota}`)),
      ...unknown.map((d) => domainObject(d, 'ms-DS-MachineAccountQuota could not be read')),
    ];
    if (nonZero.length > 0) {
      return fail({
        reason: `Authenticated users can create computer accounts in ${plural(nonZero.length, 'domain')}.`,
        summary: nonZero.map((d) => `${d.dnsRoot}: ${d.machineAccountQuota}`).join('; '),
        facts,
        affectedObjects,
      });
    }
    if (unknown.length > 0) {
      return review({
        reason: `The machine account quota could not be read for ${plural(unknown.length, 'domain')}.`,
        summary: 'The effective quota is unknown for some domains.',
        facts,
        affectedObjects,
      });
    }
    return pass({
      reason: 'ms-DS-MachineAccountQuota is 0 in every domain.',
      summary: `${plural(domains.length, 'domain')} checked.`,
      facts,
    });
  },
});

export const adRecycleBin = defineControl({
  id: 'AD-DOM-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Active Directory Recycle Bin is enabled',
  technology: 'ad',
  category: 'Domain configuration',
  subcategory: 'Recovery',
  description: 'Checks that the Active Directory Recycle Bin optional feature is enabled for the forest.',
  rationale:
    'Without the Recycle Bin, a deleted user, group or OU loses most of its attributes (including group memberships), and recovery requires an authoritative restore from backup with domain controller downtime. With it enabled, deleted objects can be restored intact in minutes, which matters after both mistakes and destructive attacks.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'The collected Active Directory forest (the feature is forest-wide).' },
  requiredEvidence: ['ad.forest'],
  optionalEvidence: [],
  evaluation: {
    logic: 'PASS when ad.forest reports recycleBinEnabled = true; FAIL otherwise.',
    parameters: {},
  },
  expectedState: 'The Active Directory Recycle Bin is enabled for the forest.',
  remediation: {
    summary: 'Enable the Recycle Bin once for the forest from Active Directory Administrative Center or PowerShell.',
    steps: [
      'Confirm the forest functional level is Windows Server 2008 R2 or higher (Get-ADForest).',
      'Open Active Directory Administrative Center (dsac.exe), select the forest root domain and choose "Enable Recycle Bin" in the Tasks pane, or use the PowerShell command below.',
      'Wait for replication to all domain controllers, then refresh Active Directory Administrative Center to see the Deleted Objects container.',
    ],
    scriptExample: [
      '# Review, then run as an Enterprise Admin. AdminSecOps never runs this. Enabling cannot be undone.',
      "Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target contoso.com",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Enabling the Recycle Bin is irreversible.',
    'Objects deleted before the feature was enabled cannot be restored with it.',
    'Deleted objects are kept for the deleted object lifetime (by default equal to the tombstone lifetime, typically 180 days), which slightly increases directory database size.',
  ],
  impact: 'Deleted objects are retained with their attributes for the deleted object lifetime; no impact on users.',
  rollback: ['The feature cannot be disabled once enabled. No rollback is required because it has no user-facing effect.'],
  validation: [
    "Run Get-ADOptionalFeature -Filter \"name -eq 'Recycle Bin Feature'\" and confirm EnabledScopes is not empty.",
    'Re-run the AdminSecOps Active Directory collector and confirm AD-DOM-002 is PASS.',
  ],
  references: [AD_REF.recycleBin],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CP-10' },
  ],
  tags: ['recovery', 'domain-configuration', 'active-directory'],
  evaluate: (ctx) => {
    const forest = ctx.data('ad.forest');
    const facts = [fact('Forest', forest.name), fact('Forest functional level', forest.forestMode), fact('Recycle Bin enabled', forest.recycleBinEnabled)];
    if (forest.recycleBinEnabled) {
      return pass({ reason: 'The Active Directory Recycle Bin is enabled.', summary: `Recycle Bin enabled for forest ${forest.name}.`, facts });
    }
    return fail({
      reason: 'The Active Directory Recycle Bin is not enabled.',
      summary: `Deleted objects in forest ${forest.name} can only be recovered from backup.`,
      facts,
      affectedObjects: [affected('adForest', forest.name, forest.name, 'Recycle Bin optional feature is not enabled')],
    });
  },
});

const MINIMUM_LEVEL = 'Windows2016Domain';

export const adDomainFunctionalLevel = defineControl({
  id: 'AD-DOM-003',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'Domain functional level is Windows Server 2016 or later',
  technology: 'ad',
  category: 'Domain configuration',
  subcategory: 'Functional level',
  description: 'Checks that every domain runs at the Windows Server 2016 domain functional level or higher.',
  rationale:
    'Several security features depend on the domain functional level, for example domain controller-side Protected Users protections (2012 R2), and automatic rolling of NTLM secrets for smart-card-only accounts and Privileged Access Management features (2016). A low functional level also indicates that very old domain controllers were, or still are, present.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.domains'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain, the domainMode value (for example Windows2012R2Domain) is ranked by the inventory helper. FAIL when a domain is below Windows2016Domain; REVIEW when the value is not recognised; PASS when every domain is Windows2016Domain or higher.',
    parameters: {},
  },
  expectedState: 'Every domain is at the Windows Server 2016 domain functional level or higher.',
  remediation: {
    summary: 'Replace or upgrade domain controllers running older Windows Server versions, then raise the domain (and forest) functional level.',
    steps: [
      'List domain controllers and their operating systems (Get-ADDomainController -Filter * | Select HostName, OperatingSystem). All must run Windows Server 2016 or later.',
      'Replace older domain controllers (see AD-DC-004). Migrate SYSVOL replication from FRS to DFSR before adding Windows Server 2019 or later domain controllers; this is an OS promotion prerequisite, not a prerequisite for the Windows Server 2016 functional level itself.',
      'Raise the domain functional level in Active Directory Domains and Trusts (right-click the domain > Raise Domain Functional Level) or with PowerShell.',
      'When all domains are raised, raise the forest functional level as well.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin (domain) / Enterprise Admin (forest). AdminSecOps never runs this.',
      'Get-ADDomainController -Filter * | Select-Object HostName, OperatingSystem',
      'Set-ADDomainMode -Identity contoso.com -DomainMode Windows2016Domain',
      'Set-ADForestMode -Identity contoso.com -ForestMode Windows2016Forest',
    ].join('\n'),
    effort: 'high',
  },
  implementationConsiderations: [
    'Raising the functional level is effectively one-way in practice and prevents adding domain controllers that run older Windows Server versions.',
    'Raising to Windows Server 2012 R2 or higher changes some Kerberos behaviour for Protected Users members; review AD-PRIV-001 guidance.',
    'SYSVOL must replicate with DFSR (not FRS) before domain controllers running Windows Server 2019 or later can be added.',
  ],
  impact: 'Enables newer security features; older domain controllers can no longer join the domain.',
  rollback: [
    'Lowering the functional level is only possible in limited cases (for example from 2016 to 2012 R2 when no dependent optional features are enabled). Test in a lab first.',
  ],
  validation: [
    'Run Get-ADDomain | Select-Object DomainMode in each domain and confirm Windows2016Domain or higher.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-DOM-003 is PASS.',
  ],
  references: [AD_REF.functionalLevels, AD_REF.protectedUsers],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-6' },
  ],
  tags: ['domain-configuration', 'functional-level', 'active-directory'],
  evaluate: (ctx) => {
    const domains = ctx.data('ad.domains');
    if (domains.length === 0) return notAssessed(NO_DOMAINS);
    const required = functionalLevelRank(MINIMUM_LEVEL);
    const ranked = domains.map((d) => ({ domain: d, rank: functionalLevelRank(d.domainMode) }));
    const below = ranked.filter((r) => r.rank >= 0 && r.rank < required);
    const unknown = ranked.filter((r) => r.rank < 0);
    const facts = [
      fact('Domains evaluated', domains.length),
      fact('Domains below Windows Server 2016 level', below.length),
      fact('Domains with an unrecognised level', unknown.length),
    ];
    const affectedObjects = [
      ...below.map((r) => domainObject(r.domain, `Domain functional level ${r.domain.domainMode}`)),
      ...unknown.map((r) => domainObject(r.domain, `Unrecognised domain functional level "${r.domain.domainMode}"`)),
    ];
    if (below.length > 0) {
      return fail({
        reason: `${plural(below.length, 'domain')} run below the Windows Server 2016 domain functional level.`,
        summary: below.map((r) => `${r.domain.dnsRoot}: ${r.domain.domainMode}`).join('; '),
        facts,
        affectedObjects,
      });
    }
    if (unknown.length > 0) {
      return review({
        reason: `The functional level of ${plural(unknown.length, 'domain')} was not recognised.`,
        summary: 'Some domain functional levels could not be interpreted.',
        facts,
        affectedObjects,
      });
    }
    return pass({
      reason: 'Every domain is at the Windows Server 2016 domain functional level or higher.',
      summary: domains.map((d) => `${d.dnsRoot}: ${d.domainMode}`).join('; '),
      facts,
    });
  },
});

/** Windows (non-MIT) trust types. */
const WINDOWS_TRUST_TYPES = new Set(['uplevel', 'downlevel']);
/** Directions in which the collected domain trusts the target (SID filtering is applied by the trusting side). */
const TRUSTING_DIRECTIONS = new Set(['outbound', 'bidirectional']);

function trustObject(trust: AdTrust, detail: string) {
  return affected('adTrust', `${trust.domain}->${trust.target}`, `${trust.domain} -> ${trust.target}`, detail);
}

export const adExternalTrustSidFiltering = defineControl({
  id: 'AD-TRU-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'External trusts have SID filtering (quarantine) enabled',
  technology: 'ad',
  category: 'Trusts',
  subcategory: 'SID filtering',
  description:
    'Checks that every external (non-forest, cross-forest) Windows domain trust in which a collected domain trusts another domain has SID filtering (the quarantine attribute) enabled.',
  rationale:
    'When a domain trusts an external domain, users from that domain present security identifiers (SIDs) in their authorization data. Without SID filtering, an administrator of the trusted domain (or an attacker who controls it) can add SIDs of your privileged groups to their users\' SID history and gain administrative access in your domain. SID filtering discards SIDs that do not belong to the trusted domain. A disabled filter often indicates a change made for a domain migration that was never reverted.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Domains with external Windows trusts (not forest trusts, not trusts inside the forest, not MIT realm trusts) whose direction is outbound or bidirectional from the collected domain.',
  },
  requiredEvidence: ['ad.trusts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'A trust is in scope when intraForest = false, forestTransitive = false, trustType is Uplevel or Downlevel and direction is Outbound or BiDirectional (the collected domain trusts the target). FAIL when any in-scope trust has sidFilteringQuarantined = false; PASS when all in-scope trusts are quarantined; NOT_APPLICABLE when no trust is in scope. Inbound-only external trusts are noted because filtering for them is configured in the other domain; forest trusts are not evaluated by this control.',
    parameters: {},
  },
  expectedState: 'SID filtering (quarantine) is enabled on every external trust.',
  remediation: {
    summary: 'Enable SID filtering on each listed external trust with netdom, after confirming that no SID-history-based migration still depends on it.',
    steps: [
      'Ask the owner of the trust whether a domain migration using SID history is still in progress. If migrated users still rely on SID history to reach resources, re-permission those resources with the users\' new SIDs first.',
      'On a domain controller of the trusting domain, enable quarantine for the trusted domain with netdom trust (see the script example).',
      'Test access from users of the trusted domain to resources in your domain.',
      'Review whether the trust is still required at all; remove trusts that are no longer used, and consider selective authentication for the remaining ones.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin of the trusting domain. AdminSecOps never runs this.',
      '# Show the current state:',
      'netdom trust contoso.com /domain:fabrikam.com /quarantine',
      '# Enable SID filtering (quarantine):',
      'netdom trust contoso.com /domain:fabrikam.com /quarantine:Yes',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'SID filtering breaks access that depends on SID history from the trusted domain (typical during ongoing migrations) and on universal groups of other domains; plan re-permissioning first.',
    'Do not apply quarantine to trusts inside the same forest; Microsoft states this breaks replication and forest operations.',
  ],
  impact: 'Users from the trusted domain keep access granted to their own accounts and groups, but SIDs from other domains in their token (including SID history) are ignored.',
  rollback: ['Disable filtering again with netdom trust <trusting> /domain:<trusted> /quarantine:No (only for a time-limited migration).'],
  validation: [
    'Run netdom trust <trusting domain> /domain:<trusted domain> /quarantine and confirm it reports that SID filtering is enabled, or Get-ADTrust -Filter * | Select Target, SIDFilteringQuarantined.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-TRU-001 is PASS.',
  ],
  references: [AD_REF.netdomTrust, AD_REF.mdiUnsecureSidHistory, AD_REF.attackSidHistoryInjection],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'MITRE-ATTACK', id: 'T1134.005' },
  ],
  tags: ['trusts', 'sid-filtering', 'privileged-access', 'active-directory'],
  evaluate: (ctx) => {
    const trusts = ctx.data('ad.trusts');
    const external = trusts.filter((t) => !t.intraForest && !t.forestTransitive && WINDOWS_TRUST_TYPES.has(t.trustType.toLowerCase()));
    const inScope = external.filter((t) => TRUSTING_DIRECTIONS.has(t.direction.toLowerCase()));
    const inboundOnly = external.filter((t) => !TRUSTING_DIRECTIONS.has(t.direction.toLowerCase()));
    const forestTrusts = trusts.filter((t) => !t.intraForest && t.forestTransitive).length;
    const unfiltered = inScope.filter((t) => !t.sidFilteringQuarantined);
    const facts = [
      fact('Trusts collected', trusts.length),
      fact('External trusts trusted by collected domains', inScope.length),
      fact('Without SID filtering', unfiltered.length),
      fact('Forest trusts (not evaluated)', forestTrusts),
    ];
    const notes = [
      ...(inboundOnly.length > 0
        ? [
            `${plural(inboundOnly.length, 'inbound-only external trust')} (${inboundOnly.map((t) => `${t.domain} <- ${t.target}`).join(', ')}) are configured in the other domain; ask its administrators to confirm SID filtering there.`,
          ]
        : []),
    ];
    if (inScope.length === 0) {
      return notApplicable({
        reason: 'No external Windows trusts in which a collected domain trusts another domain were found.',
        summary: `${plural(trusts.length, 'trust')} collected; none is an outbound or bidirectional external trust.`,
        facts,
        notes,
      });
    }
    if (unfiltered.length > 0) {
      return fail({
        reason: `${plural(unfiltered.length, 'external trust')} do not filter SIDs from the trusted domain.`,
        summary: unfiltered.map((t) => `${t.domain} -> ${t.target}`).join(', '),
        facts,
        affectedObjects: unfiltered.map((t) => trustObject(t, `${t.direction} ${t.trustType} external trust without SID filtering (quarantine)`)),
        notes,
      });
    }
    return pass({
      reason: 'Every external trust has SID filtering (quarantine) enabled.',
      summary: `${plural(inScope.length, 'external trust')} checked.`,
      facts,
      notes,
    });
  },
});
