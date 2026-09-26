import { daysSince, windowsLifecycleStatus, type LifecycleStatus } from '@adminsecops/inventory';
import type { DatasetData } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notApplicable, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';
import { computerObject, qualifiedName, type AdComputer } from './shared.js';

type DomainController = DatasetData<'ad.domainControllers'>[number];

const DAY_MS = 24 * 60 * 60 * 1000;

function isWindows(computer: AdComputer): boolean {
  return /windows/i.test(computer.operatingSystem ?? '');
}

function lastLogonDetail(computer: AdComputer, at: Date): string {
  const days = daysSince(computer.lastLogonTimestamp, at);
  return days === null ? 'last logon unknown' : `last logon about ${days} days ago`;
}

/** Days from the assessment date until end of support (negative when already past). */
function daysUntil(status: LifecycleStatus, at: Date): number {
  return Math.floor((Date.parse(`${status.endOfSupport}T23:59:59Z`) - at.getTime()) / DAY_MS);
}

const ESU_NOTE =
  'Extended Security Updates (ESU) are not visible in directory data. A system covered by a paid or Azure-provided ESU programme still receives security updates; confirm coverage and record an exception for it.';

export const adLapsCoverage = defineControl({
  id: 'AD-CMP-001',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'LAPS manages the local administrator password on Windows computers',
  technology: 'ad',
  category: 'Computer security',
  subcategory: 'Local administrator passwords',
  description:
    'Checks that every enabled Windows computer that is not a domain controller has a Windows LAPS or legacy Microsoft LAPS password expiration time in Active Directory, which shows its local administrator password is managed and rotated.',
  rationale:
    'When local administrator accounts share the same password across computers, compromising one machine gives an attacker administrator access to all of them (pass-the-hash and credential reuse). LAPS sets a unique, random, regularly rotated password on each computer and stores it in Active Directory with access control. Microsoft Defender for Identity reports computers not protected by LAPS.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Enabled domain-joined Windows computers other than domain controllers.' },
  requiredEvidence: ['ad.computers'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Scope: enabled computers with isDomainController = false whose operatingSystem contains "Windows". A computer is managed when windowsLapsExpiration (msLAPS-PasswordExpirationTime) or legacyLapsExpiration (ms-Mcs-AdmPwdExpirationTime) is present; these expiration attributes are readable by authenticated users, so an empty value only shows missing AD backup evidence; hybrid devices may use Microsoft Entra ID. REVIEW when any in-scope computer lacks AD expiration evidence. REVIEW when all are managed but the latest expiration time of some computers is more than expiredGraceDays in the past (password not rotated, often because the device is offline or LAPS is failing). PASS otherwise. NOT_APPLICABLE when there are no in-scope computers. Computers without an operating system value are excluded and noted.',
    parameters: { expiredGraceDays: 30 },
  },
  expectedState: 'Every enabled domain-joined Windows computer other than domain controllers has its local administrator password managed by Windows LAPS (or legacy LAPS during migration).',
  remediation: {
    summary: 'Deploy Windows LAPS through Group Policy or Intune to every Windows computer, backing up passwords to Active Directory, and restrict who can read them.',
    steps: [
      'Update the Active Directory schema for Windows LAPS once per forest (Update-LapsADSchema) and grant computers permission to update their own password attributes on their OUs (Set-LapsADComputerSelfPermission).',
      'Create or edit a GPO linked to the workstation and member server OUs: Computer Configuration > Policies > Administrative Templates > System > LAPS. Enable "Configure password backup directory" = Active Directory, and set password complexity, length (for example 15+) and age (for example 30 days).',
      'Restrict who can read passwords (Set-LapsADReadPasswordPermission) to the help desk or tier groups that need them; do not grant broad read access.',
      'For devices still using legacy Microsoft LAPS, migrate to Windows LAPS (built into supported Windows versions) and retire the legacy client-side extension.',
      'Investigate computers in the finding that stay unmanaged: GPO not applied, device offline, or not a Windows device despite its OS string.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin (schema update requires Schema Admins). AdminSecOps never runs this.',
      'Update-LapsADSchema',
      "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=contoso,DC=com'",
      "Set-LapsADReadPasswordPermission -Identity 'OU=Workstations,DC=contoso,DC=com' -AllowedPrincipals 'CONTOSO\\Workstation Admins'",
      '# Check a computer (reads metadata only when run without password read rights):',
      "Get-LapsADPassword -Identity PC001 -AsPlainText:$false",
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Computers that back up their LAPS password to Microsoft Entra ID instead of Active Directory have no expiration time in AD and require review here; confirm backup and rotation in the Entra admin center.',
    'Scripts or tools that relied on a shared local administrator password stop working once LAPS rotates it; move them to domain accounts with scoped rights.',
    'Windows LAPS is built into Windows 10/11 and Windows Server 2019 and later with the April 2023 updates; older supported systems need legacy LAPS or an upgrade.',
    'Protect who can read LAPS passwords as carefully as administrator group membership.',
  ],
  impact: 'Each computer gets a unique local administrator password that changes automatically. Help desk staff retrieve passwords from AD when needed.',
  rollback: ['Unlink or disable the LAPS GPO. The last password set by LAPS remains in place on each computer until changed manually.'],
  validation: [
    "Run Get-ADComputer -Filter * -Properties msLAPS-PasswordExpirationTime,ms-Mcs-AdmPwdExpirationTime and confirm every Windows computer has a value.",
    'Re-run the AdminSecOps Active Directory collector and confirm AD-CMP-001 is PASS.',
  ],
  references: [AD_REF.lapsOverview, AD_REF.mdiLaps, AD_REF.attackPassTheHash],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1550.002' },
  ],
  tags: ['laps', 'local-administrator', 'lateral-movement', 'active-directory'],
  evaluate: (ctx) => {
    const grace = ctx.num('expiredGraceDays');
    const computers = ctx.data('ad.computers');
    const enabledMembers = computers.filter((c) => c.enabled && !c.isDomainController);
    const unknownOs = enabledMembers.filter((c) => c.operatingSystem === null).length;
    const inScope = enabledMembers.filter(isWindows);
    const notes = unknownOs > 0 ? [`${plural(unknownOs, 'enabled computer')} have no operating system value and were not evaluated (often never-joined or non-Windows objects).`] : [];
    if (inScope.length === 0) {
      return notApplicable({
        reason: 'There are no enabled Windows computers other than domain controllers in the collected domains.',
        summary: `${plural(computers.length, 'computer account')} collected.`,
        notes,
      });
    }
    const unmanaged = inScope.filter((c) => c.windowsLapsExpiration === null && c.legacyLapsExpiration === null);
    const expired = inScope
      .filter((c) => !unmanaged.includes(c))
      .map((c) => {
        const ages = [c.windowsLapsExpiration, c.legacyLapsExpiration].map((t) => daysSince(t, ctx.assessedAt)).filter((d): d is number => d !== null);
        return { computer: c, overdue: Math.min(...ages) };
      })
      .filter((e) => e.overdue > grace);
    const windowsLaps = inScope.filter((c) => c.windowsLapsExpiration !== null).length;
    const legacyOnly = inScope.filter((c) => c.windowsLapsExpiration === null && c.legacyLapsExpiration !== null).length;
    const facts = [
      fact('Enabled Windows computers (excluding DCs)', inScope.length),
      fact('Managed by Windows LAPS', windowsLaps),
      fact('Managed by legacy LAPS only', legacyOnly),
      fact('Without AD-backed LAPS expiration evidence', unmanaged.length),
      fact(`LAPS expiration more than ${grace} days overdue`, expired.length),
    ];
    if (legacyOnly > 0) {
      notes.push(`${plural(legacyOnly, 'computer')} still use legacy Microsoft LAPS only; plan migration to Windows LAPS, which supports password encryption and history.`);
    }
    const expiredObjects = expired.map((e) => computerObject(e.computer, `LAPS password expired about ${e.overdue} days ago; ${lastLogonDetail(e.computer, ctx.assessedAt)}`));
    if (unmanaged.length > 0) {
      const pct = Math.round((unmanaged.length / inScope.length) * 100);
      return review({
        reason: `${plural(unmanaged.length, 'Windows computer')} (${pct}% of ${inScope.length}) have no AD-backed LAPS expiration evidence; verify whether hybrid devices back up to Microsoft Entra ID before concluding they are unmanaged.`,
        summary: `LAPS coverage could not be confirmed from AD in ${[...new Set(unmanaged.map((c) => c.domain))].join(', ')}.`,
        facts,
        affectedObjects: [
          ...unmanaged.map((c) => computerObject(c, `No LAPS password expiration time; ${c.operatingSystem ?? 'OS unknown'}; ${lastLogonDetail(c, ctx.assessedAt)}`)),
          ...expiredObjects,
        ],
        notes,
      });
    }
    if (expired.length > 0) {
      return review({
        reason: `Every Windows computer has LAPS, but the password of ${plural(expired.length, 'computer')} expired more than ${grace} days ago and was not rotated.`,
        summary: 'Some LAPS-managed computers are not rotating their password (offline devices or LAPS processing errors).',
        facts,
        affectedObjects: expiredObjects,
        notes,
      });
    }
    return pass({
      reason: 'Every enabled Windows computer other than domain controllers has a current LAPS-managed local administrator password.',
      summary: `${plural(inScope.length, 'computer')} managed by LAPS.`,
      facts,
      notes,
    });
  },
});

export const adUnsupportedComputers = defineControl({
  id: 'AD-CMP-002',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'No enabled computers run unsupported Windows versions',
  technology: 'ad',
  category: 'Computer security',
  subcategory: 'Operating system lifecycle',
  description:
    'Uses the operating system name recorded on each enabled computer account (other than domain controllers, see AD-DC-004) to find Windows versions that were past end of support on the assessment date.',
  rationale:
    'Unsupported Windows versions no longer receive security updates, so newly discovered vulnerabilities stay exploitable forever. Such systems are commonly used for initial access and lateral movement, and often force weaker domain-wide settings (for example NTLMv1, SMBv1 or RC4) to keep them working.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Enabled domain-joined computers other than domain controllers.' },
  requiredEvidence: ['ad.computers'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each enabled computer with isDomainController = false, the operatingSystem string is matched against the AdminSecOps Windows lifecycle table (end of extended support for servers, end of servicing for clients). FAIL when any computer runs a version whose end-of-support date is before the assessment date (ctx.assessedAt). Computers whose OS is not in the table (for example Windows 11, LTSC editions, non-Windows) produce REVIEW because support is unknown. PASS only when every in-scope computer matches a supported version. Extended Security Updates are not modelled.',
    parameters: {},
  },
  expectedState: 'All enabled computers run Windows versions that are within Microsoft support on the assessment date.',
  remediation: {
    summary: 'Upgrade or replace computers running unsupported Windows versions; isolate those that cannot be replaced yet and confirm any ESU coverage.',
    steps: [
      'Confirm each listed computer still exists and is used (check the last logon detail). Disable and remove stale computer accounts.',
      'Plan in-place upgrades or replacements to a supported Windows version; for servers, migrate the workload to a supported Windows Server version.',
      'If a system cannot be upgraded yet, enrol it in Extended Security Updates where available, restrict its network access to the minimum required, and document the exception with an end date.',
      'After replacement, delete the old computer account.',
    ],
    scriptExample: [
      '# Read-only inventory query; review the output. AdminSecOps never runs this.',
      "Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem,LastLogonDate | Group-Object OperatingSystem | Sort-Object Count -Descending | Select-Object Count, Name",
    ].join('\n'),
    effort: 'high',
  },
  implementationConsiderations: [
    'The operating system value is written by the computer itself and may be outdated for machines that have not contacted a domain controller recently.',
    ESU_NOTE,
    'Legacy line-of-business applications are the usual blocker; engage application owners early and consider virtualisation or application compatibility options.',
  ],
  impact: 'Upgrades require maintenance windows and application testing.',
  rollback: ['Not applicable: upgrades are rolled back with the system\'s own backup or recovery procedures.'],
  validation: [
    'Re-run the AdminSecOps Active Directory collector and confirm AD-CMP-002 is PASS.',
  ],
  references: [AD_REF.lifecycleFaqWindows, AD_REF.attackRemoteServices],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SA-22' },
    { framework: 'NIST-800-53r5', id: 'SI-2' },
    { framework: 'MCSB', id: 'PV-6' },
    { framework: 'MITRE-ATTACK', id: 'T1210' },
  ],
  tags: ['lifecycle', 'patching', 'unsupported-software', 'active-directory'],
  evaluate: (ctx) => {
    const computers = ctx.data('ad.computers').filter((c) => c.enabled && !c.isDomainController);
    const statuses = computers.map((c) => ({ computer: c, status: windowsLifecycleStatus(c.operatingSystem, ctx.assessedAt) }));
    const unsupported = statuses.filter((s): s is { computer: AdComputer; status: LifecycleStatus } => s.status?.unsupported === true);
    const unknown = statuses.filter((s) => s.status === undefined).length;
    const byProduct = new Map<string, number>();
    for (const s of unsupported) byProduct.set(s.status.product, (byProduct.get(s.status.product) ?? 0) + 1);
    const facts = [
      fact('Enabled computers evaluated (excluding DCs)', computers.length),
      fact('Unsupported on the assessment date', unsupported.length),
      fact('Operating system not in the lifecycle table', unknown),
    ];
    const notes = [
      ...(unknown > 0
        ? [`${plural(unknown, 'computer')} run an operating system that AdminSecOps does not track (for example Windows 11 releases, LTSC editions or non-Windows systems); check their support status separately.`]
        : []),
      ...(unsupported.length > 0 ? [ESU_NOTE] : []),
    ];
    if (computers.length === 0) {
      return notApplicable({ reason: 'There are no enabled computers other than domain controllers.', summary: 'No member computers to evaluate.' });
    }
    if (unsupported.length > 0) {
      return fail({
        reason: `${plural(unsupported.length, 'enabled computer')} run a Windows version that is past end of support.`,
        summary: [...byProduct.entries()].map(([product, count]) => `${product}: ${count}`).join('; '),
        facts,
        affectedObjects: unsupported.map((s) =>
          computerObject(s.computer, `${s.computer.operatingSystem ?? ''}: support ended ${s.status.endOfSupport}; ${lastLogonDetail(s.computer, ctx.assessedAt)}`),
        ),
        notes,
      });
    }
    if (unknown > 0) {
      return review({
        reason: `Support status could not be determined for ${plural(unknown, 'enabled computer')} from directory metadata.`,
        summary: 'Unknown releases, editions and non-Windows products need separate lifecycle evidence.',
        facts,
        affectedObjects: statuses.filter((s) => s.status === undefined).map((s) => computerObject(s.computer, `Support status unknown: ${s.computer.operatingSystem ?? 'OS not reported'}`)),
        notes,
      });
    }
    return pass({
      reason: 'No enabled computer runs a Windows version that is past end of support.',
      summary: `${plural(computers.length, 'computer')} checked against the lifecycle table.`,
      facts,
      notes,
    });
  },
});

function dcObject(dc: DomainController, detail: string) {
  return affected('adDomainController', dc.hostName, qualifiedName(dc.domain, dc.hostName), detail);
}

export const adUnsupportedDomainControllers = defineControl({
  id: 'AD-DC-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Domain controllers run supported Windows Server versions',
  technology: 'ad',
  category: 'Domain controllers',
  subcategory: 'Operating system lifecycle',
  description:
    'Checks the operating system of every domain controller against Microsoft end-of-support dates on the assessment date, and warns about domain controllers that reach end of support soon.',
  rationale:
    'Domain controllers hold every credential in the domain. A domain controller without security updates exposes the whole forest to vulnerabilities that will never be fixed, and old domain controllers also block raising the functional level and adopting newer protections.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every domain controller in the collected domains.' },
  requiredEvidence: ['ad.domainControllers'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Each domain controller operatingSystem is matched against the AdminSecOps Windows lifecycle table. FAIL when any domain controller runs a version whose end of extended support is before the assessment date. REVIEW when the operating system is missing or not recognised. PASS otherwise; domain controllers reaching end of support within warningDays are noted.',
    parameters: { warningDays: 180 },
  },
  expectedState: 'All domain controllers run Windows Server versions within extended support on the assessment date.',
  remediation: {
    summary: 'Promote new domain controllers on a supported Windows Server version, transfer roles, and demote the unsupported ones.',
    steps: [
      'Deploy new servers with a supported Windows Server version and promote them as domain controllers (Install-ADDSDomainController) in the same sites.',
      'Transfer FSMO roles from unsupported domain controllers if they hold any (Move-ADDirectoryServerOperationMasterRole).',
      'Update DNS server settings, DHCP options and any application configurations that reference the old domain controllers by name or IP.',
      'Demote the unsupported domain controllers (Uninstall-ADDSDomainController) and clean up their metadata.',
      'Raise the domain functional level afterwards (see AD-DOM-003).',
    ],
    scriptExample: [
      '# Read-only inventory; review the output. AdminSecOps never runs this.',
      'Get-ADDomainController -Filter * | Select-Object HostName, Site, OperatingSystem, OperationMasterRoles',
    ].join('\n'),
    effort: 'high',
  },
  implementationConsiderations: [
    'Check that SYSVOL uses DFSR before introducing Windows Server 2019 or later domain controllers.',
    'Keep at least two healthy domain controllers per domain during the migration.',
    ESU_NOTE,
  ],
  impact: 'Planned server replacements; clients follow DNS-based domain controller location automatically.',
  rollback: ['Keep the old domain controller online until the new ones are verified; re-transfer FSMO roles back if needed.'],
  validation: [
    'Run Get-ADDomainController -Filter * | Select HostName, OperatingSystem and confirm only supported versions remain.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-DC-004 is PASS.',
  ],
  references: [AD_REF.lifecycleFaqWindows, AD_REF.functionalLevels, AD_REF.attackRemoteServices],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SA-22' },
    { framework: 'NIST-800-53r5', id: 'SI-2' },
    { framework: 'MCSB', id: 'PV-6' },
    { framework: 'MITRE-ATTACK', id: 'T1210' },
  ],
  tags: ['domain-controllers', 'lifecycle', 'unsupported-software', 'active-directory'],
  evaluate: (ctx) => {
    const warningDays = ctx.num('warningDays');
    const dcs = ctx.data('ad.domainControllers');
    if (dcs.length === 0) {
      return notAssessed({ reason: 'The domain controller dataset contains no domain controllers.', summary: 'No domain controllers were returned by the collector.' });
    }
    const statuses = dcs.map((dc) => ({ dc, status: windowsLifecycleStatus(dc.operatingSystem, ctx.assessedAt) }));
    const unsupported = statuses.filter((s): s is { dc: DomainController; status: LifecycleStatus } => s.status?.unsupported === true);
    const unknown = statuses.filter((s) => s.status === undefined);
    const soon = statuses.filter(
      (s): s is { dc: DomainController; status: LifecycleStatus } =>
        s.status !== undefined && !s.status.unsupported && daysUntil(s.status, ctx.assessedAt) <= warningDays,
    );
    const facts = [
      fact('Domain controllers', dcs.length),
      fact('Unsupported', unsupported.length),
      fact('Operating system not recognised', unknown.length),
      fact(`Reaching end of support within ${warningDays} days`, soon.length),
    ];
    const notes = soon.map(
      (s) => `${s.dc.hostName} (${s.status.product}) reaches end of support on ${s.status.endOfSupport}; plan its replacement now.`,
    );
    const affectedObjects = [
      ...unsupported.map((s) => dcObject(s.dc, `${s.dc.operatingSystem ?? ''}: support ended ${s.status.endOfSupport}`)),
      ...unknown.map((s) => dcObject(s.dc, `Operating system not recognised: ${s.dc.operatingSystem ?? 'not reported'}`)),
    ];
    if (unsupported.length > 0) {
      return fail({
        reason: `${plural(unsupported.length, 'domain controller')} run a Windows Server version that is past end of support.`,
        summary: unsupported.map((s) => `${s.dc.hostName}: ${s.status.product}`).join('; '),
        facts,
        affectedObjects,
        notes: [...notes, ESU_NOTE],
      });
    }
    if (unknown.length > 0) {
      return review({
        reason: `The operating system of ${plural(unknown.length, 'domain controller')} could not be matched to a supported version.`,
        summary: 'Support status of some domain controllers could not be determined.',
        facts,
        affectedObjects,
        notes,
      });
    }
    return pass({
      reason: 'Every domain controller runs a supported Windows Server version.',
      summary: dcs.map((dc) => `${dc.hostName}: ${dc.operatingSystem ?? ''}`).join('; '),
      facts,
      notes,
    });
  },
});
