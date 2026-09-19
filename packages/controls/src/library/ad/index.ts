import type { ControlDefinition } from '../../define.js';
import { adAccountReversibleEncryption, adPasswordNotRequired } from './account-flags.js';
import { adLapsCoverage, adUnsupportedComputers, adUnsupportedDomainControllers } from './computers.js';
import { adPrivilegedNotDelegated, adUnconstrainedDelegation } from './delegation.js';
import { adDcSmbSigning, adLdapChannelBinding, adLdapSigning } from './domain-controllers.js';
import { adDomainFunctionalLevel, adExternalTrustSidFiltering, adMachineAccountQuota, adRecycleBin } from './domain.js';
import { adKrbPreauthDisabled, adKrbPrivilegedSpn, adKrbtgtPasswordAge, adKrbUserSpn } from './kerberos.js';
import { adPwdLockoutThreshold, adPwdMinimumLength, adPwdReversibleEncryption } from './password-policy.js';
import { adForestAdminGroupsEmpty, adStalePrivilegedAccounts } from './privileged-accounts.js';

export const AD_CONTROLS: readonly ControlDefinition[] = [
  adPwdMinimumLength,
  adPwdReversibleEncryption,
  adPwdLockoutThreshold,
  adKrbtgtPasswordAge,
  adKrbPreauthDisabled,
  adKrbPrivilegedSpn,
  adKrbUserSpn,
  adUnconstrainedDelegation,
  adPrivilegedNotDelegated,
  adStalePrivilegedAccounts,
  adForestAdminGroupsEmpty,
  adPasswordNotRequired,
  adAccountReversibleEncryption,
  adMachineAccountQuota,
  adRecycleBin,
  adDomainFunctionalLevel,
  adLapsCoverage,
  adUnsupportedComputers,
  adLdapSigning,
  adLdapChannelBinding,
  adDcSmbSigning,
  adUnsupportedDomainControllers,
  adExternalTrustSidFiltering,
];
