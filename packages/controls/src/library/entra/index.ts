import type { ControlDefinition } from '../../define.js';
import { entraAppSecretLifetime, entraControlPlaneAppPermissions, entraDataAccessAppPermissions } from './applications.js';
import { entraMembersRegisteredForMfa, entraWeakMethodsDisabled } from './authentication-methods.js';
import { entraCaBlockLegacyAuth, entraCaMfaAdmins, entraCaMfaAllUsers } from './conditional-access.js';
import {
  entraCaBlockDeviceCode,
  entraCaPhishingResistantAdmins,
  entraCaSignInRisk,
  entraCaUserRisk,
} from './conditional-access-advanced.js';
import {
  entraGlobalAdminMaximum,
  entraGlobalAdminMinimum,
  entraPrivilegedCloudOnly,
  entraPrivilegedMfaRegistered,
  entraPrivilegedNoPermanent,
} from './privileged-roles.js';
import {
  entraGuestAccessRestricted,
  entraGuestInvitesRestricted,
  entraStaleGuests,
  entraUserConsentRestricted,
  entraUsersCannotCreateTenants,
  entraUsersCannotRegisterApps,
} from './tenant-settings.js';

export const ENTRA_CONTROLS: readonly ControlDefinition[] = [
  entraCaMfaAllUsers,
  entraCaMfaAdmins,
  entraCaBlockLegacyAuth,
  entraCaPhishingResistantAdmins,
  entraCaBlockDeviceCode,
  entraCaSignInRisk,
  entraCaUserRisk,
  entraGlobalAdminMaximum,
  entraGlobalAdminMinimum,
  entraPrivilegedCloudOnly,
  entraPrivilegedNoPermanent,
  entraPrivilegedMfaRegistered,
  entraMembersRegisteredForMfa,
  entraWeakMethodsDisabled,
  entraUsersCannotRegisterApps,
  entraUserConsentRestricted,
  entraAppSecretLifetime,
  entraControlPlaneAppPermissions,
  entraDataAccessAppPermissions,
  entraGuestAccessRestricted,
  entraGuestInvitesRestricted,
  entraStaleGuests,
  entraUsersCannotCreateTenants,
];
