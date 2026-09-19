import type { ControlDefinition } from '../../define.js';
import { azDefenderPlans, azDefenderSecurityContacts } from './defender.js';
import { azKeyVaultPurgeProtection, azKeyVaultRbac } from './key-vault.js';
import { azActivityLogExport } from './logging.js';
import { azNsgNoInternetRdp, azNsgNoInternetSsh } from './network.js';
import { azRbacGuestPrivileged, azRbacOwnerCount } from './rbac.js';
import { azStorageMinimumTls, azStorageNoAnonymousBlob, azStorageSecureTransfer } from './storage.js';

export const AZURE_CONTROLS: readonly ControlDefinition[] = [
  azRbacOwnerCount,
  azRbacGuestPrivileged,
  azDefenderPlans,
  azDefenderSecurityContacts,
  azStorageNoAnonymousBlob,
  azStorageSecureTransfer,
  azStorageMinimumTls,
  azKeyVaultPurgeProtection,
  azKeyVaultRbac,
  azNsgNoInternetRdp,
  azNsgNoInternetSsh,
  azActivityLogExport,
];
