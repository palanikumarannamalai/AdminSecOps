import type { ControlDefinition } from '../../define.js';
import { hybridBlockHardMatch, hybridBlockSoftMatch, hybridPasswordProtectionEnforced, hybridSyncRecent } from './directory-sync.js';

export const HYBRID_CONTROLS: readonly ControlDefinition[] = [
  hybridBlockHardMatch,
  hybridBlockSoftMatch,
  hybridSyncRecent,
  hybridPasswordProtectionEnforced,
];
