import type { ControlDefinition } from '../../define.js';
import { entraCaBlockLegacyAuth, entraCaMfaAdmins, entraCaMfaAllUsers } from './conditional-access.js';

export const ENTRA_CONTROLS: readonly ControlDefinition[] = [entraCaMfaAllUsers, entraCaMfaAdmins, entraCaBlockLegacyAuth];
