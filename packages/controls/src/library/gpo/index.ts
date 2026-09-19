import type { ControlDefinition } from '../../define.js';
import { gpoUnusedObjects } from './hygiene.js';
import { gpoNoPreferencePasswords } from './passwords.js';
import { gpoLanManagerAuthLevel, gpoNoWdigest } from './security-options.js';

export const GPO_CONTROLS: readonly ControlDefinition[] = [gpoNoPreferencePasswords, gpoUnusedObjects, gpoLanManagerAuthLevel, gpoNoWdigest];
