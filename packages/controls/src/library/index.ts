import type { ControlDefinition } from '../define.js';
import { AD_CONTROLS } from './ad/index.js';
import { ADCS_CONTROLS } from './adcs/index.js';
import { AZURE_CONTROLS } from './azure/index.js';
import { ENTRA_CONTROLS } from './entra/index.js';
import { GPO_CONTROLS } from './gpo/index.js';
import { HYBRID_CONTROLS } from './hybrid/index.js';
import { INTUNE_CONTROLS } from './intune/index.js';
import { M365_CONTROLS } from './m365/index.js';
import { WINDOWS_CONTROLS } from './windows/index.js';

/** Version of the control library as a whole; bump when controls are added or changed. */
export const CONTROL_LIBRARY_VERSION = '0.3.0';

/** Every implemented control, validated for unique IDs at load time. */
export const CONTROL_LIBRARY: readonly ControlDefinition[] = [
  ...ENTRA_CONTROLS,
  ...HYBRID_CONTROLS,
  ...M365_CONTROLS,
  ...INTUNE_CONTROLS,
  ...AZURE_CONTROLS,
  ...AD_CONTROLS,
  ...ADCS_CONTROLS,
  ...GPO_CONTROLS,
  ...WINDOWS_CONTROLS,
];

const seen = new Set<string>();
for (const control of CONTROL_LIBRARY) {
  if (seen.has(control.metadata.id)) throw new Error(`Duplicate control ID ${control.metadata.id}`);
  seen.add(control.metadata.id);
}

export function getControl(id: string): ControlDefinition | undefined {
  return CONTROL_LIBRARY.find((c) => c.metadata.id === id);
}
