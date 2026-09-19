import type { ControlDefinition } from '../../define.js';
import { winCredentialGuard, winLsaProtection, winNtlmv2Only, winWdigestDisabled } from './credentials.js';
import { winFirewallEnabled, winRdpNla, winSmb1Disabled, winSmbSigning } from './network.js';
import { winDefenderRealTime, winOsSupported, winPowerShellScriptBlockLogging } from './protection.js';

export const WINDOWS_CONTROLS: readonly ControlDefinition[] = [
  winSmb1Disabled,
  winSmbSigning,
  winFirewallEnabled,
  winRdpNla,
  winLsaProtection,
  winWdigestDisabled,
  winNtlmv2Only,
  winPowerShellScriptBlockLogging,
  winDefenderRealTime,
  winCredentialGuard,
  winOsSupported,
];
