import type { ControlDefinition } from '../../define.js';
import {
  intuneNoPolicyNoncompliant,
  intunePlatformCoverage,
  intuneWindowsBitLocker,
} from './compliance.js';
import { intuneCaRequireCompliantDevice } from './conditional-access.js';

export const INTUNE_CONTROLS: readonly ControlDefinition[] = [
  intuneNoPolicyNoncompliant,
  intunePlatformCoverage,
  intuneWindowsBitLocker,
  intuneCaRequireCompliantDevice,
];
