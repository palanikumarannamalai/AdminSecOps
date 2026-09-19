import type { ControlDefinition } from '../../define.js';
import { adcsEsc1EnrolleeSuppliesSubject, adcsEsc2AnyPurpose, adcsEsc3EnrollmentAgent, adcsEsc4TemplateAcl } from './templates.js';

export const ADCS_CONTROLS: readonly ControlDefinition[] = [
  adcsEsc1EnrolleeSuppliesSubject,
  adcsEsc2AnyPurpose,
  adcsEsc4TemplateAcl,
  adcsEsc3EnrollmentAgent,
];
