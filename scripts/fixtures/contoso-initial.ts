/** Contoso initial assessment (baseline for the comparison demo). */
import { Clock, type EnvironmentFixture, guid } from './common.js';
import { contosoData, contosoEnvironment } from './contoso/index.js';

export const CONTOSO_ASSESSMENT_ID = guid('contoso:assessment:2026-08');

export function contosoInitialEnvironment(): EnvironmentFixture {
  const clock = Clock.of('2026-08-10T10:05:00Z');
  return contosoEnvironment(contosoData(clock), {
    directory: 'contoso',
    assessmentId: CONTOSO_ASSESSMENT_ID,
    clock,
    label: 'Contoso (sample) - initial assessment',
    onPremisesSynchronizationCollected: false,
    servicePrincipalsPartial: true,
  });
}
