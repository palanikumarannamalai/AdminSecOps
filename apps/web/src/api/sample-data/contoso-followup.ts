// Bundled fictional sample evidence (contoso-followup). Generated from fixtures/assessments/contoso-followup; see ../samples.ts.
const files = import.meta.glob<string>('../../../../../fixtures/assessments/contoso-followup/**/*.json', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const PREFIX = '../../../../../fixtures/assessments/contoso-followup/';
export default files;
