// Bundled fictional sample evidence (contoso). Generated from fixtures/assessments/contoso; see ../samples.ts.
const files = import.meta.glob<string>('../../../../../fixtures/assessments/contoso/**/*.json', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const PREFIX = '../../../../../fixtures/assessments/contoso/';
export default files;
