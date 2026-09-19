// Bundled fictional sample evidence (fabrikam). Generated from fixtures/assessments/fabrikam; see ../samples.ts.
const files = import.meta.glob<string>('../../../../../fixtures/assessments/fabrikam/**/*.json', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const PREFIX = '../../../../../fixtures/assessments/fabrikam/';
export default files;
