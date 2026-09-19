import type { SampleInfo, SampleName } from './types';

/*
 * Fictional sample evidence packages, bundled at build time from fixtures/assessments/.
 * Each sample is one lazily loaded JavaScript chunk containing the raw JSON text exactly as
 * committed, so the manifest SHA-256 hashes verify in the browser like a real package.
 * Loading a sample fetches only that static chunk of the application itself.
 */
type SampleModule = { default: Record<string, string>; PREFIX: string };

const modules: Record<SampleName, () => Promise<SampleModule>> = {
  contoso: () => import('./sample-data/contoso'),
  'contoso-followup': () => import('./sample-data/contoso-followup'),
  fabrikam: () => import('./sample-data/fabrikam'),
};

export const SAMPLES: readonly SampleInfo[] = [
  {
    name: 'contoso',
    title: 'Contoso (fictional sample)',
    description:
      'Fictional hybrid organisation: Microsoft 365, Entra ID, Intune, Azure, Active Directory, AD CS, Group Policy and a Windows server, with a realistic mix of issues.',
  },
  {
    name: 'fabrikam',
    title: 'Fabrikam (fictional sample)',
    description: 'Fictional on-premises organisation assessed with the Active Directory, AD CS, Group Policy and Windows modules only.',
  },
  {
    name: 'contoso-followup',
    title: 'Contoso follow-up (fictional sample)',
    description: 'The same fictional tenant 30 days later after partial remediation. Load it with Contoso to try Compare.',
  },
];

/** Package files (path -> bytes) of a bundled sample. */
export async function loadSampleFiles(name: SampleName): Promise<Map<string, Uint8Array>> {
  const module = await modules[name]();
  const encoder = new TextEncoder();
  const files = new Map<string, Uint8Array>();
  for (const [key, text] of Object.entries(module.default)) {
    files.set(key.slice(module.PREFIX.length), encoder.encode(text));
  }
  return files;
}
