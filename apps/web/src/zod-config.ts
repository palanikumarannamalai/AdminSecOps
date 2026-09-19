import { z } from 'zod';

/*
 * Imported first by main.tsx, before any schema module is evaluated.
 *
 * Zod otherwise probes `new Function` to decide whether it may compile faster parsers. The
 * application's Content-Security-Policy has no 'unsafe-eval', and browsers report that probe
 * as a policy violation even though Zod catches it. Validation results are identical; only
 * the JIT fast path is skipped.
 */
z.config({ jitless: true });
