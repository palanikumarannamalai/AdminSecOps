import { randomUUID } from 'node:crypto';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine';
import { createAuth, decryptTokens } from './auth.js';
import { collectEntra } from './collector/index.js';
import type { Config } from './config.js';
import type { PostgresStore } from './store.js';

export async function processNext(store:PostgresStore, config:Config):Promise<boolean> {
  const job=await store.claim();
  if(!job) return false;
  try {
    if(job.tenantId!==config.tenantId) throw new Error('Unexpected tenant');
    const tokens=await createAuth(config).refresh(decryptTokens(job.encryptedTokens,config.tokenEncryptionKey));
    const bundle=await collectEntra({tenantId:job.tenantId,assessmentId:randomUUID(),accessToken:tokens.accessToken,signal:AbortSignal.timeout(600_000)});
    const result=runAssessment(bundle,CONTROL_LIBRARY);
    await store.complete(job,result);
  } catch {
    await store.fail(job,'Assessment could not finish. Check Microsoft consent and sign in again before retrying.');
  }
  return true;
}
export function startWorker(store:PostgresStore,config:Config):()=>Promise<void> {
  let stopping=false;
  let wake: (()=>void)|undefined;
  const done=(async()=>{
    while(!stopping) {
      try {
        await store.cleanup();
        if(await processNext(store,config)) continue;
      } catch { console.error('Worker operation failed; retrying.'); }
      await new Promise<void>(resolve=>{ const timer=setTimeout(resolve,3000); wake=()=>{clearTimeout(timer);resolve();}; });
    }
  })();
  return async()=>{stopping=true;wake?.();await done;};
}
