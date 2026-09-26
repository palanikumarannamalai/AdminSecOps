import { randomUUID } from 'node:crypto';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine';
import { createAuth, decryptTokens } from './auth.js';
import { collectOnline, type ExchangeRunner } from './collector/index.js';
import { isApprovedUser, type Config } from './config.js';
import { resolveJobConnectors } from './connectors.js';
import type { PostgresStore } from './store.js';

export async function processNext(store:PostgresStore, config:Config, exchangeRunner?:ExchangeRunner):Promise<boolean> {
  const job=await store.claim();
  if(!job) return false;
  try {
    if(!isApprovedUser(config,job.tenantId,job.userId)) throw new Error('Tenant user is no longer approved');
    const auth=createAuth(config);
    // The Graph authorization (and its one-hour role verification) gates every connector.
    const tokens=await auth.refresh(decryptTokens(job.encryptedTokens,config.tokenEncryptionKey),job.tenantId);
    const connectors=await resolveJobConnectors(auth,config,job,exchangeRunner);
    const bundle=await collectOnline({tenantId:job.tenantId,assessmentId:randomUUID(),accessToken:tokens.accessToken,...(tokens.scopes?{grantedScopes:tokens.scopes}:{}),azure:connectors.azure,exchange:connectors.exchange,signal:AbortSignal.timeout(600_000)});
    const result=runAssessment(bundle,CONTROL_LIBRARY);
    await store.complete(job,result);
  } catch {
    await store.fail(job,'Assessment could not finish. Check Microsoft consent and sign in again before retrying.');
  }
  return true;
}
export function startWorker(store:PostgresStore,config:Config,exchangeRunner?:ExchangeRunner):()=>Promise<void> {
  let stopping=false;
  let wake: (()=>void)|undefined;
  const done=(async()=>{
    while(!stopping) {
      try {
        await store.cleanup();
        if(await processNext(store,config,exchangeRunner)) continue;
      } catch { console.error('Worker operation failed; retrying.'); }
      await new Promise<void>(resolve=>{ const timer=setTimeout(resolve,3000); wake=()=>{clearTimeout(timer);resolve();}; });
    }
  })();
  return async()=>{stopping=true;wake?.();await done;};
}
