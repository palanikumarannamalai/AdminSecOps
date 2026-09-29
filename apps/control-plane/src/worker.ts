import { randomUUID } from 'node:crypto';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine';
import { createAuth, decryptTokens } from './auth.js';
import { collectOnline, type ExchangeRunner } from './collector/index.js';
import { isApprovedUser, type Config } from './config.js';
import { resolveJobConnectors } from './connectors.js';
import type { PostgresStore } from './store.js';
import { UsageCounters, failureCode, type FailureCode } from './usage.js';

export async function processNext(store:PostgresStore,config:Config,exchangeRunner?:ExchangeRunner,usage=new UsageCounters(store,config.usage)):Promise<boolean> {
  const job=await store.claim();
  if(!job) return false;
  const consented=config.usage.counting&&await store.hasUsageConsent(job.tenantId);
  let stage:FailureCode='NOT_APPROVED';
  try {
    if(!isApprovedUser(config,job.tenantId,job.userId)) throw new Error('Tenant user is no longer approved');
    stage='CONSENT_OR_TOKEN';
    const auth=createAuth(config);
    // The Graph authorization (and its one-hour role verification) gates every connector.
    const tokens=await auth.refresh(decryptTokens(job.encryptedTokens,config.tokenEncryptionKey),job.tenantId);
    const connectors=await resolveJobConnectors(auth,config,job,exchangeRunner);
    stage='COLLECTION_FAILED';
    const bundle=await collectOnline({...(job.modules ? {modules:job.modules}:{}),onProgress:(dataset,status)=>store.progress(job,dataset,status),tenantId:job.tenantId,assessmentId:randomUUID(),accessToken:tokens.accessToken,...(tokens.scopes?{grantedScopes:tokens.scopes}:{}),azure:connectors.azure,exchange:connectors.exchange,signal:AbortSignal.timeout(600_000)});
    const result=runAssessment(bundle,CONTROL_LIBRARY);
    stage='UNKNOWN';
    await store.complete(job,result);
    if(consented) void usage.completed(result,job.tenantId);
  } catch(error) {
    if(await store.fail(job,'Assessment could not finish. Check Microsoft consent and sign in again before retrying.')&&consented) void usage.failed(failureCode(stage,error),1,job.tenantId);
  }
  return true;
}
export function startWorker(store:PostgresStore,config:Config,exchangeRunner?:ExchangeRunner):()=>Promise<void> {
  let stopping=false;
  const usage=new UsageCounters(store,config.usage);
  let wake: (()=>void)|undefined;
  const done=(async()=>{
    while(!stopping) {
      try {
        await store.cleanup(config.usage.retentionDays);
        if(await processNext(store,config,exchangeRunner,usage)) continue;
      } catch { console.error('Worker operation failed; retrying.'); }
      await new Promise<void>(resolve=>{ const timer=setTimeout(resolve,3000); wake=()=>{clearTimeout(timer);resolve();}; });
    }
  })();
  return async()=>{stopping=true;wake?.();await done;};
}
