import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fastifyStatic from '@fastify/static';
import { Pool } from 'pg';
import { PowerShellExchangeRunner } from './collector/index.js';
import { loadConfig } from './config.js';
import { buildServer } from './server.js';
import { PostgresStore } from './store.js';
import { startWorker } from './worker.js';

const config=loadConfig();
// The Exchange Online runner exists only when the connector is enabled and a PowerShell path is configured.
const exchangeRunner=config.connectors.exchange&&config.exchangePwshPath!==null?new PowerShellExchangeRunner({pwshPath:config.exchangePwshPath}):undefined;
const pool=new Pool({connectionString:config.databaseUrl,max:5,connectionTimeoutMillis:10000,idleTimeoutMillis:30000,
  ssl: {rejectUnauthorized:true}});
pool.on('error',()=>console.error('Database connection error.'));
const store=new PostgresStore(pool);
await store.initialize();
const app=await buildServer({config,store,...(exchangeRunner?{exchangeRunner}:{})});
app.addHook('onSend',async(request,reply,payload)=>{
  if(!request.url.includes('/report.html')) reply.header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'");
  return payload;
});
await app.register(fastifyStatic,{root:path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../web/dist-online'),dotfiles:'deny',index:['index.html']});
// The product domain serves a public introduction; authentication stays on PUBLIC_URL.
app.get('/', async (request, reply) => {
  const productHost = request.hostname === 'adminsecops.com' || request.hostname === 'www.adminsecops.com';
  return reply.sendFile(productHost ? 'product.html' : 'index.html');
});
const stopWorker=startWorker(store,config,exchangeRunner);
await app.listen({host:'0.0.0.0',port:config.port});
console.log('AdminSecOps control plane started.');
let stopping=false;
async function stop():Promise<void>{
  if(stopping) return;
  stopping=true;
  await app.close();
  await stopWorker();
  await pool.end();
}
process.on('SIGTERM',()=>{void stop();});
process.on('SIGINT',()=>{void stop();});
