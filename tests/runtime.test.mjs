import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Wallet} from 'ethers';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {issueSession,readSession} from '../src/worker.mjs';
test('Flask-compatible identity sessions reject altered issuer, tampering and expiry',async()=>{
 const w=Wallet.createRandom(),session=await issueSession(w.address,'isolated-secret',1000);
 assert.equal(await readSession(session.token,'isolated-secret',1001),w.address);
 assert.equal(JSON.parse(Buffer.from(session.token.split('.')[1],'base64url')).identity,w.address);
 assert.equal(await readSession(session.token,'other-secret',1001),null);
 assert.equal(await readSession(session.token,'isolated-secret',1900),null);
 assert.equal(await readSession(session.token,'isolated-secret',999),null);
 const parts=session.token.split('.');parts[1]=Buffer.from(JSON.stringify({identity:Wallet.createRandom().address,type:'access',exp:9999,nbf:0})).toString('base64url');
 assert.equal(await readSession(parts.join('.'),'isolated-secret',1001),null);
});
test('real Worker preserves tracking, escapes records, redacts credentials, freezes writes and verifies wallet gates',async()=>{
 execFileSync(process.execPath,['node_modules/wrangler/bin/wrangler.js','deploy','--dry-run','--outdir','build/worker'],{stdio:'pipe'});
 const base={name:'imgshare-test',modules:true,scriptPath:'build/worker/worker.js',compatibilityDate:'2026-10-12',bindings:{AUTH_DOMAIN:'imgshare.test',SESSION_SECRET:'isolated-secret',READ_ONLY:'false',RPC_URL:'https://rpc.test'},d1Databases:{DB:'isolated-test'},assets:{directory:'build/assets',binding:'ASSETS',run_worker_first:true},outboundService:async request=>{
  assert.equal(new URL(request.url).hostname,'rpc.test');const body=await request.json();assert.equal(body.method,'eth_call');assert.equal(body.params[0].to,'0x382f5DfE9eE6e309D1B9D622735e789aFde6BADe');
  const result=body.params[0].data==='0x313ce567'?18n:100n*10n**18n+1n;
  return new Response(JSON.stringify({jsonrpc:'2.0',id:1,result:'0x'+result.toString(16).padStart(64,'0')}));
 }};
 const convert=options=>{const opts=convertV4MiniflareOptions(options);opts.workers[0].config.assets.hasUserWorker=true;return opts;};
 const mf=new Miniflare(convert(base));
 try{
  let db=await mf.getD1Database('DB');for(const sql of readFileSync('migrations/0001_tracking.sql','utf8').split(';').filter(x=>x.trim()))await db.prepare(sql).run();
  assert.equal((await mf.dispatchFetch('https://imgshare.test/')).status,200);
  const pixel=await mf.dispatchFetch('https://imgshare.test/cG9vcAo.gif',{headers:{'CF-Connecting-IP':'192.0.2.1',cookie:'secret-cookie',authorization:'secret-auth','X-Api-Key':'secret-key','X-Diagnostic':'<script>alert(1)</script>'}});
  assert.equal(pixel.status,200);assert.equal(pixel.headers.get('cache-control'),'no-store');assert.equal((await pixel.arrayBuffer()).byteLength,readFileSync('static/clowntown.gif').length);
  const stored=await db.prepare('SELECT * FROM hits').all();assert.equal(stored.results.length,1);assert.equal(stored.results[0].ipaddr,'192.0.2.1');assert.doesNotMatch(stored.results[0].headers,/secret-cookie|secret-auth|secret-key/);
  const track=await (await mf.dispatchFetch('https://imgshare.test/track')).text();assert.match(track,/192.0.2.1/);assert.match(track,/&lt;script&gt;/);assert.doesNotMatch(track,/<script>/);
  await mf.dispatchFetch('https://imgshare.test/cG9vcAo.gif',{method:'HEAD'});assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM hits').first()).n,1);
  await Promise.all(Array.from({length:4},async()=>{const response=await mf.dispatchFetch('https://imgshare.test/cG9vcAo.gif');assert.equal(response.status,200);await response.arrayBuffer();}));
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM hits').first()).n,5);
  await mf.setOptions(convert({...base,bindings:{...base.bindings,READ_ONLY:'true'}}));db=await mf.getD1Database('DB');
  const frozen=await mf.dispatchFetch('https://imgshare.test/cG9vcAo.gif');await frozen.arrayBuffer();assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM hits').first()).n,5);
  assert.equal((await mf.dispatchFetch('https://imgshare.test/secret')).status,401);
  const w=Wallet.createRandom(),other=Wallet.createRandom(),now=Math.floor(Date.now()/1000),bucket=now-now%600;
  const login=async(signature)=>mf.dispatchFetch('https://imgshare.test/login',{method:'POST',body:JSON.stringify([w.address,signature]),headers:{'Content-Type':'application/json'}});
  for(const [signer,domain,epoch] of [[other,'imgshare.test',bucket],[w,'wrong.test',bucket],[w,'imgshare.test',bucket-600]])assert.equal((await login(await signer.signMessage(`Signing in to ${domain} at ${epoch}`))).status,401);
  const accepted=await login(await w.signMessage(`Signing in to imgshare.test at ${bucket}`));assert.deepEqual(await accepted.json(),{login:true});const cookies=accepted.headers.getSetCookie();assert.equal(cookies.length,2);assert.ok(cookies[0].includes('Secure; HttpOnly; SameSite=Lax'));
  const gate=await mf.dispatchFetch('https://imgshare.test/secret',{headers:{cookie:cookies[0].split(';')[0]}});assert.equal(gate.status,200);assert.match(await gate.text(),/Galaxy is on Orion/);
  assert.equal((await mf.dispatchFetch('https://imgshare.test/missing')).status,404);
  assert.equal((await mf.dispatchFetch('https://imgshare.test/track',{method:'POST'})).status,405);
 }finally{await mf.dispose();}
});
