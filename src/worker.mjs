import {getAddress,verifyMessage,Interface} from 'ethers';
const erc20=new Interface(['function decimals() view returns(uint8)','function balanceOf(address) view returns(uint256)']);
const gst='0x382f5DfE9eE6e309D1B9D622735e789aFde6BADe';
const encoder=new TextEncoder();
const b64=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=v=>Uint8Array.from(atob(v.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
const html=v=>new Response(v,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
const escape=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sensitive=/^(cookie|set-cookie|authorization|proxy-authorization|.*(?:token|secret|api[-_]?key).*)$/i;
export function safeHeaders(headers){return [...headers].map(([k,v])=>`${k}: ${sensitive.test(k)?'[redacted]':v}`).join('\r\n');}
async function key(secret){return crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);}
export async function issueSession(address,secret,now=Math.floor(Date.now()/1000)){
  const claims={fresh:false,iat:now,jti:crypto.randomUUID(),type:'access',identity:address,nbf:now,csrf:crypto.randomUUID(),exp:now+900};
  const input=b64(encoder.encode(JSON.stringify({alg:'HS256',typ:'JWT'})))+'.'+b64(encoder.encode(JSON.stringify(claims)));
  return {token:input+'.'+b64(await crypto.subtle.sign('HMAC',await key(secret),encoder.encode(input))),csrf:claims.csrf};
}
export async function readSession(value,secret,now=Math.floor(Date.now()/1000)){
  try{
    if(!value||value.length>4096)return null;
    const [head,body,sig,...extra]=value.split('.');if(extra.length||!sig)return null;
    const header=JSON.parse(new TextDecoder().decode(unb64(head)));if(header.alg!=='HS256'||header.typ!=='JWT')return null;
    if(!await crypto.subtle.verify('HMAC',await key(secret),unb64(sig),encoder.encode(head+'.'+body)))return null;
    const claims=JSON.parse(new TextDecoder().decode(unb64(body)));
    if(claims.type!=='access'||!Number.isInteger(claims.exp)||!Number.isInteger(claims.nbf)||claims.exp<=now||claims.nbf>now)return null;
    return getAddress(claims.identity);
  }catch{return null;}
}
async function boundedJson(request){
  const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0;const chunks=[];
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>8192){await reader.cancel();throw Error('Too large');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder().decode(bytes));
}
function cookie(request,name){return request.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1);}
async function call(env,method,args=[]){
  if(!env.RPC_URL)throw Error('RPC unavailable');
  const response=await fetch(env.RPC_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_call',params:[{to:gst,data:erc20.encodeFunctionData(method,args)},'latest']}),signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw Error('RPC unavailable');const value=await response.json();if(value.error||typeof value.result!=='string')throw Error('Invalid RPC result');
  return erc20.decodeFunctionResult(method,value.result)[0];
}
export default{async fetch(request,env){
  const path=new URL(request.url).pathname;
  if(path==='/login'){
    if(request.method!=='POST')return json({error:'Method Not Allowed'},405);
    if(!env.SESSION_SECRET)return json({error:'Login temporarily unavailable'},503);
    try{
      const input=await boundedJson(request);if(!Array.isArray(input)||input.length!==2)return json({login:false},400);
      const address=getAddress(input[0]),now=Math.floor(Date.now()/1000),bucket=now-now%600;
      if(verifyMessage(`Signing in to ${env.AUTH_DOMAIN} at ${bucket}`,input[1])!==address)return json({login:false},401);
      const session=await issueSession(address,env.SESSION_SECRET,now),response=json({login:true});
      response.headers.append('Set-Cookie',`access_token_cookie=${session.token}; Path=/; Secure; HttpOnly; SameSite=Lax`);
      response.headers.append('Set-Cookie',`csrf_access_token=${session.csrf}; Path=/; Secure; SameSite=Lax`);return response;
    }catch{return json({login:false},401);}
  }
  if(!['GET','HEAD'].includes(request.method))return json({error:'Method Not Allowed'},405);
  if(path==='/cG9vcAo.gif'){
    if(request.method==='GET'&&env.READ_ONLY!=='true'){
      const ip=request.headers.get('CF-Connecting-IP')||request.headers.get('X-Forwarded-For')||'';
      try{
        for(let attempt=0;;attempt++){
          try{await env.DB.prepare('INSERT INTO hits(time,ipaddr,headers) VALUES(?,?,?)').bind(new Date().toISOString(),ip,safeHeaders(request.headers)).run();break;}
          catch(error){if(attempt>=3||!String(error.message).includes('UNIQUE constraint failed: hits.time'))throw error;}
        }
      }
      catch{console.error('Tracking insert failed');}
    }
    const response=await env.ASSETS.fetch(new Request(new URL('/static/clowntown.gif',request.url),{method:request.method}));
    const headers=new Headers(response.headers);headers.set('Cache-Control','no-store');if(env.READ_ONLY==='true')headers.set('X-Tracking-Read-Only','true');return new Response(response.body,{status:response.status,headers});
  }
  if(path==='/track'){
    const {results}=await env.DB.prepare('SELECT time,ipaddr,headers FROM hits ORDER BY time DESC LIMIT 100').all();
    const rows=results.map(h=>`<tr><td><a href="https://who.is/whois-ip/ip-address/${encodeURIComponent(h.ipaddr??'')}">${escape(h.ipaddr)}</a><br>${escape(h.time)}</td><td><pre>${escape((h.headers??'').split(/\r?\n/).map(line=>sensitive.test(line.split(':')[0])?line.split(':')[0]+': [redacted]':line).join('\n'))}</pre></td></tr>`).join('\n');
    return html(`<!DOCTYPE html><html><title>Hello there.</title><body><h2>list of clowns:</h2>${env.READ_ONLY==='true'?'<p>Tracking is temporarily read-only during migration.</p>':''}<table>${rows}</table></body></html>`);
  }
  if(path==='/secret'){
    const address=env.SESSION_SECRET&&await readSession(cookie(request,'access_token_cookie'),env.SESSION_SECRET);if(!address)return json({msg:'Missing or invalid access token'},401);
    try{
      const [decimals,raw]=await Promise.all([call(env,'decimals'),call(env,'balanceOf',[address])]);
      return html('HELLO '+address+' '+(raw>100n*10n**BigInt(decimals)?"The Galaxy is on Orion's Belt":'You need more than 100 GST to view this message.'));
    }catch{return json({error:'Token verification temporarily unavailable'},503);}
  }
  return env.ASSETS.fetch(request);
}};
