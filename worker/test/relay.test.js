import test from 'node:test';
import assert from 'node:assert/strict';
import {Miniflare} from 'miniflare';
import {fileURLToPath} from 'node:url';

test('actual Worker and Durable Object: auth, websocket, chunking, busy, local-only, disconnect',async()=>{
 const origin='https://portal.example.test';
 const deviceKey='test-device-only-'.repeat(3),portalKey='test-portal-only-'.repeat(3);
 const mf=new Miniflare({modules:true,modulesRules:[{type:"ESModule",include:["**/*.js"]}],scriptPath:fileURLToPath(new URL('../src/index.js',import.meta.url)),compatibilityDate:'2026-07-01',bindings:{APP_ORIGIN:origin,DEVICE_SECRET:deviceKey,PORTAL_KEY:portalKey,SESSION_SECRET:'test-session-only-'.repeat(3)},durableObjects:{BANK:{className:'BankRelay',useSQLite:true}}});
 const fetch=(path,options={})=>mf.dispatchFetch(origin+path,options);
 let socket;
 try{
  assert.equal((await fetch('/api/connection')).status,401);
  assert.equal((await fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://evil.test'},body:JSON.stringify({key:portalKey})})).status,403);
  const login=await fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({key:portalKey})});
  assert.equal(login.status,200);const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.match(login.headers.get('set-cookie'),/HttpOnly; Secure; SameSite=Strict/);
  const proxy=data=>fetch('/api/bank',{method:'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json'},body:JSON.stringify(data)});
  assert.equal((await proxy({method:'GET',path:'/api/state'})).status,503);
  assert.equal((await fetch('/device',{headers:{Upgrade:'websocket',Authorization:'Bearer wrong'}})).status,401);
  const connected=await fetch('/device',{headers:{Upgrade:'websocket',Authorization:'Bearer '+deviceKey}});
  assert.equal(connected.status,101);socket=connected.webSocket;socket.accept();
  const incoming=[];let notify;socket.addEventListener('message',event=>{incoming.push(event.data);notify?.();});
  async function next(){if(!incoming.length)await new Promise(r=>notify=r);notify=null;return incoming.shift();}
  socket.send('ping');assert.equal(await next(),'pong');
  assert.deepEqual(await (await fetch('/api/connection',{headers:{Cookie:cookie}})).json(),{online:true});
  assert.equal((await proxy({method:'POST',path:'/api/wifi',body:'{}'})).status,400);
  const waiting=proxy({method:'GET',path:'/api/state',token:'a'.repeat(48)});const req=JSON.parse(await next());
  assert.equal(req.type,'request');assert.equal(req.path,'/api/state');
  assert.equal((await proxy({method:'GET',path:'/api/status'})).status,409);
  socket.send(JSON.stringify({type:'start',id:req.id,status:200}));
  const body=JSON.stringify({name:'José',bank:{transactions:[]}});
  socket.send(JSON.stringify({type:'chunk',id:req.id,data:Buffer.from(body).toString('base64')}));socket.send(JSON.stringify({type:'end',id:req.id}));
  assert.equal(await (await waiting).text(),body);
  const pending=proxy({method:'POST',path:'/api/transaction',body:'{"amount":10}'});await next();socket.close();assert.equal((await pending).status,502);
 }finally{try{socket?.close();}catch{}await mf.dispose();}
});
