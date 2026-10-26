import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {Miniflare} from 'miniflare';
import {fileURLToPath} from 'node:url';

const origin='https://portal.example.test';
const secrets={DEVICE_SECRET:'test-device-only-'.repeat(3),PORTAL_KEY:'test-portal-only-'.repeat(3),SESSION_SECRET:'test-session-only-'.repeat(3)};
function fixture(overrides={}) {
 const mf=new Miniflare({modules:true,modulesRules:[{type:'ESModule',include:['**/*.js']}],scriptPath:fileURLToPath(new URL('../src/index.js',import.meta.url)),compatibilityDate:'2026-07-01',bindings:{APP_ORIGIN:origin,...secrets,...overrides},durableObjects:{BANK:{className:'BankRelay',useSQLite:true}}});
 const fetch=(path,options={})=>mf.dispatchFetch(origin+path,options);
 const session=(key=secrets.PORTAL_KEY,headers={})=>fetch('/api/session',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',...headers},body:JSON.stringify({key})});
 async function login(){const response=await session();assert.equal(response.status,200);return response.headers.get('set-cookie').split(';')[0];}
 const proxy=(cookie,data,headers={})=>fetch('/api/bank',{method:'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json',...headers},body:JSON.stringify(data)});
 async function connect(){
  const response=await fetch('/device',{headers:{Upgrade:'websocket',Authorization:'Bearer '+secrets.DEVICE_SECRET}});assert.equal(response.status,101);
  const socket=response.webSocket;socket.accept();const queue=[];let waiter;
  socket.addEventListener('message',event=>{queue.push(event.data);waiter?.();});
  const next=async()=>{if(!queue.length)await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{waiter=null;reject(new Error('No device request within 3 seconds'));},3000);waiter=()=>{clearTimeout(timer);resolve();};});waiter=null;return queue.shift();};
  const send=data=>socket.send(JSON.stringify(data));
  const reply=(id,body='{}')=>{send({type:'start',id,status:200});send({type:'chunk',id,data:Buffer.from(body).toString('base64')});send({type:'end',id});};
  return {socket,next,send,reply};
 }
 return {mf,fetch,session,login,proxy,connect};
}
function signedCookie(exp,secret=secrets.SESSION_SECRET){const payload=exp+'.'+'a'.repeat(32);return '__Host-cb_remote='+payload+'.'+createHmac('sha256',secret).update(payload).digest('hex');}

test('session signatures, expiry, origin checks, logout and bounded login attempts',async()=>{
 const f=fixture();try{
  const now=Math.floor(Date.now()/1000);
  for(const cookie of ['__Host-cb_remote=invalid',signedCookie(now-1),signedCookie(now+20000),signedCookie(now+1000,'wrong-signing-key')])assert.equal((await f.fetch('/api/connection',{headers:{Cookie:cookie}})).status,401);
  const cookie=await f.login();
  assert.equal((await f.fetch('/api/connection',{headers:{Cookie:cookie}})).status,200);
  assert.equal((await f.proxy(cookie,{method:'GET',path:'/api/status'},{Origin:'https://attacker.example'})).status,403);
  assert.equal((await f.fetch('/api/session',{method:'DELETE',headers:{Cookie:cookie}})).status,403);
  const logout=await f.fetch('/api/session',{method:'DELETE',headers:{Cookie:cookie,Origin:origin}});assert.equal(logout.status,200);assert.match(logout.headers.get('set-cookie'),/Max-Age=0/);
  assert.equal((await f.mf.dispatchFetch('https://wrong.example/api/connection',{headers:{Cookie:cookie}})).status,403);
  // A distinct IP isolates the attempt bucket from the successful login above.
  const responses=await Promise.all(Array.from({length:9},()=>f.session('wrong',{'CF-Connecting-IP':'192.0.2.44'})));
  assert.equal(responses.filter(r=>r.status===401).length,8);assert.equal(responses.filter(r=>r.status===429).length,1);
  assert.equal((await f.session(secrets.PORTAL_KEY,{'CF-Connecting-IP':'192.0.2.44'})).status,429);
 }finally{await f.mf.dispose();}
});

test('invalid configuration fails closed and large/malformed browser bodies never reach a device',async()=>{
 const bad=fixture({SESSION_SECRET:secrets.PORTAL_KEY});try{assert.equal((await bad.session()).status,503);}finally{await bad.mf.dispose();}
 const f=fixture();try{
  const cookie=await f.login();
  for(const body of ['{', 'null', JSON.stringify({method:'GET',path:'/api/status',extra:'x'}), JSON.stringify({method:'POST',path:'/api/login',body:JSON.stringify({password:'x'.repeat(1100)})}), ' '.repeat(4097)]){
   assert.equal((await f.fetch('/api/bank',{method:'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json'},body})).status,400);
  }
  assert.equal((await f.proxy(cookie,{method:'POST',path:'/api/child',body:'{"id":1,"name":"Alex","goalCredits":100,"active":false}'})).status,400);
  for(const path of ['/api/parents','/api/wifi','/api/cloud','/api/remote','/api/ota/install','/api/backup','/api/restore','/api/archive'])assert.equal((await f.proxy(cookie,{method:'POST',path,body:'{}'})).status,400);
 }finally{await f.mf.dispose();}
});

test('duplicate devices rejected; mismatched response IDs ignored; parent and transaction identifiers preserved',async()=>{
 const f=fixture();let d;try{
  const cookie=await f.login();d=await f.connect();
  assert.equal((await f.fetch('/device',{headers:{Upgrade:'websocket',Authorization:'Bearer '+secrets.DEVICE_SECRET}})).status,409);
  const body=JSON.stringify({requestId:'1'.repeat(32),expectedRevision:7,childId:2,amount:10,allowDebt:true});
  const pending=f.proxy(cookie,{method:'POST',path:'/api/transaction',token:'a'.repeat(48),body});const request=JSON.parse(await d.next());
  assert.equal(request.token,'a'.repeat(48));assert.equal(request.body,body);
  d.reply('b'.repeat(32),'{}');d.reply(request.id,'{"ok":true,"revision":8}');
  const response=await pending;assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,revision:8});
  assert.equal(response.headers.get('cache-control'),'no-store');
 }finally{try{d?.socket.close();}catch{}await f.mf.dispose();}
});

test('malformed device responses fail closed, never confirm a mutation, and enforce bounds',async()=>{
 const f=fixture();const sockets=[];try{
  const cookie=await f.login();
  const cases=[
   (d,id)=>d.send({type:'chunk',id,data:'e30='}),
   (d,id)=>{d.send({type:'start',id,status:200});d.send({type:'start',id,status:200});},
   (d,id)=>{d.send({type:'start',id,status:200});d.send({type:'chunk',id,data:'!!!!'});},
   (d,id)=>{d.send({type:'start',id,status:200});d.send({type:'chunk',id,data:Buffer.alloc(769).toString('base64')});},
   (d,id)=>{d.send({type:'start',id,status:200});d.send({type:'chunk',id,data:Buffer.from([0xff]).toString('base64')});d.send({type:'end',id});},
   (d,id)=>d.reply(id,'{"unfinished":'),
   (d,id)=>d.send({type:'start',id,status:199}),
   d=>d.socket.send('x'.repeat(2049)),
   d=>d.socket.send(new Uint8Array([1,2,3]).buffer),
   (d,id)=>{d.send({type:'start',id,status:200});for(let n=0;n<92;n++)d.send({type:'chunk',id,data:Buffer.alloc(768,32).toString('base64')});}
  ];
  for(let n=0;n<cases.length;n++){
   const d=await f.connect();sockets.push(d.socket);const pending=f.proxy(cookie,{method:'POST',path:'/api/transaction',body:'{"amount":10}'});const request=JSON.parse(await d.next());cases[n](d,request.id);
   const response=await pending;assert.equal(response.status,502,'invalid response case '+n);assert.match((await response.json()).error,/Invalid device response/);
   d.socket.close();
  }
 }finally{for(const socket of sockets)try{socket.close();}catch{}await f.mf.dispose();}
});
