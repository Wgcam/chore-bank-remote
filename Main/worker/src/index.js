import {encoder,validateRequest,decodeChunk} from './protocol.js';

const cookieName='__Host-cb_remote';
const ttl=4*60*60;
function json(value,status=200,headers={}) {return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});}
function error(message,status){return json({error:message},status);}
function hex(bytes){return Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');}
async function hmac(secret,text){const key=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',key,encoder.encode(text)));}
async function equal(a,b){const [x,y]=await Promise.all([crypto.subtle.digest('SHA-256',encoder.encode(a)),crypto.subtle.digest('SHA-256',encoder.encode(b))]);const p=new Uint8Array(x),q=new Uint8Array(y);let d=0;for(let i=0;i<32;i++)d|=p[i]^q[i];return d===0;}
function configured(env){try{return new URL(env.APP_ORIGIN).origin===env.APP_ORIGIN && env.APP_ORIGIN.startsWith('https://') && ['DEVICE_SECRET','PORTAL_KEY','SESSION_SECRET'].every(k=>typeof env[k]==='string'&&env[k].length>=32&&env[k].length<=256) && new Set([env.DEVICE_SECRET,env.PORTAL_KEY,env.SESSION_SECRET]).size===3;}catch{return false;}}
async function readJson(request,max){if(Number(request.headers.get('Content-Length'))>max)throw new Error('large');if(!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json'))throw new Error('format');const reader=request.body?.getReader();if(!reader)throw new Error('body');let n=0,parts=[];try{for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>max)throw new Error('large');parts.push(value);}}catch(e){await reader.cancel();throw e;}const bytes=new Uint8Array(n);let p=0;for(const part of parts){bytes.set(part,p);p+=part.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
async function session(request,env){const raw=request.headers.get('Cookie')||'';const match=raw.split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='));if(!match)return false;const token=match.slice(cookieName.length+1);if(!/^\d{10}\.[a-f0-9]{32}\.[a-f0-9]{64}$/.test(token))return false;const [exp,nonce,sig]=token.split('.'),now=Math.floor(Date.now()/1000);if(+exp<=now||+exp>now+ttl+60)return false;return equal(sig,await hmac(env.SESSION_SECRET,exp+'.'+nonce));}
function stub(env){return env.BANK.get(env.BANK.idFromName('single-bank'));}
async function internal(env,path,body){return stub(env).fetch(new Request('https://internal'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));}

export default {async fetch(request,env){
 const url=new URL(request.url),path=url.pathname;
 if(!path.startsWith('/api/')&&path!=='/device')return env.ASSETS.fetch(request);
 if(!configured(env))return error('Remote service is not configured.',503);
 if(url.origin!==env.APP_ORIGIN)return error('Unrecognized service address.',403);
 try{
  if(path==='/device'){
   if(request.method!=='GET'||request.headers.get('Upgrade')?.toLowerCase()!=='websocket')return error('WebSocket required.',426);
   const auth=request.headers.get('Authorization')||'';
   if(auth.length>300||!auth.startsWith('Bearer ')||!await equal(auth.slice(7),env.DEVICE_SECRET))return error('Device authentication failed.',401);
   // The DO is private to this Worker; never forward caller-controlled internal paths.
   return stub(env).fetch(new Request('https://internal/device',{headers:{Upgrade:'websocket'}}));
  }
  const origin=request.headers.get('Origin');
  if(request.method!=='GET'&&origin!==env.APP_ORIGIN)return error('Request origin rejected.',403);
  if(path==='/api/session'&&request.method==='POST'){
   const ip=request.headers.get('CF-Connecting-IP')||'unknown';
   const bucket=await hmac(env.SESSION_SECRET,'login:'+ip);
   const allowed=await internal(env,'/rate',{bucket});if(allowed.status!==200)return error('Too many attempts. Try again later.',429);
   const data=await readJson(request,1024);
   if(typeof data.key!=='string'||data.key.length>256||!await equal(data.key,env.PORTAL_KEY))return error('Portal key is incorrect.',401);
   const payload=(Math.floor(Date.now()/1000)+ttl)+'.'+crypto.randomUUID().replaceAll('-','');
   const value=payload+'.'+await hmac(env.SESSION_SECRET,payload);
   return json({ok:true},200,{'Set-Cookie':`${cookieName}=${value}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Strict`});
  }
  if(path==='/api/session'&&request.method==='DELETE')return json({ok:true},200,{'Set-Cookie':`${cookieName}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`});
  if(!await session(request,env))return error('Sign in to the remote portal.',401);
  if(path==='/api/connection'&&request.method==='GET')return internal(env,'/connection',{});
  if(path==='/api/bank'&&request.method==='POST'){
   const data=await readJson(request,4096);if(!validateRequest(data))return error('Operation unavailable remotely or invalid request.',400);
   return internal(env,'/request',data);
  }
  return error('Not found.',404);
 }catch{return error('Request rejected. Check the format and connection.',400);}
}};

export class BankRelay {
 constructor(state,env){this.state=state;this.env=env;this.pending=null;state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping','pong'));}
 device(){const sockets=this.state.getWebSockets('device');return sockets.find(s=>s.readyState===1);}
 online(){const socket=this.device();if(!socket)return null;const seen=this.state.getWebSocketAutoResponseTimestamp(socket)?.getTime()||socket.deserializeAttachment()?.connectedAt||0;if(Date.now()-seen>90000){socket.close(1001,'Heartbeat expired');return null;}return socket;}
 async fetch(request){
  const path=new URL(request.url).pathname;
  if(path==='/device'){
   // Reject duplicate device credentials rather than silently replacing an active unit.
   if(this.online())return error('Device already connected.',409);
   const pair=new WebSocketPair();this.state.acceptWebSocket(pair[1],['device']);pair[1].serializeAttachment({connectedAt:Date.now()});
   return new Response(null,{status:101,webSocket:pair[0]});
  }
  if(path==='/rate'){
   const {bucket}=await request.json();if(!/^[a-f0-9]{64}$/.test(bucket))return error('Invalid bucket.',400);
   const window=Math.floor(Date.now()/60000);
   const allowed=await this.state.storage.transaction(async storage=>{
    let rate=await storage.get('login-rate');if(!rate||rate.window!==window)rate={window,total:0,buckets:{}};
    const count=rate.buckets[bucket]||0;if(count>=8||rate.total>=100)return false;
    rate.total++;rate.buckets[bucket]=count+1;await storage.put('login-rate',rate);return true;
   });return allowed?json({ok:true}):error('Rate limited.',429);
  }
  if(path==='/connection')return json({online:!!this.online()});
  if(path!=='/request')return error('Not found.',404);
  const data=await request.json();if(!validateRequest(data))return error('Invalid request.',400);
  if(this.pending)return error('Bank is busy. Wait for the current operation.',409);
  const socket=this.online();if(!socket)return error('Bank is offline.',503);
  const id=crypto.randomUUID().replaceAll('-',''),message=JSON.stringify({type:'request',id,...data});
  if(encoder.encode(message).length>4096)return error('Request too large.',413);
  return new Promise(resolve=>{
   const timer=setTimeout(()=>this.finish(error('Device response timed out. The operation may have completed; refresh before another change.',504)),20000);
   this.pending={id,socket,resolve,timer,status:0,chunks:[],bytes:0};
   try{socket.send(message);}catch{this.finish(error('Device disconnected. Refresh before another change.',502));}
  });
 }
 finish(response){const p=this.pending;if(!p)return;this.pending=null;clearTimeout(p.timer);p.resolve(response);}
 webSocketMessage(socket,message){
  if(typeof message!=='string'||encoder.encode(message).length>2048){socket.close(1009,'Message too large');if(this.pending?.socket===socket)this.finish(error('Invalid device response.',502));return;}
  if(message==='ping'){socket.send('pong');return;}
  const p=this.pending;if(!p||p.socket!==socket)return;
  try{
   const m=JSON.parse(message);if(m.id!==p.id)return;
   if(m.type==='start'){if(p.status||!Number.isInteger(m.status)||m.status<200||m.status>599)throw new Error();p.status=m.status;}
   else if(m.type==='chunk'){if(!p.status)throw new Error();const bytes=decodeChunk(m.data);p.bytes+=bytes.length;if(p.bytes>70000)throw new Error();p.chunks.push(bytes);}
   else if(m.type==='end'){
    if(!p.status)throw new Error();const bytes=new Uint8Array(p.bytes);let offset=0;for(const part of p.chunks){bytes.set(part,offset);offset+=part.length;}
    // All allowed APIs speak JSON. Reject incomplete/invalid responses rather than reporting success.
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);JSON.parse(text);
    this.finish(new Response(text,{status:p.status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}));
   }else if(m.type==='error')this.finish(error('Device could not complete the response. Refresh before another change.',502));else throw new Error();
  }catch{this.finish(error('Invalid device response. Refresh before another change.',502));socket.close(1008,'Invalid response');}
 }
 webSocketClose(socket){if(this.pending?.socket===socket)this.finish(error('Device disconnected. The operation may have completed; refresh before another change.',502));try{socket.close(1000,'Closed');}catch{}}
 webSocketError(socket){this.webSocketClose(socket);}
}
