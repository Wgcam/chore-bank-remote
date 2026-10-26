import test from 'node:test';
import assert from 'node:assert/strict';
import {validateRequest,decodeChunk} from '../src/protocol.js';
test('allowlist excludes device administration and URL tricks',()=>{
 for(const path of ['/api/wifi','/api/remote/credentials','/api/ota/install','/api/restore','/api/archive','/api/parents','https://evil.test','/api/state?x=1','/api/../api/state'])assert.equal(validateRequest({method:'POST',path,body:'{}'}),false);
 assert.ok(validateRequest({method:'GET',path:'/api/state',token:'a'.repeat(48)}));
 assert.ok(validateRequest({method:'POST',path:'/api/transaction',body:'{"amount":10}'}));
 assert.equal(validateRequest({method:'POST',path:'/api/login',body:JSON.stringify({password:'x'.repeat(1024)})}),false);
 assert.equal(validateRequest({method:'GET',path:'/api/state',token:'\r\nHost: evil'}),false);
 assert.equal(validateRequest({method:'POST',path:'/api/login',body:'null'}),false);
});
test('response chunks bounded, canonical base64 and UTF8 bytes',()=>{
 const input=Buffer.from('José: €');assert.deepEqual(Buffer.from(decodeChunk(input.toString('base64'))),input);
 for(const value of ['','!!','AAA',Buffer.alloc(769).toString('base64')])assert.throws(()=>decodeChunk(value));
});

test('child editing cannot bypass local-only archiving or reinstatement',()=>{
 const child={id:1,name:'Alex',goal:'Toy',goalUnit:'credits',goalCredits:100,goalCents:0,opening:0};
 const valid=body=>validateRequest({method:'POST',path:'/api/child',body:JSON.stringify(body)});
 assert.equal(valid(child),true);
 assert.equal(valid({...child,active:false}),false);
 assert.equal(valid({...child,active:true}),false);
 assert.equal(valid({...child,unknown:'future field'}),false);
});
