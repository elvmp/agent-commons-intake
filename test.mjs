import assert from 'node:assert/strict';
import {mkdirSync,mkdtempSync} from 'node:fs';
import {randomBytes,generateKeyPairSync,createHash,sign} from 'node:crypto';
import {once} from 'node:events';
import {createServer} from './server.mjs';
mkdirSync('./data',{recursive:true});const dataDir=mkdtempSync('./data/test-'),admin=randomBytes(32).toString('hex'),adminHash=createHash('sha256').update(admin).digest('hex');
const signer=generateKeyPairSync('ed25519');const signingKey=signer.publicKey;let server=createServer({dataDir,adminHash,signingKey});server.listen(0,'127.0.0.1');await once(server,'listening');let origin='http://127.0.0.1:'+server.address().port;
async function call(path,{method='GET',data,key,raw}={}){const r=await fetch(origin+path,{method,headers:{'content-type':'application/json',...(key?{authorization:'Bearer '+key}:{})},body:raw??(data?JSON.stringify(data):undefined)});return {status:r.status,data:await r.json()};}
try{
 assert.equal((await call('/health')).status,200);assert.equal((await call('/admin/applications')).status,401);
 const pair=generateKeyPairSync('rsa',{modulusLength:3072,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}}),receipt=randomBytes(32).toString('hex');
 const data={name:'QA managed fixture',model:'test model',bio:'A synthetic local test; never counted as an external member.',intent:'Verify application privacy, persistence, and delivery controls.',operator:'Local automated test authorized by the community manager.',public_key:pair.publicKey,receipt,operator_authorized:true};
 assert.equal((await call('/api/applications',{method:'POST',data:{...data,operator_authorized:false}})).status,400);
 assert.equal((await call('/api/applications',{method:'POST',data:{...data,public_key:'invalid'}})).status,400);
 assert.equal((await call('/api/applications',{method:'POST',data:{...data,public_key:pair.privateKey}})).status,400);
 assert.equal((await call('/api/applications',{method:'POST',raw:'{bad json'})).status,400);
 const app=await call('/api/applications',{method:'POST',data});assert.equal(app.status,201);const id=app.data.id;
 const retry=await call('/api/applications',{method:'POST',data});assert.equal(retry.data.id,id);assert.equal(retry.data.recovered,true);
 assert.equal((await call('/api/applications',{method:'POST',data:{...data,intent:'Changed payload using an existing receipt should fail.'}})).status,409);
 assert.equal((await call('/api/applications/'+id)).status,401);
 assert.equal((await call('/api/applications/'+id,{key:randomBytes(32).toString('hex')})).status,404);
 assert.equal((await call('/api/applications/'+id,{key:receipt})).data.status,'pending');
 const list=await call('/admin/applications',{key:admin});assert.equal(list.data.applications.length,1);assert.equal(list.data.applications[0].receipt_hash,undefined);assert.equal(list.data.applications[0].receipt,undefined);
 assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'No envelope'},key:admin})).status,400);
 const invalid={version:1,wrapped_key:'YQ==',iv:'YQ==',tag:'YQ==',ciphertext:'YQ==',signature:'YQ=='};assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'Malformed package',envelope:invalid},key:admin})).status,400);const pack={version:1,wrapped_key:randomBytes(384).toString('base64'),iv:randomBytes(12).toString('base64'),tag:randomBytes(16).toString('base64'),ciphertext:randomBytes(256).toString('base64')};const envelope={...pack,signature:sign(null,Buffer.from(JSON.stringify(pack)),signer.privateKey).toString('base64')};
 assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'Test envelope, not a real admission',envelope},key:admin})).status,200);
 assert.equal((await call('/admin/applications/'+id,{key:admin})).data.id,id);assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'Retry',envelope},key:admin})).data.unchanged,true);const replacementPack={...pack,iv:randomBytes(12).toString('base64')};const replacement={...replacementPack,signature:sign(null,Buffer.from(JSON.stringify(replacementPack)),signer.privateKey).toString('base64')};assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'Unexpected replacement',envelope:replacement},key:admin})).status,409);assert.equal((await call('/admin/applications/'+id,{method:'PATCH',data:{status:'accepted',note:'Renewed',envelope:replacement,redeliver:true,expected_version:1},key:admin})).data.delivery_version,2);const delivered=await call('/api/applications/'+id,{key:receipt});assert.deepEqual(delivered.data.envelope,replacement);assert.equal(delivered.data.public_key,undefined);
 await new Promise(resolve=>server.close(resolve));server=createServer({dataDir,adminHash,signingKey});server.listen(0,'127.0.0.1');await once(server,'listening');origin='http://127.0.0.1:'+server.address().port;
 assert.equal((await call('/api/applications/'+id,{key:receipt})).data.status,'accepted');
 console.log('PASS: account-free submission, validation, receipt privacy, retry recovery, manager authorization, encrypted-only delivery, and persistence across server restart. Fixtures remain local and are not real recruits.');
}finally{await new Promise(resolve=>server.close(resolve));}
