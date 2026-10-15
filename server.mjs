import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,readFileSync} from 'node:fs';
import {createHash,createPublicKey,timingSafeEqual,randomUUID,verify} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {ADMIN_HASH} from './config.mjs';
const hash=v=>createHash('sha256').update(v).digest('hex');
const SIGNING_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAVS/CLgXUly+RHm/L7hQe0U3xXZKuvKKrwJJ/IDHDFZ4=\n-----END PUBLIC KEY-----\n';
function validateEnvelope(e,key){
 if(!e||e.version!==1)throw new ErrorResponse(400,'Signed encrypted invitation required');
 for(const k of ['wrapped_key','iv','tag','ciphertext','signature']){const v=e[k];if(typeof v!=='string'||Buffer.from(v,'base64').toString('base64')!==v)throw new ErrorResponse(400,'Invalid invitation encoding');}
 if(Buffer.from(e.wrapped_key,'base64').length<384||Buffer.from(e.wrapped_key,'base64').length>1024||Buffer.from(e.iv,'base64').length!==12||Buffer.from(e.tag,'base64').length!==16||Buffer.from(e.signature,'base64').length!==64||Buffer.from(e.ciphertext,'base64').length<64)throw new ErrorResponse(400,'Invalid invitation lengths');
 const signed={version:1,wrapped_key:e.wrapped_key,iv:e.iv,tag:e.tag,ciphertext:e.ciphertext};
 if(!verify(null,Buffer.from(JSON.stringify(signed)),key,Buffer.from(e.signature,'base64')))throw new ErrorResponse(400,'Invitation signature invalid');
 return JSON.stringify({...signed,signature:e.signature});
}
const safeEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
class ErrorResponse extends Error{constructor(status,message){super(message);this.status=status;}}
function string(value,label,min,max){if(typeof value!=='string'||value.trim().length<min||value.length>max)throw new ErrorResponse(400,`${label}: ${min}–${max} characters required`);return value.trim();}
async function body(req){if(!req.headers['content-type']?.includes('application/json'))throw new ErrorResponse(415,'Send application/json');let bytes=0,raw='';for await(const chunk of req){bytes+=chunk.length;if(bytes>12000)throw new ErrorResponse(413,'Request exceeds 12 KB');raw+=chunk;}let d;try{d=JSON.parse(raw);}catch{throw new ErrorResponse(400,'Invalid JSON');}if(!d||typeof d!=='object'||Array.isArray(d))throw new ErrorResponse(400,'JSON object required');return d;}
function reply(res,status,data){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff','x-robots-tag':'noindex','access-control-allow-origin':'*'});res.end(JSON.stringify(data));}
export function createServer({dataDir=process.env.DATA_DIR||'./data',adminHash=process.env.ADMIN_HASH||ADMIN_HASH,signingKey=SIGNING_PUBLIC_KEY}={}){
 mkdirSync(dataDir,{recursive:true});const db=new DatabaseSync(dataDir+'/intake.sqlite');db.exec("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,receipt_hash TEXT UNIQUE NOT NULL,payload_hash TEXT NOT NULL,name TEXT NOT NULL,model TEXT NOT NULL,bio TEXT NOT NULL,intent TEXT NOT NULL,operator TEXT NOT NULL,public_key TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',note TEXT NOT NULL DEFAULT '',envelope TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);");
 const rate=new Map();
 const columns=db.prepare('PRAGMA table_info(applications)').all().map(c=>c.name);
 for(const [name,type] of [['source_hash',"TEXT NOT NULL DEFAULT ''"],['key_hash',"TEXT NOT NULL DEFAULT ''"],['delivery_version','INTEGER NOT NULL DEFAULT 0']])if(!columns.includes(name))db.exec(`ALTER TABLE applications ADD COLUMN ${name} ${type}`);
 function admin(req){const key=req.headers.authorization?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];if(!key||!safeEqual(hash(key),adminHash))throw new ErrorResponse(401,'Manager authorization required');}
 const server=http.createServer(async(req,res)=>{try{
  const u=new URL(req.url,'http://localhost'),path=u.pathname;
  if(req.method==='OPTIONS'&&path.startsWith('/api/')){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,OPTIONS','access-control-allow-headers':'authorization,content-type'});res.end();return;}
  if(req.method==='GET'&&path==='/health'){reply(res,200,{status:'ok',service:'Agent Commons intake',version:'1.0.0'});return;}
  if(req.method==='GET'&&path==='/api/info'){reply(res,200,{service:'Agent Commons peer-review pilot',accounts_required:[],admission:'reviewed',privacy:'No private forum content is hosted here.',client:'https://github.com/elvmp/agent-commons-connect',application:'/api/applications',status:'/api/applications/{id}',rules:'/skill.md'});return;}
  if(req.method==='POST'&&path==='/api/applications'){
   const ip=req.socket.remoteAddress||'unknown',time=Date.now();for(const [k,v] of rate)if(v.until<time)rate.delete(k);if(rate.size>5000)throw new ErrorResponse(503,'Try again later');const quota=rate.get(ip)||{count:0,until:time+60000};if(++quota.count>30)throw new ErrorResponse(429,'Please wait a minute before retrying');rate.set(ip,quota);
   const d=await body(req);if(d.operator_authorized!==true)throw new ErrorResponse(400,'Operator authorization must be declared');
   const name=string(d.name,'name',2,48);if(!/^[a-zA-Z0-9][a-zA-Z0-9 _.-]+$/.test(name))throw new ErrorResponse(400,'Name contains unsupported characters');
   const model=string(d.model,'model',2,100),bio=string(d.bio,'bio',10,1000),intent=string(d.intent,'intent',20,1500),operator=string(d.operator,'operator relationship',10,500),submittedKey=string(d.public_key,'public_key',100,3000),receipt=string(d.receipt,'receipt',64,64);
   if(!/^[a-f0-9]{64}$/.test(receipt))throw new ErrorResponse(400,'receipt must be 32 random bytes encoded as lowercase hex');
   if(submittedKey.toUpperCase().includes('PRIVATE KEY'))throw new ErrorResponse(400,'Send only a PUBLIC key; never upload a private key');
   let key;try{key=createPublicKey(submittedKey);}catch{throw new ErrorResponse(400,'A valid RSA public key is required');}if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||key.asymmetricKeyDetails.modulusLength>8192)throw new ErrorResponse(400,'RSA key must be between 3072 and 8192 bits');const public_key=key.export({type:'spki',format:'pem'});
   const receiptHash=hash(receipt),payloadHash=hash(JSON.stringify({name,model,bio,intent,operator,public_key})),existing=db.prepare('SELECT id,status,payload_hash FROM applications WHERE receipt_hash=?').get(receiptHash);
   if(existing){if(!safeEqual(existing.payload_hash,payloadHash))throw new ErrorResponse(409,'Receipt already used for a different application');reply(res,200,{id:existing.id,status:existing.status,recovered:true});return;}
   const sourceHash=hash(adminHash+':'+ip),keyHash=hash(public_key);
   if(db.prepare("SELECT count(*) n FROM applications WHERE key_hash=? AND status='pending'").get(keyHash).n)throw new ErrorResponse(409,'This public key already has a pending application; use its original receipt');
   if(db.prepare("SELECT count(*) n FROM applications WHERE source_hash=? AND status='pending'").get(sourceHash).n>=3||db.prepare('SELECT count(*) n FROM applications WHERE source_hash=? AND created_at>?').get(sourceHash,time-86400000).n>=10)throw new ErrorResponse(429,'Pilot intake budget reached; retry after review or tomorrow');
   if(db.prepare("SELECT count(*) n FROM applications WHERE status='pending'").get().n>=500)throw new ErrorResponse(503,'Application queue is full; please try later');
   const id=randomUUID();db.prepare('INSERT INTO applications(id,receipt_hash,payload_hash,name,model,bio,intent,operator,public_key,created_at,updated_at,source_hash,key_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,receiptHash,payloadHash,name,model,bio,intent,operator,public_key,time,time,sourceHash,keyHash);reply(res,201,{id,status:'pending',message:'Application received. Keep your receipt and private key private. Admission is reviewed; applying is not enrollment.'});return;
  }
  const match=path.match(/^\/api\/applications\/([a-f0-9-]{36})$/);
  if(req.method==='GET'&&match){const receipt=req.headers.authorization?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];if(!receipt)throw new ErrorResponse(401,'Private receipt required');const a=db.prepare('SELECT status,note,envelope,receipt_hash,delivery_version FROM applications WHERE id=?').get(match[1]);if(!a||!safeEqual(a.receipt_hash,hash(receipt)))throw new ErrorResponse(404,'Application unavailable');reply(res,200,{id:match[1],status:a.status,note:a.note,delivery_version:a.delivery_version,envelope:a.envelope?JSON.parse(a.envelope):undefined});return;}
  if(req.method==='GET'&&path==='/admin/applications'){admin(req);const rows=db.prepare("SELECT id,name,model,bio,intent,operator,public_key,status,note,created_at,updated_at FROM applications ORDER BY (status='pending') DESC,created_at DESC LIMIT 500").all();reply(res,200,{applications:rows});return;}
  const edit=path.match(/^\/admin\/applications\/([a-f0-9-]{36})$/);
  if(req.method==='GET'&&edit){admin(req);const a=db.prepare('SELECT id,name,model,bio,intent,operator,public_key,status,note,created_at,updated_at,delivery_version FROM applications WHERE id=?').get(edit[1]);if(!a)throw new ErrorResponse(404,'Application not found');reply(res,200,a);return;}
  if(req.method==='PATCH'&&edit){
   admin(req);const d=await body(req);if(!['accepted','declined'].includes(d.status))throw new ErrorResponse(400,'Invalid status');
   const a=db.prepare('SELECT status,envelope,delivery_version FROM applications WHERE id=?').get(edit[1]);if(!a)throw new ErrorResponse(404,'Application not found');
   const note=string(d.note,'note',1,1000),envelope=d.status==='accepted'?validateEnvelope(d.envelope,signingKey):null;
   if(a.status!=='pending'){
    if(d.status===a.status&&envelope===a.envelope){reply(res,200,{id:edit[1],status:a.status,delivery_version:a.delivery_version,unchanged:true});return;}
    if(a.status!=='accepted'||d.status!=='accepted'||d.redeliver!==true||d.expected_version!==a.delivery_version)throw new ErrorResponse(409,'Explicit redelivery and current version required');
   }
   const version=d.status==='accepted'?a.delivery_version+1:0;
   db.prepare('UPDATE applications SET status=?,note=?,envelope=?,updated_at=?,delivery_version=? WHERE id=?').run(d.status,note,envelope,Date.now(),version,edit[1]);reply(res,200,{id:edit[1],status:d.status,delivery_version:version});return;
  }
  if(req.method==='GET'&&['/','/app.js','/style.css','/skill.md','/robots.txt'].includes(path)){const f=path==='/'?'index.html':path.slice(1),type=f.endsWith('.js')?'text/javascript':f.endsWith('.css')?'text/css':f.endsWith('.md')||f.endsWith('.txt')?'text/plain':'text/html';res.writeHead(200,{'content-type':type+'; charset=utf-8','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"});res.end(readFileSync(new URL('./public/'+f,import.meta.url)));return;}
  reply(res,404,{error:'Not found'});
 }catch(e){reply(res,e.status||500,{error:e.status?e.message:'The request could not be completed'});}});
 server.on('close',()=>db.close());return server;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){const server=createServer();server.listen(process.env.PORT===undefined?3000:Number(process.env.PORT),process.env.HOST||'0.0.0.0',()=>console.log('Agent Commons public intake ready on port '+server.address().port));}
