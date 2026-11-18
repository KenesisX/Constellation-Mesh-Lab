/* Constellation Mesh Lab message security, built only on the browser's WebCrypto.
   Key agreement: ECDH (P-521 where available) -> HKDF-SHA-512 -> one chain per direction.
   Each message: HMAC-SHA-256 ratchet step -> fresh AES-256-GCM key. Header and serial number are authenticated. */
const Secure=(()=>{
const S=(globalThis.crypto||{}).subtle,te=new TextEncoder(),td=new TextDecoder();
const CURVES=['P-256','P-384','P-521'],BITS={'P-256':256,'P-384':384,'P-521':528};
const available=()=>!!S;
const cat=(...a)=>{let n=0;for(const x of a)n+=x.length;const o=new Uint8Array(n);n=0;for(const x of a){o.set(x,n);n+=x.length}return o};
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
async function hmac(key,data){const k=await S.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);return new Uint8Array(await S.sign('HMAC',k,data))}
async function hkdf(ikm,salt,info,len){const k=await S.importKey('raw',ikm,'HKDF',false,['deriveBits']);return new Uint8Array(await S.deriveBits({name:'HKDF',hash:'SHA-512',salt,info},k,len*8))}
async function newIdentity(){for(const c of['P-521','P-384','P-256']){try{const kp=await S.generateKey({name:'ECDH',namedCurve:c},false,['deriveBits']);return{kp,curve:c,pub:new Uint8Array(await S.exportKey('raw',kp.publicKey))}}catch(e){}}throw new Error('This browser has no ECDH support')}
const nonce=serial=>{const n=new Uint8Array(12);new DataView(n.buffer).setUint32(8,serial);return n};
function pad(msg){const n=Math.ceil((msg.length+2)/32)*32,o=new Uint8Array(n);o[0]=msg.length>>8;o[1]=msg.length&255;o.set(msg,2);return o}
function unpad(p){const n=(p[0]<<8)|p[1];if(n>p.length-2)throw new Error('bad padding');return p.slice(2,2+n)}
async function aes(mk,usage){return S.importKey('raw',mk,'AES-GCM',false,[usage])}

class Session{
  constructor(sendKey,recvKey,info){this.s={k:sendKey,n:0};this.r={k:recvKey,n:0,skipped:new Map()};this.info=info}
  async seal(mkHeader,text){const serial=this.s.n,mk=await hmac(this.s.k,Uint8Array.of(1));this.s.k=await hmac(this.s.k,Uint8Array.of(2));this.s.n++;
    const ct=new Uint8Array(await S.encrypt({name:'AES-GCM',iv:nonce(serial),additionalData:mkHeader(serial)},await aes(mk,'encrypt'),pad(te.encode(text))));return{serial,ct}}
  async open(serial,header,ct){const dec=async mk=>td.decode(unpad(new Uint8Array(await S.decrypt({name:'AES-GCM',iv:nonce(serial),additionalData:header},await aes(mk,'decrypt'),ct))));
    if(serial<this.r.n){const mk=this.r.skipped.get(serial);if(!mk)throw new Error('replayed or already used serial');let t;try{t=await dec(mk)}catch(e){throw new Error('authentication failed')}this.r.skipped.delete(serial);return t}
    if(serial-this.r.n>500)throw new Error('serial too far ahead');
    let ck=this.r.k,mk=null;const hold=[];
    for(let i=this.r.n;i<=serial;i++){mk=await hmac(ck,Uint8Array.of(1));ck=await hmac(ck,Uint8Array.of(2));if(i<serial)hold.push([i,mk])}
    let t;try{t=await dec(mk)}catch(e){throw new Error('authentication failed')}
    this.r.k=ck;this.r.n=serial+1;for(const[i,k]of hold)this.r.skipped.set(i,k);
    while(this.r.skipped.size>500)this.r.skipped.delete(this.r.skipped.keys().next().value);
    return t}}

async function makeSession(secret,myId,peerId,info){const lo=Math.min(myId,peerId),hi=Math.max(myId,peerId),okm=await hkdf(secret,Uint8Array.of(lo,hi),te.encode('Constellation Mesh Lab v1 chains'),64);
  const up=okm.slice(0,32),down=okm.slice(32);return myId===lo?new Session(up,down,info):new Session(down,up,info)}

class Station{
  constructor(id){this.id=id;this.peers=new Map();this.identity=null}
  async init(){this.identity=await newIdentity();return this}
  hello(dst,isReply){return{type:1,src:this.id,dst,serial:0,payload:cat(Uint8Array.of(CURVES.indexOf(this.identity.curve)+1,isReply?1:0),this.identity.pub)}}
  async onHello(src,p){const curve=CURVES[p[0]-1];if(curve!==this.identity.curve)throw new Error('peer uses '+(curve||'an unknown curve')+', this station uses '+this.identity.curve);
    const pub=p.slice(2),key=await S.importKey('raw',pub,{name:'ECDH',namedCurve:curve},false,[]);
    const secret=new Uint8Array(await S.deriveBits({name:'ECDH',public:key},this.identity.kp.privateKey,BITS[curve]));
    const mine=this.identity.pub,first=this.id<src?mine:pub,second=this.id<src?pub:mine,fp=hex(new Uint8Array(await S.digest('SHA-256',cat(first,second)))).slice(0,24).match(/.{4}/g).join(' ');
    this.peers.set(src,await makeSession(secret,this.id,src,{mode:'ECDH '+curve+' + HKDF-SHA-512',fingerprint:fp}));return p[1]===0}
  async usePassphrase(peer,pass){const lo=Math.min(this.id,peer),hi=Math.max(this.id,peer),k=await S.importKey('raw',te.encode(pass),'PBKDF2',false,['deriveBits']);
    const secret=new Uint8Array(await S.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:cat(te.encode('CML-psk'),Uint8Array.of(lo,hi)),iterations:600000},k,512));
    this.peers.set(peer,await makeSession(secret,this.id,peer,{mode:'Shared passphrase, PBKDF2 600,000 rounds',fingerprint:null}))}
  header(type,dst,serial){return Uint8Array.of(type,this.id,dst,serial>>>24,(serial>>>16)&255,(serial>>>8)&255,serial&255)}
  async encryptText(dst,text){const s=this.peers.get(dst);if(!s)throw new Error('no keys with station '+dst);const{serial,ct}=await s.seal(n=>this.header(0,dst,n),text);return{type:0,src:this.id,dst,serial,payload:ct}}
  /* f is a parsed frame. Returns {kind:'text'|'hello'|'error'|'ignored', ...}. */
  async receive(f){if(f.dst!==this.id)return{kind:'ignored'};
    try{if(f.type===1){const reply=await this.onHello(f.src,f.payload);return{kind:'hello',from:f.src,reply:reply?this.hello(f.src,true):null}}
      if(f.type===0){const s=this.peers.get(f.src);if(!s)return{kind:'error',reason:'no keys with station '+f.src};return{kind:'text',from:f.src,serial:f.serial,text:await s.open(f.serial,f.header,f.payload)}}
      return{kind:'ignored'}}catch(e){return{kind:'error',reason:e.message}}}}

async function bench(){const k=await S.generateKey({name:'AES-GCM',length:256},false,['encrypt']),buf=new Uint8Array(1<<21),t0=performance.now();let n=0;
  while(performance.now()-t0<120){await S.encrypt({name:'AES-GCM',iv:nonce(n++)},k,buf)}return n*buf.length/((performance.now()-t0)/1e3)}
return{available,Station,Session,newIdentity,bench,hex,pad,unpad}})();
if(typeof module!=='undefined')module.exports=Secure;
