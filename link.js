/* Modem and Messages tabs: real frames through an emulated channel or the local radio bridge. */
const LK={fs:1e6,mode:'emu',bridge:null,rxEmu:new Modem.Receiver(1e6),rxRad:null,rand:Modem.rng(2026),frames:[],air:[],burst:null,lastTx:null,lastRx:null,lastResult:'',beacon:0,cursor:-1,per:null,st:{},chat:{1:[],2:[]},bench:null,encMs:null,status:'',busy:false};
const TYPES={0:'encrypted data',1:'key hello',3:'beacon'};
const hexs=(b,n)=>Array.from(b.slice(0,n),x=>x.toString(16).padStart(2,'0')).join(' ')+(b.length>n?' …':'');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const isLocal=id=>LK.mode==='emu'||V.gLocal==='Both'||V.gLocal==='Station '+id;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

async function airRaw(bytes,note,quiet){const mod=V.oMod==='16QAM'?1:0,t=Modem.tx(bytes,mod),f=Modem.parseFrame(bytes);
  const e={f,bytes,mod,note:note||'',air:Modem.airtime(bytes.length,mod,LK.fs)*1e3,result:'',said:''};
  if(!quiet){LK.air.unshift(e);if(LK.air.length>60)LK.air.length=60}
  LK.lastTx={bytes,mod,t,payload:f.payload.length};LK.lastRx=null;
  if(LK.mode==='radio'){try{await fetch('api/tx',{method:'POST',body:Modem.toInterleaved(t)});e.result='sent'}catch(x){e.result='bridge error'}LK.lastResult=e.result;return e}
  const ch=Modem.channel(t,{snr:V.oSnr,cfo:V.oCfo,fs:LK.fs,lead:700,trail:500,rand:LK.rand});LK.burst=ch;
  const got=LK.rxEmu.push(ch.re,ch.im);e.result=got.some(g=>g.ok)?'decoded':got.length?'check failed':'not detected';LK.lastResult=e.result;
  for(const g of got)await onFrame(g,e);return e}

async function onFrame(g,e){const f=g.ok?Modem.parseFrame(g.bytes):null;LK.lastRx=g;LK.frames.unshift({g,f});if(LK.frames.length>40)LK.frames.length=40;
  if(!f)return;
  for(const id of[1,2]){if(!isLocal(id)||f.dst!==id||!LK.st[id])continue;const res=await LK.st[id].receive(f);
    if(res.kind==='text'){LK.chat[id].push({dir:'in',text:res.text,meta:'#'+res.serial+' from station '+res.from+', '+g.stats.snrDb.toFixed(0)+' dB'});e.said='decrypted by station '+id}
    else if(res.kind==='hello'){e.said='keys agreed at station '+id;if(res.reply)await airRaw(Modem.buildFrame(res.reply),'key exchange reply')}
    else if(res.kind==='error')e.said='rejected: '+res.reason}}

async function poll(){if(LK.mode!=='radio')return;
  try{const r=await fetch('api/rx?cursor='+LK.cursor);LK.cursor=+r.headers.get('X-Next');const f=new Float32Array(await r.arrayBuffer()),n=f.length>>1;
    if(n){const re=new Float64Array(n),im=new Float64Array(n);for(let k=0;k<n;k++){re[k]=f[2*k];im[k]=f[2*k+1]}
      const got=LK.rxRad.push(re,im);if(got.length||!LK.burst)LK.burst={re,im};
      for(const g of got){const e={f:g.ok?Modem.parseFrame(g.bytes):null,bytes:g.bytes,mod:g.mod,note:'heard on the radio',air:g.stats.airMs,result:g.ok?'decoded':'check failed',said:''};if(e.f)LK.air.unshift(e);LK.lastResult=e.result;await onFrame(g,e)}
      if(got.length)drawLink()}
    LK.status='Radio bridge live at '+(LK.fs/1e3)+' kS/s'}catch(x){LK.status='Radio bridge is not answering. Is bridge.py still running?'}
  $('lkStatus').textContent=LK.status;setTimeout(poll,150)}

function setMode(){const want=V.oChan==='Radio bridge'?'radio':'emu';
  if(want==='radio'&&!LK.bridge){LK.status='Radio mode needs the local bridge: run bridge.py from the download and open the page it serves.';$('oChan').value='Emulated channel';V.oChan='Emulated channel';LK.mode='emu';LK.fs=1e6;drawLink();return}
  LK.mode=want;LK.fs=want==='radio'?LK.bridge.rate:1e6;
  if(want==='radio'){LK.rxRad=new Modem.Receiver(LK.fs);LK.cursor=-1;LK.burst=null;poll()}else LK.status='Emulated channel: both ends run in this page.';
  drawLink()}

async function initStations(fresh){if(!Secure.available()){LK.status='This browser does not expose WebCrypto here, so encryption is off.';return false}
  for(const id of[1,2])if(!LK.st[id]||(fresh&&isLocal(id)))LK.st[id]=await new Secure.Station(id).init();return true}
async function handshake(){if(!await initStations(true))return;const from=isLocal(1)?1:2;await airRaw(Modem.buildFrame(LK.st[from].hello(3-from,false)),'key exchange');drawLink()}
async function sendText(id,text,tamper){const st=LK.st[id],item={dir:'out',text,meta:'encrypting'};LK.chat[id].push(item);
  try{const t0=performance.now(),fr=await st.encryptText(3-id,text);LK.encMs=performance.now()-t0;if(tamper)fr.payload[3]^=1;
    const e=await airRaw(Modem.buildFrame(fr),tamper?'one bit flipped in flight':'');
    item.meta='#'+fr.serial+', '+fr.payload.length+' encrypted bytes, '+(LK.mode==='radio'&&!e.said?'sent':e.said.startsWith('decrypted')?'delivered':e.said||e.result)}
  catch(x){item.meta='not sent: '+x.message}drawLink()}
async function replay(){const e=LK.air.find(q=>q.f&&q.f.type===0&&!q.note);if(!e){LK.status='Send a message first, then replay it.';drawLink();return}await airRaw(e.bytes,'replayed by an attacker');drawLink()}
async function usePass(){const p=$('sPass').value;if(p.length<12){LK.status='Use a passphrase of at least 12 characters.';drawLink();return}
  if(!await initStations(false))return;LK.status='Stretching the passphrase';drawLink();for(const id of[1,2])if(isLocal(id))await LK.st[id].usePassphrase(3-id,p);LK.status='Passphrase keys ready. The other station must enter the same passphrase.';drawLink()}
async function beacons(){if(LK.busy)return;LK.busy=true;const N=LK.mode==='radio'?20:100;let ok=0,sn=0;
  for(let i=0;i<N;i++){const p=new Uint8Array(24);crypto.getRandomValues(p);const e=await airRaw(Modem.buildFrame({type:3,src:1,dst:255,serial:LK.beacon++,payload:p}),'beacon',true);
    if(e.result==='decoded'&&LK.lastRx){ok++;sn+=LK.lastRx.stats.snrDb}if(LK.mode==='radio')await pause(120);else if(i%20===19)await pause(0)}
  LK.per=LK.mode==='radio'?null:{N,ok,snr:ok?sn/ok:null,at:V.oSnr,mod:V.oMod};LK.busy=false;drawLink()}

function drawLink(){const tx=LK.lastTx,g=LK.lastRx,fs=LK.fs;
  $('lkStatus').textContent=$('msNote').textContent=LK.status;
  if(tx){const air=Modem.airtime(tx.bytes.length,tx.mod,fs);
    tiles('moTx',[{k:'Payload',v:tx.payload+' bytes'},{k:'Frame with header and check',v:tx.bytes.length+' bytes',h:'type, from, to, 32-bit serial, CRC-16'},{k:'After error-correction coding',v:tx.t.codedBits+' bits',h:'rate 1/2, constraint length 7'},
      {k:'Symbols',v:tx.t.nsym,h:Modem.overheadSyms+' are preamble, sync and length field'},{k:'Samples on air',v:tx.t.re.length,h:(fs/1e3)+' kS/s'},{k:'Airtime',v:(air*1e3).toFixed(2)+' ms'},
      {k:'Coded bit rate',v:fmtRate(Modem.bitRate(tx.mod,fs)),h:tx.mod?'16-QAM':'QPSK'},{k:'Payload rate for this frame',v:fmtRate(tx.payload*8/air),h:'short frames pay more overhead'}])}
  else tiles('moTx',[{k:'Nothing sent yet',v:'n/a'}]);
  const rx=[];
  if(g){const s=g.stats,f=g.ok?Modem.parseFrame(g.bytes):null;
    rx.push({k:'Frame check',v:g.ok?'passed':'failed',s:g.ok?'good':'crit',h:f?(TYPES[f.type]||'type '+f.type)+', serial #'+f.serial:'CRC-16 mismatch'},
      {k:'SNR from decided symbols',v:s.snrDb.toFixed(1)+' dB',s:s.snrDb>10?'good':s.snrDb>5?'warn':'crit'},
      {k:'Frequency offset found',v:s.cfoHz.toFixed(0)+' Hz',h:LK.mode==='emu'?'set to '+V.oCfo+' Hz':'radio oscillator difference'},
      {k:'In-band power',v:s.rssiDb.toFixed(1)+' dBFS'},{k:'Noise floor in the gap before',v:s.floorDb===null?'n/a':s.floorDb.toFixed(1)+' dBFS'},
      {k:'Packet over gap',v:s.floorDb===null?'n/a':(s.rssiDb-s.floorDb).toFixed(1)+' dB'},{k:'Sync word match',v:(s.sync*100).toFixed(0)+' %'})}
  else rx.push({k:'Receiver',v:LK.lastResult||'waiting',s:LK.lastResult==='not detected'?'crit':'',h:LK.lastResult==='not detected'?'raise the SNR or use QPSK':LK.mode==='radio'?'listening on the bridge':''});
  if(LK.per)rx.push({k:'Beacon test',v:LK.per.ok+' of '+LK.per.N+' decoded',s:LK.per.ok===LK.per.N?'good':LK.per.ok>LK.per.N*.8?'warn':'crit',h:LK.per.mod+' at '+LK.per.at+' dB set, '+(LK.per.snr===null?'none measured':LK.per.snr.toFixed(1)+' dB measured')});
  tiles('moRx',rx);
  if(LK.burst&&cur==='modem'){const b=LK.burst,n=b.re.length,st=Math.max(1,Math.floor(n/900)),x=[],y=[];for(let k=0;k+st<=n;k+=st){let m=0;for(let j=0;j<st;j++){const a=Math.hypot(b.re[k+j],b.im[k+j]);if(a>m)m=a}x.push(k/fs*1e3);y.push(m)}
    plot('cBurst',{series:[{x,y,color:'--accent',fill:true}],xmin:0,xmax:n/fs*1e3,ymin:0})}
  if(cur==='modem'){if(g)scatter('cMod',[{n:g.syms.r.length,x:i=>g.syms.r[i],y:i=>g.syms.i[i],r:1.6,color:'--accent',alpha:.6}],1.7);else cv('cMod')}
  $('moTable').innerHTML='<tr><th>Serial</th><th>Type</th><th>Route</th><th>Bytes</th><th>Modulation</th><th>SNR</th><th>Offset</th><th>Power</th><th>Gap floor</th><th>Check</th></tr>'+(LK.frames.length?LK.frames.map(q=>{const s=q.g.stats,f=q.f;
    return`<tr><td>${f?'#'+f.serial:''}</td><td>${f?TYPES[f.type]||f.type:''}</td><td>${f?f.src+' → '+f.dst:''}</td><td>${q.g.len}</td><td>${q.g.mod?'16-QAM':'QPSK'}</td><td>${s.snrDb.toFixed(1)} dB</td><td>${s.cfoHz.toFixed(0)} Hz</td><td>${s.rssiDb.toFixed(1)}</td><td>${s.floorDb===null?'':s.floorDb.toFixed(1)}</td><td><span class="pill ${q.g.ok?'good':'crit'}">${q.g.ok?'ok':'failed'}</span></td></tr>`}).join(''):'<tr><td colspan="10">No frames decoded yet.</td></tr>');
  /* Messages */
  const s1=LK.st[1]&&LK.st[1].peers.get(2),s2=LK.st[2]&&LK.st[2].peers.get(1),ses=isLocal(1)?s1:s2,both=LK.mode==='emu'||V.gLocal==='Both',match=!both||(s1&&s2&&s1.info.fingerprint===s2.info.fingerprint);
  const rate=Modem.bitRate(V.oMod==='16QAM'?1:0,fs);
  tiles('msMeas',[{k:'Cipher',v:'AES-256-GCM',h:'a new key for every message'},
    {k:'Key agreement',v:ses?ses.info.mode:'no keys yet',s:ses?'good':'crit',h:ses?'':'press New key exchange'},
    {k:'Safety number',v:ses&&ses.info.fingerprint?ses.info.fingerprint:'n/a',s:ses&&ses.info.fingerprint?(match?'good':'crit'):'',h:ses&&ses.info.fingerprint?'both operators must read the same digits':'passphrase mode has none'},
    {k:'Possible keys',v:'2^256',h:'about 1.16 × 10^77'},
    {k:'Encryption speed here',v:LK.bench?(LK.bench/1e6).toFixed(0)+' MB/s':'measuring',h:LK.bench?Math.round(LK.bench*8/rate).toLocaleString()+' times faster than this radio link':''},
    {k:'Cost per message',v:'16-byte tag, padded to 32',h:LK.encMs!==null?'last one took '+LK.encMs.toFixed(2)+' ms to encrypt':''}]);
  for(const id of[1,2]){const box=$('ch'+id),loc=isLocal(id);$('chT'+id).textContent='Station '+id+(loc?'':' (remote)');$('in'+id).disabled=!loc;box.replaceChildren();
    if(!LK.chat[id].length){const d=document.createElement('div');d.className='note';d.textContent=loc?'No messages yet.':'This station is on the other machine.';box.appendChild(d)}
    for(const m of LK.chat[id]){const d=document.createElement('div'),sm=document.createElement('small');d.className='bub '+m.dir;d.textContent=m.text;sm.textContent=m.meta;d.appendChild(sm);box.appendChild(d)}
    box.scrollTop=box.scrollHeight}
  $('airTable').innerHTML='<tr><th>What</th><th>Route</th><th>Serial</th><th>Bytes</th><th>Payload as sent</th><th>Airtime</th><th>Channel</th><th>Receiver</th></tr>'+(LK.air.length?LK.air.map(e=>`<tr><td>${esc(e.f?TYPES[e.f.type]||e.f.type:'')}${e.note?' ('+esc(e.note)+')':''}</td><td>${e.f?e.f.src+' → '+e.f.dst:''}</td><td>${e.f?'#'+e.f.serial:''}</td><td>${e.bytes.length}</td><td>${e.f?hexs(e.f.payload,10):''}</td><td>${e.air.toFixed(1)} ms</td><td><span class="pill ${e.result==='decoded'||e.result==='sent'?'good':'crit'}">${esc(e.result)}</span></td><td>${esc(e.said)}</td></tr>`).join(''):'<tr><td colspan="8">Nothing sent yet.</td></tr>')}
function drawModem(){drawLink()}
function drawMessages(){drawLink();if(!LK.bench&&Secure.available())Secure.bench().then(v=>{LK.bench=v;drawLink()}).catch(()=>{})}

ctl('moCtl',[
  {id:'oChan',label:'Channel',type:'select',opts:['Emulated channel','Radio bridge'],val:'Emulated channel'},
  {id:'oMod',label:'Modulation',type:'select',opts:['QPSK','16QAM'],val:'QPSK'},
  {id:'oSnr',label:'Emulated SNR per symbol',min:0,max:30,step:1,val:12,unit:' dB'},
  {id:'oCfo',label:'Emulated frequency offset',min:-3000,max:3000,step:100,val:400,unit:' Hz'},
  {id:'gLocal',label:'Stations on this machine, radio mode',type:'select',opts:['Both','Station 1','Station 2'],val:'Both'},
  {id:'oSend',label:'Transmit one frame',type:'btn',click:async()=>{const p=new TextEncoder().encode($('oText').value).slice(0,2000);await airRaw(Modem.buildFrame({type:3,src:1,dst:255,serial:LK.beacon++,payload:p}),'beacon');drawLink()}},
  {id:'oBeac',label:'Send a run of beacons',type:'btn',ghost:true,click:beacons}],id=>{if(id==='oChan')setMode();else drawLink()});
ctl('msCtl',[
  {id:'sKeys',label:'New key exchange over the air',type:'btn',click:handshake},
  {id:'sPassGo',label:'Use the shared passphrase instead',type:'btn',ghost:true,click:usePass},
  {id:'sReplay',label:'Attack: replay the last message',type:'btn',ghost:true,click:replay},
  {id:'sTamper',label:'Attack: flip one bit in flight',type:'btn',ghost:true,click:()=>{const id=isLocal(1)?1:2;if(LK.st[id]&&LK.st[id].peers.get(3-id))sendText(id,'This message gets one bit flipped in flight.',true)}}],null);
for(const id of[1,2])$('f'+id).addEventListener('submit',ev=>{ev.preventDefault();const inp=$('in'+id),t=inp.value.trim();if(!t||!isLocal(id))return;inp.value='';
  if(!LK.st[id]||!LK.st[id].peers.get(3-id)){LK.chat[id].push({dir:'out',text:t,meta:'not sent: no keys yet, press New key exchange'});drawLink();return}sendText(id,t)});
$('oFile').addEventListener('change',async ev=>{const file=ev.target.files[0],msg=$('oFileMsg');if(!file)return;msg.textContent='Reading '+file.name;
  try{const buf=await file.arrayBuffer(),fmt=$('oFmt').value,fs=+$('oRate').value||250000;let src,sc,off=0;
    if(fmt==='cf32'){src=new Float32Array(buf,0,buf.byteLength>>2);sc=1}else if(fmt==='cu8'){src=new Uint8Array(buf);sc=1/127.5;off=127.5}else if(fmt==='cs8'){src=new Int8Array(buf);sc=1/127}else{src=new Int16Array(buf,0,buf.byteLength>>1);sc=1/32768}
    const n=src.length>>1,rx=new Modem.Receiver(fs),C=1<<16;let found=0,ok=0;
    for(let o=0;o<n;o+=C){const m=Math.min(C,n-o),re=new Float64Array(m),im=new Float64Array(m);for(let k=0;k<m;k++){re[k]=(src[2*(o+k)]-off)*sc;im[k]=(src[2*(o+k)+1]-off)*sc}
      for(const g of rx.push(re,im)){found++;if(g.ok)ok++;LK.lastRx=g;LK.frames.unshift({g,f:g.ok?Modem.parseFrame(g.bytes):null});if(LK.frames.length>40)LK.frames.length=40}
      if((o/C)%16===15){msg.textContent='Decoding, '+Math.round(o/n*100)+'%';await pause(0)}}
    const keep=LK.fs;LK.fs=fs;msg.textContent=file.name+': '+(n/fs).toFixed(2)+' s, '+found+' frames found, '+ok+' passed the check.';drawLink();LK.fs=keep}
  catch(x){msg.textContent='Could not read that file: '+x.message}});

(async()=>{LK.status='Emulated channel: both ends run in this page.';
  if(/^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)){try{const j=await(await fetch('api/status')).json();if(j&&j.ok){LK.bridge=j;$('oChan').value='Radio bridge';V.oChan='Radio bridge'}}catch(e){}}
  if(await initStations(false)){setMode();
    if(LK.mode==='emu'){await handshake();await sendText(1,'Example: link check from station 1.');await sendText(2,'Example: station 2 reads you.')}}
  else setMode();
  if(cur==='modem'||cur==='messages')redraw[cur]();else drawLink()})();
