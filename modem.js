/* Constellation Mesh Lab frame modem.
   Bytes -> scramble -> rate 1/2 convolutional code (K=7) -> QPSK or 16-QAM -> root-raised-cosine pulses.
   Receiver: repeated-preamble detection, frequency offset estimate, sync word timing, phase tracking, soft Viterbi, CRC-16. */
const Modem=(()=>{
const SPS=4,SPAN=8,BETA=.35,Q=Math.SQRT1_2,K16=1/Math.sqrt(10);
function rrc(beta,sps,span){const N=span*sps,h=[];
  for(let i=0;i<=N;i++){const t=(i-N/2)/sps;let v;
    if(Math.abs(t)<1e-9)v=1-beta+4*beta/Math.PI;
    else if(Math.abs(Math.abs(4*beta*t)-1)<1e-9)v=beta/Math.SQRT2*((1+2/Math.PI)*Math.sin(Math.PI/(4*beta))+(1-2/Math.PI)*Math.cos(Math.PI/(4*beta)));
    else v=(Math.sin(Math.PI*t*(1-beta))+4*beta*t*Math.cos(Math.PI*t*(1+beta)))/(Math.PI*t*(1-(4*beta*t)**2));
    h.push(v)}
  let e=0;for(const v of h)e+=v*v;e=Math.sqrt(e);return Float64Array.from(h,v=>v/e)}
const H=rrc(BETA,SPS,SPAN),L=H.length;
function lfsr(n,seed){let s=seed;const o=new Uint8Array(n);for(let i=0;i<n;i++){const b=((s>>6)^(s>>3))&1;s=((s<<1)|b)&0x7f;o[i]=b}return o}
function mapBits(bits,mod){const bps=mod?4:2,n=Math.ceil(bits.length/bps),r=new Float64Array(n),im=new Float64Array(n),g=k=>k<bits.length?bits[k]:0;
  for(let k=0;k<n;k++){if(mod){const o=4*k;r[k]=(2*g(o)-1)*(g(o+1)?1:3)*K16;im[k]=(2*g(o+2)-1)*(g(o+3)?1:3)*K16}else{r[k]=(2*g(2*k)-1)*Q;im[k]=(2*g(2*k+1)-1)*Q}}
  return{r,i:im}}
const BLK=mapBits(lfsr(16,0x5b),0),NREP=8,PRE=BLK.r.length*NREP,SFD=mapBits(lfsr(48,0x2d),0),NSFD=SFD.r.length,LEAD=mapBits(lfsr(16,0x11),0),TAIL=mapBits(lfsr(16,0x37),0),NSIG=22;
const PD=BLK.r.length*SPS,PW=(NREP-1)*PD;
const G1=0o171,G2=0o133,O1=new Uint8Array(128),O2=new Uint8Array(128);
for(let s=0;s<128;s++){const p=x=>{x^=x>>4;x^=x>>2;x^=x>>1;return x&1};O1[s]=p(s&G1);O2[s]=p(s&G2)}
function convEnc(bits){const n=bits.length,o=new Uint8Array(2*(n+6));let sr=0;for(let i=0;i<n+6;i++){sr=((sr<<1)|(i<n?bits[i]:0))&0x7f;o[2*i]=O1[sr];o[2*i+1]=O2[sr]}return o}
function viterbi(soft,nbits){const T=nbits+6,NS=64,dec=new Uint8Array(T*NS);let pm=new Float64Array(NS).fill(-1e18),nm=new Float64Array(NS);pm[0]=0;
  for(let t=0;t<T;t++){const a=soft[2*t],b=soft[2*t+1];
    for(let ns=0;ns<NS;ns++){const s0=ns,s1=ns|64,m0=pm[s0>>1]+(O1[s0]?a:-a)+(O2[s0]?b:-b),m1=pm[s1>>1]+(O1[s1]?a:-a)+(O2[s1]?b:-b);
      if(m1>m0){nm[ns]=m1;dec[t*NS+ns]=1}else{nm[ns]=m0;dec[t*NS+ns]=0}}
    const x=pm;pm=nm;nm=x}
  const out=new Uint8Array(nbits);let s=0;for(let t=T-1;t>=0;t--){if(t<nbits)out[t]=s&1;s=(s>>1)|(dec[t*NS+s]<<5)}return out}
function toBits(bytes){const o=new Uint8Array(bytes.length*8);for(let i=0;i<bytes.length;i++)for(let b=0;b<8;b++)o[8*i+b]=(bytes[i]>>(7-b))&1;return o}
function toBytes(bits){const o=new Uint8Array(bits.length>>3);for(let i=0;i<o.length;i++){let v=0;for(let b=0;b<8;b++)v=(v<<1)|bits[8*i+b];o[i]=v}return o}
function scramble(bytes){const w=toBytes(lfsr(bytes.length*8,0x6e)),o=new Uint8Array(bytes.length);for(let i=0;i<o.length;i++)o[i]=bytes[i]^w[i];return o}
function crc16(b,n){let c=0xffff;for(let i=0;i<n;i++){c^=b[i]<<8;for(let k=0;k<8;k++)c=c&0x8000?((c<<1)^0x1021)&0xffff:(c<<1)&0xffff}return c}
function sigBits(len,mod){const v=(len<<1)|mod,chk=((v>>8)^(v>>4)^v^0xA)&15,w=(v<<4)|chk,o=new Uint8Array(16);for(let i=0;i<16;i++)o[i]=(w>>(15-i))&1;return o}
const paySyms=(len,mod)=>Math.ceil(2*(8*len+6)/(mod?4:2));

/* Frame: type(1) src(1) dst(1) serial(4, big endian) payload crc16(2). Type 0 data, 1 key hello, 3 beacon. */
function buildFrame(f){const p=f.payload||new Uint8Array(0),b=new Uint8Array(9+p.length);b[0]=f.type;b[1]=f.src;b[2]=f.dst;b[3]=f.serial>>>24;b[4]=(f.serial>>>16)&255;b[5]=(f.serial>>>8)&255;b[6]=f.serial&255;b.set(p,7);
  const c=crc16(b,b.length-2);b[b.length-2]=c>>8;b[b.length-1]=c&255;return b}
function parseFrame(b){if(b.length<9)return null;return{type:b[0],src:b[1],dst:b[2],serial:((b[3]<<24)|(b[4]<<16)|(b[5]<<8)|b[6])>>>0,payload:b.slice(7,b.length-2),header:b.slice(0,7)}}

function tx(bytes,mod,amp){mod=mod?1:0;amp=amp||.6;if(bytes.length>2047)throw new Error('Frame too long: 2047 bytes is the limit');
  const sig=mapBits(convEnc(sigBits(bytes.length,mod)),0),coded=convEnc(toBits(scramble(bytes))),pay=mapBits(coded,mod);
  const n=LEAD.r.length+PRE+NSFD+NSIG+pay.r.length+TAIL.r.length,sr=new Float64Array(n),si=new Float64Array(n);let o=0;
  const put=s=>{sr.set(s.r,o);si.set(s.i,o);o+=s.r.length};
  put(LEAD);for(let k=0;k<NREP;k++)put(BLK);put(SFD);put(sig);put(pay);put(TAIL);
  const N=n*SPS+L,re=new Float64Array(N),im=new Float64Array(N);
  for(let k=0;k<n;k++){const a=sr[k]*amp,b=si[k]*amp,q=k*SPS;for(let j=0;j<L;j++){re[q+j]+=a*H[j];im[q+j]+=b*H[j]}}
  return{re,im,amp,nsym:n,codedBits:coded.length,paySyms:pay.r.length,frameBytes:bytes.length}}

function rng(seed){let a=seed>>>0;return()=>{a|=0;a=a+0x6D2B79F5|0;let t=Math.imul(a^a>>>15,1|a);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296}}
function gauss(r){let u=0;while(u<1e-12)u=r();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*r())}
/* Emulated channel: noise-only gap before and after, carrier offset, random phase, white noise at the given SNR per symbol. */
function channel(t,o){const r=o.rand,lead=o.lead||0,trail=o.trail||0,n=t.re.length,N=lead+n+trail,re=new Float64Array(N),im=new Float64Array(N);
  const sg=Math.sqrt(t.amp*t.amp/Math.pow(10,o.snr/10)/2),w=2*Math.PI*o.cfo/o.fs,p0=r()*6.283;
  for(let k=0;k<N;k++){re[k]=gauss(r)*sg;im[k]=gauss(r)*sg}
  for(let k=0;k<n;k++){const c=Math.cos(w*k+p0),s=Math.sin(w*k+p0);re[lead+k]+=t.re[k]*c-t.im[k]*s;im[lead+k]+=t.re[k]*s+t.im[k]*c}
  return{re,im}}

class Receiver{
  constructor(fs){this.fs=fs;this.cap=1<<16;this.r=new Float64Array(this.cap);this.i=new Float64Array(this.cap);this.fr=new Float64Array(this.cap);this.fi=new Float64Array(this.cap);this.flen=0;this.len=0;this.base=0;this.pos=0;this.thr=.25;this.px=0;this.py=0;this.dx=0;this.dy=0;this.detections=0}
  push(re,im){const add=re.length;
    if(this.len+add>this.cap){while(this.len+add>this.cap)this.cap*=2;for(const k of['r','i','fr','fi']){const a=new Float64Array(this.cap);a.set(this[k].subarray(0,this.len));this[k]=a}}
    for(let k=0;k<add;k++){this.dx=re[k]-this.px+.999*this.dx;this.dy=im[k]-this.py+.999*this.dy;this.px=re[k];this.py=im[k];this.r[this.len]=this.dx;this.i[this.len]=this.dy;this.len++}
    for(let n=this.flen;n+L<=this.len;n++){let a=0,b=0;for(let j=0;j<L;j++){a+=this.r[n+j]*H[j];b+=this.i[n+j]*H[j]}this.fr[n]=a;this.fi[n]=b;this.flen=n+1}
    const out=[];for(;;){const s=this.step();if(s===null)break;if(s!==true)out.push(s)}
    if(this.pos>32768){const sh=this.pos-1024;for(const k of['r','i','fr','fi'])this[k].copyWithin(0,sh,this.len);this.len-=sh;this.flen-=sh;this.pos-=sh;this.base+=sh}
    return out}
  step(){const r=this.r,im=this.i,fr_=this.fr,fi_=this.fi,len=this.flen,D=PD,W=PW;let n=this.pos;
    if(n+W+D+1>len)return null;
    let pr=0,pi=0,r1=0,r2=0;
    const add=(a,sg)=>{const b=a+D;pr+=sg*(fr_[b]*fr_[a]+fi_[b]*fi_[a]);pi+=sg*(fi_[b]*fr_[a]-fr_[b]*fi_[a]);r1+=sg*(fr_[a]*fr_[a]+fi_[a]*fi_[a]);r2+=sg*(fr_[b]*fr_[b]+fi_[b]*fi_[b])};
    for(let k=0;k<W;k++)add(n+k,1);
    const metric=()=>{const m=Math.max(r1,r2);return m>1e-9?(pr*pr+pi*pi)/(m*m):0};
    while(metric()<=this.thr){if(n+W+D+1>=len){this.pos=n;return null}add(n,-1);add(n+W,1);n++}
    if(n+2*W+D+1>len){this.pos=n;return null}
    let bn=n,bm=metric(),bpr=pr,bpi=pi;
    for(let q=n;q<n+W;q++){add(q,-1);add(q+W,1);const m=metric();if(m>bm){bm=m;bn=q+1;bpr=pr;bpi=pi}}
    this.detections++;
    const w=Math.atan2(bpi,bpr)/D,S=40,e=bn+PRE*SPS,skip=bn+W;
    if(e-S-1<0){this.pos=skip;return true}
    if(e+S+(NSFD+NSIG)*SPS+L+2>len){this.pos=n;return null}
    const mf=(o,mu)=>{let a=0,b=0;const q=mu<0?o-1:o,f=mu<0?1+mu:mu;
      for(let j=0;j<L;j++){const k=q+j,xr=r[k]+(r[k+1]-r[k])*f,xi=im[k]+(im[k+1]-im[k])*f,c=Math.cos(w*(o+j)),s=-Math.sin(w*(o+j)),h=H[j];a+=(xr*c-xi*s)*h;b+=(xr*s+xi*c)*h}return[a,b]};
    const corr=(t,mu)=>{let cr=0,ci=0,en=0;for(let k=0;k<NSFD;k++){const[a,b]=mf(t+k*SPS,mu);cr+=a*SFD.r[k]+b*SFD.i[k];ci+=b*SFD.r[k]-a*SFD.i[k];en+=a*a+b*b}return[cr,ci,en]};
    let bt=e,bc=-1;const mag=new Float64Array(2*S+1);
    for(let t=e-S;t<=e+S;t++){const c=corr(t,0),m=c[0]*c[0]+c[1]*c[1];mag[t-e+S]=m;if(m>bc){bc=m;bt=t}}
    let mu=0;const ix=bt-e+S;if(ix>0&&ix<2*S){const a=Math.sqrt(mag[ix-1]),b=Math.sqrt(mag[ix]),c=Math.sqrt(mag[ix+1]),d=a-2*b+c;if(d<0)mu=Math.max(-.5,Math.min(.5,.5*(a-c)/d))}
    const C=corr(bt,mu),q=(C[0]*C[0]+C[1]*C[1])/(NSFD*C[2]+1e-30);
    if(q<.4){this.pos=skip;return true}
    const gr=C[0]/NSFD,gi=C[1]/NSFD,g2=gr*gr+gi*gi;let ph=0,fr=0,ev=0,es=0;
    const dem=(k0,cnt,mod,keep)=>{const soft=new Float32Array(cnt*(mod?4:2));
      for(let k=0;k<cnt;k++){const[a,b]=mf(bt+(NSFD+k0+k)*SPS,mu),yr=(a*gr+b*gi)/g2,yi=(b*gr-a*gi)/g2,c=Math.cos(ph),s=Math.sin(ph),zr=yr*c+yi*s,zi=yi*c-yr*s;let dr,di;
        if(mod){const lv=v=>{const u=v/K16;return(u<-2?-3:u<0?-1:u<2?1:3)*K16};dr=lv(zr);di=lv(zi);soft[4*k]=zr;soft[4*k+1]=2*K16-Math.abs(zr);soft[4*k+2]=zi;soft[4*k+3]=2*K16-Math.abs(zi)}
        else{dr=zr<0?-Q:Q;di=zi<0?-Q:Q;soft[2*k]=zr;soft[2*k+1]=zi}
        const er=(zi*dr-zr*di)/(dr*dr+di*di);ph+=.06*er+fr;fr+=.0008*er;
        if(keep){ev+=(zr-dr)**2+(zi-di)**2;es+=dr*dr+di*di;if(keep.r.length<800){keep.r.push(zr);keep.i.push(zi)}}}
      return soft};
    const sb=viterbi(dem(0,NSIG,0,null),16);let v=0;for(let k=0;k<16;k++)v=(v<<1)|sb[k];
    const chk=v&15,body=v>>4,flen=body>>1,mod=body&1;
    if(chk!==(((body>>8)^(body>>4)^body^0xA)&15)||flen<9){this.pos=skip;return true}
    const ns=paySyms(flen,mod),end=bt+(NSFD+NSIG+ns)*SPS;
    if(end+L+2>len){this.pos=n;return null}
    const keep={r:[],i:[]},bytes=scramble(toBytes(viterbi(dem(NSIG,ns,mod,keep),flen*8)));
    const ok=crc16(bytes,flen-2)===((bytes[flen-2]<<8)|bytes[flen-1]);
    const ps=bt-(PRE+LEAD.r.length)*SPS;let pw=0;for(let k=bt;k<end;k++)pw+=fr_[k]*fr_[k]+fi_[k]*fi_[k];pw/=end-bt;
    let fl=null;if(ps-160>=0){let a=0;for(let k=ps-160;k<ps-32;k++)a+=fr_[k]*fr_[k]+fi_[k]*fi_[k];fl=10*Math.log10(a/128+1e-12)}
    this.pos=end+TAIL.r.length*SPS/2;
    return{ok,bytes,mod,len:flen,syms:keep,start:this.base+ps,stats:{snrDb:10*Math.log10(es/(ev+1e-12)),cfoHz:(w+fr/SPS)*this.fs/(2*Math.PI),rssiDb:10*Math.log10(pw+1e-12),floorDb:fl,sync:q,airMs:(LEAD.r.length+PRE+NSFD+NSIG+ns+TAIL.r.length)*SPS/this.fs*1e3}}}}

const overheadSyms=LEAD.r.length+PRE+NSFD+NSIG+TAIL.r.length;
function airtime(len,mod,fs){return(overheadSyms+paySyms(len,mod))*SPS/fs}
function bitRate(mod,fs){return fs/SPS*(mod?4:2)/2}
function toInterleaved(t){const o=new Float32Array(t.re.length*2);for(let k=0;k<t.re.length;k++){o[2*k]=t.re[k];o[2*k+1]=t.im[k]}return o}
return{SPS,tx,channel,Receiver,buildFrame,parseFrame,crc16,convEnc,viterbi,toBits,toBytes,airtime,bitRate,toInterleaved,rng,gauss,overheadSyms,paySyms}})();
if(typeof module!=='undefined')module.exports=Modem;
