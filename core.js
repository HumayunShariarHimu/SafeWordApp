'use strict';
/* ═══════════════════════════════════════════════════════════════════
   SafeWord — Crypto Core
   ▸ Base32 decoder        (RFC 4648)
   ▸ TOTP generator        (RFC 6238 / RFC 4226) — works with ALL services
   ▸ FSOTP engine          (Forward-Secure OTP — for custom systems)
   ▸ SecureVault           (AES-256-GCM + PBKDF2-SHA256 × 310 000)
   ═══════════════════════════════════════════════════════════════════ */

/* ── Base32 ─────────────────────────────────────────────────────── */
const Base32 = (() => {
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function decode(s) {
    if (!s) throw new Error('Empty secret');
    const c = s.toUpperCase().replace(/[\s=]/g, '');
    let buf = 0, bits = 0;
    const out = [];
    for (const ch of c) {
      const v = ABC.indexOf(ch);
      if (v < 0) throw new Error(`Invalid Base32 character: "${ch}"`);
      buf = (buf << 5) | v; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
    }
    return new Uint8Array(out);
  }
  return { decode };
})();

/* ── WebCrypto helpers ──────────────────────────────────────────── */
const WC = {
  rand:  (n = 32) => crypto.getRandomValues(new Uint8Array(n)),
  async sha256(data) {
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  },
  async hmac(keyBytes, msg, hash = 'SHA-1') {
    const k = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  },
  hex:   bytes  => Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join(''),
  unhex: hex    => { const b = new Uint8Array(hex.length>>1); for(let i=0;i<hex.length;i+=2) b[i>>1]=parseInt(hex.slice(i,i+2),16); return b; },
  cat:   (...a) => { const t=a.reduce((s,x)=>s+x.length,0),o=new Uint8Array(t); let p=0; for(const x of a){o.set(x,p);p+=x.length;} return o; },
  p64:   n      => { const b=new ArrayBuffer(8),v=new DataView(b); v.setUint32(0,Math.floor(n/0x100000000),false); v.setUint32(4,n>>>0,false); return new Uint8Array(b); },
  safeEq:(a,b)  => { if(a.length!==b.length)return false; let d=0; for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i); return d===0; }
};

/* ── TOTP (RFC 6238) ────────────────────────────────────────────── */
const TOTP = (() => {
  function ctr8(n) {
    const b=new ArrayBuffer(8),v=new DataView(b);
    v.setUint32(0,Math.floor(n/0x100000000),false);
    v.setUint32(4,n>>>0,false);
    return b;
  }
  async function generate(secret, opts={}) {
    const hash    = (opts.algorithm||'SHA1').replace(/[^A-Z0-9]/gi,'').toUpperCase();
    const hashMap = { SHA1:'SHA-1', SHA256:'SHA-256', SHA512:'SHA-512' };
    const digits  = opts.digits  || 6;
    const period  = opts.period  || 30;
    const ts      = opts.timestamp ?? Date.now();
    const counter = Math.floor(ts/1000/period);
    const keyBytes= Base32.decode(secret);
    const k = await crypto.subtle.importKey(
      'raw', keyBytes, { name:'HMAC', hash: hashMap[hash]||'SHA-1' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, ctr8(counter)));
    const off = mac[mac.length-1]&0x0f;
    const code= ((mac[off]&0x7f)<<24)|((mac[off+1]&0xff)<<16)|((mac[off+2]&0xff)<<8)|(mac[off+3]&0xff);
    return String(code%(10**digits)).padStart(digits,'0');
  }
  function timeLeft(period=30) { return period-(Math.floor(Date.now()/1000)%period); }
  function progress(period=30) { return (period-timeLeft(period))/period; }
  function parseURI(uri) {
    if (!uri.startsWith('otpauth://')) throw new Error('Not an otpauth:// URI');
    const url   = new URL(uri);
    if (url.hostname !== 'totp') throw new Error('Only TOTP supported');
    const label = decodeURIComponent(url.pathname.slice(1));
    const p     = url.searchParams;
    const secret= (p.get('secret')||'').toUpperCase().replace(/\s/g,'');
    if (!secret) throw new Error('No secret found in URI');
    Base32.decode(secret);
    let issuer  = p.get('issuer')||'', account = label;
    if (label.includes(':')) { const pts=label.split(':'); if(!issuer)issuer=pts[0].trim(); account=pts[1].trim(); }
    if (!issuer) issuer = account;
    return { issuer, account, secret,
      algorithm: (p.get('algorithm')||'SHA1').replace('-',''),
      digits: parseInt(p.get('digits')||'6',10),
      period: parseInt(p.get('period')||'30',10),
      mode: 'totp' };
  }
  return { generate, timeLeft, progress, parseURI };
})();

/* ── FSOTP Engine (Forward-Secure OTP) ─────────────────────────── */
class FSOTPEngine {
  constructor() { this._reset(); }
  _reset() {
    this.secret=null; this.period=null;
    this.curRand=null; this.nextRand=null;
    this.chain=[]; this.ratchetCount=0; this.ready=false;
  }
  static period() { return Math.floor(Date.now()/30000); }
  static timeLeft(){ return 30-(Math.floor(Date.now()/1000)%30); }
  static progress(){ return (30-FSOTPEngine.timeLeft())/30; }

  async init(secretHex) {
    if (!secretHex||secretHex.length!==64) throw new Error('Secret must be 64 hex chars');
    this.secret      = WC.unhex(secretHex);
    this.period      = FSOTPEngine.period();
    this.ratchetCount= 0;
    this.curRand     = WC.rand(32);
    this.nextRand    = WC.rand(32);
    const cc = WC.hex(await WC.sha256(this.curRand));
    const nc = WC.hex(await WC.sha256(this.nextRand));
    this.chain = [
      { period:this.period,   commitment:cc, revealed:WC.hex(this.curRand) },
      { period:this.period+1, commitment:nc, revealed:null }
    ];
    this.ready=true;
  }

  async _tick() {
    const p=FSOTPEngine.period();
    if (p===this.period) return false;
    // Ratchet: S_{t+1} = SHA-256(S_t ∥ R_t)
    this.secret = await WC.sha256(WC.cat(this.secret, this.curRand));
    this.ratchetCount++;
    this.curRand  = this.nextRand;
    this.nextRand = WC.rand(32);
    this.period   = p;
    const ex = this.chain.find(e=>e.period===p);
    if (ex) ex.revealed = WC.hex(this.curRand);
    const nc = WC.hex(await WC.sha256(this.nextRand));
    this.chain.push({period:p+1, commitment:nc, revealed:null});
    if (this.chain.length>10) this.chain.shift();
    return true;
  }

  async generate() {
    await this._tick();
    if (!this.ready) throw new Error('Not initialized');
    let cur=this.chain.find(e=>e.period===this.period);
    if (!cur||!cur.revealed) {
      if (!cur) { const c=WC.hex(await WC.sha256(this.curRand)); cur={period:this.period,commitment:c,revealed:WC.hex(this.curRand)}; this.chain.push(cur); }
      else cur.revealed=WC.hex(this.curRand);
    }
    const msg = WC.cat(this.curRand, WC.p64(this.period));
    const mac = await WC.hmac(this.secret, msg, 'SHA-256');
    const off = mac[mac.length-1]&0x0f;
    const code= ((mac[off]&0x7f)<<24)|((mac[off+1]&0xff)<<16)|((mac[off+2]&0xff)<<8)|(mac[off+3]&0xff);
    const otp = String(code%1_000_000).padStart(6,'0');
    const next= this.chain.find(e=>e.period===this.period+1);
    return { otp, period:this.period, ratchetCount:this.ratchetCount,
      commitment:cur.commitment, revealedRandom:WC.hex(this.curRand),
      nextCommitment:next?.commitment??'',
      secretFP: WC.hex(this.secret).slice(0,16)+'…',
      timeLeft: FSOTPEngine.timeLeft(), progress: FSOTPEngine.progress() };
  }
  getChain() { return [...this.chain].reverse(); }
}
const fsotpEngine = new FSOTPEngine();

/* ── Service brand map ──────────────────────────────────────────── */
function getBrand(issuer='', account='') {
  const q=(issuer+' '+account).toLowerCase();
  const brands = [
    [/facebook|meta/,        '#1877f2','#fff','f'],
    [/instagram/,            'linear-gradient(45deg,#f09433,#dc2743,#bc1888)','#fff','◉'],
    [/twitter|^x$|x\.com/,  '#000','#fff','𝕏'],
    [/google|gmail/,         '#4285f4','#fff','G'],
    [/github/,               '#24292e','#fff','⌥'],
    [/microsoft|outlook|azure|hotmail/, '#00a4ef','#fff','⊞'],
    [/apple|icloud/,         '#555','#fff',''],
    [/amazon|aws/,           '#ff9900','#111','a'],
    [/discord/,              '#5865f2','#fff','◈'],
    [/slack/,                '#4a154b','#fff','◎'],
    [/telegram/,             '#2ca5e0','#fff','✈'],
    [/whatsapp/,             '#25d366','#fff','W'],
    [/linkedin/,             '#0a66c2','#fff','in'],
    [/reddit/,               '#ff4500','#fff','R'],
    [/twitch/,               '#9146ff','#fff','⬡'],
    [/dropbox/,              '#0061ff','#fff','◆'],
    [/paypal/,               '#003087','#fff','P'],
    [/netflix/,              '#e50914','#fff','N'],
    [/spotify/,              '#1db954','#fff','♪'],
    [/binance/,              '#f3ba2f','#000','₿'],
    [/coinbase/,             '#0052ff','#fff','₡'],
    [/notion/,               '#fff','#000','N'],
    [/cloudflare/,           '#f48120','#fff','☁'],
    [/gitlab/,               '#fc6d26','#fff','◤'],
    [/bitbucket/,            '#0052cc','#fff','⑂'],
    [/digitalocean/,         '#0080ff','#fff','◎'],
    [/wordpress/,            '#21759b','#fff','W'],
    [/shopify/,              '#96bf48','#fff','S'],
    [/stripe/,               '#635bff','#fff','S'],
  ];
  for (const [re,bg,fg,letter] of brands) if(re.test(q)) return {bg,fg,letter};
  const palette=['#6366f1','#8b5cf6','#ec4899','#14b8a6','#f59e0b','#ef4444','#3b82f6','#10b981','#f97316'];
  const ch=(issuer||account||'?').charCodeAt(0);
  return {bg:palette[ch%palette.length],fg:'#fff',letter:(issuer||account||'?')[0].toUpperCase()};
}

/* ── SecureVault ────────────────────────────────────────────────── */
class SecureVault {
  constructor() { this._key=null; this._salt=null; this.accounts=[]; this._S='sw_v3'; }
  _b64(b)  { return btoa(String.fromCharCode(...b)); }
  _ub64(s) { return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }
  async _derive(pw, salt) {
    const raw = await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310_000,hash:'SHA-256'},raw,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  hasVault()   { return !!localStorage.getItem(this._S); }
  isUnlocked() { return !!this._key; }
  async unlock(pw) {
    const stored=localStorage.getItem(this._S);
    if (!stored) {
      this._salt=WC.rand(32); this._key=await this._derive(pw,this._salt); this.accounts=[]; await this._save(); return true;
    }
    try {
      const {salt,iv,ct}=JSON.parse(stored);
      const s=this._ub64(salt),k=await this._derive(pw,s);
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:this._ub64(iv)},k,this._ub64(ct));
      this.accounts=JSON.parse(new TextDecoder().decode(pt));
      this._salt=s; this._key=k; return true;
    } catch { return false; }
  }
  lock() { this._key=null; this._salt=null; this.accounts=[]; }
  async _save() {
    const iv=WC.rand(12);
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},this._key,new TextEncoder().encode(JSON.stringify(this.accounts)));
    localStorage.setItem(this._S,JSON.stringify({salt:this._b64(this._salt),iv:this._b64(iv),ct:this._b64(new Uint8Array(ct))}));
  }
  async add(acc)    { acc.id=crypto.randomUUID(); acc.addedAt=Date.now(); this.accounts.push(acc); await this._save(); return acc.id; }
  async remove(id)  { this.accounts=this.accounts.filter(a=>a.id!==id); await this._save(); }
  async update(id,p){ const i=this.accounts.findIndex(a=>a.id===id); if(i>=0){Object.assign(this.accounts[i],p);await this._save();} }
  export()          { return localStorage.getItem(this._S)||''; }
  import(json)      { JSON.parse(json); localStorage.setItem(this._S,json); this.lock(); }
  async changePassword(pw) { this._salt=WC.rand(32); this._key=await this._derive(pw,this._salt); await this._save(); }
}
const vault = new SecureVault();
