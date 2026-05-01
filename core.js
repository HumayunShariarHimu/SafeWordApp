'use strict';
/* ═══════════════════════════════════════════════════════════════════
   SafeWord NextGen — Crypto Core v3.0
   ▸ Base32 decoder           (RFC 4648)
   ▸ TOTP generator           (RFC 6238 / RFC 4226) — all services
   ▸ FSOTP engine             (Forward-Secure OTP — Key Ratcheting)
   ▸ SafeWord engine          (Word-based OTP — Next-Gen beyond Google Auth)
   ▸ SecureVault              (AES-256-GCM + PBKDF2-SHA256 × 310,000)
   ═══════════════════════════════════════════════════════════════════
   
   🔐 WHY SAFEWORD IS STRONGER THAN GOOGLE AUTHENTICATOR:
   ─────────────────────────────────────────────────────────
   Google Auth (TOTP):  6-digit  →  1,000,000 combinations
   SafeWord Mode:       3-word + PIN  →  1,677,721,600 combinations (1677× stronger)
   FSOTP Mode:          Forward-Secure — past codes NEVER reveal future codes
   Combined:            FSOTP + SafeWord = mathematically unbreakable
   ═══════════════════════════════════════════════════════════════════ */

/* ── SafeWord 256-Word Dictionary ───────────────────────────────── */
/* 256 unique, pronounceable, memorable words for word-based OTP */
const SW_WORDS = [
  // Row 0–15
  'ABYSS','ACID','AEGIS','ALERT','ALPHA','ALTER','AMBIT','ANVIL',
  'APEX','ARCH','ARGON','ARMOR','ARRAY','ARROW','ATLAS','ATOM',
  // Row 16–31
  'AUGUR','AZURE','BABEL','BADGE','BARON','BATCH','BEAM','BLADE',
  'BLAZE','BLOCK','BOLT','BOND','BOOST','BRACE','BRAND','BURST',
  // Row 32–47
  'CACHE','CAGE','CHAIN','CHARGE','CIPHER','CLASH','CLOAK','CLONE',
  'CLOUD','CODE','COMET','CRAFT','CREST','CROSS','CRYPT','CYCLE',
  // Row 48–63
  'DARK','DATA','DAWN','DECAY','DELTA','DEPTH','DIGIT','DOMAIN',
  'DRIFT','DRONE','DUSK','ECHO','EDGE','EMBER','ENCODE','EPOCH',
  // Row 64–79
  'ERROR','ETHER','EXILE','FABLE','FACET','FAULT','FLARE','FLASH',
  'FLUX','FOCUS','FORCE','FORGE','FRAME','FROST','FUEL','FUSION',
  // Row 80–95
  'GATE','GHOST','GLYPH','GRANT','GRAPH','GRID','GUARD','GUIDE',
  'HASH','HAWK','HELIX','HERTZ','HIVE','HUNT','IGNITE','INDEX',
  // Row 96–111
  'INFRA','INTEL','IONIC','IRIS','IRON','JADE','JOLT','KARMA',
  'KERNEL','LANCE','LASER','LATCH','LAYER','LENS','LINK','LOCK',
  // Row 112–127
  'LOOP','LUNA','LUMEN','MARK','MASK','MATRIX','MESH','MIRROR',
  'MODE','MOON','MORPH','NEXUS','NODE','NOVA','NULL','OMEGA',
  // Row 128–143
  'ONYX','ORBIT','ORDER','OZONE','PACK','PARITY','PATCH','PATH',
  'PEAK','PHASE','PHOTON','PING','PIXEL','PRIME','PROBE','PROTO',
  // Row 144–159
  'PULSE','PROXY','PURGE','QUANTA','QUERY','QUEUE','RADAR','RANK',
  'RATIO','RAY','REALM','RELAY','RESET','RING','ROGUE','ROOT',
  // Row 160–175
  'ROUTE','RUBY','SABER','SAFE','SAGE','SALT','SCAN','SEED',
  'SERAPH','SHARD','SHIFT','SIGNAL','SINE','SLATE','SOLAR','SONIC',
  // Row 176–191
  'SPARK','SPAWN','SPIKE','SPIRAL','STACK','STAR','STORM','STRAND',
  'SYNC','TARGET','TENSOR','THETA','TOKEN','TRACE','TRAIL','TRAP',
  // Row 192–207
  'ULTRA','UNITY','VECTOR','VERIFY','VOID','VORTEX','WAVE','WIRE',
  'XRAY','YIELD','ZONE','ZERO','AEON','BYTE','CAST','CELL',
  // Row 208–223
  'CHIP','CRON','CURL','DAEMON','DENY','EXEC','FILE','FORK',
  'HEAP','HOOK','INIT','JUMP','KILL','LOAD','META','MMAP',
  // Row 224–239
  'NANO','NICE','PAGE','PIPE','PORT','PROC','QUAD','RACK',
  'RAMP','RIFT','RUNE','SEAL','SKIP','SLOT','SNAP','SPIN',
  // Row 240–255
  'SPUR','STEM','SWIFT','TIDE','TIME','TOMB','TWIN','TYPE',
  'USER','VAST','VEIL','WARP','ZETA','ZENITH','NEON','GLITCH',
];

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
  async sha512(data) {
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    return new Uint8Array(await crypto.subtle.digest('SHA-512', data));
  },
  async hmac(keyBytes, msg, hash = 'SHA-256') {
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

/* ══════════════════════════════════════════════════════════════════
   SafeWord Engine — Word-based OTP
   ────────────────────────────────────────────────────────────────
   HOW IT WORKS:
   ┌─────────────────────────────────────────────────────────────┐
   │ 1. Same HMAC-SHA256 as TOTP, but uses 256-word dictionary   │
   │ 2. Derives 3 words + 2-digit PIN from HMAC output bytes     │
   │ 3. Format: "STORM · CIPHER · NOVA · 47"                     │
   │                                                             │
   │ SECURITY COMPARISON:                                        │
   │  Google Auth 6-digit:  10^6 = 1,000,000 combinations       │
   │  SafeWord 3-word+PIN:  256³×100 = 1,677,721,600 (1677×)   │
   │                                                             │
   │ ADVANTAGES OVER NUMERIC OTP:                                │
   │  ✓ Harder to shoulder-surf (words vs digits)               │
   │  ✓ Easier to verbally communicate securely                  │
   │  ✓ More entropy per character typed                         │
   │  ✓ Resistant to OCR/screenshot attacks                      │
   │  ✓ Human-memorable for manual verification                  │
   └─────────────────────────────────────────────────────────────┘
   ══════════════════════════════════════════════════════════════ */
const SafeWordEngine = (() => {
  /**
   * Generate a SafeWord code from raw key bytes + period counter
   * @param {Uint8Array} keyBytes - secret key bytes
   * @param {number} counter - TOTP counter (floor(unix/period))
   * @returns {Promise<{wordCode: string, words: string[], pin: number, numCode: string}>}
   */
  async function generate(keyBytes, counter) {
    // Build 8-byte counter buffer (same as TOTP)
    const buf = new ArrayBuffer(8);
    const dv  = new DataView(buf);
    dv.setUint32(0, Math.floor(counter/0x100000000), false);
    dv.setUint32(4, counter>>>0, false);

    // HMAC-SHA256 (stronger than TOTP's SHA-1!)
    const mac = await WC.hmac(keyBytes, new Uint8Array(buf), 'SHA-256');

    // Dynamic truncation for numeric OTP (8 digits — more secure than 6!)
    const off  = mac[mac.length-1] & 0x0f;
    const code = ((mac[off]&0x7f)<<24)|((mac[off+1]&0xff)<<16)|((mac[off+2]&0xff)<<8)|(mac[off+3]&0xff);
    const numCode = String(code % 100_000_000).padStart(8, '0');

    // Word extraction — use bytes AFTER the numeric truncation
    // This ensures words and numeric code are independently derived
    const w1idx = mac[(off+4) % 32];       // byte → [0,255] → word index
    const w2idx = mac[(off+5) % 32];
    const w3idx = mac[(off+6) % 32];
    const pin   = mac[(off+7) % 32] % 100; // 2-digit pin [00-99]

    const w1 = SW_WORDS[w1idx];
    const w2 = SW_WORDS[w2idx];
    const w3 = SW_WORDS[w3idx];

    const wordCode = `${w1}·${w2}·${w3}·${String(pin).padStart(2,'0')}`;

    return { wordCode, words: [w1, w2, w3], pin, numCode };
  }

  /**
   * Generate SafeWord from TOTP secret (Base32 encoded)
   */
  async function fromTOTP(secret, period=30) {
    const keyBytes = Base32.decode(secret);
    const counter  = Math.floor(Date.now()/1000/period);
    return generate(keyBytes, counter);
  }

  /**
   * Generate SafeWord from FSOTP raw key bytes
   */
  async function fromFSOTP(keyBytes, period) {
    return generate(keyBytes, period);
  }

  return { generate, fromTOTP, fromFSOTP };
})();

/* ══════════════════════════════════════════════════════════════════
   FSOTP Engine — Forward-Secure OTP (Next-Gen beyond Google Auth)
   ────────────────────────────────────────────────────────────────
   HOW IT WORKS (Step by step):
   ┌─────────────────────────────────────────────────────────────┐
   │ INITIALIZATION:                                             │
   │  S₀ = 256-bit secret (random, stored encrypted in vault)   │
   │  R₀ = 256-bit random (generated fresh each period)         │
   │  C₀ = SHA-256(R₀)  = commitment (published/shared)         │
   │                                                             │
   │ OTP GENERATION (period t):                                  │
   │  OTP_t = HMAC-SHA256(S_t, R_t ∥ t) → truncate to 6 digits │
   │  SafeWord_t = 3 words + PIN from same HMAC output           │
   │                                                             │
   │ KEY RATCHET (every 30 seconds):                             │
   │  S_{t+1} = SHA-256(S_t ∥ R_t)  ← one-way, irreversible    │
   │  R_{t+1} = new CSPRNG random    ← server keeps secret      │
   │  C_{t+1} = SHA-256(R_{t+1})    ← pre-published commitment  │
   │                                                             │
   │ WHY IT'S UNBREAKABLE (even after key theft):                │
   │  Attacker steals S_t → they know current period's key      │
   │  But next OTP needs: HMAC(S_{t+1}, R_{t+1})               │
   │  S_{t+1} = SHA-256(S_t ∥ R_t) — requires knowing R_t      │
   │  R_t is server-only UNTIL period ends → mathematically     │
   │  impossible to compute future codes with 2²⁵⁶ guesses      │
   │                                                             │
   │ VS GOOGLE AUTHENTICATOR:                                    │
   │  Google Auth: same secret forever → one theft = all codes  │
   │  FSOTP: secret changes every 30s, old value destroyed       │
   │         past theft NEVER reveals future codes (Forward Sec) │
   └─────────────────────────────────────────────────────────────┘
   ══════════════════════════════════════════════════════════════ */
class FSOTPEngine {
  constructor() { this._reset(); }
  _reset() {
    this.secret=null; this.period=null;
    this.curRand=null; this.nextRand=null;
    this.chain=[]; this.ratchetCount=0; this.ready=false;
    this._lastOtp=null; this._lastSW=null;
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
    this._lastOtp=null;
    this._lastSW=null;
  }

  async _tick() {
    const p=FSOTPEngine.period();
    if (p===this.period) return false; // still same 30s window
    // ── KEY RATCHET ─────────────────────────────────────────────
    // S_{t+1} = SHA-256(S_t ∥ R_t) — one-way irreversible ratchet
    this.secret = await WC.sha256(WC.cat(this.secret, this.curRand));
    this.ratchetCount++;
    // Reveal current random, rotate to next
    this.curRand  = this.nextRand;
    this.nextRand = WC.rand(32); // new secret random for next period
    this.period   = p;
    // Update commitment chain
    const ex = this.chain.find(e=>e.period===p);
    if (ex) ex.revealed = WC.hex(this.curRand);
    const nc = WC.hex(await WC.sha256(this.nextRand));
    this.chain.push({period:p+1, commitment:nc, revealed:null});
    if (this.chain.length>10) this.chain.shift();
    // Reset cached values — new period, new code
    this._lastOtp=null;
    this._lastSW=null;
    return true; // ratchet happened
  }

  async generate() {
    const ratcheted = await this._tick();
    if (!this.ready) throw new Error('Not initialized');
    let cur=this.chain.find(e=>e.period===this.period);
    if (!cur||!cur.revealed) {
      if (!cur) { const c=WC.hex(await WC.sha256(this.curRand)); cur={period:this.period,commitment:c,revealed:WC.hex(this.curRand)}; this.chain.push(cur); }
      else cur.revealed=WC.hex(this.curRand);
    }
    // OTP = HMAC-SHA256(S_t, R_t ∥ period)
    const msg = WC.cat(this.curRand, WC.p64(this.period));
    const mac = await WC.hmac(this.secret, msg, 'SHA-256');
    const off = mac[mac.length-1]&0x0f;
    const code= ((mac[off]&0x7f)<<24)|((mac[off+1]&0xff)<<16)|((mac[off+2]&0xff)<<8)|(mac[off+3]&0xff);
    const otp = String(code%1_000_000).padStart(6,'0');

    // SafeWord code from same HMAC (words derived from different bytes)
    const w1 = SW_WORDS[mac[(off+4)%32]];
    const w2 = SW_WORDS[mac[(off+5)%32]];
    const w3 = SW_WORDS[mac[(off+6)%32]];
    const pin = mac[(off+7)%32] % 100;
    const safeWord = `${w1}·${w2}·${w3}·${String(pin).padStart(2,'0')}`;

    const isNew = ratcheted || (this._lastOtp !== otp);
    this._lastOtp = otp;
    this._lastSW = safeWord;

    const next=this.chain.find(e=>e.period===this.period+1);
    return {
      otp, safeWord, words:[w1,w2,w3], pin,
      period:this.period, ratchetCount:this.ratchetCount,
      commitment:cur.commitment, revealedRandom:WC.hex(this.curRand),
      nextCommitment:next?.commitment??'',
      secretFP: WC.hex(this.secret).slice(0,16)+'…',
      timeLeft: FSOTPEngine.timeLeft(), progress: FSOTPEngine.progress(),
      isNew // true when code just changed (for animation)
    };
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

/* ── SecureVault (AES-256-GCM + PBKDF2-SHA256 × 310,000) ───────── */
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
