'use strict';
/* ═══════════════════════════════════════════════════════════════
   SafeWord NextGen — App Controller v3.0
   FIXES:
   ✅ FSOTP OTP now properly animates on 30s change
   ✅ Prominent countdown timer on all cards
   ✅ SafeWord (word-based) display mode
   ✅ Period tracking prevents stale renders
   ═══════════════════════════════════════════════════════════════ */

let _screen='lock', _ticker=null, _lockTimer=null, _clipTimer=null;
let _idleMs=60_000, _delTarget=null, _addPending=null;
let _fsData=null;
let _lastFsOtp=''; // track previous FSOTP OTP for change detection
let _swMode=false; // SafeWord display mode toggle
let _fsRendering=false; // prevent concurrent FSOTP renders

const $=id=>document.getElementById(id);
const $$=s=>document.querySelectorAll(s);
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

/* ── Screen router ──────────────────────────────────────────── */
function show(s){
  _screen=s;
  $$('[data-screen]').forEach(el=>el.classList.toggle('active',el.dataset.screen===s));
  if(s!=='add'&&scanner.isActive()) scanner.stop();
  if(s==='add') { switchAddTab('qr'); }
  if(s==='settings') renderSettings();
  if(s==='main')     { renderTOTP(); if(vault.accounts.find(a=>a.mode==='fsotp')) renderFSOTPCards(); }
  if(s==='fsotp-detail') renderFSOTPDetail();
  if(s==='how-it-works') renderHowItWorks();
  resetIdle();
}

/* ── Lock / Unlock ──────────────────────────────────────────── */
async function doUnlock(){
  const pw=$('lock-pw').value;
  if(!pw){toast('Enter your master password','error');return;}
  const btn=$('lock-btn');
  btn.disabled=true; btn.textContent='Decrypting…';
  const ok=await vault.unlock(pw);
  btn.disabled=false; btn.textContent=vault.hasVault()?'Unlock Vault':'Create Vault';
  $('lock-pw').value='';
  if(!ok){
    toast('Wrong password — vault remains locked','error');
    $('lock-card').classList.add('shake');
    setTimeout(()=>$('lock-card').classList.remove('shake'),600);
    return;
  }
  show('main'); startTicker(); resetIdle();
}

function doLock(){
  vault.lock(); fsotpEngine._reset();
  clearInterval(_ticker); clearTimeout(_lockTimer); clearTimeout(_clipTimer);
  scanner.stop(); _ticker=null; _fsData=null; _lastFsOtp='';
  show('lock'); updateLockUI();
}

function updateLockUI(){
  const has=vault.hasVault();
  $('lock-title').textContent   =has?'Welcome Back':'Create Vault';
  $('lock-sub').textContent     =has?'Enter master password to unlock your vault':'Set a strong master password to protect your accounts';
  $('lock-btn').textContent     =has?'Unlock Vault':'Create Vault';
  $('lock-reset').style.display =has?'block':'none';
}

/* ── Idle auto-lock ─────────────────────────────────────────── */
function resetIdle(){
  if(!vault.isUnlocked()) return;
  clearTimeout(_lockTimer);
  _lockTimer=setTimeout(doLock,_idleMs);
}
['mousedown','keydown','touchstart','scroll','pointermove'].forEach(e=>
  document.addEventListener(e,resetIdle,{passive:true}));

/* ── Ticker — runs every 200ms for smooth timer ─────────────── */
function startTicker(){
  if(_ticker) clearInterval(_ticker);
  renderAll();
  _ticker=setInterval(renderAll,200); // 200ms for smoother countdown
}

async function renderAll(){
  if(!vault.isUnlocked()) return;
  await renderTOTP();
  const fsAccs=vault.accounts.filter(a=>a.mode==='fsotp');
  if(fsAccs.length&&fsotpEngine.ready) await renderFSOTPCards();
}

/* ══════════════════════════════════════════════════════════════
   TOTP Rendering — with prominent timer
══════════════════════════════════════════════════════════════ */
async function renderTOTP(){
  const wrap=$('totp-wrap');
  if(!wrap||(_screen!=='main')) return;
  const accs=vault.accounts.filter(a=>a.mode==='totp'||!a.mode);
  if(!accs.length){
    wrap.innerHTML=`<div class="empty-state">
      <div class="empty-icon">🔐</div>
      <p class="empty-t">No TOTP Accounts</p>
      <p class="empty-s">Tap <b>+</b> to add Facebook, Google, GitHub…</p>
    </div>`;
    return;
  }
  const now=Date.now();
  const results=await Promise.all(accs.map(async a=>{
    const otp=await TOTP.generate(a.secret,{algorithm:a.algorithm,digits:a.digits,period:a.period,timestamp:now}).catch(()=>'------');
    let swCode='';
    if(_swMode){
      try{
        const sw=await SafeWordEngine.fromTOTP(a.secret,a.period||30);
        swCode=sw.wordCode;
      }catch{}
    }
    return{otp,swCode};
  }));

  wrap.innerHTML=accs.map((acc,i)=>{
    const {otp,swCode}=results[i];
    const left=TOTP.timeLeft(acc.period), prog=TOTP.progress(acc.period);
    const brand=getBrand(acc.issuer,acc.account), urgent=left<=5;
    const circ=2*Math.PI*16, off=circ*(1-prog);
    const fmt=otp.length===6?otp.slice(0,3)+' '+otp.slice(3):otp.slice(0,4)+' '+otp.slice(4);

    const swHtml=_swMode&&swCode?`
      <div class="safeword-row" onclick="copyOTP('${acc.id}','${swCode}')" title="Click to copy SafeWord">
        <span class="sw-label">SafeWord</span>
        <span class="sw-code">${esc(swCode)}</span>
      </div>`:''

    return `<div class="acc-card glass" id="card-${acc.id}">
      <div class="acc-brand" style="background:${brand.bg};color:${brand.fg}">${esc(brand.letter)}</div>
      <div class="acc-info">
        <div class="acc-issuer">${esc(acc.issuer||acc.account)}</div>
        <div class="acc-account">${esc(acc.account)}</div>
        ${swHtml}
      </div>
      <div class="acc-right">
        <div class="acc-otp-wrap">
          <div class="acc-otp ${urgent?'urgent':''}" onclick="copyOTP('${acc.id}','${otp}')" title="Tap to copy">${fmt}</div>
          <div class="acc-countdown ${urgent?'urgent':''}">
            <div class="countdown-track"><div class="countdown-fill ${urgent?'urgent':''}" style="width:${((1-prog)*100).toFixed(1)}%"></div></div>
            <span class="countdown-secs ${urgent?'urgent':''}">${left}s</span>
          </div>
        </div>
        <div class="acc-ring-wrap">
          <svg width="36" height="36" viewBox="0 0 36 36">
            <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="3"/>
            <circle cx="18" cy="18" r="16" fill="none"
              stroke="${urgent?'var(--neon-red)':'var(--neon-cyan)'}" stroke-width="3"
              stroke-linecap="round"
              stroke-dasharray="${circ.toFixed(2)}"
              stroke-dashoffset="${off.toFixed(2)}"
              transform="rotate(-90 18 18)"
              style="transition:stroke-dashoffset .2s linear${urgent?';filter:drop-shadow(0 0 4px var(--neon-red))':';filter:drop-shadow(0 0 3px var(--neon-cyan))'}"/>
          </svg>
        </div>
      </div>
      <button class="acc-del" onclick="confirmDel('${acc.id}')">✕</button>
    </div>`;
  }).join('');
}

/* ══════════════════════════════════════════════════════════════
   FSOTP Rendering — FIXED: proper animation + SafeWord
══════════════════════════════════════════════════════════════ */
async function renderFSOTPCards(){
  if(_fsRendering) return; // prevent concurrent renders
  _fsRendering=true;
  try{
    const wrap=$('fsotp-wrap');
    if(!wrap) return;
    const accs=vault.accounts.filter(a=>a.mode==='fsotp');
    if(!accs.length){ wrap.innerHTML=''; return; }

    // Init engine if needed
    if(!fsotpEngine.ready){
      const acc=accs[0];
      await fsotpEngine.init(acc.secret);
    }

    // Generate OTP — this internally calls _tick() which ratchets every 30s
    _fsData=await fsotpEngine.generate();
    const acc=accs[0];
    const brand=getBrand(acc.issuer||'SafeWord',acc.account);
    const prog=_fsData.progress;
    const circ=2*Math.PI*16, ringOff=circ*(1-prog);
    const urgent=_fsData.timeLeft<=5;
    const fmt=_fsData.otp.slice(0,3)+' '+_fsData.otp.slice(3);

    // ── CHANGE DETECTION ── Flash animation when OTP changes
    const otpChanged=(_lastFsOtp!=='' && _lastFsOtp!==_fsData.otp);
    if(otpChanged) _lastFsOtp=_fsData.otp;
    else if(_lastFsOtp==='') _lastFsOtp=_fsData.otp;

    const swHtml=_swMode?`
      <div class="safeword-row fsotp-sw" onclick="event.stopPropagation();copyText2('${esc(_fsData.safeWord)}')" title="Copy SafeWord">
        <span class="sw-label">SafeWord</span>
        <span class="sw-code">${esc(_fsData.safeWord)}</span>
      </div>`:'';

    wrap.innerHTML=`<div class="acc-card glass fsotp-card ${otpChanged?'code-changed':''}" id="card-${acc.id}" onclick="show('fsotp-detail')">
      <div class="acc-brand fsotp-brand" style="background:${brand.bg};color:${brand.fg}">${esc(brand.letter)}</div>
      <div class="acc-info">
        <div class="acc-issuer">${esc(acc.issuer||'Custom System')}<span class="fs-badge">FS-OTP</span></div>
        <div class="acc-account">${esc(acc.account)}</div>
        ${swHtml}
      </div>
      <div class="acc-right">
        <div class="acc-otp-wrap">
          <div class="acc-otp fsotp-otp ${urgent?'urgent':''}" onclick="event.stopPropagation();copyOTP('${acc.id}','${_fsData.otp}')" title="Tap to copy">${fmt}</div>
          <div class="acc-countdown ${urgent?'urgent':''}">
            <div class="countdown-track"><div class="countdown-fill fsotp-fill ${urgent?'urgent':''}" style="width:${((1-prog)*100).toFixed(1)}%"></div></div>
            <span class="countdown-secs fsotp-secs ${urgent?'urgent':''}">${_fsData.timeLeft}s</span>
          </div>
        </div>
        <div class="acc-ring-wrap">
          <svg width="36" height="36" viewBox="0 0 36 36">
            <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="3"/>
            <circle cx="18" cy="18" r="16" fill="none"
              stroke="${urgent?'var(--neon-red)':'var(--neon-purple)'}" stroke-width="3"
              stroke-linecap="round"
              stroke-dasharray="${circ.toFixed(2)}"
              stroke-dashoffset="${ringOff.toFixed(2)}"
              transform="rotate(-90 18 18)"
              style="transition:stroke-dashoffset .2s linear"/>
          </svg>
        </div>
      </div>
      <button class="acc-del" onclick="event.stopPropagation();confirmDel('${acc.id}')">✕</button>
    </div>
    <div class="fsotp-security-bar">
      <span class="fsbar-item">🔑 Ratchet #${_fsData.ratchetCount}</span>
      <span class="fsbar-sep">·</span>
      <span class="fsbar-item">🔒 Forward-Secure</span>
      <span class="fsbar-sep">·</span>
      <span class="fsbar-item detail-link" onclick="show('fsotp-detail')">Details →</span>
    </div>`;
  }finally{
    _fsRendering=false;
  }
}

/* ── FSOTP Detail Screen ────────────────────────────────────── */
async function renderFSOTPDetail(){
  if(!_fsData){
    if(!fsotpEngine.ready){
      const acc=vault.accounts.find(a=>a.mode==='fsotp');
      if(acc) await fsotpEngine.init(acc.secret);
    }
    _fsData=await fsotpEngine.generate();
  }
  const d=_fsData;
  $('fs-otp').textContent    =d.otp.slice(0,3)+' '+d.otp.slice(3);
  $('fs-period').textContent =d.period;
  $('fs-ratchet').textContent=d.ratchetCount;
  $('fs-keyfp').textContent  =d.secretFP;
  $('fs-commit').textContent =d.commitment;
  $('fs-rand').textContent   =d.revealedRandom;
  $('fs-nextcommit').textContent=d.nextCommitment;

  // Update SafeWord display
  if($('fs-safeword')) $('fs-safeword').textContent=d.safeWord||'—';
  if($('fs-sw-w1')) $('fs-sw-w1').textContent=d.words?.[0]||'—';
  if($('fs-sw-w2')) $('fs-sw-w2').textContent=d.words?.[1]||'—';
  if($('fs-sw-w3')) $('fs-sw-w3').textContent=d.words?.[2]||'—';
  if($('fs-sw-pin')) $('fs-sw-pin').textContent=String(d.pin??'--').padStart(2,'0');

  // Timer ring
  const prog=d.progress, circ=2*Math.PI*54, off=circ*(1-prog), urgent=d.timeLeft<=5;
  $('fs-ring').style.strokeDashoffset=off;
  $('fs-ring').style.stroke=urgent?'var(--neon-red)':'var(--neon-purple)';
  $('fs-timeleft').textContent=d.timeLeft+'s';
  $('fs-timeleft').className=urgent?'urgent':'';

  // Update countdown bar in detail
  const bar=$('fs-detail-bar');
  if(bar){
    bar.style.width=((1-prog)*100).toFixed(1)+'%';
    bar.className='detail-countdown-fill'+(urgent?' urgent':'');
  }

  // Chain
  const chain=fsotpEngine.getChain();
  $('fs-chain').innerHTML=chain.slice(0,5).map(e=>{
    const isCur=e.period===d.period, isFut=e.period>d.period;
    return `<div class="chain-row ${isCur?'chain-cur':isFut?'chain-fut':'chain-past'}">
      <span class="chain-period">P${e.period}</span>
      <span class="chain-commit">${e.commitment.slice(0,20)}…</span>
      <span class="chain-rev ${e.revealed?'revealed':'hidden-r'}">${e.revealed?'✓ Revealed':'🔒 Hidden'}</span>
    </div>`;
  }).join('');

  // Start detail ticker for live updates
  if(_screen==='fsotp-detail'){
    setTimeout(()=>{ if(_screen==='fsotp-detail') renderFSOTPDetail(); },300);
  }
}

/* ── SafeWord Mode Toggle ───────────────────────────────────── */
function toggleSafeWordMode(){
  _swMode=!_swMode;
  const btn=$('sw-toggle');
  if(btn){
    btn.textContent=_swMode?'◎ SafeWord ON':'○ SafeWord';
    btn.classList.toggle('active',_swMode);
  }
  renderAll();
  toast(_swMode?'SafeWord mode ON — word codes visible 🔤':'SafeWord mode OFF — numeric codes only','info');
}

/* ── Main screen tabs ───────────────────────────────────────── */
function switchMainTab(t){
  ['totp','fsotp'].forEach(x=>{
    $('main-tab-'+x).classList.toggle('active',x===t);
    $('main-pane-'+x).classList.toggle('active',x===t);
  });
  if(t==='fsotp'&&fsotpEngine.ready) renderFSOTPCards();
}

/* ── Copy OTP ───────────────────────────────────────────────── */
async function copyOTP(id,otp){
  try {
    await navigator.clipboard.writeText(otp);
    toast('Copied — clipboard clears in 30s ✓','success');
    $('card-'+id)?.classList.add('copied');
    setTimeout(()=>$('card-'+id)?.classList.remove('copied'),900);
    clearTimeout(_clipTimer);
    _clipTimer=setTimeout(()=>navigator.clipboard.writeText(''),30_000);
  } catch { toast('Copy failed','error'); }
}
async function copyText(id){
  try{
    await navigator.clipboard.writeText($(id)?.textContent||'');
    toast('Copied!','success');
  }catch{ toast('Copy failed','error'); }
}
async function copyText2(str){
  try{
    await navigator.clipboard.writeText(str);
    toast('SafeWord copied!','success');
  }catch{ toast('Copy failed','error'); }
}

/* ── Delete ─────────────────────────────────────────────────── */
function confirmDel(id){
  _delTarget=id;
  const acc=vault.accounts.find(a=>a.id===id);
  $('del-name').textContent=acc?esc(acc.issuer||acc.account):'this account';
  $('del-modal').classList.remove('hidden');
}
async function doDel(){
  if(!_delTarget) return;
  const acc=vault.accounts.find(a=>a.id===_delTarget);
  await vault.remove(_delTarget);
  if(acc?.mode==='fsotp'){ fsotpEngine._reset(); _fsData=null; _lastFsOtp=''; }
  _delTarget=null; $('del-modal').classList.add('hidden');
  renderAll(); toast('Account removed','info');
}
function cancelDel(){ _delTarget=null; $('del-modal').classList.add('hidden'); }

/* ── Add account ────────────────────────────────────────────── */
function switchAddTab(t){
  ['qr','manual','uri'].forEach(x=>{
    $('atab-'+x).classList.toggle('active',x===t);
    $('apane-'+x).classList.toggle('active',x===t);
  });
  if(t==='qr') startScanner(); else if(scanner.isActive()) scanner.stop();
}
async function startScanner(){
  $('scan-status').textContent='Initialising camera…';
  $('scan-status').className='scan-status';
  $('add-preview').classList.add('hidden');
  try {
    await scanner.start($('qr-video'),$('qr-canvas'),onQRFound);
    $('scan-status').textContent='Point camera at QR code…';
  } catch(e) {
    $('scan-status').textContent='Camera error: '+(e.message||e);
    $('scan-status').className='scan-status err';
  }
}
function onQRFound(acc){
  acc.mode='totp';
  _addPending=acc;
  $('pv-issuer').textContent =acc.issuer||'—';
  $('pv-account').textContent=acc.account||'—';
  $('pv-algo').textContent   =acc.algorithm||'SHA1';
  $('pv-digits').textContent =acc.digits||6;
  $('pv-period').textContent =(acc.period||30)+'s';
  $('scan-status').textContent='✓ QR detected!';
  $('scan-status').className='scan-status ok';
  $('add-preview').classList.remove('hidden');
}
async function confirmAdd(){
  if(!_addPending) return;
  const pending={..._addPending};
  await vault.add(pending);
  _addPending=null;
  $('add-preview').classList.add('hidden');
  show('main'); toast(`${pending.issuer||'Account'} added!`,'success');
}
function rescan(){ _addPending=null; $('add-preview').classList.add('hidden'); startScanner(); }

/* Manual */
function resetManual(){ ['m-issuer','m-account','m-secret'].forEach(id=>{const el=$(id);if(el)el.value='';}); $('m-algo').value='SHA1'; $('m-digits').value='6'; $('m-period').value='30'; $('m-err').textContent=''; }
async function doAddManual(){
  const issuer=$('m-issuer').value.trim(), account=$('m-account').value.trim();
  const secret=$('m-secret').value.trim().toUpperCase().replace(/\s/g,'');
  const algo=$('m-algo').value, digits=parseInt($('m-digits').value), period=parseInt($('m-period').value);
  $('m-err').textContent='';
  if(!account){$('m-err').textContent='Account name required';return;}
  if(!secret) {$('m-err').textContent='Secret key required';return;}
  try { Base32.decode(secret); } catch(e){$('m-err').textContent='Invalid secret: '+e.message;return;}
  try { await TOTP.generate(secret,{algorithm:algo,digits,period}); } catch(e){$('m-err').textContent='TOTP error: '+e.message;return;}
  const btn=$('m-add-btn'); btn.disabled=true; btn.textContent='Adding…';
  await vault.add({issuer:issuer||account,account,secret,algorithm:algo,digits,period,mode:'totp'});
  btn.disabled=false; btn.textContent='Add Account';
  show('main'); toast(`${issuer||account} added!`,'success');
}

/* URI */
async function doAddURI(){
  const uri=$('m-uri').value.trim(); $('m-uri-err').textContent='';
  if(!uri) return;
  try {
    const acc=TOTP.parseURI(uri); acc.mode='totp';
    await vault.add(acc); show('main'); toast(`${acc.issuer||acc.account} added!`,'success');
  } catch(e){ $('m-uri-err').textContent='Invalid URI: '+e.message; }
}

/* ── Add FSOTP account ──────────────────────────────────────── */
async function doAddFSOTP(){
  if(vault.accounts.find(a=>a.mode==='fsotp')){ toast('Only one FSOTP account allowed per vault','error'); return; }
  const name=$('fs-name').value.trim()||'Custom System';
  const account=$('fs-account').value.trim()||'user';
  let secret=$('fs-secret').value.trim();
  if(!secret) { secret=WC.hex(WC.rand(32)); $('fs-secret').value=secret; }
  if(!/^[0-9a-fA-F]{64}$/.test(secret)){ toast('Secret must be 64 hex chars (256 bits)','error'); return; }
  await vault.add({issuer:name,account,secret,mode:'fsotp'});
  await fsotpEngine.init(secret);
  _lastFsOtp='';
  show('main'); switchMainTab('fsotp');
  toast('FSOTP activated — Forward Secrecy engaged! 🛡','success');
}
function genFSOTPSecret(){ $('fs-secret').value=WC.hex(WC.rand(32)); }

/* ── Settings ───────────────────────────────────────────────── */
function renderSettings(){
  $('s-count').textContent=vault.accounts.length;
  $('s-idle').value=_idleMs/1000;
}
function doSetIdle(){ const v=parseInt($('s-idle').value); if(v>=10&&v<=600){_idleMs=v*1000;toast('Auto-lock updated','success');resetIdle();} }
async function doChangePw(){
  const cur=$('s-cur').value,nw=$('s-new').value,cf=$('s-cnf').value;
  if(!cur||!nw||!cf){toast('Fill all fields','error');return;}
  if(nw!==cf){toast('Passwords do not match','error');return;}
  if(nw.length<8){toast('Minimum 8 characters','error');return;}
  const t=new SecureVault(); const ok=await t.unlock(cur);
  if(!ok){toast('Wrong current password','error');return;}
  await vault.changePassword(nw);
  $('s-cur').value=$('s-new').value=$('s-cnf').value='';
  toast('Master password updated!','success');
}
function doExport(){ const b=new Blob([vault.export()],{type:'application/json'}); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=`safeword-backup-${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(u); toast('Encrypted backup exported','success'); }
function doImport(){ const inp=document.createElement('input'); inp.type='file'; inp.accept='.json'; inp.onchange=e=>{ const f=e.target.files[0]; if(!f)return; const r=new FileReader(); r.onload=ev=>{try{vault.import(ev.target.result);show('lock');updateLockUI();toast('Backup imported — unlock to continue','success');}catch{toast('Invalid backup file','error');}}; r.readAsText(f); }; inp.click(); }

/* ── Toggle password visibility ─────────────────────────────── */
function toggleVis(id,btn){ const el=$(id); if(!el)return; el.type=el.type==='password'?'text':'password'; btn.textContent=el.type==='password'?'👁':'🙈'; }

/* ── How It Works screen ────────────────────────────────────── */
function renderHowItWorks(){
  // Static content — rendered in HTML
}

/* ── Toast ──────────────────────────────────────────────────── */
function toast(msg,type='info'){
  const z=$('toast-zone'), t=document.createElement('div');
  t.className=`toast toast-${type}`; t.textContent=msg;
  z.appendChild(t);
  requestAnimationFrame(()=>t.classList.add('show'));
  setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),350);},3000);
}

/* ── Init ───────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded',()=>{
  updateLockUI(); show('lock');
  $('lock-pw').addEventListener('keydown',e=>{ if(e.key==='Enter') doUnlock(); });
});

// Intercept vault.unlock to also init FSOTP engine
const _origUnlock=vault.unlock.bind(vault);
vault.unlock=async function(pw){
  const ok=await _origUnlock(pw);
  if(ok){
    const fsAcc=vault.accounts.find(a=>a.mode==='fsotp');
    if(fsAcc&&!fsotpEngine.ready){
      await fsotpEngine.init(fsAcc.secret);
      _lastFsOtp='';
    }
  }
  return ok;
};
