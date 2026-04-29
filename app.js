'use strict';
/* ═══════════════════════════════════════════════════════════════
   SafeWord — App Controller
   ═══════════════════════════════════════════════════════════════ */
let _screen='lock', _ticker=null, _lockTimer=null, _clipTimer=null;
let _idleMs=60_000, _delTarget=null, _addPending=null;
let _fsData=null; // current FSOTP generate() result

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
  if(s==='main')     { renderTOTP(); if(vault.accounts.find(a=>a.mode==='fsotp')) renderFSOTP(); }
  if(s==='fsotp-detail') renderFSOTPDetail();
  resetIdle();
}

/* ── Lock / Unlock ──────────────────────────────────────────── */
async function doUnlock(){
  const pw=$('lock-pw').value;
  if(!pw){toast('Enter your master password','error');return;}
  const btn=$('lock-btn');
  btn.disabled=true; btn.textContent='Unlocking…';
  const ok=await vault.unlock(pw);
  btn.disabled=false; btn.textContent=vault.hasVault()?'Unlock':'Create Vault';
  $('lock-pw').value='';
  if(!ok){
    toast('Wrong password','error');
    $('lock-card').classList.add('shake');
    setTimeout(()=>$('lock-card').classList.remove('shake'),600);
    return;
  }
  show('main'); startTicker(); resetIdle();
}
function doLock(){
  vault.lock(); fsotpEngine._reset();
  clearInterval(_ticker); clearTimeout(_lockTimer); clearTimeout(_clipTimer);
  scanner.stop(); _ticker=null;
  show('lock'); updateLockUI();
}
function updateLockUI(){
  const has=vault.hasVault();
  $('lock-title').textContent   =has?'Welcome Back':'Create Vault';
  $('lock-sub').textContent     =has?'Enter master password to unlock':'Set a strong password to protect your accounts';
  $('lock-btn').textContent     =has?'Unlock':'Create Vault';
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

/* ── Ticker ─────────────────────────────────────────────────── */
function startTicker(){
  if(_ticker) clearInterval(_ticker);
  renderAll();
  _ticker=setInterval(renderAll,300);
}
async function renderAll(){
  if(!vault.isUnlocked()) return;
  await renderTOTP();
  // FSOTP accounts
  const fsAccs=vault.accounts.filter(a=>a.mode==='fsotp');
  if(fsAccs.length&&fsotpEngine.ready) renderFSOTPCards();
}

/* ══════════════════════════════════════════════════════════════
   TOTP Rendering
══════════════════════════════════════════════════════════════ */
async function renderTOTP(){
  const wrap=$('totp-wrap');
  if(!wrap) return;
  const accs=vault.accounts.filter(a=>a.mode==='totp'||!a.mode);
  if(!accs.length){
    wrap.innerHTML=`<div class="empty-state"><div class="empty-icon">🔒</div><p class="empty-t">No TOTP accounts</p><p class="empty-s">Tap + to add Facebook, Google, Twitter…</p></div>`;
    return;
  }
  const now=Date.now();
  const otps=await Promise.all(accs.map(a=>TOTP.generate(a.secret,{algorithm:a.algorithm,digits:a.digits,period:a.period,timestamp:now}).catch(()=>'------')));
  wrap.innerHTML=accs.map((acc,i)=>{
    const otp=otps[i], left=TOTP.timeLeft(acc.period), prog=TOTP.progress(acc.period);
    const brand=getBrand(acc.issuer,acc.account), urgent=left<=5;
    const circ=2*Math.PI*14, off=circ*(1-prog);
    const fmt=otp.length===6?otp.slice(0,3)+' '+otp.slice(3):otp.slice(0,4)+' '+otp.slice(4);
    return `<div class="acc-card glass" id="card-${acc.id}">
      <div class="acc-brand" style="background:${brand.bg};color:${brand.fg}">${esc(brand.letter)}</div>
      <div class="acc-info">
        <div class="acc-issuer">${esc(acc.issuer||acc.account)}</div>
        <div class="acc-account">${esc(acc.account)}</div>
      </div>
      <div class="acc-right">
        <div class="acc-otp ${urgent?'urgent':''}" onclick="copyOTP('${acc.id}','${otp}')">${fmt}</div>
        <div class="acc-timer-row">
          <svg width="34" height="34" viewBox="0 0 34 34">
            <circle cx="17" cy="17" r="14" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="2.5"/>
            <circle cx="17" cy="17" r="14" fill="none"
              stroke="${urgent?'#ff4d6d':'#00e5ff'}" stroke-width="2.5"
              stroke-linecap="round"
              stroke-dasharray="${circ.toFixed(2)}"
              stroke-dashoffset="${off.toFixed(2)}"
              transform="rotate(-90 17 17)"
              style="transition:stroke-dashoffset .3s linear"/>
            <text x="17" y="21" text-anchor="middle" fill="${urgent?'#ff4d6d':'rgba(255,255,255,.5)'}" font-size="8" font-family="monospace">${left}</text>
          </svg>
        </div>
      </div>
      <button class="acc-del" onclick="confirmDel('${acc.id}')">✕</button>
    </div>`;
  }).join('');
}

/* ══════════════════════════════════════════════════════════════
   FSOTP Rendering
══════════════════════════════════════════════════════════════ */
async function renderFSOTPCards(){
  const wrap=$('fsotp-wrap');
  if(!wrap) return;
  const accs=vault.accounts.filter(a=>a.mode==='fsotp');
  if(!accs.length){ wrap.innerHTML=''; return; }
  if(!fsotpEngine.ready){
    const acc=accs[0];
    await fsotpEngine.init(acc.secret);
  }
  _fsData=await fsotpEngine.generate();
  const acc=accs[0];
  const brand=getBrand(acc.issuer||'SafeWord',acc.account);
  const prog=1-(_fsData.timeLeft/30);
  const circ=2*Math.PI*14, off=circ*(1-prog), urgent=_fsData.timeLeft<=5;
  const fmt=_fsData.otp.slice(0,3)+' '+_fsData.otp.slice(3);
  wrap.innerHTML=`<div class="acc-card glass fsotp-card" id="card-${acc.id}" onclick="show('fsotp-detail')">
    <div class="acc-brand" style="background:${brand.bg};color:${brand.fg}">${esc(brand.letter)}</div>
    <div class="acc-info">
      <div class="acc-issuer">${esc(acc.issuer||'Custom System')}<span class="fs-badge">FSOTP</span></div>
      <div class="acc-account">${esc(acc.account)}</div>
    </div>
    <div class="acc-right">
      <div class="acc-otp ${urgent?'urgent':''}" onclick="event.stopPropagation();copyOTP('${acc.id}','${_fsData.otp}')">${fmt}</div>
      <div class="acc-timer-row">
        <svg width="34" height="34" viewBox="0 0 34 34">
          <circle cx="17" cy="17" r="14" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="2.5"/>
          <circle cx="17" cy="17" r="14" fill="none"
            stroke="${urgent?'#ff4d6d':'#a78bfa'}" stroke-width="2.5"
            stroke-linecap="round"
            stroke-dasharray="${circ.toFixed(2)}"
            stroke-dashoffset="${off.toFixed(2)}"
            transform="rotate(-90 17 17)"
            style="transition:stroke-dashoffset .3s linear"/>
          <text x="17" y="21" text-anchor="middle" fill="${urgent?'#ff4d6d':'rgba(255,255,255,.5)'}" font-size="8" font-family="monospace">${_fsData.timeLeft}</text>
        </svg>
      </div>
    </div>
    <button class="acc-del" onclick="event.stopPropagation();confirmDel('${acc.id}')">✕</button>
  </div>`;
}

/* ── FSOTP Detail Screen ────────────────────────────────────── */
async function renderFSOTPDetail(){
  if(!_fsData) { _fsData=await fsotpEngine.generate(); }
  const d=_fsData;
  $('fs-otp').textContent    =d.otp.slice(0,3)+' '+d.otp.slice(3);
  $('fs-period').textContent =d.period;
  $('fs-ratchet').textContent=d.ratchetCount;
  $('fs-keyfp').textContent  =d.secretFP;
  $('fs-commit').textContent =d.commitment;
  $('fs-rand').textContent   =d.revealedRandom;
  $('fs-nextcommit').textContent=d.nextCommitment;
  const prog=1-(d.timeLeft/30), circ=2*Math.PI*48, off=circ*(1-prog), urgent=d.timeLeft<=5;
  $('fs-ring').style.strokeDashoffset=off;
  $('fs-ring').style.stroke=urgent?'#ff4d6d':'#a78bfa';
  $('fs-timeleft').textContent=d.timeLeft+'s';
  // chain
  const chain=fsotpEngine.getChain();
  $('fs-chain').innerHTML=chain.slice(0,5).map(e=>{
    const isCur=e.period===d.period, isFut=e.period>d.period;
    return `<div class="chain-row ${isCur?'chain-cur':isFut?'chain-fut':'chain-past'}">
      <span class="chain-period">P${e.period}</span>
      <span class="chain-commit">${e.commitment.slice(0,16)}…</span>
      <span class="chain-rev ${e.revealed?'revealed':'hidden-r'}">${e.revealed?'✓ Revealed':'🔒 Hidden'}</span>
    </div>`;
  }).join('');
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
    toast('OTP copied — clears in 30s ✓','success');
    $('card-'+id)?.classList.add('copied');
    setTimeout(()=>$('card-'+id)?.classList.remove('copied'),800);
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
  if(acc?.mode==='fsotp') fsotpEngine._reset();
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
    $('scan-status').textContent='Point at QR code…';
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
  await vault.add({..._addPending});
  _addPending=null;
  $('add-preview').classList.add('hidden');
  show('main'); toast(`${_addPending?.issuer||'Account'} added!`,'success');
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
  if(vault.accounts.find(a=>a.mode==='fsotp')){ toast('Only one FSOTP account allowed','error'); return; }
  const name=$('fs-name').value.trim()||'Custom System';
  const account=$('fs-account').value.trim()||'user';
  let secret=$('fs-secret').value.trim();
  if(!secret) { secret=WC.hex(WC.rand(32)); $('fs-secret').value=secret; }
  if(!/^[0-9a-fA-F]{64}$/.test(secret)){ toast('Secret must be 64 hex chars','error'); return; }
  await vault.add({issuer:name,account,secret,mode:'fsotp'});
  await fsotpEngine.init(secret);
  show('main'); switchMainTab('fsotp');
  toast('FSOTP account created — Forward Secrecy active!','success');
}
function genFSOTPSecret(){ $('fs-secret').value=WC.hex(WC.rand(32)); }

/* ── Settings ───────────────────────────────────────────────── */
function renderSettings(){
  $('s-count').textContent=vault.accounts.length;
  $('s-idle').value=_idleMs/1000;
}
function doSetIdle(){ const v=parseInt($('s-idle').value); if(v>=10&&v<=600){_idleMs=v*1000;toast('Updated','success');resetIdle();} }
async function doChangePw(){
  const cur=$('s-cur').value,nw=$('s-new').value,cf=$('s-cnf').value;
  if(!cur||!nw||!cf){toast('Fill all fields','error');return;}
  if(nw!==cf){toast('Passwords do not match','error');return;}
  if(nw.length<8){toast('Minimum 8 characters','error');return;}
  const t=new SecureVault(); const ok=await t.unlock(cur);
  if(!ok){toast('Wrong current password','error');return;}
  await vault.changePassword(nw);
  $('s-cur').value=$('s-new').value=$('s-cnf').value='';
  toast('Password changed!','success');
}
function doExport(){ const b=new Blob([vault.export()],{type:'application/json'}); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=`safeword-backup-${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(u); toast('Backup exported','success'); }
function doImport(){ const inp=document.createElement('input'); inp.type='file'; inp.accept='.json'; inp.onchange=e=>{ const f=e.target.files[0]; if(!f)return; const r=new FileReader(); r.onload=ev=>{try{vault.import(ev.target.result);show('lock');updateLockUI();toast('Backup imported — unlock to continue','success');}catch{toast('Invalid backup file','error');}}; r.readAsText(f); }; inp.click(); }

/* ── Toggle password visibility ─────────────────────────────── */
function toggleVis(id,btn){ const el=$(id); if(!el)return; el.type=el.type==='password'?'text':'password'; btn.textContent=el.type==='password'?'👁':'🙈'; }

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
  // Restore FSOTP engine if already have FSOTP account in vault (after re-unlock)
});

// After unlock, init FSOTP engine if FSOTP account exists
const _origUnlock=vault.unlock.bind(vault);
vault.unlock=async function(pw){
  const ok=await _origUnlock(pw);
  if(ok){
    const fsAcc=vault.accounts.find(a=>a.mode==='fsotp');
    if(fsAcc&&!fsotpEngine.ready) await fsotpEngine.init(fsAcc.secret);
  }
  return ok;
};
