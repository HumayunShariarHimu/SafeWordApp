'use strict';
class QRScanner {
  constructor(){ this._stream=null; this._raf=null; this._active=false; }
  async start(video, canvas, onFound) {
    if (this._active) return;
    this._active=true;
    const ctx=canvas.getContext('2d',{willReadFrequently:true});
    try {
      this._stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment',width:{ideal:1280},height:{ideal:720}}});
    } catch {
      this._stream=await navigator.mediaDevices.getUserMedia({video:true});
    }
    video.srcObject=this._stream;
    video.setAttribute('playsinline','true');
    await video.play();
    const tick=()=>{
      if (!this._active) return;
      this._raf=requestAnimationFrame(tick);
      if (video.readyState!==video.HAVE_ENOUGH_DATA) return;
      const w=video.videoWidth,h=video.videoHeight;
      if (!w||!h) return;
      canvas.width=w; canvas.height=h;
      ctx.drawImage(video,0,0,w,h);
      if (typeof jsQR==='undefined') return;
      const code=jsQR(ctx.getImageData(0,0,w,h).data,w,h,{inversionAttempts:'dontInvert'});
      if (!code) return;
      const l=code.location;
      ctx.strokeStyle='#00e5ff'; ctx.lineWidth=4;
      ctx.beginPath();
      ctx.moveTo(l.topLeftCorner.x,l.topLeftCorner.y);
      ctx.lineTo(l.topRightCorner.x,l.topRightCorner.y);
      ctx.lineTo(l.bottomRightCorner.x,l.bottomRightCorner.y);
      ctx.lineTo(l.bottomLeftCorner.x,l.bottomLeftCorner.y);
      ctx.closePath(); ctx.stroke();
      try { const acc=TOTP.parseURI(code.data); this.stop(); onFound(acc); } catch {}
    };
    tick();
  }
  stop() {
    this._active=false;
    if (this._raf) cancelAnimationFrame(this._raf);
    if (this._stream) this._stream.getTracks().forEach(t=>t.stop());
    this._stream=null; this._raf=null;
  }
  isActive(){ return this._active; }
}
const scanner = new QRScanner();
