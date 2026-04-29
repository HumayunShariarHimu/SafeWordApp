# 🔐 SafeWord — Dual-Mode Secure Authenticator

> TOTP for all services · FSOTP with Forward Secrecy · AES-256-GCM · Glassmorphism UI

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/YOUR_USERNAME/safeword)

---

## 🔑 Two Modes

### Mode 1 — TOTP (RFC 6238)
Works with **every** 2FA service: Facebook, Google, Twitter, GitHub, Instagram, Discord, etc.
- Scan QR code, manual entry, or paste otpauth:// URI
- SHA-1 / SHA-256 / SHA-512
- 6 or 8 digit codes, 30s or 60s periods

### Mode 2 — FSOTP (Forward-Secure OTP)
For your **own apps/systems**. Even if secret key is stolen, future codes are **mathematically impossible** to predict.
```
Key ratchet:  S_{t+1} = SHA-256(S_t ∥ R_t)
OTP:          HMAC-SHA256(S_t, R_t ∥ period)
Commitment:   SHA-256(R_t) published before period starts
Security:     2²⁵⁶ attempts needed to predict next R_t
```

---

## 🛡 Security Stack

| Layer | Technology |
|---|---|
| OTP Standard | RFC 6238 TOTP + Custom FSOTP |
| Vault Encryption | AES-256-GCM |
| Key Derivation | PBKDF2-SHA256 × 310,000 iterations |
| Randomness | crypto.getRandomValues (CSPRNG) |
| Crypto Engine | WebCrypto API (browser-native) |
| Storage | localStorage (encrypted) |
| Network | Zero — 100% offline |

---

## 📁 Structure

```
SafeWord/
├── index.html       # Single-page app
├── manifest.json    # PWA manifest
├── vercel.json      # Deploy + security headers
├── css/style.css    # Glassmorphism dark UI
└── js/
    ├── core.js      # TOTP + FSOTP + SecureVault
    ├── scanner.js   # QR scanner
    └── app.js       # UI controller
```

---

## 🚀 Deploy

```bash
git init && git add . && git commit -m "SafeWord v2"
git remote add origin https://github.com/YOUR/safeword.git
git push -u origin main
# vercel.com → New Project → Import → Deploy
```

---

MIT License
