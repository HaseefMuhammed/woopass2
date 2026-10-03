# WOO PASS — Private Family Vault
### Complete Technical Architecture, Security Specifications & User Guide
**Developed By: TEB Innovations**

---

## 1. Executive Summary

**WOO PASS** is a state-of-the-art, zero-knowledge private family digital vault and credential management system designed and engineered by **TEB Innovations**. Built to provide high-grade confidentiality without sacrificing user-friendly simplicity, WooPass combines military-grade **AES-256-GCM** client-side encryption, a **two-tier security gate with cryptographically randomized keypads**, cloud synchronization via **Google Firebase (Firestore & Auth)**, and installable **Progressive Web App (PWA)** technology for mobile and desktop platforms.

---

## 2. General Information & Metadata

| Attribute | Specification |
|---|---|
| **Product Name** | WOO PASS — Private Family Vault |
| **Developer / Creator** | **TEB Innovations** |
| **Release Version** | 2.5.0 (PWA Enabled) |
| **Target Platforms** | Android (PWA), iOS (Safari PWA), Windows, macOS, Linux |
| **Deployment Targets** | Netlify, Firebase Hosting, Local Node.js Server |
| **License & Privacy** | Private Family Vault &bull; Proprietary |

---

## 3. Technology Stack & Architecture

### 3.1 Frontend Layer
- **Core Structure**: Semantic HTML5 with accessible ARIA standards.
- **Styling**: Tailored Dark-Mode Design System in Vanilla CSS (`css/app.css` & `css/responsive.css`) featuring subtle radial ambient illumination, glassmorphic card overlays (`backdrop-filter: blur(16px)`), and micro-animations.
- **UI Components**: Bootstrap 5.3.3 (Modals, Grid System, Toasts) paired with Bootstrap Icons.
- **Typography**: Google Fonts Inter (`300`, `400`, `500`, `600`, `700`, `800`).

### 3.2 Security & Cryptography Engine
- **Cipher Algorithm**: AES-GCM (Galois/Counter Mode) with 256-bit key length via the W3C Web Cryptography API (`window.crypto.subtle`).
- **Key Derivation**: PBKDF2 (Password-Based Key Derivation Function 2) utilizing SHA-256 hashing across **100,000 iterations** with cryptographically randomized salts.
- **Initialization Vector (IV)**: Fresh, non-repeating 12-byte (96-bit) cryptographically strong random IV generated for every individual record encryption.

### 3.3 Progressive Web App (PWA) Layer
- **Manifest Specification**: [`manifest.json`](file:///d:/Anu/VS/woopass/manifest.json) declaring `standalone` display mode, orientation locks, theme color (`#0b0f19`), and high-res PNG icons.
- **Service Worker (`sw.js`)**: Cache-first and stale-while-revalidate caching strategies for instantaneous offline launch, automatic cache purging on upgrade, and zero network disruption for external APIs.
- **Installation Portal (`app.html`)**: Standalone installation gateway with device detection, interactive installation triggers (`beforeinstallprompt`), and platform-specific guides for Android, iOS, and Desktop.

### 3.4 Backend & Cloud Infrastructure
- **Authentication**: Firebase Authentication (Email/Password & Token persistence).
- **Encrypted Database**: Cloud Firestore (Structured collections partitioned per user under `users/{uid}/passwords` and `users/{uid}/notes`).
- **Server Environment**: Zero-dependency Node.js HTTP server (`server.js`) with native MIME management and network discovery.

---

## 4. Multi-Layer Security Model

```
                    ┌────────────────────────────────────────┐
                    │          INTERNET / BROWSER            │
                    └──────────────────┬─────────────────────┘
                                       │
                         [Platform Security Guard]
                         - DevTools Inspection Blocked
                         - Desktop Right-Click Disabled
                         - F12 / Ctrl+Shift+I / Ctrl+U Blocked
                                       │
                                       ▼
                    ┌────────────────────────────────────────┐
                    │      TIER 1: HOME SECURITY GATE        │
                    │   - Cryptographically Shuffled Keypad  │
                    │   - 6-Digit Passcode Gate (849201)     │
                    │   - Rate-Limiting & Lockdown Timer     │
                    └──────────────────┬─────────────────────┘
                                       │
                                       ▼
                    ┌────────────────────────────────────────┐
                    │      TIER 2: ACCOUNT AUTHENTICATION     │
                    │   - Registered Email + 6-Digit PIN     │
                    │   - PBKDF2 Key Derivation (100k iters) │
                    │   - In-Memory Master Key Decryption    │
                    └──────────────────┬─────────────────────┘
                                       │
                                       ▼
                    ┌────────────────────────────────────────┐
                    │         AES-256-GCM VAULT DATA         │
                    │   - Stored Passwords (Encrypted)       │
                    │   - Important Notes (Encrypted)        │
                    │   - Digital Healthcard (Cookie sync)   │
                    │   - Cloud Storage Link (Direct Link)   │
                    └────────────────────────────────────────┘
```

### 4.1 Anti-Inspection & DevTools Deterrent
To safeguard sensitive credentials from shoulder-surfing, browser inspection, and local tampering, WooPass incorporates `js/security-guard.js`:
- Blocks `F12`, `Ctrl+Shift+I`, `Ctrl+Shift+J`, and `Ctrl+U`.
- Intercepts desktop right-click context menus while preserving normal touch interactions on mobile devices.
- Auto-redirects unauthorized inspect attempts.

### 4.2 Cryptographically Randomized Virtual Keypad
- Eliminates touch-signature tracking and video shoulder-surfing.
- Powered by a Fisher-Yates shuffling algorithm seeded with `crypto.getRandomValues()`.
- Automatically re-scrambles positions `0–9` on screen loads, failed attempts, and via the manual **Shuffle Keypad** button.

### 4.3 Zero-Knowledge Data Encryption
- Plaintext passwords and notes **never** leave the client browser.
- Before transmission to Cloud Firestore, every record is encrypted with a unique 12-byte IV using the user's PBKDF2-derived master key.
- Even in the event of a database breach, stored data remains unreadable ciphertext.

---

## 5. Core Application Features

### 5.1 Stored Passwords Vault
- Secure storage for website URLs, usernames/emails, passwords, and private notes.
- One-click copy to clipboard with automatic clear timer.
- Interactive **Reveal / Mask** toggles for passwords.
- Built-in **Cryptographic Password Generator** supporting adjustable length, uppercase, lowercase, numbers, and symbols with live entropy scoring.

### 5.2 Important Confidential Notes
- Secure repository for recovery keys, backup codes, lockbox combinations, and private memoranda.
- Full-text search across titles and note contents.

### 5.3 Zoe Health Plus Digital Healthcard
- Embedded digital healthcare card portal.
- Persistent cookie state management ensuring the card is preserved across sessions and accessible immediately upon vault login.

### 5.4 Manage Documents & Cloud Link Integration
- One-tap portal to connected cloud storage (Google Drive folders, Google Apps Script web apps, OneDrive, or company document portals).
- Customizable link URL editable directly from the dashboard settings.

### 5.5 Profile Picture & Avatar Sync
- In-browser image compression engine converting photos to lightweight, optimized assets.
- Real-time profile picture synchronization with Firebase user profiles.

---

## 6. Progressive Web App (PWA) & Installation Guide

### 6.1 Installation via `/app.html`
WooPass features a dedicated installation portal at `http://<domain>/app.html`:
- **Android / Google Chrome**: Tap **"Add WooPass to Home Screen"** to trigger the native installation dialog.
- **iOS Safari (iPhone / iPad)**:
  1. Tap the **Share** button (`⎋`) in the bottom Safari toolbar.
  2. Scroll down and tap **"Add to Home Screen"** (`➕`).
  3. Tap **"Add"** in the top-right corner.
- **Desktop (Chrome / Edge / Brave)**: Click the Install button in the address bar or use the install button on `app.html` to run WooPass in its own frameless window.

### 6.2 Running Locally
WooPass includes a built-in Node.js server requiring zero external dependencies:
```bash
# Start the local server
npm start
# Or directly via Node.js
node server.js
```
The server binds to port `3000` and displays both local and network WiFi IP addresses for easy mobile testing.

---

## 7. Project File Structure

```
woopass/
├── assets/
│   ├── icon.png                 # App icon mark
│   ├── logo.png                 # Transparent white logo vector
│   ├── icon-192.png             # 192x192 PWA home screen icon
│   ├── icon-512.png             # 512x512 PWA splash & launcher icon
│   ├── icon-apple-touch.png     # 180x180 iOS home screen icon
│   └── badge-72.png             # 72x72 notification badge
├── css/
│   ├── app.css                  # Core design tokens, vault themes, layout
│   └── responsive.css           # Mobile & tablet responsive adaptations
├── js/
│   ├── auth.js                  # Authentication controller & gate logic
│   ├── crypto.js                # WebCrypto AES-256-GCM & PBKDF2 engine
│   ├── firebase-config.js       # Firebase SDK configuration & rate limits
│   ├── firebase-init.js         # Firebase Auth & Firestore initialization
│   ├── keypad.js                # Randomized Fisher-Yates numeric keypad engine
│   ├── security-guard.js        # Anti-DevTools & inspection deterrent
│   ├── security.js              # Security event auditing
│   ├── session.js               # Auto-lockout & inactivity manager
│   ├── ui.js                    # View router, toast notifications, modals
│   └── vault.js                 # CRUD controller for passwords and notes
├── firebase/
│   └── firestore.rules          # Firestore database security rules
├── app.html                     # PWA install portal & mobile instructions
├── index.html                   # Main single-page application vault
├── logo.png                     # Official master brandmark (2000x2000)
├── manifest.json                # Web App Manifest for PWA installation
├── netlify.toml                 # Netlify deployment configuration & security headers
├── firebase.json                # Firebase Hosting & Firestore rules configuration
├── package.json                 # Project scripts & startup entrypoint
├── server.js                    # Local zero-dependency webapp HTTP server
└── WOOPASS_DOCUMENTATION.md     # Official documentation
```

---

## 8. Deployment Best Practices

### Netlify Deployment
1. Connect your private repository to Netlify.
2. The included [`netlify.toml`](file:///d:/Anu/VS/woopass/netlify.toml) automatically sets HTTP security headers:
   - `Content-Security-Policy`
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Service-Worker-Allowed: /`
   - Single Page App routing rules.

### Firebase Hosting Deployment
```bash
firebase login
firebase deploy
```
The validated [`firebase.json`](file:///d:/Anu/VS/woopass/firebase.json) automatically serves the app shell, applies `Service-Worker-Allowed` headers, and deploys [`firebase/firestore.rules`](file:///d:/Anu/VS/woopass/firebase/firestore.rules).

---

## 9. Developer Attribution & Credits

- **Engineering & Development**: **TEB Innovations**
- **Architecture**: Zero-Knowledge Client-Side Encrypted Web Application
- **Proprietary Notice**: Designed and developed exclusively by **TEB Innovations**. All rights reserved.
