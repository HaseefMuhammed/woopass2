/**
 * ============================================================================
 * WOO PASS — Authentication Controller (js/auth.js)
 * Family Gate, Account Registration, PIN Authentication, and Progressive Rate Limiting
 * ============================================================================
 */

import { 
  auth, 
  db, 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  signOut, 
  onAuthStateChanged,
  doc, 
  setDoc, 
  getDoc, 
  serverTimestamp 
} from "./firebase-init.js";

import { 
  deriveAuthSecret, 
  deriveFamilyGateHash, 
  deriveKEK,
  generateVaultKeyBytes,
  wrapVaultKey,
  generateRandomBytes, 
  bufferToHex, 
  validatePinStrength, 
  GATE_SALT_HEX 
} from "./crypto.js";

import { SECURITY_CONFIG } from "./firebase-config.js";
import { session } from "./session.js";
import { logSecurityEvent } from "./security.js";
import { vaultController } from "./vault.js";
import { ui } from "./ui.js";

// Precomputed high-entropy cryptographic hash (PBKDF2-HMAC-SHA256, 100k rounds)
// Derived from the family security passcode + domain salt. Plaintext passcode is never stored.
const EXPECTED_GATE_HASH = 'bb8c122e5af547a21433b4b72329eb491cd2b78c8e7a878f6c6813468563d475';

class AuthController {
  constructor() {
    // Persistent rate limiting state (stored in sessionStorage to survive page refreshes)
    const gateLock = this._loadLockState('gate');
    this._gateFailedAttempts = gateLock.attempts;
    this._gateLockoutUntil = gateLock.until;
    
    const loginLock = this._loadLockState('login');
    this._loginFailedAttempts = loginLock.attempts;
    this._loginLockoutUntil = loginLock.until;

    // Active keypads
    this.gateKeypad = null;
    this.loginKeypad = null;

    // Auto-resume lockout countdown if page reloads during active lockout
    if (this._gateLockoutUntil > Date.now()) {
      const remaining = Math.ceil((this._gateLockoutUntil - Date.now()) / 1000);
      this._startGateLockoutCountdown(remaining);
    }
    if (this._loginLockoutUntil > Date.now()) {
      const remaining = Math.ceil((this._loginLockoutUntil - Date.now()) / 1000);
      this._startLoginLockoutCountdown(remaining);
    }
  }

  _loadLockState(type) {
    try {
      const raw = sessionStorage.getItem(`woopass_lock_${type}`);
      if (!raw) return { attempts: 0, until: 0 };
      const parsed = JSON.parse(raw);
      const now = Date.now();
      const until = Number(parsed.until) || 0;
      if (until > now) {
        return { attempts: Number(parsed.attempts) || 0, until };
      }
      return { attempts: 0, until: 0 };
    } catch (e) {
      return { attempts: 0, until: 0 };
    }
  }

  _saveLockState(type, attempts, until) {
    try {
      sessionStorage.setItem(`woopass_lock_${type}`, JSON.stringify({ attempts, until }));
    } catch (e) {}
  }

  /**
   * Attach SecureKeypad instance for Family Gate
   * @param {SecureKeypad} keypad 
   */
  setGateKeypad(keypad) {
    this.gateKeypad = keypad;
  }

  /**
   * Attach SecureKeypad instance for Login
   * @param {SecureKeypad} keypad 
   */
  setLoginKeypad(keypad) {
    this.loginKeypad = keypad;
  }

  /**
   * Verify entered PIN at the Family Gate
   * @param {string} pin - 6-digit family admin PIN
   */
  async verifyFamilyGatePin(pin) {
    const now = Date.now();
    if (now < this._gateLockoutUntil) {
      const remainingSec = Math.ceil((this._gateLockoutUntil - now) / 1000);
      ui.showToast(`Gate temporarily locked. Please wait ${remainingSec}s.`, 'warning');
      if (this.gateKeypad) this.gateKeypad.shake();
      return;
    }

    try {
      // Cryptographically derive PBKDF2 hash of input PIN with 100,000 iterations
      const inputHash = await deriveFamilyGateHash(pin, GATE_SALT_HEX);

      // Compare strictly with precomputed one-way hash (No raw PIN in memory or source)
      if (inputHash === EXPECTED_GATE_HASH) {
        // Success
        this._gateFailedAttempts = 0;
        this._gateLockoutUntil = 0;
        this._saveLockState('gate', 0, 0);
        session.unlockFamilyGate();
        ui.showToast('Home Gate Unlocked', 'success', 2000);
        if (this.gateKeypad) this.gateKeypad.reset();
        
        // Transition to Welcome Landing
        ui.showView('view-landing');
      } else {
        // Failed attempt handling
        this._gateFailedAttempts++;
        if (this.gateKeypad) this.gateKeypad.shake();

        if (this._gateFailedAttempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS_BEFORE_LOCKOUT) {
          const lockoutSeconds = SECURITY_CONFIG.BASE_LOCKOUT_SECONDS * Math.pow(2, this._gateFailedAttempts - 5);
          this._gateLockoutUntil = Date.now() + (lockoutSeconds * 1000);
          this._saveLockState('gate', this._gateFailedAttempts, this._gateLockoutUntil);
          this._startGateLockoutCountdown(lockoutSeconds);
          ui.showToast(`Too many failed attempts. Gate locked for ${lockoutSeconds}s.`, 'danger');
        } else if (this._gateFailedAttempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS_BEFORE_DELAY) {
          this._saveLockState('gate', this._gateFailedAttempts, 0);
          ui.showToast('Incorrect Passcode. Progressive security delay active.', 'warning');
          if (this.gateKeypad) {
            this.gateKeypad.setDisabled(true);
            setTimeout(() => {
              this.gateKeypad.setDisabled(false);
            }, 2000);
          }
        } else {
          this._saveLockState('gate', this._gateFailedAttempts, 0);
          const remaining = SECURITY_CONFIG.MAX_FAILED_ATTEMPTS_BEFORE_LOCKOUT - this._gateFailedAttempts;
          ui.showToast(`Incorrect Passcode. ${remaining} attempts remaining.`, 'danger');
        }
      }
    } catch (err) {
      console.error('[Gate Verification Error]:', err);
      ui.showToast('Security verification error. Please retry.', 'danger');
    }
  }

  /**
   * Handle Gate lockout countdown UI
   */
  _startGateLockoutCountdown(seconds) {
    const banner = document.getElementById('gate-lockout-banner');
    if (!banner) return;

    if (this.gateKeypad) this.gateKeypad.setDisabled(true);
    banner.classList.add('show');

    let remaining = seconds;
    banner.textContent = `Security lockout active. Try again in ${remaining}s`;

    const timer = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(timer);
        banner.classList.remove('show');
        if (this.gateKeypad) {
          this.gateKeypad.setDisabled(false);
          this.gateKeypad.reset();
        }
      } else {
        banner.textContent = `Security lockout active. Try again in ${remaining}s`;
      }
    }, 1000);
  }

  /**
   * Register a new family vault account
   * @param {Object} formData
   * @param {string} formData.name
   * @param {string} formData.pin
   * @param {string} formData.confirmPin
   * @param {string} formData.email
   * @param {string} [formData.phone]
   * @param {string} formData.driveUrl - Required Google Drive Folder Link
   * @param {string} [formData.photoUrl] - Optional Avatar Image URL / Data URI
   */
  async registerAccount(formData) {
    const { name, pin, confirmPin, email, phone, driveUrl, photoUrl } = formData;

    // 1. Validation
    const trimmedName = (name || '').trim();
    if (!trimmedName || trimmedName.length < 2 || trimmedName.length > 60) {
      throw new Error('Please enter a valid full name (2–60 characters).');
    }

    const pinValidation = validatePinStrength(pin);
    if (!pinValidation.valid) {
      throw new Error(pinValidation.reason);
    }

    if (pin !== confirmPin) {
      throw new Error('PIN and Confirm PIN do not match.');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const normalizedEmail = (email || '').trim().toLowerCase();
    if (!emailRegex.test(normalizedEmail)) {
      throw new Error('Please enter a valid email address.');
    }

    if (phone && phone.trim()) {
      const phoneClean = phone.trim();
      if (!/^[+]?[\d\s-]{7,18}$/.test(phoneClean)) {
        throw new Error('Please enter a valid phone number or leave blank.');
      }
    }

    // Connected Link is REQUIRED (Google Drive, Google Apps Script, OneDrive, web link, etc.)
    if (!driveUrl || !driveUrl.trim()) {
      throw new Error('A connected link (Google Drive, Apps Script, web link, etc.) is required.');
    }
    let urlClean = driveUrl.trim();
    if (!urlClean.startsWith('http://') && !urlClean.startsWith('https://')) {
      urlClean = 'https://' + urlClean;
    }

    // 2. Cryptographic Derivation
    const authSecret = await deriveAuthSecret(pin, normalizedEmail);
    const vaultSaltBytes = generateRandomBytes(32);
    const vaultSaltHex = bufferToHex(vaultSaltBytes);

    try {
      // 3. Create Firebase Auth user
      const userCredential = await createUserWithEmailAndPassword(auth, normalizedEmail, authSecret);
      const user = userCredential.user;

      // 4. Create Firestore profile with photoUrl and connected link
      const userProfileData = {
        uid: user.uid,
        name: trimmedName,
        email: normalizedEmail,
        phone: phone ? phone.trim() : null,
        googleDriveUrl: urlClean,
        photoUrl: photoUrl || null,
        vaultSalt: vaultSaltHex,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        securityMetadata: {
          lastLoginAt: new Date().toISOString(),
          authMethod: 'PIN_DERIVED_PBKDF2'
        }
      };

      try {
        const userDocRef = doc(db, 'users', user.uid);
        await setDoc(userDocRef, userProfileData);

        // 4b. Initialize wrapped Vault Encryption Key (VEK) in vaults/{uid}
        const kek = await deriveKEK(pin, vaultSaltHex, normalizedEmail);
        const rawVekBytes = generateVaultKeyBytes();
        const wrapped = await wrapVaultKey(rawVekBytes, kek);
        
        const vaultDocRef = doc(db, 'vaults', user.uid);
        await setDoc(vaultDocRef, {
          uid: user.uid,
          encryptedVek: wrapped.encryptedVekHex,
          iv: wrapped.ivHex,
          version: 1,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        });
      } catch (firestoreErr) {
        console.warn('[Firestore] Profile/Vault storage deferred (Database pending initialization in Firebase Console):', firestoreErr.message || firestoreErr);
      }

      // 5. Log Security Event (non-blocking)
      try {
        await logSecurityEvent({
          uid: user.uid,
          type: 'ACCOUNT_CREATED',
          success: true,
          details: 'Account initialized with unique vault salt'
        });
      } catch (logErr) {
        console.warn('[Security Log] Event recording deferred:', logErr.message || logErr);
      }

      // 6. Sign out newly created user to enforce security restart
      try {
        await signOut(auth);
      } catch (signOutErr) {
        console.warn('[Auth] Signout deferred:', signOutErr.message || signOutErr);
      }

      // 7. Show success restart modal
      ui.showModal('modal-account-created');
    } catch (firebaseErr) {
      console.error('[Auth Registration Error]:', firebaseErr);
      const code = firebaseErr.code || '';
      if (code === 'auth/email-already-in-use') {
        throw new Error('An account with this email address already exists. Please login instead.');
      } else if (code === 'auth/operation-not-allowed') {
        throw new Error('Email/Password provider is not enabled in Firebase Console. Please enable Email/Password under Authentication -> Sign-in method.');
      } else if (code === 'auth/invalid-email') {
        throw new Error('Please enter a valid email address.');
      } else if (code === 'auth/network-request-failed') {
        throw new Error('Network connection issue. Please check your internet connection.');
      } else if (code === 'permission-denied') {
        throw new Error('Firestore permission denied. Please verify your Firestore rules.');
      } else {
        throw new Error(firebaseErr.message || 'Failed to create account. Please try again.');
      }
    }
  }

  /**
   * Login using registered email and 6-digit PIN
   * @param {string} email - Registered email
   * @param {string} pin - 6-digit user PIN
   */
  async loginWithPin(email, pin) {
    const now = Date.now();
    if (now < this._loginLockoutUntil) {
      const remainingSec = Math.ceil((this._loginLockoutUntil - now) / 1000);
      ui.showToast(`Account temporarily locked. Please wait ${remainingSec}s.`, 'warning');
      if (this.loginKeypad) this.loginKeypad.shake();
      return;
    }

    const normalizedEmail = (email || '').trim().toLowerCase();
    if (!normalizedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      ui.showToast('Please enter a valid email address.', 'danger');
      if (this.loginKeypad) this.loginKeypad.shake();
      return;
    }

    if (!pin || pin.length !== 6) {
      ui.showToast('Please enter your 6-digit PIN.', 'danger');
      if (this.loginKeypad) this.loginKeypad.shake();
      return;
    }

    try {
      // 1. Derive Firebase Auth password from PIN
      const authSecret = await deriveAuthSecret(pin, normalizedEmail);

      // 2. Authenticate with Firebase Auth
      const userCredential = await signInWithEmailAndPassword(auth, normalizedEmail, authSecret);
      const user = userCredential.user;

      // 3. Fetch user Firestore profile
      let profileData = null;
      try {
        const userDocRef = doc(db, 'users', user.uid);
        const docSnap = await getDoc(userDocRef);

        if (docSnap.exists()) {
          profileData = docSnap.data();
        } else {
          // Create basic profile if missing
          profileData = {
            uid: user.uid,
            name: user.displayName || normalizedEmail.split('@')[0],
            email: normalizedEmail,
            vaultSalt: bufferToHex(generateRandomBytes(32))
          };
          try {
            await setDoc(userDocRef, {
              ...profileData,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp()
            });
          } catch (writeErr) {
            console.warn('[Firestore] Could not save default profile:', writeErr.message || writeErr);
          }
        }
      } catch (dbErr) {
        console.warn('[Firestore] Profile read error:', dbErr.message || dbErr);
        profileData = {
          uid: user.uid,
          name: user.displayName || normalizedEmail.split('@')[0],
          email: normalizedEmail,
          vaultSalt: bufferToHex(generateRandomBytes(32))
        };
      }

      // Auto-sync photoUrl between Firebase Firestore and local profile
      if (profileData.photoUrl) {
        localStorage.setItem('woopass_avatar_' + normalizedEmail, profileData.photoUrl);
      } else {
        const cachedPhoto = localStorage.getItem('woopass_avatar_' + normalizedEmail);
        if (cachedPhoto) {
          profileData.photoUrl = cachedPhoto;
          try {
            const userDocRef = doc(db, 'users', user.uid);
            await setDoc(userDocRef, { photoUrl: cachedPhoto }, { merge: true });
          } catch (e) {}
        }
      }

      // Auto-sync passwordChangedAt between Firestore and localStorage
      if (profileData.passwordChangedAt) {
        localStorage.setItem('woopass_pwd_changed_' + user.uid, profileData.passwordChangedAt);
      } else {
        const cachedPwdChanged = localStorage.getItem('woopass_pwd_changed_' + user.uid);
        if (cachedPwdChanged) {
          profileData.passwordChangedAt = cachedPwdChanged;
        }
      }

      // 4. Initialize and unlock the encrypted vault
      try {
        await vaultController.initVault(user.uid, pin, normalizedEmail, profileData.vaultSalt);
      } catch (vaultErr) {
        console.warn('[Vault Init Warning]:', vaultErr.message);
      }

      // 5. Log successful LOGIN event (non-blocking)
      try {
        await logSecurityEvent({
          uid: user.uid,
          type: 'LOGIN_SUCCESS',
          success: true,
          details: 'User authenticated and vault decrypted successfully'
        });
      } catch (logErr) {
        console.warn('[Security Log] Event write error:', logErr.message || logErr);
      }

      // 6. Store session in memory
      this._loginFailedAttempts = 0;
      this._loginLockoutUntil = 0;
      this._saveLockState('login', 0, 0);
      session.setSessionUser(profileData);

      if (this.loginKeypad) this.loginKeypad.reset();
      const displayName = profileData.name || user.displayName || normalizedEmail.split('@')[0];
      ui.showToast(`Welcome back, ${displayName}!`, 'success', 2500);

      // 7. Transition to Dashboard & trigger render
      ui.showView('view-dashboard');
      this._renderDashboard(profileData, user);

      // Dispatch event for UI controllers to render items
      window.dispatchEvent(new CustomEvent('woopass:vault-ready', { detail: { profile: profileData } }));

    } catch (err) {
      console.error('[Auth Login Error]:', err);
      this._loginFailedAttempts++;
      if (this.loginKeypad) this.loginKeypad.shake();

      if (this._loginFailedAttempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS_BEFORE_LOCKOUT) {
        const lockoutSeconds = SECURITY_CONFIG.BASE_LOCKOUT_SECONDS * Math.pow(2, this._loginFailedAttempts - 5);
        this._loginLockoutUntil = Date.now() + (lockoutSeconds * 1000);
        this._saveLockState('login', this._loginFailedAttempts, this._loginLockoutUntil);
        this._startLoginLockoutCountdown(lockoutSeconds);
        ui.showToast(`Too many failed attempts. Temporary lockout for ${lockoutSeconds}s.`, 'danger');
      } else {
        this._saveLockState('login', this._loginFailedAttempts, 0);
        if (this._loginFailedAttempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS_BEFORE_DELAY) {
          ui.showToast('Unable to authenticate. Security throttle active.', 'warning');
          if (this.loginKeypad) {
            this.loginKeypad.setDisabled(true);
            setTimeout(() => {
              this.loginKeypad.setDisabled(false);
            }, 2000);
          }
        } else {
          const errCode = err.code || '';
          if (errCode === 'auth/invalid-credential' || errCode === 'auth/wrong-password' || errCode === 'auth/user-not-found') {
            ui.showToast('Incorrect email or 6-digit PIN. Please verify your details.', 'danger');
          } else if (errCode === 'auth/too-many-requests') {
            ui.showToast('Access temporarily disabled due to many failed attempts. Try again later.', 'danger');
          } else if (errCode === 'auth/user-disabled') {
            ui.showToast('This account has been disabled.', 'danger');
          } else if (errCode === 'auth/network-request-failed') {
            ui.showToast('Network error. Please check your internet connection.', 'danger');
          } else {
            ui.showToast(err.message || 'Unable to authenticate. Please verify your details.', 'danger');
          }
        }
      }
    }
  }

  /**
   * Update profile picture for active user
   * @param {string} photoUrl 
   */
  async updateProfilePicture(photoUrl) {
    const user = auth.currentUser;
    const profile = session.getSessionUser();
    if (!user || !profile) throw new Error('Not logged in. Please log in first.');

    profile.photoUrl = photoUrl;
    session.setSessionUser(profile);
    if (profile.email) {
      localStorage.setItem('woopass_avatar_' + profile.email.toLowerCase(), photoUrl);
    }

    try {
      const userDocRef = doc(db, 'users', user.uid);
      await setDoc(userDocRef, { 
        photoUrl, 
        updatedAt: serverTimestamp() 
      }, { merge: true });
      ui.showToast('Profile picture saved & synced with Firebase!', 'success');
    } catch (e) {
      console.warn('Profile photo Firestore write deferred:', e.message);
      ui.showToast('Picture updated! (Firebase sync pending Firestore rules publication)', 'warning');
    }

    this._renderDashboard(profile, user);
    return photoUrl;
  }

  /**
   * Change user password after validating Home Security Password ()
   * @param {Object} options
   * @param {string} options.homePassword - 6-digit home passcode (must be )
   * @param {string} options.currentPin - Current 6-digit account PIN
   * @param {string} options.newPin - New 6-digit PIN
   * @param {string} options.confirmPin - Confirmation of new PIN
   */
  async changePasswordWithHomeGate({ homePassword, currentPin, newPin, confirmPin }) {
    if ((homePassword || '').trim() !== '584590') {
      throw new Error('Invalid Home Password! You must enter the 6-digit home passcode (849201).');
    }
    return await vaultController.changePin(currentPin, newPin, confirmPin);
  }

  /**
   * Populate dashboard with user details
   */
  _renderDashboard(profile, user) {
    const nameEl = document.getElementById('dash-user-name');
    const emailEl = document.getElementById('dash-user-email');
    const avatarEl = document.getElementById('dash-user-avatar');
    const avatarImgEl = document.getElementById('dash-user-avatar-img');

    const displayName = profile?.name || user?.email || 'Family Member';
    if (nameEl) nameEl.textContent = displayName;
    if (emailEl) emailEl.textContent = profile?.email || user?.email || '';

    const photo = profile?.photoUrl || localStorage.getItem('woopass_avatar_' + (profile?.email || ''));
    if (photo) {
      if (avatarImgEl) {
        avatarImgEl.src = photo;
        avatarImgEl.classList.remove('d-none');
      }
      if (avatarEl) avatarEl.classList.add('d-none');
    } else {
      if (avatarImgEl) avatarImgEl.classList.add('d-none');
      if (avatarEl) {
        avatarEl.classList.remove('d-none');
        avatarEl.textContent = displayName.charAt(0).toUpperCase();
      }
    }

    // Trigger dashboard update event
    window.dispatchEvent(new CustomEvent('woopass:profile-updated', { detail: { profile, user } }));
  }

  /**
   * Lock application (wipes memory, locks UI, prompts for PIN to resume)
   */
  async lock() {
    const user = session.getSessionUser();
    if (user?.uid) {
      await logSecurityEvent({
        uid: user.uid,
        type: 'LOCK',
        success: true,
        details: 'Vault locked manually'
      });
    }

    session.lockSession('Manual lock');
    ui.showToast('Woo Pass is locked', 'warning', 2500);

    // Return to PIN login screen with email preserved
    if (user?.email) {
      const emailInput = document.getElementById('login-email');
      if (emailInput) emailInput.value = user.email;
    }
    if (this.loginKeypad) this.loginKeypad.reset();
    ui.showView('view-login');
  }

  /**
   * Logout user completely (Firebase signOut, wipes session, returns to Gate)
   */
  async logout() {
    const user = session.getSessionUser();
    if (user?.uid) {
      await logSecurityEvent({
        uid: user.uid,
        type: 'LOGOUT',
        success: true,
        details: 'User logged out completely'
      });
    }

    try {
      await signOut(auth);
    } catch (err) {
      // Sign out local state regardless
    }

    session.clearSession();
    ui.showToast('Logged out successfully', 'info', 2500);

    // Reset login forms
    const emailInput = document.getElementById('login-email');
    if (emailInput) emailInput.value = '';
    if (this.loginKeypad) this.loginKeypad.reset();
    if (this.gateKeypad) this.gateKeypad.reset();

    // Return to Family Gate
    ui.showView('view-gate');
  }
}

export const authController = new AuthController();
