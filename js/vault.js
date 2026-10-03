/**
 * ============================================================================
 * WOO PASS — Vault Controller (js/vault.js)
 * Zero-Trust Client-Side Encrypted Vault Engine (Part 2 Production Core)
 * ============================================================================
 * 
 * SECURITY ARCHITECTURE:
 * 1. Zero-Trust Storage: Firestore ONLY stores AES-256-GCM encrypted records.
 *    Plaintext secrets are never transmitted or stored remotely.
 * 2. Key Hierarchy:
 *    User PIN + Salt -> PBKDF2 (100k rounds) -> KEK -> decrypts random 256-bit VEK.
 * 3. Volatile In-Memory Cache: Decrypted records exist strictly in memory closures.
 *    Wiped immediately on Lock, Inactivity Timeout, or Logout.
 * 4. Local Search: Plaintext searching is strictly client-side over decrypted records.
 * 5. Encrypted Backup: Generates structured, encrypted .woopass backup packages.
 */

import { 
  db, 
  auth, 
  doc, 
  setDoc, 
  getDoc, 
  deleteDoc, 
  collection, 
  getDocs, 
  serverTimestamp,
  updatePassword,
  EmailAuthProvider,
  reauthenticateWithCredential
} from "./firebase-init.js";

import { 
  deriveKEK, 
  deriveAuthSecret,
  generateVaultKeyBytes, 
  importRawAESKey, 
  wrapVaultKey, 
  unwrapVaultKey, 
  rewrapVaultKey, 
  encryptVaultRecord, 
  decryptVaultRecord,
  validatePinStrength,
  bufferToHex
} from "./crypto.js";

import { logSecurityEvent } from "./security.js";
import { session } from "./session.js";

class VaultController {
  constructor() {
    // Active decrypted Vault Encryption Key (CryptoKey) in memory closure
    this._vaultKey = null;
    
    // In-memory decrypted record stores (never exposed on window or persistence)
    this._items = {
      passwords: [],
      banking: [],
      cards: [],
      notes: []
    };

    this._isInitialized = false;
  }

  /**
   * Check if the vault encryption key is unlocked in memory
   * @returns {boolean}
   */
  isUnlocked() {
    return Boolean(this._vaultKey && this._isInitialized);
  }

  /**
   * Wipe decrypted keys and records from volatile memory immediately
   */
  clearMemory() {
    this._vaultKey = null;
    this._items = {
      passwords: [],
      banking: [],
      cards: [],
      notes: []
    };
    this._isInitialized = false;
  }

  /**
   * Initialize and unlock the vault on user authentication
   * @param {string} uid - Firebase Auth UID
   * @param {string} pin - 6-digit user PIN
   * @param {string} email - Normalized user email
   * @param {string} vaultSaltHex - User's unique 32-byte salt
   */
  async initVault(uid, pin, email, vaultSaltHex) {
    if (!uid || !pin || !email) {
      throw new Error('Missing credentials for vault initialization');
    }

    try {
      // 1. Derive Key Encryption Key (KEK) via PBKDF2 (100,000 iterations)
      const kek = await deriveKEK(pin, vaultSaltHex, email);

      // 2. Fetch or create wrapped Vault Encryption Key (VEK)
      const vaultDocRef = doc(db, 'vaults', uid);
      let vaultSnap = null;
      try {
        vaultSnap = await getDoc(vaultDocRef);
      } catch (e) {
        console.warn('[Vault] Firestore vaults read warning:', e.message);
      }

      if (vaultSnap && vaultSnap.exists()) {
        // Unwrap existing VEK
        const vaultData = vaultSnap.data();
        this._vaultKey = await unwrapVaultKey(vaultData.encryptedVek, vaultData.iv, kek);
      } else {
        // Initialize fresh 256-bit random VEK and wrap it with KEK
        const rawVekBytes = generateVaultKeyBytes();
        const wrapped = await wrapVaultKey(rawVekBytes, kek);
        this._vaultKey = await importRawAESKey(rawVekBytes);

        try {
          await setDoc(vaultDocRef, {
            uid: uid,
            encryptedVek: wrapped.encryptedVekHex,
            iv: wrapped.ivHex,
            version: 1,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp()
          });
        } catch (writeErr) {
          console.warn('[Vault] Deferred writing wrapped key to Firestore:', writeErr.message);
        }
      }

      this._isInitialized = true;

      // 3. Load and decrypt all user vault records from Firestore
      await this.reloadVault(uid);

      return true;
    } catch (err) {
      this.clearMemory();
      console.error('[Vault Init Error]:', err);
      throw new Error('Unable to decrypt vault keys. Please verify your PIN.');
    }
  }

  /**
   * Load and decrypt all items from Firestore into memory
   * @param {string} uid 
   */
  /**
   * Load and decrypt all items from Firestore into volatile memory.
   * Zero-Trust: Reads ONLY encrypted documents from vaultItems/{uid}/items.
   * Plaintext data is never written to or read from unencrypted collections.
   * @param {string} uid 
   */
  async reloadVault(uid) {
    if (!this._vaultKey || !uid) return;

    this._items = { passwords: [], banking: [], cards: [], notes: [] };
    const itemsMap = { passwords: new Map(), notes: new Map(), banking: new Map(), cards: new Map() };

    // Clean up any legacy plaintext cache from prior vulnerable versions
    ['passwords', 'notes', 'banking', 'cards'].forEach(cat => {
      try {
        localStorage.removeItem(`woopass_store_${uid}_${cat}`);
      } catch (e) {}
    });

    const encryptedCacheList = [];

    // 1. Load from encrypted Firestore collection: vaultItems/{uid}/items
    try {
      const itemsCollectionRef = collection(db, 'vaultItems', uid, 'items');
      const querySnap = await getDocs(itemsCollectionRef);

      const decryptPromises = [];

      querySnap.forEach(docSnap => {
        const data = docSnap.data();
        const id = docSnap.id;

        encryptedCacheList.push({ id, ...data });

        decryptPromises.push(
          (async () => {
            try {
              if (data.ciphertext && data.iv) {
                const decryptedPayload = await decryptVaultRecord(data.ciphertext, data.iv, this._vaultKey);
                const item = {
                  id: id,
                  type: data.type || decryptedPayload.type || 'passwords',
                  createdAt: data.createdAtClient || new Date().toISOString(),
                  updatedAt: data.updatedAtClient || new Date().toISOString(),
                  ...decryptedPayload
                };

                const typeKey = item.type === 'password' ? 'passwords' : item.type;
                if (itemsMap[typeKey]) {
                  itemsMap[typeKey].set(item.id, item);
                }
              }
            } catch (decErr) {
              console.warn(`[Vault] Record ${id} decryption notice:`, decErr.message);
            }
          })()
        );
      });

      await Promise.all(decryptPromises);

      // Save encrypted offline cache (ciphertext only, zero plaintext)
      if (encryptedCacheList.length > 0) {
        try {
          localStorage.setItem(`woopass_vault_enc_${uid}`, JSON.stringify(encryptedCacheList));
        } catch (e) {}
      }
    } catch (loadErr) {
      console.warn('[Vault] Firestore encrypted read notice, checking encrypted local cache:', loadErr.message);

      // 2. Offline Fallback: Load from encrypted local cache
      try {
        const rawEnc = localStorage.getItem(`woopass_vault_enc_${uid}`);
        if (rawEnc) {
          const encList = JSON.parse(rawEnc);
          if (Array.isArray(encList)) {
            const offlineDecrypts = encList.map(async (data) => {
              try {
                if (data.ciphertext && data.iv) {
                  const decryptedPayload = await decryptVaultRecord(data.ciphertext, data.iv, this._vaultKey);
                  const item = {
                    id: data.id,
                    type: data.type || decryptedPayload.type || 'passwords',
                    createdAt: data.createdAtClient || new Date().toISOString(),
                    updatedAt: data.updatedAtClient || new Date().toISOString(),
                    ...decryptedPayload
                  };
                  const typeKey = item.type === 'password' ? 'passwords' : item.type;
                  if (itemsMap[typeKey]) {
                    itemsMap[typeKey].set(item.id, item);
                  }
                }
              } catch (e) {}
            });
            await Promise.all(offlineDecrypts);
          }
        }
      } catch (offlineErr) {
        console.warn('[Vault] Offline encrypted cache read notice:', offlineErr.message);
      }
    }

    // Convert Maps to sorted arrays in volatile memory
    ['passwords', 'notes', 'banking', 'cards'].forEach(cat => {
      this._items[cat] = Array.from(itemsMap[cat].values());
      this._items[cat].sort((a, b) => new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0));
    });
  }

  /**
   * Get all in-memory decrypted items for a category
   * @param {'passwords'|'banking'|'cards'|'notes'} category 
   * @returns {Array<Object>}
   */
  getItems(category) {
    const list = this._items[category] || [];
    return [...list];
  }

  /**
   * Get a single item by ID and category
   * @param {'passwords'|'banking'|'cards'|'notes'} category 
   * @param {string} id 
   * @returns {Object|null}
   */
  getItemById(category, id) {
    const list = this._items[category] || [];
    const item = list.find(it => it.id === id);
    return item ? { ...item } : null;
  }

  /**
   * Search items locally across decrypted fields
   * @param {'passwords'|'banking'|'cards'|'notes'|'all'} category 
   * @param {string} query 
   * @returns {Array<Object>}
   */
  searchItems(category, query) {
    const cleanQuery = (query || '').trim().toLowerCase();
    if (!cleanQuery) {
      return category === 'all' 
        ? [...this._items.passwords, ...this._items.banking, ...this._items.cards, ...this._items.notes]
        : this.getItems(category);
    }

    const searchInList = (list) => {
      return list.filter(item => {
        const title = (item.title || item.bankName || item.cardName || '').toLowerCase();
        const notes = (item.notes || item.content || '').toLowerCase();
        const username = (item.username || item.accountHolder || item.cardholder || '').toLowerCase();
        const site = (item.website || '').toLowerCase();
        const accNum = (item.accountNumber || item.lastFour || '').toLowerCase();

        return title.includes(cleanQuery) || 
               notes.includes(cleanQuery) || 
               username.includes(cleanQuery) || 
               site.includes(cleanQuery) ||
               accNum.includes(cleanQuery);
      });
    };

    if (category === 'all') {
      return [
        ...searchInList(this._items.passwords),
        ...searchInList(this._items.notes)
      ];
    }

    return searchInList(this._items[category] || []);
  }

  /**
   * Save a vault item (Create or Update)
   * Zero-Trust: Encrypts payload client-side with AES-256-GCM BEFORE writing to Firestore.
   * Strictly writes ONLY to vaultItems/{uid}/items. Never writes unencrypted records.
   * @param {'passwords'|'notes'|'banking'|'cards'} category 
   * @param {Object} itemData - Item payload
   * @param {string} [existingId] - ID if updating existing record
   * @returns {Promise<Object>} Saved item with ID
   */
  async saveItem(category, itemData, existingId = null) {
    const currentUser = auth.currentUser;
    if (!currentUser) {
      throw new Error('User session not authenticated. Please log in.');
    }
    if (!this._vaultKey) {
      throw new Error('Vault is locked. Unlock vault before saving records.');
    }

    const uid = currentUser.uid;
    const itemId = existingId || 'item_' + Date.now() + '_' + bufferToHex(generateVaultKeyBytes().slice(0, 4));
    const nowIso = new Date().toISOString();

    const fullSavedItem = {
      ...itemData,
      id: itemId,
      type: category,
      category: category,
      uid: uid,
      updatedAt: nowIso,
      createdAt: itemData.createdAt || nowIso
    };

    let firestoreSuccess = false;
    let lastFirestoreError = null;

    // 1. Client-Side AES-256-GCM Encryption (Zero-Trust)
    let docData = null;
    try {
      const encrypted = await encryptVaultRecord(fullSavedItem, this._vaultKey);
      docData = {
        type: category,
        ciphertext: encrypted.ciphertextHex,
        iv: encrypted.ivHex,
        version: encrypted.version,
        updatedAtClient: nowIso,
        createdAtClient: fullSavedItem.createdAt,
        serverUpdatedAt: serverTimestamp()
      };

      const itemDocRef = doc(db, 'vaultItems', uid, 'items', itemId);
      await setDoc(itemDocRef, docData);
      firestoreSuccess = true;

      // Clean up legacy unencrypted document if it ever existed
      try {
        const legacyDocRef = doc(db, 'users', uid, category, itemId);
        await deleteDoc(legacyDocRef);
      } catch (cleanErr) {}

    } catch (encSaveErr) {
      lastFirestoreError = encSaveErr;
      console.error('[Vault Save Error]:', encSaveErr);
    }

    // 2. Update in-memory decrypted store (strictly volatile memory only)
    const targetList = this._items[category] || [];
    const existingIndex = targetList.findIndex(it => it.id === itemId);
    if (existingIndex >= 0) {
      targetList[existingIndex] = fullSavedItem;
    } else {
      targetList.unshift(fullSavedItem);
    }
    targetList.sort((a, b) => new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0));
    this._items[category] = targetList;

    // 3. Purge legacy plaintext from localStorage
    try {
      localStorage.removeItem(`woopass_store_${uid}_${category}`);
    } catch (e) {}

    // 4. Update encrypted offline cache with ciphertext
    if (docData) {
      try {
        const rawEnc = localStorage.getItem(`woopass_vault_enc_${uid}`);
        let encList = rawEnc ? JSON.parse(rawEnc) : [];
        if (!Array.isArray(encList)) encList = [];
        const idx = encList.findIndex(x => x.id === itemId);
        const encRecord = { id: itemId, ...docData };
        if (idx >= 0) {
          encList[idx] = encRecord;
        } else {
          encList.unshift(encRecord);
        }
        localStorage.setItem(`woopass_vault_enc_${uid}`, JSON.stringify(encList));
      } catch (cacheErr) {}
    }

    // 5. Log security event
    const eventType = existingId 
      ? `${category.toUpperCase().replace(/S$/, '')}_UPDATED` 
      : `${category.toUpperCase().replace(/S$/, '')}_CREATED`;

    try {
      await logSecurityEvent({
        uid: uid,
        type: eventType,
        success: firestoreSuccess,
        details: `Record ${itemId.slice(0, 10)} saved securely (AES-256-GCM)`
      });
    } catch (e) {}

    return {
      ...fullSavedItem,
      syncedToFirebase: firestoreSuccess,
      firestoreError: lastFirestoreError
    };
  }

  /**
   * Delete a vault item
   * Removes from vaultItems/{uid}/items/{id} and encrypted cache
   * @param {'passwords'|'notes'|'banking'|'cards'} category 
   * @param {string} id 
   */
  async deleteItem(category, id) {
    const currentUser = auth.currentUser;
    if (!currentUser) {
      throw new Error('User session not authenticated.');
    }

    const uid = currentUser.uid;

    // 1. Delete from vaultItems/{uid}/items/{id}
    try {
      const itemDocRef = doc(db, 'vaultItems', uid, 'items', id);
      await deleteDoc(itemDocRef);
    } catch (delErr) {
      console.warn('[Vault Delete Encrypted Notice]:', delErr.message);
    }

    // 2. Clean up legacy unencrypted document if present
    try {
      const legacyDocRef = doc(db, 'users', uid, category, id);
      await deleteDoc(legacyDocRef);
    } catch (cleanErr) {}

    // 3. Remove from in-memory cache
    this._items[category] = (this._items[category] || []).filter(it => it.id !== id);

    // 4. Update encrypted offline cache
    try {
      const rawEnc = localStorage.getItem(`woopass_vault_enc_${uid}`);
      if (rawEnc) {
        let encList = JSON.parse(rawEnc);
        if (Array.isArray(encList)) {
          encList = encList.filter(x => x.id !== id);
          localStorage.setItem(`woopass_vault_enc_${uid}`, JSON.stringify(encList));
        }
      }
      localStorage.removeItem(`woopass_store_${uid}_${category}`);
    } catch (e) {}

    // 5. Log Security Event
    try {
      const eventType = `${category.toUpperCase().replace(/S$/, '')}_DELETED`;
      await logSecurityEvent({
        uid: uid,
        type: eventType,
        success: true,
        details: `Record ${id.slice(0, 10)} deleted`
      });
    } catch (e) {}

    return true;
  }

  /**
   * Change User PIN
   * Re-encrypts the wrapped Vault Encryption Key (VEK) with a new Key Encryption Key (KEK)
   * without having to re-encrypt any individual vault items.
   * Updates Firebase Auth password credential derived from new PIN.
   * 
   * @param {string} currentPin 
   * @param {string} newPin 
   * @param {string} confirmPin 
   */
  async changePin(currentPin, newPin, confirmPin) {
    const currentUser = auth.currentUser;
    const profile = session.getSessionUser();
    if (!currentUser || !profile) {
      throw new Error('User session not active.');
    }

    if (newPin !== confirmPin) {
      throw new Error('New PIN and Confirm PIN do not match.');
    }

    const validation = validatePinStrength(newPin);
    if (!validation.valid) {
      throw new Error(validation.reason);
    }

    if (currentPin === newPin) {
      throw new Error('New PIN must be different from current PIN.');
    }

    const uid = currentUser.uid;
    const email = (profile.email || currentUser.email).trim().toLowerCase();
    const vaultSaltHex = profile.vaultSalt || bufferToHex(generateVaultKeyBytes());

    // 1. Fetch existing wrapped VEK from Firestore
    const vaultDocRef = doc(db, 'vaults', uid);
    const vaultSnap = await getDoc(vaultDocRef);

    if (!vaultSnap.exists()) {
      throw new Error('Vault metadata not found. Please contact support.');
    }

    const vaultData = vaultSnap.data();

    // 2. Re-wrap VEK using rewrapVaultKey
    let rewrapped = null;
    try {
      rewrapped = await rewrapVaultKey(
        currentPin,
        newPin,
        email,
        vaultSaltHex,
        vaultData.encryptedVek,
        vaultData.iv
      );
    } catch (wrapErr) {
      throw new Error('Current PIN is incorrect. Vault key could not be unlocked.');
    }

    // 3. Update Firestore wrapped VEK record
    await setDoc(vaultDocRef, {
      uid: uid,
      encryptedVek: rewrapped.newEncryptedVekHex,
      iv: rewrapped.newIvHex,
      version: (vaultData.version || 1) + 1,
      updatedAt: serverTimestamp()
    });

    // 4. Update Firebase Auth derived password
    const newAuthSecret = await deriveAuthSecret(newPin, email);
    try {
      await updatePassword(currentUser, newAuthSecret);
    } catch (authErr) {
      if (authErr && authErr.code === 'auth/requires-recent-login') {
        try {
          const currentAuthSecret = await deriveAuthSecret(currentPin, email);
          const cred = EmailAuthProvider.credential(email, currentAuthSecret);
          await reauthenticateWithCredential(currentUser, cred);
          await updatePassword(currentUser, newAuthSecret);
        } catch (reauthErr) {
          console.warn('[Vault] Reauthentication password update warning:', reauthErr.message);
        }
      } else {
        console.warn('[Vault] updatePassword warning:', authErr?.message);
      }
    }

    // 4b. Record passwordChangedAt in user profile & localStorage
    const changedTimestamp = new Date().toISOString();
    try {
      const userDocRef = doc(db, 'users', uid);
      await setDoc(userDocRef, {
        passwordChangedAt: changedTimestamp,
        updatedAt: serverTimestamp()
      }, { merge: true });
    } catch (e) {
      console.warn('[Vault] passwordChangedAt write deferred:', e.message);
    }

    localStorage.setItem(`woopass_pwd_changed_${uid}`, changedTimestamp);
    if (profile) {
      profile.passwordChangedAt = changedTimestamp;
      session.setSessionUser(profile);
    }

    // 5. Update active in-memory VEK
    this._vaultKey = rewrapped.newVekKey;

    // 6. Log Security Event
    try {
      await logSecurityEvent({
        uid: uid,
        type: 'PIN_CHANGED',
        success: true,
        details: 'Vault encryption key successfully re-wrapped with new PIN'
      });
    } catch (logErr) {}

    // Dispatch event for UI controllers to update password notices
    window.dispatchEvent(new CustomEvent('woopass:password-changed', { 
      detail: { uid, passwordChangedAt: changedTimestamp } 
    }));

    return true;
  }

  /**
   * Update connected document or cloud storage URL (Google Drive, Apps Script, etc.)
   * @param {string} driveUrl 
   */
  async updateGoogleDriveUrl(driveUrl) {
    const currentUser = auth.currentUser;
    const profile = session.getSessionUser();
    if (!currentUser || !profile) {
      throw new Error('User session not active.');
    }

    let cleanUrl = (driveUrl || '').trim();
    if (!cleanUrl) {
      throw new Error('Please enter a link (e.g., Google Drive, Google Apps Script, web portal).');
    }
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    const uid = currentUser.uid;
    const userDocRef = doc(db, 'users', uid);

    try {
      await setDoc(userDocRef, {
        googleDriveUrl: cleanUrl,
        updatedAt: serverTimestamp()
      }, { merge: true });
    } catch (err) {
      console.warn('[Vault] Firestore link write notice:', err.message);
    }

    // Update in-memory session profile
    profile.googleDriveUrl = cleanUrl;
    session.setSessionUser(profile);

    await logSecurityEvent({
      uid: uid,
      type: 'LINK_UPDATED',
      success: true,
      details: 'Connected folder/portal reference updated'
    });

    return cleanUrl;
  }

  /**
   * Export encrypted .woopass backup package
   * Zero plaintext passwords/PINs in export file.
   */
  async exportBackup() {
    if (!this._vaultKey) {
      throw new Error('Vault is locked. Cannot export while locked.');
    }

    const currentUser = auth.currentUser;
    const profile = session.getSessionUser();
    if (!currentUser || !profile) {
      throw new Error('Session not active.');
    }

    const uid = currentUser.uid;
    const vaultDocRef = doc(db, 'vaults', uid);
    const vaultSnap = await getDoc(vaultDocRef);

    let wrappedKeyMeta = null;
    if (vaultSnap.exists()) {
      wrappedKeyMeta = vaultSnap.data();
    }

    // Fetch all encrypted records from Firestore
    const itemsCollectionRef = collection(db, 'vaultItems', uid, 'items');
    const querySnap = await getDocs(itemsCollectionRef);
    const encryptedRecords = [];

    querySnap.forEach(docSnap => {
      encryptedRecords.push({
        id: docSnap.id,
        ...docSnap.data()
      });
    });

    const backupPayload = {
      format: 'WOOPASS_ENCRYPTED_VAULT_BACKUP',
      formatVersion: 2,
      exportTimestamp: new Date().toISOString(),
      vaultSalt: profile.vaultSalt || '',
      wrappedKey: {
        encryptedVek: wrappedKeyMeta?.encryptedVek || '',
        iv: wrappedKeyMeta?.iv || '',
        version: wrappedKeyMeta?.version || 1
      },
      encryptedRecords: encryptedRecords,
      meta: {
        totalRecords: encryptedRecords.length,
        algorithm: 'AES-256-GCM + PBKDF2-HMAC-SHA256'
      }
    };

    const jsonBlob = new Blob([JSON.stringify(backupPayload, null, 2)], { type: 'application/json' });
    const downloadUrl = URL.createObjectURL(jsonBlob);
    const dateStr = new Date().toISOString().split('T')[0];
    const fileName = `woopass_backup_${dateStr}.woopass`;

    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);

    await logSecurityEvent({
      uid: uid,
      type: 'EXPORT_COMPLETED',
      success: true,
      details: `Encrypted backup exported (${encryptedRecords.length} records)`
    });

    return { totalRecords: encryptedRecords.length, fileName };
  }

  /**
   * Import & restore from a .woopass encrypted backup file
   * @param {string} fileContent 
   * @param {string} backupPin 
   */
  async importBackup(fileContent, backupPin) {
    if (!this._vaultKey) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const currentUser = auth.currentUser;
    const profile = session.getSessionUser();
    if (!currentUser || !profile) {
      throw new Error('Session not active.');
    }

    let parsed = null;
    try {
      parsed = JSON.parse(fileContent);
    } catch (e) {
      throw new Error('Invalid backup file format. Expected valid .woopass JSON file.');
    }

    if (!parsed || parsed.format !== 'WOOPASS_ENCRYPTED_VAULT_BACKUP' || !parsed.wrappedKey) {
      throw new Error('Incompatible or corrupted .woopass backup file.');
    }

    const email = (profile.email || currentUser.email).trim().toLowerCase();
    const backupSalt = parsed.vaultSalt || profile.vaultSalt;

    // 1. Derive KEK for the backup with the provided PIN
    let backupVek = null;
    try {
      const backupKek = await deriveKEK(backupPin, backupSalt, email);
      backupVek = await unwrapVaultKey(parsed.wrappedKey.encryptedVek, parsed.wrappedKey.iv, backupKek);
    } catch (kErr) {
      throw new Error('Incorrect backup PIN. Could not decrypt backup key material.');
    }

    // 2. Decrypt records from backup and re-encrypt with current active VEK
    const records = parsed.encryptedRecords || [];
    let restoredCount = 0;

    for (const rec of records) {
      try {
        if (rec.ciphertext && rec.iv) {
          const decryptedPayload = await decryptVaultRecord(rec.ciphertext, rec.iv, backupVek);
          const category = rec.type || decryptedPayload.type || 'passwords';
          
          await this.saveItem(category, decryptedPayload);
          restoredCount++;
        }
      } catch (rErr) {
        console.warn(`[Vault Restore] Skipped record:`, rErr.message);
      }
    }

    // Refresh active in-memory lists
    await this.reloadVault(currentUser.uid);

    await logSecurityEvent({
      uid: currentUser.uid,
      type: 'BACKUP_RESTORED',
      success: true,
      details: `Restored ${restoredCount} records from .woopass backup`
    });

    return restoredCount;
  }

  /**
   * Get counts of items across all categories
   * @returns {{ passwords: number, banking: number, cards: number, notes: number, total: number }}
   */
  getStats() {
    const pw = (this._items.passwords || []).length;
    const bk = (this._items.banking || []).length;
    const cd = (this._items.cards || []).length;
    const nt = (this._items.notes || []).length;
    return {
      passwords: pw,
      banking: bk,
      cards: cd,
      notes: nt,
      total: pw + bk + cd + nt
    };
  }
}

export const vaultController = new VaultController();
