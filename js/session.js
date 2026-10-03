/**
 * ============================================================================
 * WOO PASS — Session Management Module (js/session.js)
 * 5-Minute Inactivity Auto-Lock, 4:30 Warning Modal, and Memory-Only State
 * ============================================================================
 */

import { SECURITY_CONFIG } from "./firebase-config.js";
import { ui } from "./ui.js";
import { vaultController } from "./vault.js";

class SessionManager {
  constructor() {
    // Memory-only session state (Zero localStorage / sessionStorage usage)
    this._userProfile = null;
    this._isLocked = true;
    this._isGateUnlocked = false;

    // Timer handles
    this._lockTimer = null;
    this._warningTimer = null;
    this._lastActivityTime = Date.now();
    this._throttleTimeout = null;

    // Lock callback
    this._onLockCallback = null;
    this._boundActivityListener = this._handleUserActivity.bind(this);

    // Cross-Tab Synchronization (BroadcastChannel)
    this._initCrossTabSync();
  }

  /**
   * Set up non-sensitive cross-tab broadcast synchronization
   */
  _initCrossTabSync() {
    if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
      try {
        this._syncChannel = new BroadcastChannel('woopass_security_sync');
        this._syncChannel.onmessage = (event) => {
          const action = event.data?.action;
          if (action === 'LOCK' && !this._isLocked) {
            this.lockSession('Cross-tab lock synchronization', false);
          } else if (action === 'LOGOUT') {
            this.clearSession(false);
            if (this._onLockCallback) {
              this._onLockCallback('Logged out from another tab');
            }
          }
        };
      } catch (e) {
        console.warn('[Session] BroadcastChannel unavailable:', e.message);
      }
    }
  }

  /**
   * Broadcast safe action to other open tabs
   */
  _broadcastAction(action) {
    if (this._syncChannel) {
      try {
        this._syncChannel.postMessage({ action, timestamp: Date.now() });
      } catch (e) {}
    }
  }

  /**
   * Set callback to invoke when application automatically or manually locks
   * @param {Function} callback 
   */
  setOnLock(callback) {
    this._onLockCallback = callback;
  }

  /**
   * Unlock the installation Family Admin Gate for this session
   */
  unlockFamilyGate() {
    this._isGateUnlocked = true;
  }

  /**
   * Check if Family Admin Gate is unlocked
   * @returns {boolean}
   */
  isFamilyGateUnlocked() {
    return this._isGateUnlocked;
  }

  /**
   * Store user profile in volatile memory upon successful authentication
   * @param {Object} profile 
   */
  setSessionUser(profile) {
    this._userProfile = { ...profile };
    this._isLocked = false;
    this.startInactivityMonitoring();
  }

  /**
   * Get in-memory user profile
   * @returns {Object|null}
   */
  getSessionUser() {
    return this._userProfile ? { ...this._userProfile } : null;
  }

  /**
   * Check if the session is currently locked
   * @returns {boolean}
   */
  isLocked() {
    return this._isLocked;
  }

  /**
   * Start 5-minute inactivity watchdog and user activity listeners
   */
  startInactivityMonitoring() {
    this.stopInactivityMonitoring();
    this._lastActivityTime = Date.now();

    // Attach activity event listeners
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'];
    events.forEach(evt => {
      window.addEventListener(evt, this._boundActivityListener, { passive: true });
    });

    this._armTimers();
  }

  /**
   * Stop inactivity watchdog
   */
  stopInactivityMonitoring() {
    if (this._lockTimer) clearTimeout(this._lockTimer);
    if (this._warningTimer) clearTimeout(this._warningTimer);
    this._lockTimer = null;
    this._warningTimer = null;

    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'];
    events.forEach(evt => {
      window.removeEventListener(evt, this._boundActivityListener);
    });
  }

  /**
   * Arm the warning (4:30) and lock (5:00) timers
   */
  _armTimers() {
    if (this._lockTimer) clearTimeout(this._lockTimer);
    if (this._warningTimer) clearTimeout(this._warningTimer);

    // 4 Minutes 30 Seconds warning modal
    this._warningTimer = setTimeout(() => {
      this._showSessionExpiringWarning();
    }, SECURITY_CONFIG.SESSION_WARNING_MS);

    // 5 Minutes full lock
    this._lockTimer = setTimeout(() => {
      this.lockSession('Inactivity timeout (5 minutes)');
    }, SECURITY_CONFIG.SESSION_TIMEOUT_MS);
  }

  /**
   * Throttled user activity handler
   */
  _handleUserActivity() {
    if (this._isLocked) return;

    const now = Date.now();
    // Throttle activity timer resets to at most once every 1000ms for high performance
    if (now - this._lastActivityTime > 1000) {
      this._lastActivityTime = now;
      this._armTimers();
    }
  }

  /**
   * Explicitly extend the session (called when user clicks "Continue Session" in modal)
   */
  continueSession() {
    ui.hideModal('modal-session-expiring');
    this._lastActivityTime = Date.now();
    this._armTimers();
    ui.showToast('Session extended securely', 'success', 2500);
  }

  /**
   * Display the 4:30 session expiring modal
   */
  _showSessionExpiringWarning() {
    if (this._isLocked) return;
    ui.showModal('modal-session-expiring');
  }

  /**
   * Lock the application:
   * 1. Marks session locked
   * 2. Clears sensitive in-memory state and decrypted vault keys
   * 3. Clears sensitive forms
   * 4. Returns to secure PIN unlock screen
   */
  lockSession(reason = 'Manual lock', broadcast = true) {
    this._isLocked = true;
    this.stopInactivityMonitoring();
    ui.hideModal('modal-session-expiring');

    // Wipe sensitive vault key and decrypted memory cache immediately
    vaultController.clearMemory();

    // Wipe any sensitive input elements in DOM
    const sensitiveInputs = document.querySelectorAll('input[type="password"], input[type="text"], input[type="email"], input[type="tel"], textarea');
    sensitiveInputs.forEach(input => {
      if (input.id !== 'login-email') {
        input.value = '';
      }
    });

    if (broadcast) {
      this._broadcastAction('LOCK');
    }

    if (this._onLockCallback) {
      this._onLockCallback(reason);
    }
  }

  /**
   * Completely clear session state on full Logout
   */
  clearSession(broadcast = true) {
    this.stopInactivityMonitoring();
    this._userProfile = null;
    this._isLocked = true;
    this._isGateUnlocked = false;

    // Wipe decrypted vault keys and records
    vaultController.clearMemory();

    if (broadcast) {
      this._broadcastAction('LOGOUT');
    }
  }
}

export const session = new SessionManager();
