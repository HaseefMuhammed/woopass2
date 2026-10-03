/**
 * ============================================================================
 * WOO PASS — Firebase Configuration (js/firebase-config.js)
 * Frontend web client credentials for Firebase Services
 * ============================================================================
 */

export const firebaseConfig = {
  apiKey: "AIzaSyCAHsyVgN62FI9xTQKVt9OjeWGEuDnG-j0",
  authDomain: "woopass.firebaseapp.com",
  projectId: "woopass",
  storageBucket: "woopass.firebasestorage.app",
  messagingSenderId: "1099334703793",
  appId: "1:1099334703793:web:fb29b19e27429d59ae6090"
};

// Application security settings
export const SECURITY_CONFIG = {
  // 5 minutes in milliseconds
  SESSION_TIMEOUT_MS: 5 * 60 * 1000,
  // 4 minutes 30 seconds warning modal in milliseconds
  SESSION_WARNING_MS: 4.5 * 60 * 1000,
  // Failed login rate limit thresholds
  MAX_FAILED_ATTEMPTS_BEFORE_DELAY: 3,
  MAX_FAILED_ATTEMPTS_BEFORE_LOCKOUT: 5,
  // Home Gate PIN is stored only as a PBKDF2 hash in the auth module — never in config
  BASE_LOCKOUT_SECONDS: 30
};
