/**
 * ============================================================================
 * WOO PASS — Security Audit & Telemetry Module (js/security.js)
 * Security event logging, device telemetry, and Security Center metrics
 * ============================================================================
 */

import { 
  db, 
  collection, 
  addDoc, 
  serverTimestamp, 
  query, 
  where, 
  orderBy, 
  limit, 
  getDocs,
  getAppCheckStatus 
} from "./firebase-init.js";

/**
 * Detect client browser and OS in a privacy-preserving manner
 * @returns {{ browser: string, os: string, platform: string, screen: string }}
 */
export function getClientDeviceMetadata() {
  const userAgent = navigator.userAgent || '';
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';

  // Basic OS Detection
  if (/Windows/i.test(userAgent)) os = 'Windows';
  else if (/Macintosh|Mac OS/i.test(userAgent)) os = 'macOS';
  else if (/Android/i.test(userAgent)) os = 'Android';
  else if (/iPhone|iPad|iPod/i.test(userAgent)) os = 'iOS';
  else if (/Linux/i.test(userAgent)) os = 'Linux';

  // Basic Browser Detection
  if (/Edg/i.test(userAgent)) browser = 'Microsoft Edge';
  else if (/Chrome/i.test(userAgent) && !/Edg/i.test(userAgent)) browser = 'Google Chrome';
  else if (/Safari/i.test(userAgent) && !/Chrome/i.test(userAgent)) browser = 'Apple Safari';
  else if (/Firefox/i.test(userAgent)) browser = 'Mozilla Firefox';

  return {
    browser,
    os,
    platform: navigator.platform || 'Unknown',
    screen: typeof window !== 'undefined' ? `${window.screen.width}x${window.screen.height}` : 'N/A',
    viewport: typeof window !== 'undefined' ? `${window.innerWidth}x${window.innerHeight}` : 'N/A'
  };
}

/**
 * Record a security event in Firestore
 * NEVER logs passwords, PINs, master keys, or sensitive vault data.
 * 
 * @param {Object} params
 * @param {string} params.uid - Authenticated user Firebase UID
 * @param {string} params.type - Event type
 * @param {boolean} [params.success=true] - Event status
 * @param {string} [params.details] - Non-sensitive audit note
 */
export async function logSecurityEvent({ uid, type, success = true, details = '' }) {
  if (!uid) return;

  try {
    const deviceMetadata = getClientDeviceMetadata();
    const eventData = {
      uid: uid,
      type: type,
      success: Boolean(success),
      details: details ? details.substring(0, 100) : '',
      device: `${deviceMetadata.browser} on ${deviceMetadata.os}`,
      screen: deviceMetadata.screen,
      userAgent: (navigator.userAgent || '').substring(0, 200),
      timestamp: serverTimestamp(),
      createdAtClient: new Date().toISOString()
    };

    const eventsRef = collection(db, 'security_events');
    await addDoc(eventsRef, eventData);
  } catch (err) {
    // Audit logging is non-blocking to prevent UI disruption
    console.warn('[Security Log] Audit write suppressed:', err.message || err);
  }
}

/**
 * Fetch recent security audit events for current user
 * @param {string} uid 
 * @param {number} count 
 * @returns {Promise<Array>}
 */
export async function fetchUserSecurityEvents(uid, count = 10) {
  if (!uid) return [];

  try {
    const eventsRef = collection(db, 'security_events');
    const q = query(
      eventsRef,
      where('uid', '==', uid),
      orderBy('timestamp', 'desc'),
      limit(count)
    );

    const snapshot = await getDocs(q);
    const events = [];
    snapshot.forEach(docSnap => {
      const data = docSnap.data();
      events.push({
        id: docSnap.id,
        type: data.type || 'UNKNOWN',
        device: data.device || 'Unknown device',
        success: data.success,
        details: data.details || '',
        timestamp: data.timestamp ? data.timestamp.toDate() : new Date(data.createdAtClient || Date.now())
      });
    });
    return events;
  } catch (err) {
    return [];
  }
}

/**
 * Compile comprehensive telemetry payload for the Part 2 Security Center
 * @param {Object} currentUser - Firebase Auth User
 * @param {Object} profile - Firestore Profile Data
 * @param {Object} vaultStats - Decrypted vault item counters
 * @returns {Promise<Object>}
 */
export async function compileSecurityCenterData(currentUser, profile = {}, vaultStats = {}) {
  const deviceMeta = getClientDeviceMetadata();
  const appCheck = getAppCheckStatus();
  let recentLogs = [];

  if (currentUser && currentUser.uid) {
    recentLogs = await fetchUserSecurityEvents(currentUser.uid, 8);
  }

  const creationTime = currentUser?.metadata?.creationTime 
    ? new Date(currentUser.metadata.creationTime).toLocaleString() 
    : 'Active';

  const lastSignInTime = currentUser?.metadata?.lastSignInTime 
    ? new Date(currentUser.metadata.lastSignInTime).toLocaleString() 
    : 'Active Session';

  return {
    authStatus: currentUser ? 'Authenticated (Active Session)' : 'Unauthenticated',
    uid: currentUser ? currentUser.uid : 'N/A',
    email: currentUser ? currentUser.email : 'N/A',
    emailVerified: currentUser ? (currentUser.emailVerified ? 'Verified' : 'Active') : 'N/A',
    provider: currentUser?.providerData?.[0]?.providerId || 'password',
    accountCreated: creationTime,
    lastSignIn: lastSignInTime,
    deviceInfo: `${deviceMeta.browser} on ${deviceMeta.os} (${deviceMeta.screen})`,
    appCheckStatus: appCheck.initialized ? `Active (${appCheck.mode})` : 'Standby / Local',
    vaultSaltConfigured: Boolean(profile?.vaultSalt),
    driveConnected: Boolean(profile?.googleDriveUrl),
    driveUrl: profile?.googleDriveUrl || null,
    vaultStats: vaultStats,
    encryptionSpec: 'AES-256-GCM + PBKDF2 (100,000 rounds) Key Hierarchy',
    recentLogs
  };
}
