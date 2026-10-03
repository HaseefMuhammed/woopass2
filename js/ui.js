/**
 * ============================================================================
 * WOO PASS — UI & View Manager (js/ui.js)
 * View routing, custom Toast notifications, Modal management, and Secure Clipboard
 * ============================================================================
 */

export class UIManager {
  constructor() {
    this.currentView = null;
    this.toastContainer = null;
    this.modals = {};
    this._clipboardTimer = null;
    this.init();
  }

  init() {
    this._ensureToastContainer();
    this._initBootstrapModals();
  }

  /**
   * Ensure the toast container exists in the DOM
   */
  _ensureToastContainer() {
    let container = document.getElementById('vault-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'vault-toast-container';
      container.className = 'vault-toast-container';
      document.body.appendChild(container);
    }
    this.toastContainer = container;
  }

  /**
   * Initialize Bootstrap modals dynamically or from known list
   */
  _initBootstrapModals() {
    const modalIds = [
      'modal-account-created',
      'modal-session-expiring',
      'modal-security-lockout',
      'modal-security-center',
      'modal-view-password',
      'modal-add-password',
      'modal-view-banking',
      'modal-add-banking',
      'modal-view-card',
      'modal-add-card',
      'modal-view-note',
      'modal-add-note',
      'modal-change-pin',
      'modal-export-backup',
      'modal-import-backup',
      'modal-confirm-delete',
      'modal-confirm-logout',
      'modal-change-drive-url',
      'modal-change-photo',
      'modal-add-document-guidance',
      'modal-settings'
    ];

    modalIds.forEach(id => {
      const el = document.getElementById(id);
      if (el && window.bootstrap && window.bootstrap.Modal) {
        this.modals[id] = new window.bootstrap.Modal(el, {
          backdrop: 'static',
          keyboard: false
        });
      }
    });
  }

  /**
   * Switch active application view
   * @param {string} viewId - Element ID of target view (e.g. 'view-gate', 'view-login', 'view-dashboard')
   */
  showView(viewId) {
    const views = document.querySelectorAll('.view-section');
    views.forEach(view => {
      view.classList.remove('active');
    });

    const targetView = document.getElementById(viewId);
    if (targetView) {
      targetView.classList.add('active');
      this.currentView = viewId;
      window.scrollTo({ top: 0, behavior: 'smooth' });
      window.dispatchEvent(new CustomEvent('woopass:view-changed', { detail: { viewId } }));
    }
  }

  /**
   * Show a custom floating toast notification
   * @param {string} message - Message text
   * @param {'success'|'danger'|'warning'|'info'} [type='info'] - Toast style
   * @param {number} [duration=3500] - Duration in ms
   */
  showToast(message, type = 'info', duration = 3500) {
    this._ensureToastContainer();

    const toast = document.createElement('div');
    toast.className = `vault-toast toast-${type}`;
    
    let iconClass = 'bi-info-circle-fill';
    if (type === 'success') iconClass = 'bi-check-circle-fill';
    else if (type === 'danger') iconClass = 'bi-shield-x';
    else if (type === 'warning') iconClass = 'bi-exclamation-triangle-fill';

    toast.innerHTML = `
      <i class="bi ${iconClass} vault-toast-icon"></i>
      <span class="vault-toast-text">${this.escapeHTML(message)}</span>
    `;

    this.toastContainer.appendChild(toast);

    // Trigger show transition
    requestAnimationFrame(() => {
      toast.classList.add('show');
    });

    // Auto dismiss
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, duration);
  }

  /**
   * Copy sensitive value to clipboard with toast notification and auto-clear timer
   * @param {string} text 
   * @param {string} [label='Value'] 
   * @param {number} [autoClearSeconds=30] 
   */
  async copyToClipboard(text, label = 'Password', autoClearSeconds = 30) {
    if (!text) {
      this.showToast('Nothing to copy', 'warning');
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      this.showToast(`✓ ${label} copied to clipboard (auto-clears in ${autoClearSeconds}s)`, 'success', 3000);

      // Schedule clipboard clear where supported
      if (this._clipboardTimer) clearTimeout(this._clipboardTimer);
      this._clipboardTimer = setTimeout(async () => {
        try {
          if (document.hasFocus()) {
            await navigator.clipboard.writeText('');
          }
        } catch (e) {
          // Clipboard clear may be restricted by browser if document lost focus
        }
      }, autoClearSeconds * 1000);
    } catch (err) {
      // Fallback for restricted clipboard contexts
      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        this.showToast(`✓ ${label} copied`, 'success');
      } catch (fbErr) {
        this.showToast('Unable to copy to clipboard', 'danger');
      }
    }
  }

  /**
   * Open a registered modal by ID
   * @param {string} modalId 
   */
  showModal(modalId) {
    const el = document.getElementById(modalId);
    if (!el) return;

    if (!this.modals[modalId] && window.bootstrap && window.bootstrap.Modal) {
      this.modals[modalId] = new window.bootstrap.Modal(el, { backdrop: 'static', keyboard: false });
    }

    if (this.modals[modalId]) {
      this.modals[modalId].show();
    }
  }

  /**
   * Close a registered modal by ID
   * @param {string} modalId 
   */
  hideModal(modalId) {
    if (this.modals[modalId]) {
      this.modals[modalId].hide();
    } else {
      const el = document.getElementById(modalId);
      if (el && window.bootstrap && window.bootstrap.Modal) {
        const instance = window.bootstrap.Modal.getInstance(el);
        if (instance) instance.hide();
      }
    }
  }

  /**
   * Escape HTML to prevent XSS in rendering
   * @param {string} str 
   * @returns {string}
   */
  escapeHTML(str) {
    if (str === null || str === undefined) return '';
    const p = document.createElement('p');
    p.textContent = String(str);
    return p.innerHTML;
  }

  /**
   * Mask a secret string, leaving optional last N characters visible
   * @param {string} str 
   * @param {number} visibleEnd 
   * @returns {string}
   */
  maskString(str, visibleEnd = 4) {
    if (!str) return '••••••••';
    const clean = String(str).trim();
    if (clean.length <= visibleEnd) {
      return '••••••••';
    }
    const unmasked = clean.slice(-visibleEnd);
    return `••••••••${unmasked}`;
  }
}

export const ui = new UIManager();
