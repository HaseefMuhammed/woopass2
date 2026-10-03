/**
 * ============================================================================
 * WOO PASS — Randomized Numeric Keypad Engine (js/keypad.js)
 * High-security virtual PIN entry system with cryptographically randomized layout
 * ============================================================================
 */

import { generateRandomBytes } from "./crypto.js";

export class SecureKeypad {
  /**
   * @param {Object} options
   * @param {HTMLElement} options.container - Container element to render keypad into
   * @param {HTMLElement} options.dotsContainer - Container element holding the 6 PIN dots
   * @param {Function} options.onComplete - Callback when 6 digits are entered: (pin) => {}
   * @param {Function} [options.onChange] - Optional callback on change: (length) => {}
   * @param {number} [options.maxDigits=6] - Number of PIN digits (default: 6)
   * @param {boolean} [options.enableKeyboard=true] - Enable physical keyboard entry
   */
  constructor(options) {
    this.container = options.container;
    this.dotsContainer = options.dotsContainer;
    this.onComplete = options.onComplete || (() => {});
    this.onChange = options.onChange || (() => {});
    this.maxDigits = options.maxDigits || 6;
    this.enableKeyboard = options.enableKeyboard !== false;
    this.shuffle = options.shuffle !== false; // Enable layout scrambling by default for security
    
    // Private in-memory PIN state
    this._pin = '';
    this._disabled = false;
    this._boundKeyHandler = this._handlePhysicalKey.bind(this);
    
    this.init();
  }

  /**
   * Initialize keypad and event listeners
   */
  init() {
    this.render();
    if (this.enableKeyboard) {
      window.addEventListener('keydown', this._boundKeyHandler);
    }
  }

  /**
   * Clean up event listeners
   */
  destroy() {
    if (this.enableKeyboard) {
      window.removeEventListener('keydown', this._boundKeyHandler);
    }
    if (this.container) {
      this.container.innerHTML = '';
    }
  }

  /**
   * Cryptographically secure Fisher-Yates array shuffle
   * @param {Array} array 
   * @returns {Array}
   */
  _secureShuffle(array) {
    const result = [...array];
    const randomBytes = generateRandomBytes(result.length * 2);
    let byteIdx = 0;
    
    for (let i = result.length - 1; i > 0; i--) {
      // Unbiased random integer in range [0, i]
      const rand = ((randomBytes[byteIdx] << 8) | randomBytes[byteIdx + 1]) % (i + 1);
      byteIdx = (byteIdx + 2) % randomBytes.length;
      
      const temp = result[i];
      result[i] = result[rand];
      result[rand] = temp;
    }
    return result;
  }

  /**
   * Re-shuffle keypad layout dynamically
   */
  shuffleLayout() {
    this.render();
  }

  /**
   * Render the keypad grid (shuffled layout if shuffle is true)
   */
  render() {
    if (!this.container) return;

    // Digits 0 to 9
    let digits = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    if (this.shuffle) {
      digits = this._secureShuffle(digits);
    }

    this.container.innerHTML = '';
    this.container.className = 'keypad-grid';

    // Digits in positions 1 to 9 (Rows 1 to 3)
    for (let i = 0; i < 9; i++) {
      const digit = digits[i];
      const btn = this._createButton(digit.toString(), () => this.appendDigit(digit));
      btn.setAttribute('aria-label', `Number ${digit}`);
      this.container.appendChild(btn);
    }

    // Row 4: Clear Button
    const clearBtn = this._createButton('CLR', () => this.clear(), true);
    clearBtn.setAttribute('aria-label', 'Clear PIN');
    this.container.appendChild(clearBtn);

    // Row 4: 10th Digit (Position between Clear and Backspace)
    const tenthDigit = digits[9];
    const zeroBtn = this._createButton(tenthDigit.toString(), () => this.appendDigit(tenthDigit));
    zeroBtn.setAttribute('aria-label', `Number ${tenthDigit}`);
    this.container.appendChild(zeroBtn);

    // Row 4: Backspace Button
    const backspaceBtn = this._createButton('<i class="bi bi-backspace"></i>', () => this.backspace(), true, true);
    backspaceBtn.setAttribute('aria-label', 'Delete last digit');
    this.container.appendChild(backspaceBtn);

    this._updateDots();
  }

  /**
   * Helper to create a keypad button
   */
  _createButton(content, onClick, isAction = false, isHTML = false) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `keypad-btn ${isAction ? 'action-btn' : ''}`;
    if (isHTML) {
      btn.innerHTML = content;
    } else {
      btn.textContent = content;
    }
    btn.disabled = this._disabled;

    btn.addEventListener('click', (e) => {
      e.preventDefault();
      if (this._disabled) return;
      
      // Tactile button press feedback
      btn.style.transform = 'scale(0.92)';
      setTimeout(() => { btn.style.transform = ''; }, 100);
      
      onClick();
    });

    return btn;
  }

  /**
   * Handle physical keyboard event if active and focused on keypad screen
   */
  _handlePhysicalKey(e) {
    if (this._disabled) return;
    
    // If active element is a text input elsewhere, don't intercept
    if (document.activeElement && (document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA')) {
      return;
    }

    // Check if the keypad container is currently visible in DOM
    if (!this.container || this.container.offsetParent === null) {
      return;
    }

    if (e.key >= '0' && e.key <= '9') {
      e.preventDefault();
      this.appendDigit(parseInt(e.key, 10));
    } else if (e.key === 'Backspace') {
      e.preventDefault();
      this.backspace();
    } else if (e.key === 'Escape' || e.key === 'Delete') {
      e.preventDefault();
      this.clear();
    }
  }

  /**
   * Add a digit to the current PIN
   * @param {number|string} digit 
   */
  appendDigit(digit) {
    if (this._disabled || this._pin.length >= this.maxDigits) return;

    this._pin += digit.toString();
    this._updateDots();
    this.onChange(this._pin.length);

    if (this._pin.length === this.maxDigits) {
      const completedPin = this._pin;
      // Slight visual delay so user sees the 6th dot fill before processing
      setTimeout(() => {
        this.onComplete(completedPin);
      }, 80);
    }
  }

  /**
   * Remove the last entered digit
   */
  backspace() {
    if (this._disabled || this._pin.length === 0) return;
    this._pin = this._pin.slice(0, -1);
    this._updateDots();
    this.onChange(this._pin.length);
  }

  /**
   * Clear all entered digits
   */
  clear() {
    if (this._disabled) return;
    this._pin = '';
    this._updateDots();
    this.onChange(0);
  }

  /**
   * Update visual dot indicators
   */
  _updateDots() {
    if (!this.dotsContainer) return;
    const dots = this.dotsContainer.querySelectorAll('.pin-dot');
    dots.forEach((dot, index) => {
      if (index < this._pin.length) {
        dot.classList.add('filled');
        dot.classList.remove('error');
      } else {
        dot.classList.remove('filled', 'error');
      }
    });
  }

  /**
   * Trigger visual shake animation on wrong PIN
   */
  shake() {
    if (this.dotsContainer) {
      const dots = this.dotsContainer.querySelectorAll('.pin-dot');
      dots.forEach(dot => dot.classList.add('error'));
      this.dotsContainer.classList.add('shake-error');
      
      setTimeout(() => {
        this.dotsContainer.classList.remove('shake-error');
        this.clear();
        if (this.shuffle) {
          this.render();
        }
      }, 500);
    } else {
      this.clear();
      if (this.shuffle) {
        this.render();
      }
    }
  }

  /**
   * Enable or disable the entire keypad
   * @param {boolean} disabled 
   */
  setDisabled(disabled) {
    this._disabled = disabled;
    if (this.container) {
      const btns = this.container.querySelectorAll('.keypad-btn');
      btns.forEach(btn => {
        btn.disabled = disabled;
      });
    }
  }

  /**
   * Reset keypad, wipe internal PIN state, and re-shuffle the keypad digits
   */
  reset() {
    this._pin = '';
    this._disabled = false;
    this.render();
  }

  /**
   * Get current entered PIN length (never returns raw PIN for security)
   * @returns {number}
   */
  getLength() {
    return this._pin.length;
  }
}
