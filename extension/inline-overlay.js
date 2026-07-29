/**
 * inline-overlay.js — Bitwarden-style inline autofill overlay (content script).
 *
 * Loaded AFTER content.js. Enhances password and username/email inputs
 * with a SecureVault shield button positioned at the right edge of the
 * input. On click, shows a credential list popover queried from
 * background.js (lookup_credentials).
 *
 * Bitwarden-style UX:
 *   - Field button: 🛡 shield (unlocked) / 🛡🔒 (locked). NOT a 🔒 lock.
 *   - On password fields in registration forms, a generator panel appears
 *     with the generated password + a 🔑 "Fill" button and a 🔄 "Regenerate"
 *     button. After Fill, the panel morphs to a "Save to SecureVault"
 *     button that opens the popup with url + user + pass prefilled.
 *
 * Coexistence with content.js:
 *   content.js's lock-icon injection is now DISABLED (it wrapped inputs in
 *   a div, breaking layouts — see bug B5). This file is the sole owner of
 *   the field button. content.js still handles trigger_autofill messages
 *   from the context menu, but no longer injects its own icon.
 *
 * Autofill:
 *   - Uses native value setter (HTMLInputElement.prototype value setter)
 *     to bypass React/Vue controlled inputs
 *   - Dispatches input, change, blur events so frameworks see the update
 *   - Never touches the OS clipboard
 *
 * Dismissal:
 *   - Outside click, Escape key, or scroll
 *
 * E8: No window globals. Injection guard uses a private Symbol on
 * document. Domain utilities accessed via Symbol-keyed namespace
 * shared by urlMatcher.js (no window.getBaseDomain global).
 */

(function () {
  'use strict';

  // ─── E8: Private injection guard (Symbol on document, not window) ────
  // Previously: window.__svInlineOverlayInjected (string key, detectable
  // by page scripts). Now: Symbol.for('...') which is NOT enumerable
  // via Object.keys() and cannot be discovered by page scripts.
  const _svInlineOverlayInjected = Symbol.for('SecureVault.inlineOverlayInjected');
  if (document[_svInlineOverlayInjected]) return;
  document[_svInlineOverlayInjected] = true;

  // ─── E8: Access domain utilities via Symbol ───────────────────────────
  const _svUtils = Symbol.for('SecureVault.domainUtils');

  // ─── Constants ──────────────────────────────────────────────────────

  const BUTTON_SIZE = 28;
  const BUTTON_MARGIN = 4;
  const POPOVER_WIDTH = 300;
  const POPOVER_MAX_HEIGHT = 380;
  const Z_BUTTON = 2147483646;
  const Z_POPOVER = 2147483647;

  // Bitwarden-style icons (emoji for now, SVGs later).
  const ICON_SHIELD_UNLOCKED = '🛡';
  const ICON_SHIELD_LOCKED = '🛡';  // We add a 🔒 overlay in renderButtonIcon
  const ICON_KEY = '🔑';            // "Fill generated password"
  const ICON_REFRESH = '🔄';        // "Regenerate password"
  const ICON_PLUS = '➕';           // "Add new entry"

  // ─── State ──────────────────────────────────────────────────────────

  let currentInput = null;
  let buttonEl = null;
  let popoverEl = null;
  let repositionTimer = null;
  let hideTimer = null;
  let vaultUnlocked = false;  // updated on each popover query

  // ─── Settings cache (so we can honor showLockIcon / autoFillEnabled) ──

  let settings = { autoFillEnabled: true, showLockIcon: true };

  async function refreshSettings() {
    try {
      const resp = await sendMessage({ type: 'get_settings' });
      if (resp && resp.ok && resp.settings) {
        settings = resp.settings;
      }
    } catch (_) { /* keep defaults */ }
  }
  refreshSettings();

  // ─── Helpers ────────────────────────────────────────────────────────

  function isInterestingInput(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    if (el.dataset && el.dataset.svNoOverlay === '1') return false;
    const t = (el.type || '').toLowerCase();
    if (t === 'password') return true;
    if (t === 'email') return true;
    if (t === 'text' || t === '' || t === 'tel') {
      // Heuristic: name/autocomplete hints
      const ac = (el.autocomplete || '').toLowerCase();
      const nm = (el.name || '').toLowerCase();
      const ph = (el.placeholder || '').toLowerCase();
      const id = (el.id || '').toLowerCase();
      if (/username|user|login|email|account|user_id/.test(ac + ' ' + nm + ' ' + ph + ' ' + id)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Detect whether a focused password field is in a "new password" /
   * registration context (so we should show the inline generator instead
   * of the credential list). Mirrors Bitwarden's heuristic.
   */
  function isAccountCreationField(el) {
    if (!el || el.type !== 'password') return false;
    const ac = (el.autocomplete || '').toLowerCase();
    if (ac === 'new-password') return true;
    const nm = (el.name || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    if (/new[-_]?pass|pass1|create[-_]?pass|register|signup|sign[-_]?up|password1/.test(nm + ' ' + id)) {
      return true;
    }
    // Look for a sibling "confirm password" field — that's a strong signal.
    const form = el.form || closest(el, 'FORM');
    if (form) {
      const pwInputs = form.querySelectorAll('input[type="password"]');
      if (pwInputs.length >= 2) return true;
    }
    return false;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function sendMessage(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (resp) => {
          if (chrome.runtime.lastError) {
            resolve(null);
          } else {
            resolve(resp);
          }
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  // ─── Button ─────────────────────────────────────────────────────────

  function renderButtonIcon(unlocked) {
    if (unlocked) {
      return '<span style="font-size:15px;">' + ICON_SHIELD_UNLOCKED + '</span>';
    }
    // Locked: shield with a tiny lock badge in the corner.
    return '<span style="position:relative;display:inline-block;font-size:15px;">' +
      ICON_SHIELD_UNLOCKED +
      '<span style="position:absolute;bottom:-2px;right:-3px;font-size:10px;background:#1a1d27;border-radius:50%;padding:0 1px;">🔒</span>' +
      '</span>';
  }

  function ensureButton() {
    if (buttonEl && document.body.contains(buttonEl)) return buttonEl;
    buttonEl = document.createElement('div');
    buttonEl.setAttribute('data-sv-overlay-btn', '1');
    buttonEl.style.cssText = [
      'position:fixed',
      'width:' + BUTTON_SIZE + 'px',
      'height:' + BUTTON_SIZE + 'px',
      'border-radius:50%',
      'background:#1a1d27',
      'border:1.5px solid #175DDC',  // Bitwarden blue
      'box-shadow:0 2px 8px rgba(23,93,220,0.4)',
      'cursor:pointer',
      'display:none',
      'align-items:center',
      'justify-content:center',
      'color:#175DDC',
      'font-size:13px',
      'font-weight:700',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      'z-index:' + Z_BUTTON,
      'user-select:none',
      'transition:transform 0.15s ease, box-shadow 0.15s ease',
      'line-height:1'
    ].join(';');
    buttonEl.innerHTML = renderButtonIcon(false);
    buttonEl.title = 'SecureVault — fill credentials';
    buttonEl.addEventListener('mouseenter', () => {
      buttonEl.style.transform = 'scale(1.12)';
      buttonEl.style.boxShadow = '0 4px 14px rgba(23,93,220,0.6)';
    });
    buttonEl.addEventListener('mouseleave', () => {
      buttonEl.style.transform = 'scale(1)';
      buttonEl.style.boxShadow = '0 2px 8px rgba(23,93,220,0.4)';
    });
    buttonEl.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
    });
    buttonEl.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showPopover(currentInput);
    });
    document.documentElement.appendChild(buttonEl);
    return buttonEl;
  }

  function positionButton(input) {
    if (!input) return;
    const btn = ensureButton();
    const rect = input.getBoundingClientRect();
    // Position at the right edge, vertically centered. Bitwarden uses a
    // slightly smaller inset for taller inputs — we mirror that.
    const inset = rect.height >= 50 ? rect.height * 0.1 : 2;
    const top = rect.top + inset + (rect.height - 2 * inset - BUTTON_SIZE) / 2;
    const left = rect.right - BUTTON_SIZE - BUTTON_MARGIN;
    btn.style.top = top + 'px';
    btn.style.left = left + 'px';
    btn.style.display = 'flex';
  }

  function showButtonFor(input) {
    // Honor the showLockIcon setting (Bitwarden has the same toggle).
    if (!settings.showLockIcon) {
      hideButton(0);
      return;
    }
    clearTimeout(hideTimer);
    currentInput = input;
    positionButton(input);
  }

  function hideButton(delay = 200) {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      if (buttonEl) buttonEl.style.display = 'none';
    }, delay);
  }

  // ─── Popover ────────────────────────────────────────────────────────

  function showPopover(input) {
    hidePopover();
    if (!input) return;
    currentInput = input;

    popoverEl = document.createElement('div');
    popoverEl.setAttribute('data-sv-popover', '1');
    popoverEl.style.cssText = [
      'position:fixed',
      'width:' + POPOVER_WIDTH + 'px',
      'max-height:' + POPOVER_MAX_HEIGHT + 'px',
      'overflow-y:auto',
      'background:#1a1d27',
      'border:1px solid #2a2e3a',
      'border-radius:12px',
      'box-shadow:0 12px 32px rgba(0,0,0,0.45)',
      'z-index:' + Z_POPOVER,
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      'color:#f3f4f6',
      'padding:6px'
    ].join(';');

    const rect = input.getBoundingClientRect();
    let top = rect.bottom + 6;
    let left = rect.right - POPOVER_WIDTH;
    if (left < 8) left = 8;
    const estHeight = Math.min(POPOVER_MAX_HEIGHT, 340);
    if (top + estHeight > window.innerHeight - 8) {
      top = Math.max(8, rect.top - estHeight - 6);
    }
    popoverEl.style.top = top + 'px';
    popoverEl.style.left = left + 'px';

    renderPopoverLoading();
    document.documentElement.appendChild(popoverEl);

    // Event delegation for the "Open SecureVault" link (rendered in the
    // footer by various render functions).
    popoverEl.addEventListener('click', (e) => {
      if (e.target && e.target.id === 'sv-open-link') {
        e.preventDefault();
        e.stopPropagation();
        sendMessage({ type: 'open_window' });
        hidePopover();
        hideButton(0);
      }
    });

    setTimeout(() => {
      document.addEventListener('mousedown', outsideClickHandler, true);
    }, 80);

    // Decide: generator mode (registration password field) vs credential
    // list mode (everything else). Bitwarden shows the generator on
    // new-password fields.
    if (isAccountCreationField(input)) {
      renderGeneratorMode();
      return;
    }

    // Query background for matching credentials.
    sendMessage({ type: 'lookup_credentials', domain: location.href }).then((resp) => {
      if (!resp) {
        renderPopoverError('Extension unavailable');
        return;
      }
      // Update the button icon to reflect lock state.
      vaultUnlocked = !resp.locked;
      if (buttonEl) buttonEl.innerHTML = renderButtonIcon(vaultUnlocked);
      if (resp.locked) {
        renderPopoverLocked();
        return;
      }
      if (!resp.entries || resp.entries.length === 0) {
        renderPopoverEmpty();
        return;
      }
      renderPopoverEntries(resp.entries);
    });
  }

  function renderPopoverLoading() {
    if (!popoverEl) return;
    popoverEl.innerHTML =
      '<div style="padding:18px;text-align:center;color:#9ca3af;font-size:13px;">Loading…</div>';
  }

  function renderPopoverError(msg) {
    if (!popoverEl) return;
    popoverEl.innerHTML = popoverHeader('SecureVault') +
      '<div style="padding:14px;text-align:center;color:#ef4444;font-size:12px;">' + escapeHtml(msg) + '</div>' +
      popoverFooter();
  }

  function renderPopoverLocked() {
    if (!popoverEl) return;
    popoverEl.innerHTML = popoverHeader('SecureVault — locked') +
      '<div style="padding:18px;text-align:center;">' +
      '<div style="font-size:28px;margin-bottom:8px;">🛡</div>' +
      '<div style="color:#9ca3af;font-size:12px;margin-bottom:12px;">Click below to unlock your vault.</div>' +
      '<button id="sv-unlock-btn" style="width:100%;padding:9px;border:none;border-radius:8px;background:#175DDC;color:#fff;font-size:13px;font-weight:600;cursor:pointer;">Unlock SecureVault</button>' +
      '</div>' + popoverFooter();
    const btn = popoverEl.querySelector('#sv-unlock-btn');
    if (btn) btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      sendMessage({ type: 'open_window' });
      hidePopover();
      hideButton(0);
    });
  }

  function renderPopoverEmpty() {
    const base = (() => {
      const utils = window[Symbol.for('SecureVault.domainUtils')];
      if (utils && utils.getBaseDomain) return utils.getBaseDomain(location.href);
      // Fallback: simple hostname extraction (no two-part TLD handling)
      try { return new URL(location.href).hostname.replace(/^www\./, ''); } catch (_) { return location.hostname; }
    })();
    if (!popoverEl) return;
    popoverEl.innerHTML = popoverHeader('No matches') +
      '<div style="padding:18px;text-align:center;">' +
      '<div style="color:#9ca3af;font-size:12px;margin-bottom:12px;">No credentials for<br><strong style="color:#f3f4f6;">' + escapeHtml(base) + '</strong></div>' +
      '<button id="sv-add-btn" style="width:100%;padding:9px;border:none;border-radius:8px;background:#2a2e3a;color:#f3f4f6;font-size:13px;font-weight:600;cursor:pointer;">' + ICON_PLUS + ' Add new entry</button>' +
      '</div>' + popoverFooter();
    const btn = popoverEl.querySelector('#sv-add-btn');
    if (btn) btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      sendMessage({ type: 'open_window', query: { add: '1', url: location.href } });
      hidePopover();
      hideButton(0);
    });
  }

  function renderPopoverEntries(entries) {
    if (!popoverEl) return;
    let html = popoverHeader(entries.length + ' match' + (entries.length === 1 ? '' : 'es'));
    for (const entry of entries) {
      const site = escapeHtml(entry.site || entry.name || entry.url || '—');
      const user = escapeHtml(entry.user || entry.username || '');
      const initial = escapeHtml((entry.site || entry.name || entry.user || '?')[0].toUpperCase());
      // Red badge if this entry's password is known-breached.
      const breachBadge = entry.breachedCount > 0
        ? '<span style="margin-left:6px;color:#ef4444;font-size:11px;" title="Password found in ' + Number(entry.breachedCount).toLocaleString() + ' breaches">⚠</span>'
        : '';
      html +=
        '<div class="sv-item" data-sv-id="' + escapeHtml(entry.id || '') + '" style="padding:9px 10px;border-radius:8px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:background 0.1s;">' +
          '<div style="width:30px;height:30px;border-radius:50%;background:#175DDC;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0;">' + initial + '</div>' +
          '<div style="flex:1;min-width:0;">' +
            '<div style="font-size:13px;color:#f3f4f6;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + site + breachBadge + '</div>' +
            '<div style="font-size:11px;color:#9ca3af;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + user + '</div>' +
          '</div>' +
        '</div>';
    }
    html += popoverFooter();
    popoverEl.innerHTML = html;

    popoverEl.querySelectorAll('.sv-item').forEach(item => {
      const id = item.dataset.svId;
      item.addEventListener('mouseenter', () => { item.style.background = '#2a2e3a'; });
      item.addEventListener('mouseleave', () => { item.style.background = 'transparent'; });
      item.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const entry = entries.find(en => en.id === id) || entries[0];
        autofill(currentInput, entry);
        hidePopover();
        hideButton(0);
      });
    });
  }

  // ─── Generator mode (Bitwarden-style inline password generator) ──────
  //
  // Triggered when the user focuses a "new password" / registration field.
  // Shows:
  //   1. Generated password (colorized)
  //   2. 🔑 Fill button — injects password into the field, morphs to Save panel
  //   3. 🔄 Regenerate button — new password
  //
  // After Fill, panel morphs to a single "Save to SecureVault" button that
  // opens the popup with url + username + password prefilled.

  let lastGeneratedPassword = '';

  async function renderGeneratorMode() {
    if (!popoverEl) return;
    await refreshSettings();
    const resp = await sendMessage({
      type: 'generate_password',
      options: { mode: 'random', length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true }
    });
    if (!resp || !resp.ok) {
      renderPopoverError('Could not generate password');
      return;
    }
    lastGeneratedPassword = resp.password;
    popoverEl.innerHTML = popoverHeader('Generate password') +
      '<div style="padding:12px;">' +
        '<div style="font-size:11px;color:#9ca3af;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Generated password</div>' +
        '<div id="sv-gen-password" style="background:#0f1117;border:1px solid #2a2e3a;border-radius:8px;padding:10px;font-family:monospace;font-size:13px;color:#a5b4fc;word-break:break-all;margin-bottom:10px;">' + escapeHtml(resp.password) + '</div>' +
        '<div style="font-size:11px;color:#9ca3af;margin-bottom:10px;">Strength: <span style="color:#10b981;font-weight:600;">' + escapeHtml(resp.label || 'good') + '</span> · ' + (resp.entropyBits || 0) + ' bits</div>' +
        '<div style="display:flex;gap:6px;">' +
          '<button id="sv-gen-fill" style="flex:1;padding:9px;border:none;border-radius:8px;background:#175DDC;color:#fff;font-size:12px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px;">' + ICON_KEY + ' Fill</button>' +
          '<button id="sv-gen-refresh" style="padding:9px 12px;border:1px solid #2a2e3a;border-radius:8px;background:transparent;color:#f3f4f6;font-size:13px;cursor:pointer;">' + ICON_REFRESH + '</button>' +
        '</div>' +
      '</div>' + popoverFooter();
    const fillBtn = popoverEl.querySelector('#sv-gen-fill');
    const refreshBtn = popoverEl.querySelector('#sv-gen-refresh');
    if (fillBtn) fillBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      // Inject the generated password into the focused field.
      if (currentInput && lastGeneratedPassword) {
        setNativeValue(currentInput, lastGeneratedPassword);
        currentInput.dispatchEvent(new Event('input', { bubbles: true }));
        currentInput.dispatchEvent(new Event('change', { bubbles: true }));
        currentInput.dispatchEvent(new Event('blur', { bubbles: true }));
        flashGreen(currentInput);
      }
      // Morph to "Save to SecureVault" panel.
      renderSavePanel(lastGeneratedPassword);
    });
    if (refreshBtn) refreshBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const r = await sendMessage({
        type: 'generate_password',
        options: { mode: 'random', length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true }
      });
      if (r && r.ok) {
        lastGeneratedPassword = r.password;
        const pwEl = popoverEl.querySelector('#sv-gen-password');
        if (pwEl) pwEl.textContent = r.password;
      }
    });
  }

  function renderSavePanel(password) {
    if (!popoverEl) return;
    // Try to find the username field in the same form so we can prefill it.
    let username = '';
    if (currentInput) {
      const userInput = findUsernameField(currentInput);
      if (userInput) username = userInput.value || '';
    }
    popoverEl.innerHTML = popoverHeader('Save to SecureVault?') +
      '<div style="padding:12px;">' +
        '<div style="font-size:12px;color:#9ca3af;margin-bottom:8px;">Fill this password into SecureVault for:</div>' +
        '<div style="background:#0f1117;border:1px solid #2a2e3a;border-radius:8px;padding:8px 10px;margin-bottom:6px;font-size:12px;">' +
          '<div style="color:#9ca3af;font-size:10px;text-transform:uppercase;">URL</div>' +
          '<div style="color:#f3f4f6;word-break:break-all;">' + escapeHtml(location.href) + '</div>' +
        '</div>' +
        (username ? '<div style="background:#0f1117;border:1px solid #2a2e3a;border-radius:8px;padding:8px 10px;margin-bottom:6px;font-size:12px;">' +
          '<div style="color:#9ca3af;font-size:10px;text-transform:uppercase;">Username</div>' +
          '<div style="color:#f3f4f6;word-break:break-all;">' + escapeHtml(username) + '</div>' +
        '</div>' : '') +
        '<div style="background:#0f1117;border:1px solid #2a2e3a;border-radius:8px;padding:8px 10px;margin-bottom:12px;font-size:12px;">' +
          '<div style="color:#9ca3af;font-size:10px;text-transform:uppercase;">Password</div>' +
          '<div style="color:#a5b4fc;font-family:monospace;word-break:break-all;">' + escapeHtml(password) + '</div>' +
        '</div>' +
        '<button id="sv-save-btn" style="width:100%;padding:9px;border:none;border-radius:8px;background:#10b981;color:#fff;font-size:13px;font-weight:600;cursor:pointer;">Save to SecureVault</button>' +
      '</div>' + popoverFooter();
    const saveBtn = popoverEl.querySelector('#sv-save-btn');
    if (saveBtn) saveBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      // Open the popup with url + user + pass prefilled. handleWindowQuery
      // in window.js will prefill the Add modal.
      sendMessage({
        type: 'open_window',
        query: { add: '1', url: location.href, user: username, pass: password }
      });
      hidePopover();
      hideButton(0);
    });
  }

  function popoverHeader(title) {
    return '<div style="padding:6px 10px;font-size:11px;color:#9ca3af;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:6px;">' +
      '<span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#175DDC;display:flex;align-items:center;justify-content:center;color:#fff;font-size:9px;">🛡</span>' +
      escapeHtml(title) + '</div>';
  }

  function popoverFooter() {
    return '<div style="padding:6px 10px;border-top:1px solid #2a2e3a;margin-top:4px;">' +
      '<a id="sv-open-link" href="#" style="color:#175DDC;font-size:12px;text-decoration:none;font-weight:500;">Open SecureVault →</a>' +
      '</div>';
  }

  function hidePopover() {
    if (popoverEl && popoverEl.parentNode) {
      popoverEl.parentNode.removeChild(popoverEl);
    }
    popoverEl = null;
    document.removeEventListener('mousedown', outsideClickHandler, true);
  }

  function outsideClickHandler(e) {
    if (popoverEl && !popoverEl.contains(e.target) &&
        buttonEl && !buttonEl.contains(e.target)) {
      hidePopover();
    }
  }

  // ─── Autofill ───────────────────────────────────────────────────────

  function setNativeValue(el, value) {
    const proto =
      el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype :
      el.tagName === 'SELECT'   ? HTMLSelectElement.prototype   :
                                  HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
  }

  /**
   * Find the username field for a given password field.
   *
   * Strategy (Bitwarden-style heuristic):
   *   1. If the password field is inside a <form>, search the form for
   *      candidate username inputs (text/email/tel/no-type) that come
   *      BEFORE the password field.
   *   2. If no form, search the whole document for inputs that come before
   *      the password field in DOM order.
   *   3. Score each candidate by autocomplete attribute, name attribute,
   *      id, placeholder, and proximity to the password field.
   *   4. Return the best-scoring candidate, or null if none found.
   *
   * This is more aggressive than the old version, which only checked
   * type="text|email|tel" and took the first match. It now handles:
   *   - input with no type attribute (defaults to text)
   *   - input[type="text"] with autocomplete="username"
   *   - input[type="email"] with autocomplete="email"
   *   - input with name="user" / "username" / "login" / "email"
   *   - Shadow DOM is NOT supported (rare on login forms)
   */
  function findUsernameField(passwordInput) {
    if (!passwordInput) return null;

    // Build the candidate list — inputs from the same form, or from the
    // whole document if no form.
    let candidates;
    const form = passwordInput.form || closest(passwordInput, 'FORM');
    if (form) {
      candidates = Array.from(form.querySelectorAll(
        'input[type="text"],input[type="email"],input[type="tel"],input:not([type])'
      ));
    } else {
      // No form — search the whole document, but only inputs that are
      // visible and not the password field itself.
      candidates = Array.from(document.querySelectorAll(
        'input[type="text"],input[type="email"],input[type="tel"],input:not([type])'
      ));
    }

    // Filter out the password field itself, hidden inputs, and inputs
    // after the password field (those are usually "confirm password" or
    // other fields).
    const pwIdx = candidates.indexOf(passwordInput);
    candidates = candidates.filter((el, i) => {
      if (el === passwordInput) return false;
      if (el.type === 'password') return false;
      // Skip hidden / display:none inputs.
      if (el.offsetParent === null && el.getClientRects().length === 0) return false;
      // If we have a form, keep only inputs before the password field.
      if (form && pwIdx >= 0 && i >= pwIdx) return false;
      return true;
    });

    if (candidates.length === 0) {
      // Last resort: search document-wide for any input before the password.
      const all = Array.from(document.querySelectorAll(
        'input[type="text"],input[type="email"],input[type="tel"],input:not([type])'
      ));
      const allIdx = all.indexOf(passwordInput);
      if (allIdx > 0) {
        // Walk backwards from the password field to find the nearest
        // visible text-like input.
        for (let i = allIdx - 1; i >= 0; i--) {
          const el = all[i];
          if (el.type === 'password') continue;
          if (el.offsetParent === null && el.getClientRects().length === 0) continue;
          return el;
        }
      }
      return null;
    }

    // Score each candidate. Higher score = more likely to be username.
    let best = null;
    let bestScore = -1;
    for (const el of candidates) {
      let score = 0;
      const ac = (el.autocomplete || '').toLowerCase();
      const nm = (el.name || '').toLowerCase();
      const id = (el.id || '').toLowerCase();
      const ph = (el.placeholder || '').toLowerCase();
      const all = ac + ' ' + nm + ' ' + id + ' ' + ph;

      // Strong signals
      if (/username|user_id|userid/.test(all)) score += 50;
      if (ac === 'username') score += 40;
      if (/^user$/.test(nm) || /^user$/.test(id)) score += 30;
      if (/login/.test(all)) score += 20;
      if (/email/.test(all) && el.type === 'email') score += 30;
      if (/email/.test(all)) score += 15;
      if (/account/.test(all)) score += 10;

      // Proximity bonus: closer to the password field = better.
      // (Candidates list is already in DOM order, so index 0 is nearest
      // to the password field among the pre-filtered list.)
      // We don't have the original index here, but candidates were filtered
      // to only those before the password field, so the LAST one in the
      // list is the nearest.
      // Give a small bonus to later candidates (closer to password).
      score += candidates.indexOf(el) * 2;

      if (score > bestScore) {
        bestScore = score;
        best = el;
      }
    }

    // If no candidate scored above 0, just return the last one (nearest to
    // the password field) as a reasonable default.
    if (bestScore <= 0 && candidates.length > 0) {
      best = candidates[candidates.length - 1];
    }

    return best;
  }

  function closest(el, tag) {
    let p = el;
    while (p) {
      if (p.tagName === tag) return p;
      p = p.parentElement;
    }
    return null;
  }

  function autofill(passwordInput, entry) {
    if (!passwordInput) return;
    // Honor autoFillEnabled setting.
    if (settings.autoFillEnabled === false) {
      // Just flash to indicate we recognized the field but didn't autofill.
      flashGreen(passwordInput);
      return;
    }

    const isPassword = (passwordInput.type || '').toLowerCase() === 'password';
    let userInput = null;
    let pwInput = passwordInput;

    if (isPassword) {
      // Focused field is the password field — find the username field.
      userInput = findUsernameField(passwordInput);
    } else {
      // Focused field is the username field — use it directly, and find
      // the password field in the same form.
      userInput = passwordInput;
      const form = passwordInput.form || closest(passwordInput, 'FORM');
      if (form) {
        const pwInputs = form.querySelectorAll('input[type="password"]');
        if (pwInputs.length > 0) pwInput = pwInputs[pwInputs.length - 1];
      }
    }

    // Fill username first
    if (userInput && (entry.user || entry.username)) {
      const username = entry.user || entry.username;
      setNativeValue(userInput, username);
      userInput.dispatchEvent(new Event('input', { bubbles: true }));
      userInput.dispatchEvent(new Event('change', { bubbles: true }));
      userInput.dispatchEvent(new Event('blur', { bubbles: true }));
      // v10.9 FIX: Removed console.log that leaked autofill metadata in production
    } else {
      // v10.9 FIX: Removed console.log that leaked autofill field info
    }

    // Fill password
    if (pwInput && (entry.pass || entry.password)) {
      setNativeValue(pwInput, entry.pass || entry.password);
      pwInput.dispatchEvent(new Event('input', { bubbles: true }));
      pwInput.dispatchEvent(new Event('change', { bubbles: true }));
      pwInput.dispatchEvent(new Event('blur', { bubbles: true }));
      // v10.9 FIX: Removed console.log that leaked password field name in production
    }

    flashGreen(userInput);
    flashGreen(pwInput);
  }

  function flashGreen(el) {
    if (!el) return;
    const orig = el.style.backgroundColor;
    const origTransition = el.style.transition;
    el.style.transition = 'background-color 0.4s ease';
    el.style.backgroundColor = 'rgba(16,185,129,0.25)';
    setTimeout(() => {
      el.style.backgroundColor = orig;
      setTimeout(() => { el.style.transition = origTransition; }, 500);
    }, 600);
  }

  // ─── Event listeners ────────────────────────────────────────────────

  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (t && isInterestingInput(t)) {
      showButtonFor(t);
    }
  }, true);

  document.addEventListener('focusout', (e) => {
    setTimeout(() => {
      if (buttonEl && buttonEl.style.display !== 'none') {
        const active = document.activeElement;
        if (!active || !isInterestingInput(active)) {
          if (!popoverEl) hideButton(0);
        }
      }
    }, 150);
  }, true);

  document.addEventListener('mouseover', (e) => {
    if (buttonEl && (e.target === buttonEl || (buttonEl.contains && buttonEl.contains(e.target)))) {
      clearTimeout(hideTimer);
    }
  }, true);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (popoverEl) {
        hidePopover();
        e.stopPropagation();
      }
    }
  }, true);

  function scheduleReposition() {
    if (repositionTimer) cancelAnimationFrame(repositionTimer);
    repositionTimer = requestAnimationFrame(() => {
      if (currentInput && buttonEl && buttonEl.style.display !== 'none') {
        positionButton(currentInput);
      }
      if (popoverEl) {
        hidePopover();
      }
    });
  }
  window.addEventListener('scroll', scheduleReposition, true);
  window.addEventListener('resize', scheduleReposition);

  // Context-menu "Auto-fill login" trigger from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'trigger_autofill') {
      let target = document.activeElement;
      if (!target || !isInterestingInput(target)) {
        target = document.querySelector('input[type="password"]');
      }
      if (!target) {
        target = document.querySelector('input[type="email"], input[type="text"]');
      }
      if (target) {
        showButtonFor(target);
        showPopover(target);
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: 'no input found' });
      }
    }
    // Refresh settings when they change.
    if (message && message.type === 'settings_changed') {
      refreshSettings();
    }
    return true;
  });

  // ─── Initial scan ───────────────────────────────────────────────────
  setTimeout(() => {
    const active = document.activeElement;
    if (active && isInterestingInput(active)) {
      showButtonFor(active);
    }
  }, 500);
})();
