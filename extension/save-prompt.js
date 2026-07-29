/**
 * save-prompt.js — Login save prompt banner (content script).
 *
 * Detects when the user submits a login form with a new or changed
 * password and shows a top-of-page banner asking whether to save it
 * in SecureVault.
 *
 * Flow:
 *   1. On form submit (form must contain a password input): capture
 *      { url, username, password } and stash it in sessionStorage.
 *   2. Set a short timeout (1.4s) to display the banner. If the page
 *      navigates (full-page form submit), the timeout is cleared and
 *      the next page picks up the stashed capture on load.
 *   3. Before showing: check vault status (must be unlocked), check
 *      lookup_credentials to avoid prompting for known/unchanged
 *      logins, and check per-site dismissal preferences.
 *   4. Banner actions:
 *        - Save       → send save_login_prompt to background, hide banner
 *        - Not now    → hide banner, remember dismissal for 24h
 *        - Never      → hide banner, remember permanent dismissal
 *
 * Dismissal preferences are stored in chrome.storage.local under
 * `svSavePromptDismissals` keyed by base domain.
 *
 * E8: No window globals. Injection guard uses a private Symbol on
 * document. Domain utilities accessed via Symbol-keyed namespace
 * shared by urlMatcher.js (no window.getBaseDomain global).
 */

(function () {
  'use strict';

  // ─── E8: Private injection guard (Symbol on document, not window) ────
  const _svSavePromptInjected = Symbol.for('SecureVault.savePromptInjected');
  if (document[_svSavePromptInjected]) return;
  document[_svSavePromptInjected] = true;

  // ─── E8: Access domain utilities via Symbol ───────────────────────────
  const _svUtils = Symbol.for('SecureVault.domainUtils');

  const SESSION_KEY = 'sv_pending_save_v6';
  const SHOW_DELAY_MS = 1400;
  const BANNER_HEIGHT = 64;

  // ─── Helpers ────────────────────────────────────────────────────────

  function sendMessage(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (resp) => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(resp);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  // E8: Access getBaseDomain via Symbol-keyed namespace (no window global).
  // urlMatcher.js stores { getBaseDomain, domainMatches } under
  // Symbol.for('SecureVault.domainUtils') on window.
  // Fallback: simple URL API (no two-part TLD detection) if urlMatcher.js
  // hasn't loaded. If even that fails, async message to background.js.
  function getBaseDomain(url) {
    const utils = window[_svUtils];
    if (utils && utils.getBaseDomain) return utils.getBaseDomain(url);
    // Fallback: simple URL API (no two-part TLD detection — urlMatcher.js
    // handles that properly when available).
    try {
      const u = new URL(url);
      return u.hostname.replace(/^www\./, '');
    } catch (_) {
      return '';
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function setNativeValue(el, value) {
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
  }

  // ─── Dismissal preferences ──────────────────────────────────────────

  async function getDismissals() {
    const { svSavePromptDismissals } = await chrome.storage.local.get('svSavePromptDismissals');
    return svSavePromptDismissals && typeof svSavePromptDismissals === 'object'
      ? svSavePromptDismissals : {};
  }

  async function setDismissal(domain, kind /* 'temp' | 'never' */) {
    const all = await getDismissals();
    if (kind === 'never') {
      all[domain] = { never: true };
    } else {
      all[domain] = { until: Date.now() + 24 * 60 * 60 * 1000 };
    }
    await chrome.storage.local.set({ svSavePromptDismissals: all });
  }

  async function isDismissed(domain) {
    const all = await getDismissals();
    const d = all[domain];
    if (!d) return false;
    if (d.never) return true;
    if (d.until && d.until > Date.now()) return true;
    return false;
  }

  // ─── Form submit capture ────────────────────────────────────────────

  function findPasswordInputs(form) {
    return Array.from(form.querySelectorAll('input[type="password"]'));
  }

  function findUsernameInput(form, passwordInput) {
    const candidates = Array.from(form.querySelectorAll(
      'input[type="text"],input[type="email"],input[type="tel"],input:not([type])'
    ));
    // Prefer the input immediately before the password field.
    const idx = candidates.indexOf(passwordInput);
    if (idx > 0) return candidates[idx - 1];
    if (candidates.length > 0) {
      // Pick the one most likely to be a username (by heuristic).
      for (const c of candidates) {
        const ac = (c.autocomplete || '').toLowerCase();
        const nm = (c.name || '').toLowerCase();
        if (/username|user|login|email/.test(ac + ' ' + nm)) return c;
      }
      return candidates[0];
    }
    return null;
  }

  function captureForm(form) {
    const pwInputs = findPasswordInputs(form);
    if (pwInputs.length === 0) return null;
    const passwordInput = pwInputs[pwInputs.length - 1];
    const userInput = findUsernameInput(form, passwordInput);
    const password = passwordInput.value || '';
    const username = userInput ? userInput.value : '';
    if (!password) return null;
    return {
      url: location.href,
      baseDomain: getBaseDomain(location.href),
      username,
      password,
      capturedAt: Date.now()
    };
  }

  function stashCapture(capture) {
    // v10.9 FIX: DO NOT store plaintext passwords in sessionStorage.
    // Content scripts share the page's sessionStorage, meaning any
    // JavaScript running in the same page origin can read
    // sessionStorage.getItem('sv_pending_save_v6') and extract the
    // user's plaintext password. This was a direct credential exposure
    // vulnerability. Now we store only the NON-sensitive fields
    // (url, username) in sessionStorage for the save prompt, and
    // immediately send the full capture (including password) directly
    // to the background script via chrome.runtime.sendMessage, which
    // is NOT accessible to page scripts.
    try {
      const safeCapture = {
        url: capture.url,
        username: capture.username,
        baseDomain: capture.baseDomain,
        capturedAt: capture.capturedAt,
        hasPassword: !!capture.password  // just flag existence, never the value
      };
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(safeCapture));
      // Send the full capture (with password) directly to background.js
      // which stores it in chrome.storage.local (still unencrypted,
      // but NOT page-accessible like sessionStorage was).
      chrome.runtime.sendMessage({
        type: 'save_login_prompt',
        url: capture.url,
        username: capture.username,
        password: capture.password,
        baseDomain: capture.baseDomain,
        capturedAt: capture.capturedAt
      }).catch(() => {});  // background may not be ready yet
    } catch (_) {}
  }

  function popStashedCapture() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      sessionStorage.removeItem(SESSION_KEY);
      const data = JSON.parse(raw);
      // Expire stale captures (> 5 minutes old).
      if (!data || !data.capturedAt || Date.now() - data.capturedAt > 5 * 60 * 1000) {
        return null;
      }
      return data;
    } catch (_) {
      return null;
    }
  }

  function peekStashedCapture() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  // ─── Should-prompt logic ────────────────────────────────────────────

  async function shouldPromptFor(capture) {
    if (!capture) return false;
    // Vault must be unlocked.
    const status = await sendMessage({ type: 'get_status' });
    if (!status || !status.unlocked) return false;
    // Per-site dismissal.
    if (await isDismissed(capture.baseDomain)) return false;
    // Check for existing matching entry.
    const resp = await sendMessage({ type: 'lookup_credentials', domain: capture.url });
    if (resp && !resp.locked && resp.entries && resp.entries.length > 0) {
      // If any matching entry has the same password, don't prompt.
      const samePw = resp.entries.some(e => (e.pass || e.password || '') === capture.password);
      if (samePw) return false;
      // If there's a matching entry with the same username but different password,
      // we DO prompt (password changed). Otherwise (matching entry, different user),
      // still prompt — could be a new account.
    }
    return true;
  }

  // ─── Banner UI ──────────────────────────────────────────────────────

  let bannerEl = null;
  let pendingShowTimer = null;

  function showBanner(capture) {
    if (bannerEl) return; // already shown
    const site = capture.baseDomain || 'this site';
    bannerEl = document.createElement('div');
    bannerEl.setAttribute('data-sv-save-prompt', '1');
    bannerEl.style.cssText = [
      'position:fixed',
      'top:0',
      'left:0',
      'right:0',
      'min-height:' + BANNER_HEIGHT + 'px',
      'z-index:2147483645',
      'background:#175DDC',
      'color:#fff',
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      'display:flex',
      'align-items:center',
      'gap:12px',
      'padding:10px 14px',
      'box-shadow:0 4px 16px rgba(0,0,0,0.3)',
      'transform:translateY(-100%)',
      'transition:transform 0.3s cubic-bezier(0.16,1,0.3,1)',
      'flex-wrap:wrap'
    ].join(';');

    bannerEl.innerHTML =
      '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:200px;">' +
        '<div style="width:32px;height:32px;border-radius:8px;background:rgba(255,255,255,0.18);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;">🛡</div>' +
        '<div style="min-width:0;">' +
          '<div style="font-size:13px;font-weight:600;line-height:1.2;">Save this login in SecureVault?</div>' +
          '<div style="font-size:11px;opacity:0.85;margin-top:2px;">' + escapeHtml(site) +
            (capture.username ? ' · <span style="font-family:monospace;">' + escapeHtml(capture.username) + '</span>' : '') +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:6px;align-items:center;flex-shrink:0;">' +
        '<button id="sv-save-yes" style="padding:7px 14px;border:none;border-radius:7px;background:#fff;color:#175DDC;font-size:12px;font-weight:700;cursor:pointer;">Save</button>' +
        '<button id="sv-save-later" style="padding:7px 12px;border:1px solid rgba(255,255,255,0.4);border-radius:7px;background:transparent;color:#fff;font-size:12px;font-weight:600;cursor:pointer;">Not now</button>' +
        '<button id="sv-save-never" style="padding:7px 10px;border:none;border-radius:7px;background:transparent;color:rgba(255,255,255,0.85);font-size:11px;cursor:pointer;">Never</button>' +
        '<button id="sv-save-close" style="padding:7px 10px;border:none;border-radius:7px;background:transparent;color:rgba(255,255,255,0.85);font-size:14px;cursor:pointer;line-height:1;">✕</button>' +
      '</div>';

    document.documentElement.appendChild(bannerEl);

    // Slide down
    requestAnimationFrame(() => {
      if (bannerEl) bannerEl.style.transform = 'translateY(0)';
    });

    // Wire buttons
    bannerEl.querySelector('#sv-save-yes').addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      await sendMessage({
        type: 'save_login_prompt',
        url: capture.url,
        username: capture.username,
        password: capture.password
      });
      hideBanner();
      // Also forward to the window so it can show a pre-filled add form.
      sendMessage({
        type: 'open_window',
        query: { add: '1', url: capture.url, user: capture.username, pass: capture.password }
      });
    });
    bannerEl.querySelector('#sv-save-later').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDismissal(capture.baseDomain, 'temp');
      hideBanner();
    });
    bannerEl.querySelector('#sv-save-never').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDismissal(capture.baseDomain, 'never');
      hideBanner();
    });
    bannerEl.querySelector('#sv-save-close').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      hideBanner();
    });

    // Push page content down so the banner doesn't overlap (best effort).
    pushBodyDown();
  }

  function hideBanner() {
    if (!bannerEl) return;
    bannerEl.style.transform = 'translateY(-100%)';
    const toRemove = bannerEl;
    setTimeout(() => {
      if (toRemove.parentNode) toRemove.parentNode.removeChild(toRemove);
      restoreBodyOffset();
    }, 300);
    bannerEl = null;
  }

  let originalBodyMarginTop = null;
  function pushBodyDown() {
    try {
      const body = document.body;
      if (!body) return;
      if (originalBodyMarginTop === null) {
        originalBodyMarginTop = body.style.marginTop;
      }
      const current = parseInt(getComputedStyle(body).marginTop, 10) || 0;
      body.style.marginTop = (current + BANNER_HEIGHT) + 'px';
    } catch (_) {}
  }

  function restoreBodyOffset() {
    try {
      if (document.body && originalBodyMarginTop !== null) {
        document.body.style.marginTop = originalBodyMarginTop;
      }
      originalBodyMarginTop = null;
    } catch (_) {}
  }

  // ─── Display orchestration ──────────────────────────────────────────

  async function maybeShowCapture(capture) {
    const should = await shouldPromptFor(capture);
    if (should) {
      showBanner(capture);
    }
  }

  function scheduleShow(capture) {
    if (pendingShowTimer) clearTimeout(pendingShowTimer);
    pendingShowTimer = setTimeout(() => {
      pendingShowTimer = null;
      // If the capture is still stashed (no navigation happened), show it.
      const stillThere = peekStashedCapture();
      if (stillThere) {
        maybeShowCapture(stillThere);
        // Clear the stash if we showed it (or if we decided not to).
        try { sessionStorage.removeItem(SESSION_KEY); } catch (_) {}
      }
    }, SHOW_DELAY_MS);
  }

  // ─── Event wiring ───────────────────────────────────────────────────

  // Capture form submits.
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    const capture = captureForm(form);
    if (!capture) return;
    stashCapture(capture);
    scheduleShow(capture);
  }, true);

  // Also capture Enter-key "submissions" on password fields for forms
  // that don't fire a real submit event (some SPAs).
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const t = e.target;
    if (!t || t.tagName !== 'INPUT' || t.type !== 'password') return;
    const form = t.form || closest(t, 'FORM');
    if (!form) {
      // No form — capture directly.
      const capture = {
        url: location.href,
        baseDomain: getBaseDomain(location.href),
        username: '',
        password: t.value || '',
        capturedAt: Date.now()
      };
      // Try to find a sibling username input.
      const userField = findUsernameInputInDocument(t);
      if (userField) capture.username = userField.value || '';
      if (capture.password) {
        stashCapture(capture);
        scheduleShow(capture);
      }
    }
  }, true);

  function closest(el, tag) {
    let p = el;
    while (p) {
      if (p.tagName === tag) return p;
      p = p.parentElement;
    }
    return null;
  }

  function findUsernameInputInDocument(passwordInput) {
    const all = Array.from(document.querySelectorAll(
      'input[type="text"],input[type="email"],input[type="tel"],input:not([type])'
    ));
    const idx = all.indexOf(passwordInput);
    if (idx > 0) return all[idx - 1];
    return null;
  }

  // On page load, check for a stashed capture (from a previous navigation).
  function checkStashedOnLoad() {
    const stashed = peekStashedCapture();
    if (stashed) {
      // Give the page a moment to settle, then evaluate.
      setTimeout(() => {
        maybeShowCapture(stashed).then(() => {
          // Clear if we showed (or decided not to). If we showed, the banner
          // holds the capture; if not, drop it.
          try { sessionStorage.removeItem(SESSION_KEY); } catch (_) {}
        });
      }, 800);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkStashedOnLoad);
  } else {
    checkStashedOnLoad();
  }
})();
