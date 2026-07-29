/**
 * background.js — SecureVault MV3 service worker (ES module).
 *
 * Responsibilities:
 *   - Window management: open/focus a detached 460x760 popup window
 *   - Vault cache: in-memory entries + session password in chrome.storage.session
 *   - Message router for window.js and content scripts
 *   - Context menu (parent + 6 items)
 *   - Password generator (random + passphrase with inline EFF-style wordlist)
 *   - TOTP generator (RFC 6238, HMAC-SHA1 via WebCrypto)
 *   - Clipboard self-destruct timer (10s, coordinated with window context)
 *   - Auto-lock timer (polls every 30s against lockTimeoutMs)
 *   - Activity tracking (updates lastActivity on every message)
 *
 * Crypto rules:
 *   - All key derivation via crypto.subtle, keys non-extractable
 *   - Sensitive Uint8Arrays .fill(0)'d after use
 *   - Session password persists in chrome.storage.session (survives SW eviction,
 *     cleared on browser close)
 *
 * Clipboard note: service workers cannot access navigator.clipboard reliably,
 * so the actual writeText/clear happens in window.js. background.js only tracks
 * the timer and broadcasts do_clipboard_write / do_clipboard_clear messages.
 *
 * ─── E10: Module decomposition (minimal split) ──────────────────────────
 *
 * The following modules have been extracted from this file:
 *   - wordlist.js:     EFF-style passphrase wordlist (~500 words)
 *   - generator.js:    Password generation (random, passphrase, strength estimation)
 *   - domainUtils.js:  Base-domain normalization (getBaseDomain, domainMatches) — E4
 *   - breachCheck.js:  HIBP pwned-passwords checker (k-anonymity model) — pre-existing
 *   - vaultFileCrypto.js: SVLT v2 encryption/decryption (WebCrypto) — pre-existing
 *
 * Planned future decomposition (TODO — too risky for a single session):
 *   - totp.js:         TOTP generator (RFC 6238, HMAC-SHA1)
 *   - contextMenu.js:  Context menu setup + handler dispatch
 *   - clipboard.js:    Clipboard self-destruct timer + IPC coordination
 *   - autoLock.js:     Auto-lock timer + activity tracking
 *   - ipcRouter.js:    Message router (handleMessage switch statement)
 *   - runtimeCrypto.js: E2 runtime encryption layer (AES-GCM for storage)
 *   - windowManager.js: Popup window open/focus/dock logic
 *
 * Remaining in background.js for now:
 *   - Constants, settings, state
 *   - Runtime crypto (runtimeCrypto object)
 *   - Session password persistence
 *   - Window management (openWindow, focusWindow)
 *   - Context menu setup
 *   - Clipboard timer
 *   - Auto-lock timer
 *   - Message router (handleMessage)
 *   - Boot initialization
 */

import { checkPwnedPassword, vaultHealthScan, clearBreachCache } from './breachCheck.js';
import { getBaseDomain, domainMatches } from './domainUtils.js';
import { generatePassword } from './generator.js';

// ─── Constants ─────────────────────────────────────────────────────────

const DEFAULT_SETTINGS = Object.freeze({
  lockTimeoutMs: 15 * 60 * 1000,   // 15 minutes
  clipboardTimeoutMs: 10 * 1000,   // 10 seconds
  autoFillEnabled: true,
  showLockIcon: true,
  hibpCheckEnabled: false
});

// Popout window size — kept identical to the toolbar popup dimensions
// (400×560) so the layout looks the same in the detached window as it
// does in the popup. Previously this was 460×760 which made the window
// too tall and triggered the "@media (min-width:460) and (min-height:700)"
// branch in window.css, producing a layout that didn't match the popup.
const WINDOW_WIDTH = 400;
const WINDOW_HEIGHT = 560;
// Margin from the screen edge when docking the popout to the side.
const WINDOW_EDGE_MARGIN = 16;
const AUTO_LOCK_POLL_MS = 30 * 1000;
const CLIPBOARD_DEFAULT_MS = 10 * 1000;

// ─── In-memory state ──────────────────────────────────────────────────

const state = {
  cachedVault: null,          // Array<entry> or null
  unlocked: false,
  windowId: null,
  lastActivity: Date.now(),
  lastUnlockedAt: 0,
  lastEntryCount: 0,
  clipboardTimer: null,
  clipboardValue: null,
  autoLockTimer: null
};

// ─── Settings ─────────────────────────────────────────────────────────

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

async function setSettings(patch) {
  const current = await getSettings();
  const merged = { ...current, ...patch };
  await chrome.storage.local.set({ settings: merged });
  return merged;
}

// ─── Session password persistence ─────────────────────────────────────
// Stored in chrome.storage.session so it survives SW eviction but is wiped
// when the browser closes.

async function setSessionPassword(password) {
  if (password) {
    await chrome.storage.session.set({ sessionPassword: password });
  } else {
    await chrome.storage.session.remove('sessionPassword');
  }
}

async function getSessionPassword() {
  const { sessionPassword } = await chrome.storage.session.get('sessionPassword');
  return sessionPassword || null;
}

// ─── E2: Runtime encryption layer ──────────────────────────────────────
// Protects sensitive data stored in chrome.storage.local (login prompts,
// genHistory, cached vault entries). An in-memory AES-GCM key is derived
// from the master password when the vault is unlocked. The key is NEVER
// persisted to storage — it lives only in the service worker's memory.
// On lock or SW eviction, the key is lost, making all persisted ciphertext
// unreadable. This ensures that even if chrome.storage.local data is
// extracted, it cannot be decrypted without the master password.

const runtimeCrypto = {
  _key: null,          // CryptoKey (AES-256-GCM, non-extractable)
  _salt: null,         // Uint8Array(16) — persisted alongside ciphertext
  _ivCounter: 0,       // Monotonic counter for IV generation (per-session)

  /**
   * Derive a 256-bit AES-GCM key from the master password using
   * PBKDF2-SHA256 with 100k iterations. The salt is stored alongside
   * the encrypted data so the key can be re-derived on SW re-awakening
   * (after eviction) IF the session password is still available.
   */
  async initFromPassword(password) {
    if (!password) {
      this._key = null;
      this._salt = null;
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const enc = new TextEncoder();
    const pwBytes = enc.encode(password);
    const keyMaterial = await crypto.subtle.importKey(
      'raw', pwBytes, { name: 'PBKDF2' }, false, ['deriveKey']
    );
    this._key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable — key material never leaves crypto runtime
      ['encrypt', 'decrypt']
    );
    this._salt = salt;
    this._ivCounter = 0;
    // Persist the salt so we can re-derive the key after SW eviction
    // (the session password in chrome.storage.session survives eviction).
    await chrome.storage.session.set({ _rcSalt: Array.from(salt) });
  },

  /**
   * Re-derive the key from session password + persisted salt after
   * SW eviction. Called during SW initialization if session password
   * is still available.
   */
  async initFromSession() {
    const password = await getSessionPassword();
    if (!password) {
      this._key = null;
      this._salt = null;
      return false;
    }
    // Try to recover the salt from session storage.
    const { _rcSalt } = await chrome.storage.session.get('_rcSalt');
    if (!_rcSalt || !Array.isArray(_rcSalt) || _rcSalt.length !== 16) {
      // No salt persisted — derive fresh (old encrypted data becomes unreadable,
      // which is the desired behavior on key loss).
      await this.initFromPassword(password);
      return true;
    }
    const salt = new Uint8Array(_rcSalt);
    const enc = new TextEncoder();
    const pwBytes = enc.encode(password);
    const keyMaterial = await crypto.subtle.importKey(
      'raw', pwBytes, { name: 'PBKDF2' }, false, ['deriveKey']
    );
    this._key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    this._salt = salt;
    this._ivCounter = 0;
    return true;
  },

  /**
   * Encrypt a JSON-serializable value. Returns a base64 string containing
   * IV + ciphertext (with GCM auth tag). The IV is derived from a monotonic
   * counter to ensure uniqueness within a session.
   */
  async encrypt(value) {
    if (!this._key) return JSON.stringify(value); // No key = plaintext (locked state)
    const iv = new Uint8Array(12);
    // Use random bytes for first 8 bytes + counter for last 4 to ensure unique IVs
    const randomPart = crypto.getRandomValues(new Uint8Array(8));
    iv.set(randomPart, 0);
    const counterView = new DataView(iv.buffer);
    counterView.setUint32(8, this._ivCounter++);
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      this._key,
      plaintext
    );
    // Pack: iv (12 bytes) + ciphertext+tag
    const packed = new Uint8Array(iv.length + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), iv.length);
    return btoa(Array.from(packed).map(b => String.fromCharCode(b)).join(''));
  },

  /**
   * Decrypt a base64-encoded ciphertext string back to the original value.
   * Returns null if decryption fails (e.g. key mismatch / data corruption).
   */
  async decrypt(b64) {
    if (!this._key) return null; // No key = can't decrypt (locked / evicted)
    try {
      const binary = atob(b64);
      const packed = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        packed[i] = binary.charCodeAt(i);
      }
      const iv = packed.slice(0, 12);
      const ciphertext = packed.slice(12);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        this._key,
        ciphertext
      );
      return JSON.parse(new TextDecoder().decode(plaintext));
    } catch (_) {
      // Decryption failed — key mismatch, data corruption, or SW eviction
      // without a re-derived key. Return null so callers can handle it.
      return null;
    }
  },

  /**
   * Clear the key (called on lock). After this, all encrypted data in
   * chrome.storage.local becomes unreadable until the next unlock.
   */
  clear() {
    this._key = null;
    this._salt = null;
    this._ivCounter = 0;
  }
};

// ─── E2: Encrypted storage helpers ──────────────────────────────────────
// Wrappers that encrypt data before writing and decrypt on reading.
// These replace direct chrome.storage.local.set/get for sensitive data.

async function encryptedLocalSet(key, value) {
  const ciphertext = await runtimeCrypto.encrypt(value);
  await chrome.storage.local.set({ [key]: ciphertext });
}

async function encryptedLocalGet(key) {
  const data = await chrome.storage.local.get(key);
  const raw = data[key];
  if (!raw) return null;
  // If runtimeCrypto has no key (locked), try to parse as JSON (plaintext fallback)
  if (!runtimeCrypto._key) {
    try {
      return JSON.parse(raw);
    } catch (_) {
      // Not JSON — might be encrypted. Can't decrypt without key.
      return null;
    }
  }
  const decrypted = await runtimeCrypto.decrypt(raw);
  if (decrypted !== null) return decrypted;
  // Fallback: maybe stored as plaintext before E2 fix was applied
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function persistStatusMeta() {
  await chrome.storage.local.set({
    lastUnlockedAt: state.lastUnlockedAt,
    lastEntryCount: state.lastEntryCount
  });
}

async function loadStatusMeta() {
  const data = await chrome.storage.local.get(['lastUnlockedAt', 'lastEntryCount']);
  state.lastUnlockedAt = data.lastUnlockedAt || 0;
  state.lastEntryCount = data.lastEntryCount || 0;
}

// ─── Window management ────────────────────────────────────────────────

async function openWindow(queryParams = {}) {
  // If window already exists and is open, focus it.
  if (state.windowId !== null) {
    try {
      const win = await chrome.windows.get(state.windowId);
      if (win && win.id !== undefined) {
        await chrome.windows.update(state.windowId, { focused: true });
        // Optionally forward query params via runtime message.
        if (Object.keys(queryParams).length > 0) {
          try {
            await chrome.runtime.sendMessage({
              type: 'window_action',
              action: queryParams
            });
          } catch (_) { /* window may not be loaded yet */ }
        }
        return win;
      }
    } catch (_) {
      state.windowId = null;
    }
  }

  let url = 'window.html';
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(queryParams)) {
    if (v !== undefined && v !== null) qs.set(k, String(v));
  }
  const qsStr = qs.toString();
  if (qsStr) url += '?' + qsStr;

  // Position: dock the popout to the RIGHT side of the screen (not centered),
  // matching the user's request that the detached window open on the side.
  // We use chrome.system.display (now declared in the manifest) to find the
  // primary screen bounds. If for some reason the API is unavailable we leave
  // left/top unset and let Chrome pick a default location.
  let left, top;
  try {
    if (chrome.system && chrome.system.display && typeof chrome.system.display.getInfo === 'function') {
      const screens = await chrome.system.display.getInfo();
      if (screens && screens.length > 0) {
        // Prefer the screen marked as "isPrimary", otherwise fall back to
        // the first one. This matches where the user is most likely looking.
        const s = screens.find(x => x.isPrimary) || screens[0];
        // Dock to the right edge of that screen, vertically centered within
        // the work area (excludes taskbar).
        const wa = s.workArea || s.bounds;
        left = Math.max(wa.left + 0, Math.floor(wa.left + wa.width - WINDOW_WIDTH - WINDOW_EDGE_MARGIN));
        // Vertically center within the work area, but clamp so the title bar
        // never goes off-screen.
        const desiredTop = Math.floor(wa.top + (wa.height - WINDOW_HEIGHT) / 2);
        top = Math.max(wa.top, Math.min(desiredTop, wa.top + wa.height - WINDOW_HEIGHT));
      }
    }
  } catch (_) { /* system.display unavailable — use default */ }

  const createOpts = {
    url,
    type: 'popup',
    width: WINDOW_WIDTH,
    height: WINDOW_HEIGHT
  };
  if (typeof left === 'number') createOpts.left = left;
  if (typeof top === 'number') createOpts.top = top;

  const win = await chrome.windows.create(createOpts);
  state.windowId = win.id;
  return win;
}

// v10.9 FIX: Removed dead chrome.action.onClicked handler. In Chrome MV3,
// when the manifest declares default_popup: "window.html", the onClicked
// event is NEVER dispatched — the popup opens instead. This handler was
// unreachable dead code. If a popout mode is needed (no popup), the
// manifest should be changed to remove default_popup and use onClicked.
// Currently, the popup is always shown, so this handler is unnecessary.

// ─── Toolbar icon (lock state indicator) ────────────────────────────────
// Swaps the toolbar icon itself instead of drawing a colored badge:
//   default icon set        = unlocked / no vault configured
//   icons_locked/* icon set = locked (vault configured but locked),
//                             shows the black lock glyph baked into the PNG
//
// No badge text/background color is used anymore, so there's no colored
// box behind the lock — just the icon artwork.

const DEFAULT_ICONS = { 16: 'icons/icon16.png', 48: 'icons/icon48.png', 128: 'icons/icon128.png' };
const LOCKED_ICONS = { 16: 'icons_locked/icon16.png', 48: 'icons_locked/icon48.png', 128: 'icons_locked/icon128.png' };

async function updateToolbarBadge() {
  const hasVault = state.cachedVault !== null || state.lastEntryCount > 0;
  const sessionPassword = await getSessionPassword();
  const unlocked = state.unlocked && !!sessionPassword;

  let icons, badgeTitle;
  if (unlocked) {
    icons = DEFAULT_ICONS;
    badgeTitle = 'SecureVault — Unlocked';
  } else if (hasVault || (await hasStoredFileHandle())) {
    icons = LOCKED_ICONS;
    badgeTitle = 'SecureVault — Locked (click to unlock)';
  } else {
    icons = DEFAULT_ICONS;
    badgeTitle = 'SecureVault — Click to set up';
  }

  try {
    await chrome.action.setBadgeText({ text: '' });
    await chrome.action.setIcon({ path: icons });
    await chrome.action.setTitle({ title: badgeTitle });
  } catch (_) { /* action API may be unavailable in some contexts */ }
}

/**
 * Check if we have a stored FSAA file handle (in session storage or IDB).
 * This is a lightweight check — we don't read IDB here (async + slow);
 * we just check if the background knows about a cached vault.
 */
async function hasStoredFileHandle() {
  // Check chrome.storage.session for a file handle
  const data = await chrome.storage.session.get(['svltFileHandle']);
  return !!data.svltFileHandle;
}

// Update badge on startup, on lock/unlock, and periodically (every 30s)
// to catch session password expiry.
updateToolbarBadge();
setInterval(updateToolbarBadge, 30000);

chrome.windows.onRemoved.addListener((winId) => {
  if (winId === state.windowId) {
    state.windowId = null;
    // Do NOT lock on window close — session password persists.
    // Auto-lock will fire after the configured timeout.
    updateToolbarBadge();
  }
});

// ─── E14: Credential sanitization for content scripts ──────────────────
// Strips sensitive fields from entries before sending them to content
// scripts via the lookup_credentials IPC handler. Content scripts only
// need minimal data for autofill — full entries (with SSN, passport,
// license, TOTP secrets) must NEVER cross into page context.
//
// What we send per entry type:
//   LOGIN:    id, type, site, name, url, user, pass (for autofill)
//   CARD:     id, type, site, name, cardNumber, exp, cvv (for payment autofill)
//   IDENTITY: id, type, site, name, firstName, lastName, email, phone (for form fill)
//   NOTE:     id, type, site, name
//
// NEVER sent to content scripts: ssn, passport, license, totp, notes,
// folder, address, city, state, postal, country, cardholder

function sanitizeForAutofill(entry) {
  if (!entry) return null;
  const type = entry.type || 'login';
  const base = {
    id: entry.id || '',
    type: type,
    site: entry.site || entry.name || '',
    name: entry.name || entry.site || '',
    url: entry.url || '',
  };

  switch (type) {
    case 'login':
      return {
        ...base,
        user: entry.user || '',
        pass: entry.pass || entry.password || '',
        // No totp, notes, or other sensitive fields
      };
    case 'card':
      return {
        ...base,
        cardNumber: entry.cardNumber || '',
        exp: entry.exp || '',
        cvv: entry.cvv || '',
        // No cardholder, notes, or other sensitive fields
      };
    case 'identity':
      return {
        ...base,
        firstName: entry.firstName || '',
        lastName: entry.lastName || '',
        email: entry.email || '',
        phone: entry.phone || '',
        // No ssn, passport, license, address, notes, or other sensitive fields
      };
    case 'note':
      return base;  // Notes are just a name — content body is too sensitive
    default:
      return base;
  }
}

// ─── Password generator ───────────────────────────────────────────────
// E10: The wordlist (WORDLIST) and password generation functions
// (generateRandomPassword, generatePassphrase, generatePassword,
// estimateStrength, labelForBits, unbiasedRandomInt, pickRandomChar,
// shuffleArray, CHARSETS, AMBIGUOUS) have been extracted to:
//   - wordlist.js:     ~500-word EFF-style passphrase wordlist
//   - generator.js:    Password generation + strength estimation + random helpers
// background.js imports generatePassword from generator.js.
// The generator.js module imports WORDLIST from wordlist.js internally.
// This reduces background.js by ~170 lines while keeping all functionality intact.

// ─── TOTP (RFC 6238) ──────────────────────────────────────────────────

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(secret) {
  if (!secret) return new Uint8Array(0);
  // Strip spaces, dashes, underscores; uppercase.
  const cleaned = String(secret).replace(/[\s\-_]/g, '').toUpperCase();
  const out = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue; // skip invalid chars (padding etc.)
    buffer = (buffer << 5) | idx;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push((buffer >> bitsLeft) & 0xFF);
    }
  }
  return new Uint8Array(out);
}

async function generateTotp(secret) {
  if (!secret) return null;
  const keyBytes = base32Decode(secret);
  if (keyBytes.length === 0) return null;

  const epochSeconds = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epochSeconds / 30);
  const secondsLeft = 30 - (epochSeconds % 30);

  // 8-byte big-endian counter
  const counterBytes = new Uint8Array(8);
  const dv = new DataView(counterBytes.buffer);
  // DataView doesn't have setBigUint64 in all targets; do it manually.
  let v = counter;
  // We can't represent > 2^53 counters precisely; this is fine for TOTP.
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = v & 0xFF;
    v = Math.floor(v / 256);
  }

  let key;
  try {
    key = await crypto.subtle.importKey(
      'raw', keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false, ['sign']
    );
  } finally {
    keyBytes.fill(0);
  }

  const hmacBuf = await crypto.subtle.sign({ name: 'HMAC' }, key, counterBytes);
  const hmac = new Uint8Array(hmacBuf);

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0F;
  const binary =
    ((hmac[offset] & 0x7F) << 24) |
    ((hmac[offset + 1] & 0xFF) << 16) |
    ((hmac[offset + 2] & 0xFF) << 8) |
    (hmac[offset + 3] & 0xFF);
  const code = binary % 1000000;
  return {
    code: String(code).padStart(6, '0'),
    secondsLeft,
    period: 30
  };
}

// ─── Clipboard timer ──────────────────────────────────────────────────
// Actual writeText happens in window.js. background.js tracks the timer
// and broadcasts do_clipboard_clear to the window when it fires.

async function startClipboardTimer(value, timeoutMs) {
  // Clear any existing timer
  if (state.clipboardTimer) {
    clearTimeout(state.clipboardTimer);
  }
  state.clipboardValue = value;
  const ms = timeoutMs || CLIPBOARD_DEFAULT_MS;
  state.clipboardTimer = setTimeout(async () => {
    state.clipboardValue = null;
    state.clipboardTimer = null;
    // Ask the window to clear the clipboard.
    try {
      await chrome.runtime.sendMessage({ type: 'do_clipboard_clear' });
    } catch (_) { /* no listener */ }
  }, ms);
}

async function clearClipboardNow() {
  if (state.clipboardTimer) {
    clearTimeout(state.clipboardTimer);
    state.clipboardTimer = null;
  }
  state.clipboardValue = null;
  try {
    await chrome.runtime.sendMessage({ type: 'do_clipboard_clear' });
  } catch (_) { /* no listener */ }
}

// ─── Auto-lock timer ──────────────────────────────────────────────────
// E6 FIX: lastActivity is now persisted to chrome.storage.session on every
// update and restored on SW wake-up. Previously, SW eviction reset
// lastActivity to Date.now(), effectively granting a fresh timeout window
// and allowing a locked vault to stay "unlocked" indefinitely.

async function persistLastActivity() {
  await chrome.storage.session.set({ lastActivity: state.lastActivity });
}

async function restoreLastActivity() {
  const { lastActivity } = await chrome.storage.session.get('lastActivity');
  if (typeof lastActivity === 'number' && lastActivity > 0) {
    state.lastActivity = lastActivity;
  }
}

async function startAutoLockTimer() {
  if (state.autoLockTimer) clearInterval(state.autoLockTimer);
  state.autoLockTimer = setInterval(async () => {
    if (!state.unlocked) return;
    const settings = await getSettings();
    if (settings.lockTimeoutMs <= 0) return; // Never
    const idle = Date.now() - state.lastActivity;
    if (idle > settings.lockTimeoutMs) {
      await doLock();
    }
  }, AUTO_LOCK_POLL_MS);
}

// ─── Lock / unlock ────────────────────────────────────────────────────

async function doLock() {
  state.cachedVault = null;
  state.unlocked = false;
  // E2: Clear the runtime encryption key on lock. This makes all
  // encrypted data in chrome.storage.local unreadable until the next unlock.
  runtimeCrypto.clear();
  // Only clear the session PASSWORD — the encrypted vault blob stays in
  // chrome.storage.local so the resume screen (password-only) can be shown
  // on the next popup open instead of the full unlock screen (file picker
  // + password). The blob is encrypted — it's safe to keep.
  // E6: Also clear lastActivity so the auto-lock timer doesn't think
  // the vault was recently active after being locked.
  // E2: Also clear the runtime crypto salt so the key can't be re-derived.
  await chrome.storage.session.remove(['sessionPassword', 'svltFileHandle', 'lastActivity', '_rcSalt']);
  await clearClipboardNow();
  updateToolbarBadge();
  // Notify any open window.
  try {
    await chrome.runtime.sendMessage({ type: 'locked' });
  } catch (_) {}
}

// ─── Login save prompts ───────────────────────────────────────────────
// E2: Login prompts now use encrypted storage to protect passwords.

async function getLoginPrompts() {
  const prompts = await encryptedLocalGet('loginPrompts');
  return Array.isArray(prompts) ? prompts : [];
}

async function saveLoginPrompt(prompt) {
  const list = await getLoginPrompts();
  const id = crypto.randomUUID(); // E3: UUID for prompt IDs too
  const entry = {
    id,
    url: prompt.url || '',
    username: prompt.username || '',
    password: prompt.password || '',
    createdAt: Date.now()
  };
  list.push(entry);
  await encryptedLocalSet('loginPrompts', list);
  return entry;
}

async function dismissLoginPrompt(id) {
  const list = await getLoginPrompts();
  const filtered = list.filter(p => p.id !== id);
  await encryptedLocalSet('loginPrompts', filtered);
}

// ─── Notifications ────────────────────────────────────────────────────

async function notify(title, message) {
  try {
    await chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title,
      message: message || '',
      priority: 0
    });
  } catch (_) { /* notifications may be unavailable */ }
}

// ─── Context menu ─────────────────────────────────────────────────────

const MENU_PARENT = 'sv-parent';
const MENU_AUTOFILL = 'sv-autofill';
const MENU_COPY_USER = 'sv-copy-user';
const MENU_COPY_PASS = 'sv-copy-pass';
const MENU_COPY_TOTP = 'sv-copy-totp';
const MENU_GENERATE = 'sv-generate';
const MENU_ADD_LOGIN = 'sv-add-login';

function setupContextMenu() {
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: MENU_PARENT,
        title: 'SecureVault',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_AUTOFILL,
        parentId: MENU_PARENT,
        title: 'Auto-fill login',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_COPY_USER,
        parentId: MENU_PARENT,
        title: 'Copy username',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_COPY_PASS,
        parentId: MENU_PARENT,
        title: 'Copy password',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_COPY_TOTP,
        parentId: MENU_PARENT,
        title: 'Copy TOTP code',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_GENERATE,
        parentId: MENU_PARENT,
        title: 'Generate password',
        contexts: ['all']
      });
      chrome.contextMenus.create({
        id: MENU_ADD_LOGIN,
        parentId: MENU_PARENT,
        title: 'Add current login to SecureVault',
        contexts: ['all']
      });
    });
  } catch (_) { /* contextMenus may be unavailable */ }
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs[0] ? tabs[0] : null;
}

async function findBestEntryForTab(tab) {
  if (!state.cachedVault || !tab || !tab.url) return null;
  const base = getBaseDomain(tab.url);
  if (!base) return null;
  // Prefer logins whose URL matches; otherwise match by site/name.
  const candidates = state.cachedVault.filter(e =>
    !e.deleted && (e.type === 'login' || !e.type) &&
    domainMatches(tab.url, (e.url || e.login_uri || e.site || e.name || ''))
  );
  if (candidates.length === 0) return null;
  // Pick the one whose base domain equals exactly (most specific).
  const exact = candidates.find(e => getBaseDomain(e.url || e.login_uri || e.site || e.name) === base);
  return exact || candidates[0];
}

async function copyValueViaWindow(value) {
  // Ask the window (if open) to perform the actual clipboard write.
  // If window is closed, open it so the write can happen.
  if (state.windowId === null) {
    await openWindow();
    // Wait briefly for the window to boot.
    await new Promise(r => setTimeout(r, 600));
  }
  try {
    await chrome.runtime.sendMessage({ type: 'do_clipboard_write', value });
    return true;
  } catch (_) {
    return false;
  }
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  state.lastActivity = Date.now();
  persistLastActivity(); // E6: persist activity timestamp
  const menuItemId = info.menuItemId;

  if (menuItemId === MENU_GENERATE) {
    const { password } = generatePassword({
      mode: 'random', length: 20,
      uppercase: true, lowercase: true, numbers: true, symbols: true
    });
    const ok = await copyValueViaWindow(password);
    if (ok) {
      await startClipboardTimer(password, CLIPBOARD_DEFAULT_MS);
      await notify('SecureVault — password generated', 'Copied to clipboard. Self-destructs in 10s.');
    } else {
      await notify('SecureVault', 'Open the SecureVault window to copy generated passwords.');
    }
    return;
  }

  if (menuItemId === MENU_ADD_LOGIN) {
    const t = tab || await getActiveTab();
    await openWindow({ add: 1, url: t ? t.url : '' });
    return;
  }

  if (menuItemId === MENU_AUTOFILL) {
    const t = tab || await getActiveTab();
    if (t && t.id !== undefined) {
      try {
        await chrome.tabs.sendMessage(t.id, { type: 'trigger_autofill' });
      } catch (_) {}
    }
    return;
  }

  // Copy operations require a matching entry.
  const t = tab || await getActiveTab();
  const entry = await findBestEntryForTab(t);
  if (!entry) {
    await notify('SecureVault', 'No matching login found for this site.');
    return;
  }

  if (menuItemId === MENU_COPY_USER) {
    const ok = await copyValueViaWindow(entry.user || entry.username || '');
    if (ok) {
      await startClipboardTimer(entry.user || entry.username || '', CLIPBOARD_DEFAULT_MS);
      await notify('SecureVault', 'Username copied. Self-destructs in 10s.');
    }
  } else if (menuItemId === MENU_COPY_PASS) {
    const value = entry.pass || entry.password || '';
    const ok = await copyValueViaWindow(value);
    if (ok) {
      await startClipboardTimer(value, CLIPBOARD_DEFAULT_MS);
      await notify('SecureVault', 'Password copied. Self-destructs in 10s.');
    }
  } else if (menuItemId === MENU_COPY_TOTP) {
    const totp = await generateTotp(entry.totp || entry.totpSecret || '');
    if (!totp) {
      await notify('SecureVault', 'No TOTP secret on this entry.');
      return;
    }
    const ok = await copyValueViaWindow(totp.code);
    if (ok) {
      await startClipboardTimer(totp.code, Math.min(CLIPBOARD_DEFAULT_MS, totp.secondsLeft * 1000));
      await notify('SecureVault', `TOTP ${totp.code} copied. Expires in ${totp.secondsLeft}s.`);
    }
  }
});

// ─── Message router ───────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // ─── E5: IPC sender validation ──────────────────────────────────────────
  // Reject messages from unknown extensions or external senders.
  // Only messages from our own extension (same id) are allowed.
  if (sender.id !== chrome.runtime.id) {
    console.warn('[SV] Rejected message from unknown sender:', sender.id);
    sendResponse({ ok: false, error: 'Rejected: unknown sender' });
    return false;
  }

  // E6: Update activity timestamp AND persist it on every incoming message.
  state.lastActivity = Date.now();
  persistLastActivity(); // fire-and-forget — no await needed here

  // Use an async IIFE so we can return true synchronously (keeps the
  // message channel open for the async response).
  (async () => {
    try {
      const result = await handleMessage(message, sender);
      sendResponse(result);
    } catch (err) {
      console.error('[SecureVault background] message handler error:', err);
      sendResponse({ ok: false, error: String(err && err.message || err) });
    }
  })();
  return true; // async response
});

async function handleMessage(message, sender) {
  const type = message && message.type;
  switch (type) {
    case 'cache_vault': {
      const { entries, password } = message;
      state.cachedVault = Array.isArray(entries) ? entries : [];
      state.unlocked = true;
      state.lastUnlockedAt = Date.now();
      state.lastEntryCount = state.cachedVault.length;
      if (password) {
        await setSessionPassword(password);
        // E2: Initialize runtime encryption key from master password.
        // This key protects sensitive data in chrome.storage.local.
        await runtimeCrypto.initFromPassword(password);
      }
      await persistStatusMeta();
      updateToolbarBadge();
      return { ok: true, count: state.cachedVault.length };
    }

    case 'update_vault': {
      const { entries } = message;
      state.cachedVault = Array.isArray(entries) ? entries : [];
      state.unlocked = true;
      state.lastActivity = Date.now();
      await persistLastActivity(); // E6: persist activity timestamp
      state.lastEntryCount = state.cachedVault.length;
      await persistStatusMeta();
      return { ok: true, count: state.cachedVault.length };
    }

    case 'lock': {
      await doLock();
      updateToolbarBadge();
      return { ok: true };
    }

    case 'get_status': {
      const sessionPassword = await getSessionPassword();
      return {
        unlocked: state.unlocked,
        hasVault: !!state.cachedVault,
        cachedCount: state.cachedVault ? state.cachedVault.length : 0,
        hasSessionPassword: !!sessionPassword,
        lastUnlockedAt: state.lastUnlockedAt,
        lastEntryCount: state.lastEntryCount,
        windowOpen: state.windowId !== null
      };
    }

    case 'get_vault': {
      return {
        entries: state.cachedVault || [],
        locked: !state.unlocked
      };
    }

    // ─── E14: Credential sanitization for content scripts ────────────────
    // Content scripts (inline-overlay.js, save-prompt.js) only need minimal
    // data for autofill and form detection. We NEVER send the full entry
    // to content scripts because:
    //   1. Content scripts share the page's DOM (page scripts could intercept)
    //   2. SSN, passport, license, TOTP secrets are too sensitive for page context
    //   3. Card CVV is only needed for payment autofill (user explicitly triggers)
    //
    // The popup (window.js) can still access full entries since it's
    // extension-controlled and doesn't share its context with page scripts.

    case 'lookup_credentials': {
      const domain = message.domain || '';
      if (!state.unlocked || !state.cachedVault) {
        return { entries: [], locked: !state.unlocked };
      }
      const target = getBaseDomain(domain);
      const matches = state.cachedVault.filter(e => {
        if (e.deleted) return false;
        const candidate = e.url || e.login_uri || e.site || e.name || '';
        if (!candidate) return false;
        return domainMatches(domain, candidate);
      });
      // E14: Sanitize entries before sending to content scripts.
      // Only send the fields needed for autofill — strip everything else.
      const sanitized = matches.map(e => sanitizeForAutofill(e));
      return { entries: sanitized, locked: false };
    }

    case 'copy_to_clipboard': {
      // The window has ALREADY written to navigator.clipboard. We just
      // track the self-destruct timer.
      const settings = await getSettings();
      await startClipboardTimer(message.value, settings.clipboardTimeoutMs || CLIPBOARD_DEFAULT_MS);
      return { ok: true };
    }

    case 'clear_clipboard': {
      await clearClipboardNow();
      return { ok: true };
    }

    case 'generate_password': {
      const result = generatePassword(message.options || {});
      return { ok: true, password: result.password, strength: result.strength, entropyBits: result.entropyBits, label: result.label };
    }

    case 'generate_totp': {
      const totp = await generateTotp(message.secret);
      return { ok: true, totp };
    }

    case 'get_settings': {
      const settings = await getSettings();
      return { ok: true, settings };
    }

    case 'set_settings': {
      const merged = await setSettings(message.settings || {});
      // Broadcast to content scripts so they can refresh their cached
      // settings (e.g. inline-overlay.js honors showLockIcon / autoFillEnabled).
      try {
        chrome.runtime.sendMessage({ type: 'settings_changed', settings: merged }).catch(() => {});
      } catch (_) {}
      // Also broadcast to all tabs' content scripts.
      try {
        chrome.tabs.query({}, (tabs) => {
          for (const t of tabs) {
            if (t.id) {
              chrome.tabs.sendMessage(t.id, { type: 'settings_changed', settings: merged }).catch(() => {});
            }
          }
        });
      } catch (_) {}
      return { ok: true, settings: merged };
    }

    case 'save_login_prompt': {
      const entry = await saveLoginPrompt(message);
      return { ok: true, id: entry.id };
    }

    case 'get_login_prompts': {
      const list = await getLoginPrompts();
      return { ok: true, prompts: list };
    }

    case 'dismiss_login_prompt': {
      await dismissLoginPrompt(message.id);
      return { ok: true };
    }

    // ─── E2: Generator history (encrypted storage) ──────────────────────
    // genHistory stores generated passwords — sensitive data that must
    // be encrypted at rest. Window.js now delegates storage to background.js
    // via these IPC handlers.

    case 'save_gen_history': {
      const history = message.history;
      if (!Array.isArray(history)) return { ok: false, error: 'history must be an array' };
      await encryptedLocalSet('genHistory', history.slice(0, 10));
      return { ok: true };
    }

    case 'get_gen_history': {
      const history = await encryptedLocalGet('genHistory');
      return { ok: true, history: Array.isArray(history) ? history : [] };
    }

    case 'window_blur': {
      // Window lost focus — clear clipboard as a security measure.
      await clearClipboardNow();
      return { ok: true };
    }

    case 'window_ready': {
      // Window signals it's loaded; we can forward pending actions.
      state.windowId = sender.tab?.windowId || state.windowId;
      return { ok: true };
    }

    // ─── E7: Removed get_session_password handler. ────────────────────────
    // The master password must NEVER cross IPC. Instead, window.js sends
    // plaintext vault data to background.js for encryption (see encrypt_vault
    // below), and background.js returns the encrypted file data.

    case 'encrypt_vault': {
      // E7: New IPC handler — window.js sends plaintext entries, background.js
      // encrypts them internally using the session password (which never leaves
      // the SW). This replaces the old pattern where window.js requested the
      // master password via get_session_password to do local encryption.
      const sessionPassword = await getSessionPassword();
      if (!sessionPassword) {
        return { ok: false, error: 'No session password — vault is locked' };
      }
      const entries = message.entries;
      if (!Array.isArray(entries)) {
        return { ok: false, error: 'entries must be an array' };
      }
      try {
        const { encryptVaultFile: bgEncrypt } = await import('./vaultFileCrypto.js');
        const buffer = await bgEncrypt(entries, sessionPassword);
        // Convert ArrayBuffer to base64 for IPC transport.
        const bytes = new Uint8Array(buffer);
        const b64 = btoa(Array.from(bytes).map(b => String.fromCharCode(b)).join(''));
        return { ok: true, encryptedB64: b64 };
      } catch (err) {
        return { ok: false, error: 'Encryption failed: ' + (err.message || err) };
      }
    }

    case 'open_window': {
      await openWindow(message.query || {});
      return { ok: true };
    }

    case 'check_pwned': {
      // Gate behind hibpCheckEnabled setting.
      const settings = await getSettings();
      if (!settings.hibpCheckEnabled) {
        return {
          breached: false,
          count: 0,
          error: 'Breach check is disabled. Enable it in Settings.'
        };
      }
      const result = await checkPwnedPassword(message.password);
      return result;
    }

    case 'vault_health_scan': {
      const settings = await getSettings();
      if (!settings.hibpCheckEnabled) {
        return { ok: false, error: 'Breach check is disabled. Enable it in Settings.' };
      }
      try {
        const results = await vaultHealthScan(message.entries || [], (checked, total, site, result) => {
          // Send progress to the window (ignore failures — window may be closed).
          try {
            chrome.runtime.sendMessage({
              type: 'health_scan_progress',
              checked, total, site, result
            }).catch(() => {});
          } catch (_) { /* no listener */ }
        });
        return { ok: true, results };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }

    case 'clear_breach_cache': {
      clearBreachCache();
      return { ok: true };
    }

    default: {
      return { ok: false, error: 'unknown message type: ' + type };
    }
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  setupContextMenu();
  await loadStatusMeta();
  await restoreLastActivity(); // E6: restore persisted activity timestamp
  await startAutoLockTimer();
  // E6: After restoring lastActivity, check if auto-lock should fire immediately.
  const settings = await getSettings();
  if (settings.lockTimeoutMs > 0 && (Date.now() - state.lastActivity) > settings.lockTimeoutMs) {
    await doLock();
  }
});

chrome.runtime.onStartup.addListener(async () => {
  await loadStatusMeta();
  await restoreLastActivity(); // E6: restore persisted activity timestamp
  await startAutoLockTimer();
  // E6: After restoring lastActivity, check if auto-lock should fire immediately.
  const settings = await getSettings();
  if (settings.lockTimeoutMs > 0 && (Date.now() - state.lastActivity) > settings.lockTimeoutMs) {
    await doLock();
  }
});

// Also start the timer if the SW wakes for any reason (covers the case
// where onInstalled/onStartup already fired previously).
startAutoLockTimer();
loadStatusMeta();
restoreLastActivity(); // E6: restore persisted activity timestamp on SW wake
// E6: Immediately check if auto-lock should fire after restoring timestamp.
(async () => {
  try {
    const settings = await getSettings();
    if (settings.lockTimeoutMs > 0 && state.unlocked && (Date.now() - state.lastActivity) > settings.lockTimeoutMs) {
      await doLock();
    }
  } catch (_) {}
})();

// E2: Try to re-derive the runtime encryption key from session password
// + persisted salt on SW wake-up. If the session password is still in
// chrome.storage.session (survives SW eviction), we can recover the key
// and read encrypted data. If not, all encrypted data stays unreadable
// (which is the desired security behavior).
runtimeCrypto.initFromSession();
