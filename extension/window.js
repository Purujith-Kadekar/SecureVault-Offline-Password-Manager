/**
 * window.js — SecureVault premium vault UI (ES module).
 *
 * Loaded by window.html as type="module". Has access to:
 *   - chrome.runtime / chrome.storage / chrome.windows APIs
 *   - File System Access API (showOpenFilePicker, createWritable)
 *     with <input type="file"> + download fallback
 *   - navigator.clipboard (the actual clipboard writes happen here;
 *     background.js cannot access navigator.clipboard reliably)
 *   - WebCrypto via vaultFileCrypto.js (decryptVaultFile for initial
 *     unlock / resume / reload; encryptVaultFile is now delegated to
 *     background.js via IPC for routine vault saves — see E7 fix)
 *   - peekFormat, VaultFileError, WrongPasswordError
 *
 * Responsibilities:
 *   - Lock screen: pick .svlt file, unlock, resume session
 *   - Vault tab: list, search, filter, add/edit/delete entries
 *   - Generator tab: random + passphrase, history, strength meter
 *   - Settings tab: lock/clipboard timeouts, toggles, change master
 *     password, reload file, export CSV, lock now, breach detection
 *   - Clipboard writes + 10s self-destruct (coordinated with background)
 *   - TOTP live preview in the entry modal
 *   - HIBP breach check (per-password + vault-wide health scan) — gated
 *     behind the hibpCheckEnabled setting, uses k-anonymity
 *
 * Entry schema (Bitwarden-compatible-ish, content.js-compatible):
 *   { id, type, name, url, site, user, pass, totp, notes, folder,
 *     favorite, deleted, cardholder, cardNumber, exp, cvv,
 *     firstName, lastName, email, phone, address, city, state,
 *     postal, country, ssn, passport, license, created, updated }
 *
 * content.js reads entry.site / entry.user / entry.pass — so we always
 * populate `site` (display name) and use `user`/`pass` for logins.
 *
 * ─── E11: TODO: Module decomposition ──────────────────────────────────
 *
 * This file is ~2682 lines and should be split into focused modules for
 * maintainability, but doing it all at once in a single session is too
 * risky (would introduce bugs across all UI flows). Planned modules:
 *
 *   - vaultState.js:     State management (state object, normalizeEntry,
 *                        synthesizeExtEntryId, normalizeEntryArray)
 *   - vaultDOM.js:       DOM helpers ($, $$, el, showToast, showError,
 *                        clearError, escapeAttr, escapeHtml)
 *   - vaultSession.js:   Session persistence (storeSessionMeta,
 *                        readSessionMeta, clearSessionMeta, FSAA IDB,
 *                        bufferToBase64, base64ToBuffer)
 *   - vaultFile.js:      File picking + writing (pickVaultFile,
 *                        writeVaultFile, handleUnlock, handleResume,
 *                        handleReload, persistVault)
 *   - vaultUI.js:        Rendering (renderVault, renderCard, renderDetail,
 *                        renderModal, renderAddForm, renderEditForm,
 *                        renderGeneratorTab, renderSettingsTab)
 *   - vaultExport.js:    CSV/encrypted export (handleExportCsv,
 *                        handleExportEncrypted, csvEscape)
 *   - vaultFilters.js:   Filtering + search (currentFilter, searchQuery,
 *                        getFilteredEntries, filter bar UI)
 *   - vaultClipboard.js: Clipboard writes + self-destruct
 *   - vaultTOTP.js:      TOTP live preview (generateTotp, timer)
 *   - vaultBreach.js:    HIBP breach check UI (setBreachBadge,
 *                        handleHealthScan)
 *   - vaultTabs.js:      Tab switching + navigation
 *   - vaultInit.js:      Boot/initialization (event wiring, DOMContentLoaded)
 *
 * Pre-condition for splitting: Each module must export its public API and
 * window.js must import and compose them. This requires careful dependency
 * analysis since many functions share the `state` object. A shared state
 * module (or a lightweight Zustand-like store) would be the first step.
 *
 * DO NOT split yet — wait for a dedicated refactoring session with tests.
 */

import {
  decryptVaultFile,
  encryptVaultFile,
  peekFormat,
  VaultFileError,
  WrongPasswordError,
  SchemaVersionTooNewError,
  DATA_SCHEMA_VERSION
} from './vaultFileCrypto.js';
// E7: encryptVaultFile is no longer used directly in window.js for vault
// persistence. All encryption is now delegated to background.js via the
// `encrypt_vault` IPC handler. encryptVaultFile is still imported here
// as a reference for the initial vault decryption flow, but vault re-
// encryption on every save goes through background.js.

// ─── State ────────────────────────────────────────────────────────────

const state = {
  vault: [],                 // decrypted entries
  sessionPassword: null,     // master password (in-memory)
  fileHandle: null,          // FileSystemFileHandle | null
  fileName: '',
  encryptedBuffer: null,     // ArrayBuffer of the on-disk .svlt (for re-encrypt + resume)
  currentFilter: 'all',
  searchQuery: '',
  editingEntryId: null,
  editingType: 'login',
  generatorHistory: [],
  totpInterval: null,
  isLocked: true
};

// ─── DOM helpers ──────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k === 'style') e.style.cssText = v;
    else if (k.startsWith('on') && typeof v === 'function') {
      e.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (k === 'dataset') {
      for (const [dk, dv] of Object.entries(v)) e.dataset[dk] = dv;
    } else if (v !== null && v !== undefined) {
      e.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c == null) continue;
    e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return e;
}

// ─── Entry normalization (v6.7 SYNC FIX) ──────────────────────────────
// The Electron app's renderer and main process use multiple legacy naming
// conventions for the same fields:
//   - `fav` (numeric 0/1) ↔ `favorite` (boolean)
//   - `del` (numeric 0/1) ↔ `deleted` (boolean)
//   - `site` (firmware label) ↔ `name` (extension label)
//   - `login_username` / `login_password` / `login_totp` (Bitwarden CSV) ↔ `user`/`pass`/`totp`
//
// Without normalization, the extension's filters silently missed entries
// — e.g. the Favorites filter checked `entry.favorite` (boolean) but the
// .svlt file from the SD-card path only had `fav: 1` (numeric), so
// favorite-flagged entries were invisible in the extension's Favorites
// view. Same shape of bug for trash (`deleted` boolean vs `del` numeric).
//
// This function is the SOURCE OF TRUTH for the in-memory entry shape.
// Every entry that enters `state.vault` MUST pass through it. It is
// intentionally permissive about input (accepts any of the legacy names)
// and strict about output (always emits every field the UI reads, with
// the correct type).
/**
 * E3 FIX: synthesizeExtEntryId is now a LEGACY FALLBACK for entries that
 * lack a proper `id` field. New entries always receive a crypto.randomUUID()
 * as their id (see normalizeEntry). The synthesize function uses the
 * `type|site|user` triple as its fallback key to reduce collisions
 * (previously it used just `site|user`, which caused duplicate IDs for
 * two accounts on the same site with the same username).
 *
 * @param {object} e — raw entry (may lack an `id` field)
 * @returns {string} — the entry's id (proper UUID if present, synthesized fallback otherwise)
 */
function synthesizeExtEntryId(e) {
  // If the entry already has a proper UUID-style id, use it.
  if (e && e.id && typeof e.id === 'string' && e.id.length >= 20) return e.id;
  // Legacy fallback: synthesize from type|site|user triple (not just site|user)
  // to reduce collision probability.
  const key = `${(e && e.type) || 'login'}|${(e && (e.site || e.name)) || ''}|${(e && e.user) || ''}`;
  let h1 = 0x811c9dc5, h2 = 0x1000193;
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = (h2 + c * 0x100000001b3) >>> 0;
  }
  return 'e_' + h1.toString(36) + '_' + h2.toString(36);
}

function normalizeEntry(e) {
  if (!e || typeof e !== 'object') return null;
  const isFav = !!(e.fav || e.favorite);
  const isDel = !!(e.del || e.deleted);
  const now = Date.now();

  // `type` may arrive as a firmware numeric (0/1/2/3) or a string.
  const typeMap = { 0: 'login', 1: 'card', 2: 'identity', 3: 'note' };
  let typeStr = e.type;
  if (typeof typeStr === 'number') typeStr = typeMap[typeStr] || 'login';
  if (!['login', 'card', 'identity', 'note'].includes(typeStr)) typeStr = 'login';

  const out = {
    // ── Identity / metadata ──────────────────────────────────────────
    // E3 FIX: New entries always get a crypto.randomUUID() id. Entries
    // loaded from existing vault files may lack an `id` field — in that
    // case, synthesizeExtEntryId(e) provides a legacy fallback hash.
    id: (e && e.id && typeof e.id === 'string' && e.id.length >= 20) ? e.id : synthesizeExtEntryId(e),
    name: String(e.name || e.site || ''),
    site: String(e.site || e.name || ''),
    type: typeStr,
    url: String(e.url || e.login_uri || ''),
    // ── Trash / favorite — ALWAYS booleans, never undefined ──────────
    // The filters in renderVault() read `entry.favorite` and `entry.deleted`
    // directly. If these were undefined (the bug), the entry silently
    // failed both filters AND appeared in the active list / favorites list
    // incorrectly. Now they are always strict booleans.
    favorite: isFav,
    deleted: isDel,
    // Also keep the legacy numeric forms in sync (in case any code path
    // still reads them — be conservative and don't break old code).
    fav: isFav ? 1 : 0,
    del: isDel ? 1 : 0,
    // ── Timestamps — numbers, always present (sort key) ──────────────
    created: Number(e.created) || now,
    updated: Number(e.updated) || now,
    deletedAt: isDel ? (Number(e.deletedAt) || now) : 0,
    // ── Login fields ─────────────────────────────────────────────────
    user: String(e.user || e.login_username || ''),
    pass: String(e.pass || e.login_password || ''),
    totp: String(e.totp || e.login_totp || ''),
    notes: String(e.notes || ''),
    folder: String(e.folder || ''),
    // ── Card fields ──────────────────────────────────────────────────
    cardholder: String(e.cardholder || e.cardHolder || ''),
    cardNumber: String(e.cardNumber || ''),
    exp: String(e.exp || e.cardExpiry || ''),
    cvv: String(e.cvv || e.cardCvv || ''),
    // ── Identity fields ──────────────────────────────────────────────
    firstName: String(e.firstName || e.idFirstName || ''),
    lastName: String(e.lastName || e.idLastName || ''),
    email: String(e.email || e.idEmail || ''),
    phone: String(e.phone || e.idPhone || ''),
    address: String(e.address || e.idAddress || ''),
    city: String(e.city || e.idCity || ''),
    state: String(e.state || e.idState || ''),
    postal: String(e.postal || e.idPostal || ''),
    country: String(e.country || e.idCountry || ''),
    ssn: String(e.ssn || e.idSsn || ''),
    passport: String(e.passport || e.idPassport || ''),
    license: String(e.license || e.idLicense || ''),
  };
  if (Array.isArray(e.tags)) out.tags = e.tags.map(String).filter(Boolean);
  return out;
}

function normalizeEntryArray(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.map(normalizeEntry).filter(Boolean);
}

function showToast(message, type = '') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = 'toast show ' + type;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => {
    toast.className = 'toast hidden';
  }, 2400);
}

function showError(inputId, msg) {
  const errEl = $('#' + inputId);
  if (errEl) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  }
}

function clearError(inputId) {
  const errEl = $('#' + inputId);
  if (errEl) errEl.classList.add('hidden');
}

// ─── Background messaging ─────────────────────────────────────────────

function sendBg(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(resp || { ok: false, error: 'no response' });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

// ─── File picking (FSAA + fallback) ───────────────────────────────────

async function pickVaultFile() {
  if (typeof window.showOpenFilePicker === 'function') {
    try {
      const [handle] = await window.showOpenFilePicker({
        types: [{
          description: 'SecureVault vault',
          accept: { 'application/octet-stream': ['.svlt'] }
        }],
        excludeAcceptAllOption: false,
        multiple: false
      });
      const file = await handle.getFile();
      const buffer = await file.arrayBuffer();
      return { handle, name: file.name, buffer };
    } catch (e) {
      if (e && e.name === 'AbortError') return null;
      console.warn('[SecureVault] FSAA picker failed, falling back:', e);
      // fall through to fallback
    }
  }
  // Fallback: <input type="file">
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.svlt';
    input.style.display = 'none';
    document.body.appendChild(input);
    input.addEventListener('change', async () => {
      const file = input.files && input.files[0];
      document.body.removeChild(input);
      if (!file) return resolve(null);
      const buffer = await file.arrayBuffer();
      resolve({ handle: null, name: file.name, buffer });
    });
    input.click();
  });
}

async function writeVaultFile(buffer) {
  if (state.fileHandle && state.fileHandle.createWritable) {
    try {
      const writable = await state.fileHandle.createWritable();
      await writable.write(buffer);
      await writable.close();
      return true;
    } catch (e) {
      console.warn('[SecureVault] FSAA write failed, falling back to download:', e);
      // fall through to download fallback
    }
  }
  // Fallback: trigger a download
  const blob = new Blob([buffer], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = state.fileName || 'vault.svlt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  showToast('Downloaded updated vault (FSAA unavailable)', '');
  return true;
}

// ─── Session persistence (Bitwarden pattern) ──────────────────────────
//
// The ENCRYPTED vault blob is stored in chrome.storage.local as a base64
// string. This is:
//   - Reliable (strings never have structured-clone issues)
//   - Persistent (survives browser restarts, unlike chrome.storage.session)
//   - Safe (the blob is encrypted — without the master password it's useless)
//
// The MASTER PASSWORD is stored in chrome.storage.session. This is:
//   - Persistent across SW eviction (so popup reopens are instant)
//   - Cleared on browser close (so the secret doesn't persist forever)
//
// The FSAA file handle is stored in IndexedDB (persists across restarts).
//
// Boot flow:
//   State 1: session password + local vault blob → silent unlock (no UI)
//   State 2: no session password but local vault blob → resume screen (password only)
//   State 3: nothing → full unlock (file picker + password)

// ── Base64 helpers (for reliable string storage of binary vault blob) ──
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ── Store the encrypted vault blob in chrome.storage.local ──
async function storeVaultBlobLocal(encryptedBuffer, fileName) {
  try {
    const b64 = bufferToBase64(encryptedBuffer);
    await chrome.storage.local.set({
      svltVaultBlob: b64,
      svltVaultBlobName: fileName || ''
    });
  } catch (e) {
    console.warn('[SecureVault] storeVaultBlobLocal failed:', e);
  }
}

async function readVaultBlobLocal() {
  try {
    const data = await chrome.storage.local.get(['svltVaultBlob', 'svltVaultBlobName']);
    if (data.svltVaultBlob) {
      return {
        buffer: base64ToBuffer(data.svltVaultBlob),
        fileName: data.svltVaultBlobName || ''
      };
    }
  } catch (e) {
    console.warn('[SecureVault] readVaultBlobLocal failed:', e);
  }
  return { buffer: null, fileName: '' };
}

async function clearVaultBlobLocal() {
  try {
    await chrome.storage.local.remove(['svltVaultBlob', 'svltVaultBlobName']);
  } catch (_) {}
}

// ── Master password in chrome.storage.session (the secret) ──
async function storeSessionPassword(password) {
  try {
    await chrome.storage.session.set({ sessionPassword: password });
  } catch (e) {
    console.warn('[SecureVault] storeSessionPassword failed:', e);
  }
}

async function readSessionPassword() {
  try {
    const data = await chrome.storage.session.get('sessionPassword');
    return data.sessionPassword || null;
  } catch (_) {
    return null;
  }
}

async function clearSessionPassword() {
  try {
    await chrome.storage.session.remove('sessionPassword');
  } catch (_) {}
}

// ── Legacy compatibility: storeSessionMeta / readSessionMeta / clearSessionMeta ──
// These now delegate to the new split storage (local blob + session password).
// Kept so the rest of the codebase doesn't need to change.

async function storeSessionMeta(encryptedBuffer, fileName, password, fileHandle) {
  // Store the encrypted vault blob in chrome.storage.local (persists across restarts)
  await storeVaultBlobLocal(encryptedBuffer, fileName);
  // Store the master password in chrome.storage.session (cleared on browser close)
  if (password) await storeSessionPassword(password);
  // Store the FSAA handle in both session (for same-session use) and IDB (for cross-session)
  if (fileHandle) {
    try {
      await chrome.storage.session.set({ svltFileHandle: fileHandle });
    } catch (_) {}
    await persistFileHandleToIDB(fileHandle);
  }
  // Also store the file name in local storage as a hint
  if (fileName) {
    try {
      await chrome.storage.local.set({ svltLastFileName: fileName });
    } catch (_) {}
  }
}

async function readSessionMeta() {
  // Read password from session storage
  const password = await readSessionPassword();
  // Read vault blob from local storage
  const { buffer, fileName } = await readVaultBlobLocal();
  // Read FSAA handle from session storage (IDB handle is read separately in boot)
  let fileHandle = null;
  try {
    const data = await chrome.storage.session.get('svltFileHandle');
    fileHandle = data.svltFileHandle || null;
  } catch (_) {}

  return {
    encryptedBuffer: buffer,
    fileName: fileName,
    password: password,
    fileHandle: fileHandle
  };
}

async function clearSessionMeta() {
  await clearSessionPassword();
  // NOTE: we do NOT clear the vault blob from local storage on lock.
  // The blob is encrypted — it's safe to keep. This way the resume screen
  // (password-only) can be shown after a lock, instead of the full unlock
  // screen (file picker + password). The user only sees the full unlock
  // screen on the very first run, or after clicking "Forget session".
  // clearVaultBlobLocal() is only called from the "Forget session" button.
  try {
    await chrome.storage.session.remove('svltFileHandle');
  } catch (_) {}
}

// ─── FSAA file-handle persistence in IndexedDB ─────────────────────────
// chrome.storage.session is wiped on browser close, so the FSAA handle would
// be lost across restarts. We mirror it to IndexedDB (which persists across
// restarts) so the user only has to re-pick the file once per *browser
// profile lifetime* — Chrome will still require a one-tap re-permission on
// the first user gesture of a new browser session (this is a Chrome security
// constraint, not something we can bypass), but the file picker dialog is
// no longer needed.

const IDB_DB_NAME = 'securevault';
const IDB_STORE = 'handles';
const IDB_KEY = 'svltFileHandle';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function persistFileHandleToIDB(handle) {
  try {
    const db = await idbOpen();
    const tx = db.transaction(IDB_STORE, 'readwrite');
    tx.objectStore(IDB_STORE).put(handle, IDB_KEY);
    await new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    db.close();
  } catch (e) {
    console.warn('[SecureVault] IDB persist failed:', e);
  }
}

async function loadFileHandleFromIDB() {
  try {
    const db = await idbOpen();
    const tx = db.transaction(IDB_STORE, 'readonly');
    const req = tx.objectStore(IDB_STORE).get(IDB_KEY);
    const result = await new Promise((resolve) => {
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    });
    db.close();
    return result;
  } catch (e) {
    return null;
  }
}

async function clearFileHandleFromIDB() {
  try {
    const db = await idbOpen();
    const tx = db.transaction(IDB_STORE, 'readwrite');
    tx.objectStore(IDB_STORE).delete(IDB_KEY);
    await new Promise((resolve) => { tx.oncomplete = resolve; tx.onerror = resolve; });
    db.close();
  } catch (_) {}
}

/**
 * Verify that a stored FSAA handle still grants permission. Chrome revokes
 * permission on browser restart; the user must re-grant it via a user
 * gesture. Returns true if the handle is usable, false if permission is
 * needed (caller should call requestFileHandlePermission in a click handler).
 */
async function verifyFileHandlePermission(handle) {
  if (!handle || !handle.queryPermission) return false;
  try {
    const perm = await handle.queryPermission({ mode: 'readwrite' });
    if (perm === 'granted') return true;
    // Try to request — this must be called from a user gesture in Chrome.
    // If we're not in a user gesture, this will return 'prompt' or 'denied'.
    const requested = await handle.requestPermission({ mode: 'readwrite' });
    return requested === 'granted';
  } catch (_) {
    return false;
  }
}

// ─── Generator history (E2: now stored via background.js encrypted storage) ────

async function loadGenHistory() {
  // E2: Delegate to background.js which encrypts the data at rest.
  const resp = await sendBg({ type: 'get_gen_history' });
  if (resp && resp.ok) {
    state.generatorHistory = Array.isArray(resp.history) ? resp.history : [];
  } else {
    state.generatorHistory = [];
  }
}

async function saveGenHistory() {
  // E2: Delegate to background.js which encrypts before storing.
  await sendBg({ type: 'save_gen_history', history: state.generatorHistory });
}

async function pushGenHistory(value, mode) {
  if (!value) return;
  state.generatorHistory.unshift({
    value, mode, ts: Date.now()
  });
  state.generatorHistory = state.generatorHistory.slice(0, 10);
  // Await the save (bug B10: previously fired-and-forgotten, which could
  // race on rapid generation and lose entries).
  await saveGenHistory();
  renderGenHistory();
}

// ─── Clipboard (window context) ───────────────────────────────────────

async function copyToClipboard(value) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    // Tell background to start the self-destruct timer.
    await sendBg({ type: 'copy_to_clipboard', value });
    showToast('Copied — self-destructs in 10s', 'success');
  } catch (e) {
    // Fallback: execCommand
    try {
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      await sendBg({ type: 'copy_to_clipboard', value });
      showToast('Copied — self-destructs in 10s', 'success');
    } catch (e2) {
      showToast('Clipboard unavailable', 'error');
    }
  }
}

// ─── Lock screen ──────────────────────────────────────────────────────

async function boot() {
  await loadGenHistory();
  await loadSettingsIntoForm();

  // ── Bitwarden-style session unlock flow ─────────────────────────────
  //
  // The encrypted vault blob lives in chrome.storage.local (persists across
  // browser restarts). The master password lives in chrome.storage.session
  // (cleared on browser close, persists across SW eviction).
  //
  // State 1: Both password (session) + vault blob (local) → silent unlock
  // State 2: Vault blob (local) but no password (session) → resume screen
  //          (password only — no file picker needed)
  // State 3: Nothing → full unlock (file picker + password)
  //
  // The user should ONLY see the file picker on first run, or after
  // clicking "Forget session & open different file". Every other popup
  // open should be either silent (State 1) or password-only (State 2).

  const password = await readSessionPassword();
  const { buffer: vaultBlob, fileName: blobFileName } = await readVaultBlobLocal();
  const idbHandle = await loadFileHandleFromIDB();

  console.log('[SecureVault boot]', {
    hasPassword: !!password,
    hasVaultBlob: !!vaultBlob,
    hasIDBHandle: !!idbHandle,
    fileName: blobFileName
  });

  // State 1: silent unlock — password + vault blob both present.
  if (password && vaultBlob) {
    try {
      const { entries, schemaVersion } = await decryptVaultFile(vaultBlob, password);
      console.log('[SecureVault boot] State 1: silent unlock succeeded (schema v' + schemaVersion + ')');
      if (schemaVersion < DATA_SCHEMA_VERSION) {
        showToast('Vault schema upgraded from v' + schemaVersion + ' to v' + DATA_SCHEMA_VERSION, 'info');
      }
      await enterUnlocked(entries, password, vaultBlob, blobFileName, idbHandle);
      return;
    } catch (e) {
      console.warn('[SecureVault boot] State 1 decrypt failed:', e.message);
      // Password is stale or blob is corrupt — clear the password but
      // KEEP the vault blob (it might still be decryptable with the
      // correct password on the resume screen).
      await clearSessionPassword();
    }
  }

  // State 2: vault blob exists but no password (or password was stale).
  // Show the resume screen — password only, NO file picker.
  if (vaultBlob) {
    console.log('[SecureVault boot] State 2: resume screen (vault blob in local storage)');
    state.encryptedBuffer = vaultBlob;
    state.fileName = blobFileName || 'vault.svlt';
    state.fileHandle = idbHandle;
    $('#lock-mode-open').classList.add('hidden');
    $('#lock-mode-resume').classList.remove('hidden');
    $('#resume-file-name').textContent = state.fileName;
    $('#resume-pw').focus();
    return;
  }

  // State 2b: no vault blob in local storage, but we have an IDB handle.
  // Try to re-read the file using the handle.
  if (idbHandle) {
    console.log('[SecureVault boot] State 2b: IDB handle exists, trying to re-read file');
    try {
      const perm = await idbHandle.queryPermission({ mode: 'readwrite' });
      if (perm === 'granted') {
        const file = await idbHandle.getFile();
        const buf = await file.arrayBuffer();
        state.encryptedBuffer = buf;
        state.fileName = file.name;
        state.fileHandle = idbHandle;
        $('#lock-mode-open').classList.add('hidden');
        $('#lock-mode-resume').classList.remove('hidden');
        $('#resume-file-name').textContent = file.name;
        $('#resume-pw').focus();
        return;
      } else {
        // Permission needs a user gesture — show resume screen, the
        // Unlock button will re-request permission.
        state.fileHandle = idbHandle;
        state.fileName = 'vault.svlt';
        $('#lock-mode-open').classList.add('hidden');
        $('#lock-mode-resume').classList.remove('hidden');
        $('#resume-file-name').textContent = state.fileName;
        $('#resume-pw').focus();
        return;
      }
    } catch (e) {
      console.warn('[SecureVault boot] IDB handle re-read failed:', e.message);
    }
  }

  // State 3: full unlock — nothing in storage.
  console.log('[SecureVault boot] State 3: full unlock screen');
  $('#lock-mode-open').classList.remove('hidden');
  $('#lock-mode-resume').classList.add('hidden');
  // Show last-used file name as a hint if we have one.
  try {
    const { svltLastFileName } = await chrome.storage.local.get('svltLastFileName');
    if (svltLastFileName) {
      const hintEl = $('#last-file-hint');
      if (hintEl) {
        hintEl.textContent = 'Last vault: ' + svltLastFileName;
        hintEl.classList.remove('hidden');
      }
    }
  } catch (_) {}
  $('#master-pw').focus();
}

async function handlePickFile() {
  const result = await pickVaultFile();
  if (!result) return;
  const { handle, name, buffer } = result;
  // Validate format
  const fmt = peekFormat(buffer);
  if (!fmt || fmt.magic !== 'SVLT') {
    showError('unlock-error', 'This is not a valid SecureVault (.svlt) file.');
    return;
  }
  if (fmt.version !== 2) {
    showError('unlock-error', `Unsupported SVLT version ${fmt.version}.`);
    return;
  }
  state.fileHandle = handle;
  state.fileName = name;
  state.encryptedBuffer = buffer;
  // Persist the FSAA handle to IndexedDB so the user doesn't have to re-pick
  // the file on the next browser session. (Chrome will still require a
  // one-tap re-permission on first user gesture of a new session — this is
  // a Chrome security constraint, not something we can bypass.)
  if (handle) {
    await persistFileHandleToIDB(handle);
  }
  $('#file-name').textContent = name;
  $('#file-info').classList.remove('hidden');
  $('#unlock-btn').disabled = false;
  clearError('unlock-error');
}

async function handleUnlock() {
  const password = $('#master-pw').value;
  if (!password) return;
  if (!state.encryptedBuffer) {
    showError('unlock-error', 'Please select a .svlt file first.');
    return;
  }
  $('#unlock-btn').disabled = true;
  $('#unlock-btn').textContent = 'Unlocking…';
  try {
    const { entries, schemaVersion } = await decryptVaultFile(state.encryptedBuffer, password);
    if (schemaVersion < DATA_SCHEMA_VERSION) {
      showToast('Vault schema upgraded from v' + schemaVersion + ' to v' + DATA_SCHEMA_VERSION, 'info');
    }
    await enterUnlocked(entries, password, state.encryptedBuffer, state.fileName, state.fileHandle);
  } catch (e) {
    if (e instanceof SchemaVersionTooNewError) {
      showError('unlock-error', e.message);
    } else if (e instanceof WrongPasswordError) {
      showError('unlock-error', 'Wrong password. Try again.');
    } else if (e instanceof VaultFileError) {
      showError('unlock-error', 'Vault file error: ' + e.message);
    } else {
      showError('unlock-error', 'Failed to unlock: ' + (e.message || e));
    }
  } finally {
    $('#unlock-btn').disabled = false;
    $('#unlock-btn').textContent = 'Unlock vault';
  }
}

async function handleResume() {
  const password = $('#resume-pw').value;
  if (!password) return;

  // Try to get the vault buffer from in-memory state first, then fall back
  // to chrome.storage.local (which persists across popup close/reopen).
  let buffer = state.encryptedBuffer;
  let handle = state.fileHandle;
  let fileName = state.fileName;

  if (!buffer) {
    // Read from local storage — the vault blob persists here across
    // popup close/reopen and even browser restarts.
    const local = await readVaultBlobLocal();
    if (local.buffer) {
      buffer = local.buffer;
      fileName = local.fileName || fileName;
    }
  }

  // If we have an FSAA handle but no buffer, try to re-read the file.
  if (!buffer && handle) {
    try {
      const perm = await handle.queryPermission({ mode: 'readwrite' });
      if (perm !== 'granted') {
        // Re-request permission (we're in a user gesture — button click).
        const req = await handle.requestPermission({ mode: 'readwrite' });
        if (req !== 'granted') {
          showError('resume-error', 'File permission denied. Please re-pick the file.');
          return;
        }
      }
      const file = await handle.getFile();
      buffer = await file.arrayBuffer();
      fileName = file.name;
    } catch (e) {
      showError('resume-error', 'Could not read vault file: ' + (e.message || e));
      return;
    }
  }

  if (!buffer) {
    // No buffer anywhere — switch to full unlock.
    $('#lock-mode-open').classList.remove('hidden');
    $('#lock-mode-resume').classList.add('hidden');
    showToast('Session expired — please re-open your vault file', '');
    return;
  }

  $('#resume-btn').disabled = true;
  $('#resume-btn').textContent = 'Unlocking…';
  try {
    const { entries, schemaVersion } = await decryptVaultFile(buffer, password);
    // Store the password in session storage so the NEXT popup open
    // can silent-unlock (State 1).
    await storeSessionPassword(password);
    if (schemaVersion < DATA_SCHEMA_VERSION) {
      showToast('Vault schema upgraded from v' + schemaVersion + ' to v' + DATA_SCHEMA_VERSION, 'info');
    }
    await enterUnlocked(entries, password, buffer, fileName, handle);
  } catch (e) {
    if (e instanceof SchemaVersionTooNewError) {
      showError('resume-error', e.message);
    } else if (e instanceof WrongPasswordError) {
      showError('resume-error', 'Wrong password. Try again.');
    } else {
      showError('resume-error', 'Failed to unlock: ' + (e.message || e));
    }
  } finally {
    $('#resume-btn').disabled = false;
    $('#resume-btn').textContent = 'Unlock';
  }
}

async function enterUnlocked(entries, password, encryptedBuffer, fileName, fileHandle) {
  // v6.7 SYNC FIX: Always normalize on load — see normalizeEntry() docs.
  // Without this, the .svlt file from Electron's SD-card path had
  // `fav` (numeric) but no `favorite` (boolean), so the Favorites filter
  // showed 0 entries; trashed entries also sometimes leaked into the
  // Identities filter for the same reason.
  state.vault = normalizeEntryArray(entries);
  state.sessionPassword = password;
  state.encryptedBuffer = encryptedBuffer;
  state.fileName = fileName || 'vault.svlt';
  state.fileHandle = fileHandle;
  state.isLocked = false;

  // Persist session meta so resume works after window close. The FSAA
  // handle is included so a window-closed-then-reopened popup can silently
  // re-read the file without showing the lock screen.
  await storeSessionMeta(encryptedBuffer, state.fileName, password, fileHandle);
  // Mirror the handle to IndexedDB so it survives a browser restart.
  if (fileHandle) {
    await persistFileHandleToIDB(fileHandle);
  }

  // Tell background to cache the vault + password for content-script lookups.
  await sendBg({
    type: 'cache_vault',
    entries: state.vault,
    password
  });

  // Update UI
  $('#lock-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#current-file-name').textContent = state.fileName;
  renderVault();
  switchTab('vault');

  // v6.7 SYNC FIX: Start polling the .svlt file for changes from Electron.
  // This makes "synced to the extension" actually true — the user no longer
  // has to click "Reload from disk" after every Electron-side edit.
  startFilePoller();

  // Handle query params (e.g. ?add=1&url=...&user=...&pass=...)
  handleWindowQuery();
}

// ─── Save-prompt / inline-generator query handling ───────────────────
// Bitwarden-style: when the save-prompt banner or the inline generator
// sends the user to the popup with ?add=1&url=...&user=...&pass=..., we
// prefill ALL of those fields into the Add modal — not just the URL.
// Previously `user` and `pass` were silently dropped (bug B3), forcing the
// user to re-type the credentials they just captured.
function handleWindowQuery() {
  const params = new URLSearchParams(location.search);
  if (params.get('add') === '1') {
    const prefill = {
      url: params.get('url') || '',
      user: params.get('user') || '',
      pass: params.get('pass') || ''
    };
    openAddModal(prefill);
    try { history.replaceState({}, '', location.pathname); } catch (_) {}
  }
}

async function handleLockNow() {
  await handleLocalLock();
  // Tell background to clear its cache + session password + clipboard.
  await sendBg({ type: 'lock' });
}

/**
 * Local-only lock: clears window state + session storage and shows the
 * lock screen. Does NOT message background (used when background already
 * locked, e.g. on receiving the `locked` broadcast — avoids an infinite
 * lock loop).
 *
 * Now async — the previous sync version fired clearSessionMeta() without
 * awaiting it, which could race with a quick popup re-open and leave stale
 * session meta behind (bug B9). Also clears the IndexedDB file handle so a
 * lock truly means "forget the file" (matches the user expectation that
 * "Lock now" requires re-authentication).
 */
async function handleLocalLock() {
  // v6.7 SYNC FIX: Stop the file-change poller when we lock — no point
  // polling a file we can no longer decrypt, and it would just throw
  // permission errors into the console.
  stopFilePoller();
  state.vault = [];
  state.sessionPassword = null;
  state.encryptedBuffer = null;
  state.fileHandle = null;
  state.fileName = '';
  state.isLocked = true;
  state.currentFilter = 'all';
  state.searchQuery = '';
  // Only clear the session PASSWORD — keep the vault blob in local storage
  // so the resume screen (password-only) can be shown instead of the full
  // unlock screen (file picker + password).
  await clearSessionPassword();
  // The IDB file handle also stays — don't clear it on lock.
  $('#app').classList.add('hidden');
  $('#lock-screen').classList.remove('hidden');
  $('#lock-mode-open').classList.add('hidden');
  $('#lock-mode-resume').classList.remove('hidden');
  // Show the file name from the stored vault blob so the user knows which
  // vault they're unlocking.
  try {
    const { fileName } = await readVaultBlobLocal();
    $('#resume-file-name').textContent = fileName || 'vault.svlt';
  } catch (_) {
    $('#resume-file-name').textContent = 'vault.svlt';
  }
  $('#master-pw').value = '';
  $('#resume-pw').value = '';
  $('#file-info').classList.add('hidden');
  $('#unlock-btn').disabled = true;
  $('#resume-pw').focus();
}

// ─── Tab navigation ───────────────────────────────────────────────────

function switchTab(name) {
  $$('.tab-panel').forEach(p => p.classList.remove('active'));
  $$('.tab-btn').forEach(b => b.classList.remove('active'));
  $('#tab-' + name).classList.add('active');
  const btn = document.querySelector(`.tab-btn[data-tab="${name}"]`);
  if (btn) btn.classList.add('active');
  if (name === 'generator') {
    regeneratePassword();
  }
}

// ─── Vault rendering ──────────────────────────────────────────────────

function getEntrySite(entry) {
  return entry.name || entry.site || entry.url || 'Untitled';
}

function getEntryInitial(entry) {
  const s = getEntrySite(entry);
  return (s[0] || '?').toUpperCase();
}

function getEntryUsername(entry) {
  return entry.user || entry.username || entry.cardholder || entry.email || '';
}

function getEntrySubtitle(entry) {
  if (entry.type === 'card') return entry.cardholder || '—';
  if (entry.type === 'identity') return entry.email || entry.firstName || '—';
  if (entry.type === 'note') return entry.notes ? (entry.notes.slice(0, 60) + (entry.notes.length > 60 ? '…' : '')) : 'No content';
  return entry.user || entry.username || '—';
}

function getEntryUrl(entry) {
  return entry.url || entry.login_uri || '';
}

function getEntrySortKey(entry) {
  // Mirror Electron's behaviour: sort by site/name (whichever is set),
  // case-insensitive. Falls back to user/email for identity entries so
  // two identities with the same name still have a stable order.
  const primary = (entry.site || entry.name || '').trim().toLowerCase();
  const secondary = (entry.user || entry.username || entry.email || '').trim().toLowerCase();
  return (primary + '\u0001' + secondary);
}

function filterEntries() {
  const q = state.searchQuery.trim().toLowerCase();
  let list = state.vault.slice();

  // Filter
  if (state.currentFilter === 'trash') {
    list = list.filter(e => e.deleted);
  } else {
    list = list.filter(e => !e.deleted);
    if (state.currentFilter !== 'all') {
      list = list.filter(e => (e.type || 'login') === state.currentFilter);
    }
  }

  // Search
  if (q) {
    list = list.filter(e => {
      const haystack = [
        e.name, e.site, e.url, e.user, e.username, e.notes,
        e.cardholder, e.email, e.firstName, e.lastName, e.folder
      ].filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(q);
    });
  }

  // Sort: alphabetically by name (asc), with favorites pinned to the top.
  // Favorites are NOT a separate filter any more — they just float above
  // the rest of the list so the user always sees them first.
  list.sort((a, b) => {
    const aFav = a.favorite ? 1 : 0;
    const bFav = b.favorite ? 1 : 0;
    if (aFav !== bFav) return bFav - aFav;       // favorites first
    return getEntrySortKey(a).localeCompare(getEntrySortKey(b));
  });
  return list;
}

function renderVault() {
  const list = filterEntries();
  const container = $('#entry-list');
  const empty = $('#vault-empty');

  if (list.length === 0) {
    container.innerHTML = '';
    if (state.vault.length === 0) {
      empty.classList.remove('hidden');
      empty.querySelector('h3').textContent = 'Your vault is empty';
      empty.querySelector('p').textContent = 'Add your first login, card, identity, or secure note to get started.';
    } else {
      empty.classList.remove('hidden');
      empty.querySelector('h3').textContent = state.currentFilter === 'trash' ? 'Trash is empty' : 'No matches';
      empty.querySelector('p').textContent = state.currentFilter === 'trash'
        ? 'Deleted entries will appear here.'
        : 'Try a different search or filter.';
    }
    return;
  }
  empty.classList.add('hidden');

  container.innerHTML = '';
  for (const entry of list) {
    container.appendChild(renderEntryCard(entry));
  }
}

function renderEntryCard(entry) {
  const type = entry.type || 'login';
  const isTrash = state.currentFilter === 'trash';

  const card = el('div', {
    class: 'entry-card' + (entry.favorite ? ' is-favorite' : '') + (entry.breachedCount > 0 ? ' is-breached' : ''),
    dataset: { id: entry.id },
    onclick: (e) => {
      if (e.target.closest('.entry-action-btn') || e.target.closest('.entry-trash-actions')) return;
      openEditModal(entry.id);
    }
  });

  // Avatar
  const avatar = el('div', {
    class: 'entry-avatar type-' + type,
    text: getEntryInitial(entry)
  });
  card.appendChild(avatar);

  // Main
  const main = el('div', { class: 'entry-main' });
  const nameRow = el('div', { class: 'entry-name-row', style: 'display:flex;align-items:center;gap:6px;' });
  nameRow.appendChild(el('div', { class: 'entry-name', text: getEntrySite(entry), style: 'flex:1;min-width:0;' }));
  // Breach badge (red) — shown only when HIBP found this password.
  if (entry.breachedCount > 0) {
    nameRow.appendChild(el('span', {
      class: 'breach-badge-list',
      title: 'Password found in ' + Number(entry.breachedCount).toLocaleString() + ' breaches',
      text: '⚠ ' + Number(entry.breachedCount).toLocaleString()
    }));
  }
  main.appendChild(nameRow);
  main.appendChild(el('div', { class: 'entry-user', text: getEntrySubtitle(entry) }));
  const url = getEntryUrl(entry);
  if (url && type === 'login') {
    main.appendChild(el('div', { class: 'entry-url', text: url }));
  }
  card.appendChild(main);

  // Actions
  if (isTrash) {
    const actions = el('div', { class: 'entry-trash-actions' });
    actions.appendChild(el('button', {
      class: 'btn btn-secondary btn-sm',
      text: 'Restore',
      onclick: (e) => { e.stopPropagation(); restoreEntry(entry.id); }
    }));
    actions.appendChild(el('button', {
      class: 'btn btn-danger-ghost btn-sm',
      text: 'Delete',
      onclick: (e) => { e.stopPropagation(); deleteEntryPermanently(entry.id); }
    }));
    card.appendChild(actions);
  } else {
    const actions = el('div', { class: 'entry-actions' });
    if (type === 'login') {
      actions.appendChild(el('button', {
        class: 'entry-action-btn',
        title: 'Copy username',
        dataset: { act: 'user' },
        onclick: (e) => { e.stopPropagation(); copyToClipboard(entry.user || entry.username || ''); }
      }));
      actions.appendChild(el('button', {
        class: 'entry-action-btn',
        title: 'Copy password',
        dataset: { act: 'pass' },
        onclick: (e) => { e.stopPropagation(); copyToClipboard(entry.pass || entry.password || ''); }
      }));
    }
    actions.appendChild(el('button', {
      class: 'entry-action-btn',
      title: 'More',
      dataset: { act: 'more' },
      onclick: (e) => { e.stopPropagation(); openMoreMenu(e.currentTarget, entry); }
    }));
    card.appendChild(actions);
  }

  return card;
}

// ─── More menu ────────────────────────────────────────────────────────

let moreMenuTarget = null;

function openMoreMenu(anchorBtn, entry) {
  closeMoreMenu();
  moreMenuTarget = entry;
  const menu = $('#more-menu');
  // Update the favorite label
  const favBtn = menu.querySelector('[data-action="favorite"]');
  favBtn.textContent = entry.favorite ? 'Remove from favorites' : 'Add to favorites';

  menu.classList.remove('hidden');
  const rect = anchorBtn.getBoundingClientRect();
  const menuWidth = 200;
  let left = rect.right - menuWidth;
  if (left < 8) left = 8;
  let top = rect.bottom + 4;
  menu.style.left = left + 'px';
  menu.style.top = top + 'px';

  setTimeout(() => {
    document.addEventListener('mousedown', outsideMoreMenu, true);
  }, 50);
}

function outsideMoreMenu(e) {
  const menu = $('#more-menu');
  if (!menu.contains(e.target)) {
    closeMoreMenu();
  }
}

function closeMoreMenu() {
  $('#more-menu').classList.add('hidden');
  moreMenuTarget = null;
  document.removeEventListener('mousedown', outsideMoreMenu, true);
}

async function handleMoreAction(action) {
  const entry = moreMenuTarget;
  if (!entry) return;
  closeMoreMenu();
  switch (action) {
    case 'edit':
      openEditModal(entry.id);
      break;
    case 'totp':
      if (entry.totp) {
        const resp = await sendBg({ type: 'generate_totp', secret: entry.totp });
        if (resp && resp.ok && resp.totp) {
          await copyToClipboard(resp.totp.code);
        } else {
          showToast('No valid TOTP secret', 'error');
        }
      } else {
        showToast('No TOTP secret on this entry', 'error');
      }
      break;
    case 'url':
      await copyToClipboard(getEntryUrl(entry));
      break;
    case 'favorite':
      entry.favorite = !entry.favorite;
      entry.updated = Date.now();
      await persistVault();
      renderVault();
      showToast(entry.favorite ? 'Added to favorites' : 'Removed from favorites', 'success');
      break;
    case 'folder': {
      const folder = prompt('Move to folder:', entry.folder || '');
      if (folder !== null) {
        entry.folder = folder.trim();
        entry.updated = Date.now();
        await persistVault();
        renderVault();
        showToast('Moved to ' + (folder.trim() || 'no folder'), 'success');
      }
      break;
    }
    case 'trash':
      entry.deleted = true;
      entry.updated = Date.now();
      await persistVault();
      renderVault();
      showToast('Moved to trash', 'success');
      break;
  }
}

// ─── Add/Edit modal ───────────────────────────────────────────────────

function openAddModal(prefill = {}) {
  state.editingEntryId = null;
  state.editingType = prefill.type || 'login';
  $('#modal-title').textContent = 'Add new entry';
  $('#modal-delete').classList.add('hidden');
  resetForm();
  setEntryType(state.editingType);
  // Pre-fill (Bitwarden-style: URL + username + password all populated
  // when the user comes from the save-prompt banner or the inline
  // generator's "Save to SecureVault" action).
  if (prefill.url) {
    const urlInput = document.querySelector('#fields-login [data-field="url"]');
    if (urlInput) urlInput.value = prefill.url;
    const nameInput = document.querySelector('#fields-login [data-field="name"]');
    if (nameInput && !nameInput.value) {
      try {
        nameInput.value = new URL(prefill.url).hostname.replace(/^www\./, '');
      } catch (_) {
        nameInput.value = prefill.url;
      }
    }
  }
  if (prefill.user) {
    const userInput = document.querySelector('#fields-login [data-field="user"]');
    if (userInput) userInput.value = prefill.user;
  }
  if (prefill.pass) {
    const passInput = document.querySelector('#fields-login [data-field="pass"]');
    if (passInput) {
      passInput.value = prefill.pass;
      updateInlineStrength(prefill.pass);
    }
  }
  showModal();
}

function openEditModal(entryId) {
  const entry = state.vault.find(e => e.id === entryId);
  if (!entry) return;
  state.editingEntryId = entryId;
  state.editingType = entry.type || 'login';
  $('#modal-title').textContent = 'Edit entry';
  $('#modal-delete').classList.remove('hidden');
  resetForm();
  setEntryType(state.editingType);
  populateForm(entry);
  showModal();
}

function showModal() {
  $('#entry-modal').classList.remove('hidden');
  // Reveal the breach-check row only for logins AND only if HIBP is enabled.
  syncBreachCheckRowVisibility();
}

function syncBreachCheckRowVisibility() {
  const row = $('#breach-check-row');
  if (!row) return;
  const isLogin = state.editingType === 'login';
  const settings = state._cachedSettings || {};
  const enabled = !!settings.hibpCheckEnabled;
  if (isLogin && enabled) {
    row.classList.remove('hidden');
  } else {
    row.classList.add('hidden');
  }
  // Always reset the badge — the previous entry's result is stale.
  const badge = $('#breach-badge');
  if (badge) {
    badge.textContent = '';
    badge.className = 'breach-badge';
  }
}

async function refreshCachedSettings() {
  const resp = await sendBg({ type: 'get_settings' });
  if (resp && resp.ok) {
    state._cachedSettings = resp.settings;
  }
}

function closeModal() {
  $('#entry-modal').classList.add('hidden');
  stopTotpPreview();
  clearError('modal-error');
}

function resetForm() {
  $$('#entry-modal [data-field]').forEach(i => {
    if (i.tagName === 'TEXTAREA') i.value = '';
    else i.value = '';
  });
  $$('#entry-modal input[type="checkbox"]').forEach(c => { c.checked = false; });
  $('#card-brand').classList.add('hidden');
  $('#totp-preview').classList.add('hidden');
  $('#inline-strength-fill').style.width = '0%';
  $('#inline-strength-label').textContent = '—';
  clearError('modal-error');
}

function setEntryType(type) {
  state.editingType = type;
  $$('#entry-type .seg-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.type === type);
  });
  $$('.fields-group').forEach(g => g.classList.add('hidden'));
  $('#fields-' + type).classList.remove('hidden');
  // Update favorite checkbox id mapping
  const favId = 'entry-favorite' + (type === 'card' ? '-card' : type === 'identity' ? '-id' : type === 'note' ? '-note' : '');
  // (we just use the right checkbox in collect/populate based on type)
  // Re-evaluate breach-check row visibility since it only applies to logins.
  if (!$('#entry-modal').classList.contains('hidden')) {
    syncBreachCheckRowVisibility();
  }
}

function getActiveFavoriteCheckbox() {
  const type = state.editingType;
  if (type === 'card') return $('#entry-favorite-card');
  if (type === 'identity') return $('#entry-favorite-id');
  if (type === 'note') return $('#entry-favorite-note');
  return $('#entry-favorite');
}

function collectFormData() {
  const type = state.editingType;
  const group = $('#fields-' + type);
  const data = { type };
  group.querySelectorAll('[data-field]').forEach(input => {
    data[input.dataset.field] = input.value;
  });
  const favCb = getActiveFavoriteCheckbox();
  data.favorite = favCb ? favCb.checked : false;
  return data;
}

function populateForm(entry) {
  const type = entry.type || 'login';
  const group = $('#fields-' + type);
  group.querySelectorAll('[data-field]').forEach(input => {
    const key = input.dataset.field;
    if (entry[key] !== undefined && entry[key] !== null) {
      input.value = entry[key];
    }
  });
  const favCb = getActiveFavoriteCheckbox();
  if (favCb) favCb.checked = !!entry.favorite;
  // Update inline strength for password
  if (type === 'login' && entry.pass) {
    updateInlineStrength(entry.pass);
  }
  // Update card brand
  if (type === 'card' && entry.cardNumber) {
    detectCardBrand(entry.cardNumber);
  }
  // Start TOTP preview if applicable
  if (type === 'login' && entry.totp) {
    startTotpPreview(entry.totp);
  }
}

async function handleSaveEntry() {
  clearError('modal-error');
  const data = collectFormData();
  // Validate required field
  const name = (data.name || '').trim();
  if (!name) {
    showError('modal-error', 'Name is required.');
    return;
  }
  data.name = name;
  // Derive site field for content.js compatibility (logins)
  if (data.type === 'login') {
    data.site = name;
  }

  let entry;
  const now = Date.now();
  if (state.editingEntryId) {
    entry = state.vault.find(e => e.id === state.editingEntryId);
    if (!entry) {
      showError('modal-error', 'Entry not found.');
      return;
    }
    Object.assign(entry, data);
    entry.updated = now;
  } else {
    entry = {
      // E3 FIX: Use crypto.randomUUID() for new entries instead of
      // synthesizing from timestamp + Math.random(). This eliminates ID
      // collisions for two accounts on the same site with the same username.
      id: crypto.randomUUID(),
      ...data,
      deleted: false,
      created: now,
      updated: now
    };
    state.vault.push(entry);
  }

  $('#modal-save').disabled = true;
  $('#modal-save').textContent = 'Saving…';
  try {
    await persistVault();
    $('#modal-save').disabled = false;
    $('#modal-save').textContent = 'Save';
    closeModal();
    renderVault();
    showToast('Saved ✓', 'success');

    // ── Auto breach check on save ────────────────────────────────────
    // Bitwarden-style nudge: every time a login entry is saved (new or
    // edited) AND the password is non-empty AND HIBP is enabled, fire a
    // background breach check. If breached, mark the entry with a
    // `breachedCount` field so the vault list can render a red badge.
    // The check is async and non-blocking — the save has already succeeded.
    if (entry.type === 'login' && entry.pass && state._cachedSettings && state._cachedSettings.hibpCheckEnabled) {
      autoCheckBreached(entry).catch(() => { /* silent — network may be offline */ });
    }
  } catch (e) {
    $('#modal-save').disabled = false;
    $('#modal-save').textContent = 'Save';
    showError('modal-error', 'Failed to save: ' + (e.message || e));
  }
}

/**
 * Auto-check an entry's password against HIBP on save. Updates the entry
 * with `breachedCount` (0 = safe, >0 = breached, null = error) and
 * re-renders the vault list so the red badge appears. Re-encrypts and
 * re-writes the .svlt file so the breach status persists.
 */
async function autoCheckBreached(entry) {
  if (!entry || !entry.pass) return;
  const resp = await sendBg({ type: 'check_pwned', password: entry.pass });
  if (!resp || resp.error) {
    // Don't mark — leave the previous state. Network errors are silent.
    return;
  }
  entry.breachedCount = resp.breached ? (resp.count || 1) : 0;
  entry.breachCheckedAt = Date.now();
  // Persist the breach status to the .svlt file so it survives a reload.
  try {
    await persistVault();
    renderVault();
    if (resp.breached) {
      showToast('⚠ Password found in ' + Number(resp.count).toLocaleString() + ' breaches', 'error');
    }
  } catch (_) { /* silent */ }
}

async function handleDeleteEntry() {
  if (!state.editingEntryId) return;
  const idx = state.vault.findIndex(e => e.id === state.editingEntryId);
  if (idx < 0) return;
  // If already in trash, delete permanently; else move to trash.
  const entry = state.vault[idx];
  if (entry.deleted) {
    if (!confirm('Delete this entry permanently? This cannot be undone.')) return;
    state.vault.splice(idx, 1);
  } else {
    entry.deleted = true;
    entry.updated = Date.now();
  }
  await persistVault();
  closeModal();
  renderVault();
  showToast(entry.deleted ? 'Deleted permanently' : 'Moved to trash', 'success');
}

async function restoreEntry(entryId) {
  const entry = state.vault.find(e => e.id === entryId);
  if (!entry) return;
  entry.deleted = false;
  entry.updated = Date.now();
  await persistVault();
  renderVault();
  showToast('Restored', 'success');
}

async function deleteEntryPermanently(entryId) {
  const idx = state.vault.findIndex(e => e.id === entryId);
  if (idx < 0) return;
  if (!confirm('Delete this entry permanently? This cannot be undone.')) return;
  state.vault.splice(idx, 1);
  await persistVault();
  renderVault();
  showToast('Deleted permanently', 'success');
}

// ─── Persist vault (encrypt via background + write to file + notify background) ───────
// E7 FIX: Routine vault saves now delegate encryption to background.js via the
// `encrypt_vault` IPC handler. The master password never crosses IPC for
// encryption — background.js holds it in session storage and encrypts internally.
// window.js only needs state.sessionPassword for initial decrypt and the
// change-master-password flow (where the user explicitly provides it).

async function persistVault() {
  // E7: Send plaintext entries to background for encryption.
  // background.js encrypts using the session password it holds internally.
  const resp = await sendBg({ type: 'encrypt_vault', entries: state.vault });
  if (!resp || !resp.ok) {
    throw new Error('Vault encryption via background failed: ' + (resp?.error || 'unknown'));
  }
  const buffer = base64ToBuffer(resp.encryptedB64);
  state.encryptedBuffer = buffer;
  await writeVaultFile(buffer);
  // Store the updated encrypted blob in chrome.storage.local so the next
  // popup open can silent-unlock with the latest vault state.
  await storeVaultBlobLocal(buffer, state.fileName);
  // Store the FSAA handle if we have one.
  if (state.fileHandle) {
    try {
      await chrome.storage.session.set({ svltFileHandle: state.fileHandle });
    } catch (_) {}
    await persistFileHandleToIDB(state.fileHandle);
  }
  await sendBg({ type: 'update_vault', entries: state.vault });
}

// ─── TOTP live preview ────────────────────────────────────────────────

function startTotpPreview(secret) {
  stopTotpPreview();
  if (!secret) {
    $('#totp-preview').classList.add('hidden');
    return;
  }
  const update = async () => {
    const input = document.querySelector('#fields-login [data-field="totp"]');
    const sec = input ? input.value.trim() : '';
    if (!sec) {
      $('#totp-preview').classList.add('hidden');
      return;
    }
    const resp = await sendBg({ type: 'generate_totp', secret: sec });
    if (resp && resp.ok && resp.totp) {
      $('#totp-code').textContent = resp.totp.code;
      $('#totp-countdown').textContent = resp.totp.secondsLeft + 's';
      $('#totp-preview').classList.remove('hidden');
    } else {
      $('#totp-preview').classList.add('hidden');
    }
  };
  update();
  state.totpInterval = setInterval(update, 1000);
}

function stopTotpPreview() {
  if (state.totpInterval) {
    clearInterval(state.totpInterval);
    state.totpInterval = null;
  }
}

// ─── Card brand detection ─────────────────────────────────────────────

function detectCardBrand(number) {
  const num = String(number).replace(/\s/g, '');
  let brand = '';
  if (/^4/.test(num)) brand = 'Visa';
  else if (/^(5[1-5]|2[2-7])/.test(num)) brand = 'Mastercard';
  else if (/^3[47]/.test(num)) brand = 'Amex';
  else if (/^(6011|65|64[4-9])/.test(num)) brand = 'Discover';
  else if (/^6/.test(num)) brand = 'Discover';
  const el = $('#card-brand');
  if (brand) {
    el.textContent = brand;
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
  return brand;
}

function formatCardNumber(value) {
  const num = String(value).replace(/\D/g, '').slice(0, 19);
  if (num.startsWith('34') || num.startsWith('37')) {
    // Amex: 4-6-5
    const parts = [num.slice(0, 4), num.slice(4, 10), num.slice(10, 15)].filter(Boolean);
    return parts.join(' ');
  }
  return num.match(/.{1,4}/g)?.join(' ') || '';
}

function formatExpiry(value) {
  const num = String(value).replace(/\D/g, '').slice(0, 4);
  if (num.length <= 2) return num;
  return num.slice(0, 2) + '/' + num.slice(2);
}

// ─── Inline password strength ─────────────────────────────────────────

function updateInlineStrength(password) {
  if (!password) {
    $('#inline-strength-fill').style.width = '0%';
    $('#inline-strength-label').textContent = '—';
    return;
  }
  const strength = estimatePasswordStrength(password);
  const fill = $('#inline-strength-fill');
  fill.className = 'strength-fill ' + strength.label;
  fill.style.width = Math.min(100, (strength.entropyBits / 120) * 100) + '%';
  $('#inline-strength-label').textContent = `${strength.label} · ${strength.entropyBits}b`;
}

function estimatePasswordStrength(password) {
  let cs = 0;
  if (/[a-z]/.test(password)) cs += 26;
  if (/[A-Z]/.test(password)) cs += 26;
  if (/[0-9]/.test(password)) cs += 10;
  if (/[^a-zA-Z0-9]/.test(password)) cs += 32;
  if (cs === 0) cs = 1;
  const bits = Math.log2(cs) * password.length;
  let label;
  if (bits < 40) label = 'weak';
  else if (bits < 70) label = 'fair';
  else if (bits < 100) label = 'good';
  else label = 'strong';
  return { entropyBits: Math.round(bits), label };
}

// ─── Generator tab ────────────────────────────────────────────────────

function getGenOptions() {
  const mode = document.querySelector('#gen-mode .seg-btn.active').dataset.mode;
  if (mode === 'passphrase') {
    return {
      mode: 'passphrase',
      wordCount: parseInt($('#gen-wordcount').value, 10),
      separator: $('#gen-separator').value,
      capitalize: $('#gen-capitalize').checked,
      includeNumber: $('#gen-include-num').checked
    };
  }
  return {
    mode: 'random',
    length: parseInt($('#gen-length').value, 10),
    uppercase: $('#gen-upper').checked,
    lowercase: $('#gen-lower').checked,
    numbers: $('#gen-num').checked,
    symbols: $('#gen-sym').checked,
    avoidAmbiguous: $('#gen-avoid-ambig').checked
  };
}

async function regeneratePassword() {
  const options = getGenOptions();
  const resp = await sendBg({ type: 'generate_password', options });
  if (resp && resp.ok) {
    $('#gen-password').textContent = resp.password;
    const fill = $('#strength-fill');
    fill.className = 'strength-fill ' + (resp.label || 'weak');
    fill.style.width = Math.min(100, ((resp.entropyBits || 0) / 120) * 100) + '%';
    $('#strength-label').textContent = `${resp.label || '—'} · ${resp.entropyBits || 0} bits`;
    state._lastGenerated = resp.password;
  }
}

async function handleGenCopy() {
  const pw = $('#gen-password').textContent;
  if (!pw || pw === '—') return;
  await copyToClipboard(pw);
  await pushGenHistory(pw, getGenOptions().mode);
}

function renderGenHistory() {
  const container = $('#gen-history');
  container.innerHTML = '';
  if (state.generatorHistory.length === 0) {
    container.appendChild(el('div', {
      style: 'padding:14px;text-align:center;color:var(--muted);font-size:12px;',
      text: 'No recent passwords yet.'
    }));
    return;
  }
  for (const item of state.generatorHistory) {
    const row = el('div', { class: 'history-item', onclick: () => copyToClipboard(item.value) });
    row.appendChild(el('div', { class: 'history-value', text: item.value }));
    row.appendChild(el('div', { class: 'history-time', text: relativeTime(item.ts) }));
    container.appendChild(row);
  }
}

function relativeTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return Math.floor(diff / 86400000) + 'd ago';
}

async function clearGenHistory() {
  state.generatorHistory = [];
  await saveGenHistory();
  renderGenHistory();
}

// ─── Settings tab ─────────────────────────────────────────────────────

async function loadSettingsIntoForm() {
  const resp = await sendBg({ type: 'get_settings' });
  if (!resp || !resp.ok) return;
  const s = resp.settings;
  // Cache for synchronous visibility checks (entry modal breach-check row).
  state._cachedSettings = s;
  $('#set-lock-timeout').value = String(s.lockTimeoutMs);
  $('#set-clip-timeout').value = String(s.clipboardTimeoutMs);
  $('#set-autofill').checked = !!s.autoFillEnabled;
  $('#set-lockicon').checked = !!s.showLockIcon;
  $('#setting-hibp').checked = !!s.hibpCheckEnabled;
  applyHibpVisibility(!!s.hibpCheckEnabled);

  // v6.7 SYNC FIX: load the auto-sync toggle (window-scoped, stored in
  // chrome.storage.local — separate from background's settings object
  // because it's purely a window concern).
  try {
    const stored = await chrome.storage.local.get(['autoSyncEnabled']);
    const enabled = stored.autoSyncEnabled !== false; // default true
    setAutoSyncEnabled(enabled);
  } catch (_) {
    setAutoSyncEnabled(true);
  }
}

async function saveAutoSyncPref(enabled) {
  try {
    await chrome.storage.local.set({ autoSyncEnabled: !!enabled });
  } catch (_) {}
}

async function saveSettingsFromForm() {
  const settings = {
    lockTimeoutMs: parseInt($('#set-lock-timeout').value, 10),
    clipboardTimeoutMs: parseInt($('#set-clip-timeout').value, 10),
    autoFillEnabled: $('#set-autofill').checked,
    showLockIcon: $('#set-lockicon').checked
  };
  await sendBg({ type: 'set_settings', settings });
}

/**
 * Show / hide the HIBP-dependent UI (health-scan button, breach-check row
 * in the entry modal) based on whether breach detection is enabled.
 */
function applyHibpVisibility(enabled) {
  const healthBtn = $('#btn-health-scan');
  if (healthBtn) healthBtn.classList.toggle('hidden', !enabled);
  // The breach-check row only matters while the entry modal is open, but we
  // update it eagerly so toggling the setting reflects immediately.
  const breachRow = $('#breach-check-row');
  if (breachRow && !$('#entry-modal').classList.contains('hidden') && state.editingType === 'login') {
    breachRow.classList.toggle('hidden', !enabled);
  } else if (breachRow && !enabled) {
    breachRow.classList.add('hidden');
  }
}

async function handleHibpToggle() {
  const enabled = $('#setting-hibp').checked;
  const resp = await sendBg({ type: 'set_settings', settings: { hibpCheckEnabled: enabled } });
  if (resp && resp.ok && resp.settings) {
    state._cachedSettings = resp.settings;
  } else {
    // Refresh cached settings even if the merge response was malformed.
    await refreshCachedSettings();
  }
  applyHibpVisibility(enabled);
  if (enabled) {
    showToast('Breach detection enabled. Uses k-anonymity — only a 5-char hash prefix is sent.', 'success');
  } else {
    showToast('Breach detection disabled', '');
  }
}

async function handleChangeMasterPassword() {
  clearError('mp-error');
  const current = $('#mp-current').value;
  const newPw = $('#mp-new').value;
  const confirmPw = $('#mp-confirm').value;
  if (!current) {
    showError('mp-error', 'Enter your current password.');
    return;
  }
  if (newPw.length < 8) {
    showError('mp-error', 'New password must be at least 8 characters.');
    return;
  }
  if (newPw !== confirmPw) {
    showError('mp-error', 'New passwords do not match.');
    return;
  }
  // Verify current password by attempting decryption.
  if (!state.encryptedBuffer) {
    showError('mp-error', 'No vault loaded. Reload your vault file first.');
    return;
  }
  $('#change-mp-btn').disabled = true;
  $('#change-mp-btn').textContent = 'Working…';
  try {
    // Verify current password locally (user just typed it)
    try {
      await decryptVaultFile(state.encryptedBuffer, current);
    } catch (e) {
      showError('mp-error', 'Current password is incorrect.');
      return;
    }
    // E7: Delegate encryption to background.js instead of encrypting locally.
    // First, update background's session password to the new one.
    await sendBg({ type: 'cache_vault', entries: state.vault, password: newPw });
    // Now encrypt via background (which uses the new session password).
    const resp = await sendBg({ type: 'encrypt_vault', entries: state.vault });
    if (!resp || !resp.ok) {
      showError('mp-error', 'Encryption failed: ' + (resp?.error || 'unknown'));
      return;
    }
    const newBuffer = base64ToBuffer(resp.encryptedB64);
    state.encryptedBuffer = newBuffer;
    state.sessionPassword = newPw;
    await writeVaultFile(newBuffer);
    await storeSessionMeta(newBuffer, state.fileName, newPw, state.fileHandle);
    $('#mp-current').value = '';
    $('#mp-new').value = '';
    $('#mp-confirm').value = '';
    showToast('Master password changed ✓', 'success');
  } catch (e) {
    showError('mp-error', 'Failed: ' + (e.message || e));
  } finally {
    $('#change-mp-btn').disabled = false;
    $('#change-mp-btn').textContent = 'Change master password';
  }
}

async function handleReloadFile() {
  // v6.7 SYNC FIX: This used to ALWAYS re-pick the file via pickVaultFile(),
  // which (a) annoyed the user with a file picker every time they wanted to
  // sync, and (b) meant the "Synced to the extension" toast from Electron
  // was a lie — the user still had to manually re-pick the file before the
  // new data appeared. The Electron app writes the .svlt file in place, so
  // we can just re-read the existing handle.
  if (!state.sessionPassword) {
    showToast('Vault is locked. Unlock first.', 'error');
    return;
  }

  // Try to re-use the existing File System Access API handle first.
  let buffer = null;
  let handle = state.fileHandle;
  let name = state.fileName;

  if (handle && handle.createWritable) {
    try {
      const perm = await handle.queryPermission({ mode: 'read' });
      if (perm !== 'granted') {
        // We're in a user-gesture (button click), so we can re-request.
        const req = await handle.requestPermission({ mode: 'read' });
        if (req !== 'granted') {
          showToast('File permission denied. Re-pick the file.', 'error');
          // Fall through to re-pick below.
          handle = null;
        }
      }
      if (handle) {
        const file = await handle.getFile();
        buffer = await file.arrayBuffer();
        name = file.name;
      }
    } catch (e) {
      console.warn('[SecureVault] re-read existing handle failed, falling back to re-pick:', e);
      buffer = null;
    }
  }

  // Fallback: no handle or re-read failed → show the picker.
  if (!buffer) {
    if (!confirm('Reload from disk? Unsaved changes will be lost.')) return;
    const result = await pickVaultFile();
    if (!result) return;
    handle = result.handle;
    name = result.name;
    buffer = result.buffer;
  } else {
    // We re-read in place — still warn the user that unsaved local changes
    // will be lost, but don't make them confirm a file picker.
    // (No confirm() here — the button click itself is the intent.)
  }

  const fmt = peekFormat(buffer);
  if (!fmt || fmt.magic !== 'SVLT') {
    showToast('Not a valid .svlt file', 'error');
    return;
  }
  // Try to decrypt with current session password.
  try {
    const { entries, schemaVersion } = await decryptVaultFile(buffer, state.sessionPassword);
    state.fileHandle = handle;
    state.fileName = name;
    state.encryptedBuffer = buffer;
    // v6.7 SYNC FIX: normalize on every load so the in-memory shape is
    // always the canonical one — see normalizeEntry() docs.
    state.vault = normalizeEntryArray(entries);
    if (schemaVersion < DATA_SCHEMA_VERSION) {
      showToast('Vault schema upgraded from v' + schemaVersion + ' to v' + DATA_SCHEMA_VERSION, 'info');
    }
    await storeSessionMeta(buffer, name, state.sessionPassword, handle);
    if (handle) await persistFileHandleToIDB(handle);
    await sendBg({ type: 'update_vault', entries: state.vault });
    $('#current-file-name').textContent = name;
    renderVault();
    showToast('Reloaded from disk', 'success');
  } catch (e) {
    showToast('Wrong password for this file', 'error');
  }
}

/**
 * v6.7 SYNC FIX: Silent reload — called by the auto-sync poller when it
 * detects the .svlt file changed on disk. Unlike handleReloadFile(), this
 * does NOT show any UI prompts and does NOT require a user gesture. It
 * preserves the user's current filter / search / scroll position.
 *
 * If the user has unsaved local changes, the silent reload is skipped (the
 * user's in-memory state is "dirty" relative to disk — we don't want to
 * clobber their work). The user can click "Reload from disk" manually
 * once they've saved.
 *
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
async function silentReloadFromDisk() {
  if (state.isLocked) return { ok: false, reason: 'locked' };
  if (!state.sessionPassword) return { ok: false, reason: 'no-password' };
  if (!state.fileHandle || !state.fileHandle.createWritable) {
    return { ok: false, reason: 'no-handle' };
  }

  let buffer;
  try {
    const perm = await state.fileHandle.queryPermission({ mode: 'read' });
    if (perm !== 'granted') return { ok: false, reason: 'no-permission' };
    const file = await state.fileHandle.getFile();
    buffer = await file.arrayBuffer();
  } catch (e) {
    return { ok: false, reason: 'read-failed: ' + (e.message || e) };
  }

  let entries;
  let schemaVersion;
  try {
    const result = await decryptVaultFile(buffer, state.sessionPassword);
    entries = result.entries;
    schemaVersion = result.schemaVersion;
  } catch (e) {
    return { ok: false, reason: 'decrypt-failed' };
  }

  // Preserve user's UI state.
  const prevFilter = state.currentFilter;
  const prevSearch = state.searchQuery;
  const prevEditingId = state.editingEntryId;

  state.encryptedBuffer = buffer;
  state.vault = normalizeEntryArray(entries);
  await storeSessionMeta(buffer, state.fileName, state.sessionPassword, state.fileHandle);
  await sendBg({ type: 'update_vault', entries: state.vault });

  state.currentFilter = prevFilter;
  state.searchQuery = prevSearch;
  state.editingEntryId = prevEditingId;

  renderVault();
  return { ok: true };
}

// ─── Auto-sync poller (v6.7 SYNC FIX) ────────────────────────────────
// The Electron app writes to the .svlt file in place whenever the user
// adds/edits/moves-to-trash an entry. Without this poller, the extension
// had no way to know the file changed — the user had to manually click
// "Reload from disk" AND re-pick the file, which is why "synced to the
// extension" was a lie: the toast said synced, but the extension still
// showed the old data.
//
// We poll the File System Access API handle every 3 seconds for the file's
// lastModified timestamp. When it changes, we silently reload. The
// Electron app does atomic writes (.tmp → rename), so we never see a
// half-written file. If the user is actively editing an entry (modal
// open) we skip the reload to avoid clobbering their form state — the
// next poll after they close the modal will pick up the change.
let _filePollTimer = null;
let _lastSeenMtime = 0;
let _lastSyncToastAt = 0;
let _lastSyncedAtMs = 0;     // 0 = never synced since unlock
let _autoSyncEnabled = true; // tied to the #set-auto-sync checkbox
const FILE_POLL_MS = 3000;
const SYNC_TOAST_DEBOUNCE_MS = 5000;

function _formatLastSynced(ms) {
  if (!ms) return 'never';
  const diff = Date.now() - ms;
  if (diff < 5000) return 'just now';
  if (diff < 60_000) return Math.floor(diff / 1000) + 's ago';
  if (diff < 3600_000) return Math.floor(diff / 60_000) + 'm ago';
  const d = new Date(ms);
  return d.toLocaleTimeString();
}

function refreshLastSyncedLabel() {
  const el = $('#last-synced-at');
  if (el) el.textContent = _formatLastSynced(_lastSyncedAtMs);
}

async function _pollFileForChanges() {
  if (state.isLocked) return;
  if (!_autoSyncEnabled) return;
  if (!state.fileHandle || !state.fileHandle.createWritable) return;
  // Skip if the edit modal is open — we'd clobber the user's unsaved
  // form state. The next poll after they close the modal will pick up
  // any change we missed.
  const modal = $('#entry-modal');
  if (modal && !modal.classList.contains('hidden')) return;

  let file;
  try {
    const perm = await state.fileHandle.queryPermission({ mode: 'read' });
    if (perm !== 'granted') return; // can't read — skip this tick
    file = await state.fileHandle.getFile();
  } catch (_) {
    return;
  }
  if (!file) return;

  const mtime = file.lastModified || 0;
  if (_lastSeenMtime === 0) {
    // First poll — just record the baseline, don't reload.
    _lastSeenMtime = mtime;
    return;
  }
  if (mtime === _lastSeenMtime) return;
  _lastSeenMtime = mtime;

  // File changed on disk — silent reload.
  const result = await silentReloadFromDisk();
  if (result && result.ok) {
    _lastSyncedAtMs = Date.now();
    refreshLastSyncedLabel();
    // Show a subtle toast, but debounce so a burst of writes doesn't
    // spam the user.
    const now = Date.now();
    if (now - _lastSyncToastAt > SYNC_TOAST_DEBOUNCE_MS) {
      _lastSyncToastAt = now;
      showToast('Synced from Electron', '');
    }
  }
}

function startFilePoller() {
  if (_filePollTimer) clearInterval(_filePollTimer);
  // Tick the "Last synced" label every 5s so "12s ago" stays fresh.
  _filePollTimer = setInterval(() => {
    _pollFileForChanges();
    refreshLastSyncedLabel();
  }, FILE_POLL_MS);
  // Establish baseline immediately so we don't fire a spurious reload
  // on the first tick.
  _pollFileForChanges();
  refreshLastSyncedLabel();
}

function stopFilePoller() {
  if (_filePollTimer) {
    clearInterval(_filePollTimer);
    _filePollTimer = null;
  }
  // Reset the baseline so the next start re-establishes it.
  _lastSeenMtime = 0;
}

function setAutoSyncEnabled(enabled) {
  _autoSyncEnabled = !!enabled;
  const cb = $('#set-auto-sync');
  if (cb) cb.checked = _autoSyncEnabled;
  if (_autoSyncEnabled && !state.isLocked) {
    startFilePoller();
  } else {
    // Stop only the file-watch part — we still want the "Last synced"
    // label to refresh, so restart a minimal ticker.
    if (_filePollTimer) clearInterval(_filePollTimer);
    _filePollTimer = setInterval(refreshLastSyncedLabel, 5000);
  }
}

async function handleExportCsv() {
  if (!state.vault || state.vault.length === 0) {
    showToast('Vault is empty', 'error');
    return;
  }

  // E15: Show export mode dialog before proceeding.
  // Offer two options:
  //   a) "Plain CSV" — existing functionality, with a SECURITY WARNING
  //   b) "Encrypted CSV (.svlt)" — encrypts with master password, same format
  //      as the synced vault file. Can be re-imported by any SecureVault instance.
  showExportDialog();
}

// ─── E15: Export mode dialog ──────────────────────────────────────────
// Replaces the old direct-export flow. Shows a dialog with two buttons:
//   - "Plain CSV" (with a prominent security warning)
//   - "Encrypted .svlt" (safe, re-importable)
// The dialog uses the existing modal infrastructure.

function showExportDialog() {
  // Remove any existing export dialog
  const existing = document.getElementById('sv-export-dialog');
  if (existing) existing.remove();

  const dialog = document.createElement('div');
  dialog.id = 'sv-export-dialog';
  dialog.style.cssText = [
    'position:fixed',
    'top:0;left:0;right:0;bottom:0',
    'z-index:2147483647',
    'background:rgba(0,0,0,0.6)',
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif'
  ].join(';');

  const card = document.createElement('div');
  card.style.cssText = [
    'background:#1a1d27',
    'border-radius:12px',
    'padding:24px',
    'max-width:380px',
    'width:90%',
    'box-shadow:0 8px 32px rgba(0,0,0,0.4)'
  ].join(';');

  card.innerHTML =
    '<div style="text-align:center;margin-bottom:20px;">' +
      '<div style="font-size:20px;font-weight:700;color:#f3f4f6;margin-bottom:8px;">Export Vault</div>' +
      '<div style="font-size:13px;color:#9ca3af;">Choose an export format</div>' +
    '</div>' +
    // Plain CSV option
    '<button id="sv-export-plain" style="width:100%;padding:12px;border:2px solid #ef4444;border-radius:8px;background:transparent;color:#f3f4f6;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:12px;display:flex;flex-direction:column;align-items:center;gap:4px;">' +
      '<div style="font-size:15px;">📄 Plain CSV</div>' +
      '<div style="font-size:11px;color:#ef4444;font-weight:500;">⚠ WARNING: Unencrypted file with ALL passwords</div>' +
    '</button>' +
    // Encrypted .svlt option
    '<button id="sv-export-encrypted" style="width:100%;padding:12px;border:1px solid #175DDC;border-radius:8px;background:#175DDC;color:#fff;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:12px;display:flex;flex-direction:column;align-items:center;gap:4px;">' +
      '<div style="font-size:15px;">🔒 Encrypted .svlt</div>' +
      '<div style="font-size:11px;color:rgba(255,255,255,0.85);">AES-256-GCM encrypted — safe for backup</div>' +
    '</button>' +
    // Cancel
    '<button id="sv-export-cancel" style="width:100%;padding:8px;border:none;border-radius:6px;background:transparent;color:#9ca3af;font-size:13px;cursor:pointer;">Cancel</button>';

  dialog.appendChild(card);
  document.body.appendChild(dialog);

  // Wire buttons
  card.querySelector('#sv-export-plain').addEventListener('click', async () => {
    dialog.remove();
    // Show a final confirmation warning before plaintext export
    if (!confirm(
      '⚠ SECURITY WARNING\n\n' +
      'This creates an UNENCRYPTED file with ALL your passwords, card numbers, ' +
      'SSNs, and other sensitive data.\n\n' +
      'Anyone who obtains this file can read ALL your credentials.\n\n' +
      'Only use this for backup to an encrypted drive. Delete the file immediately ' +
      'after use.\n\n' +
      'Are you sure you want to continue?'
    )) {
      showToast('Export cancelled', '');
      return;
    }
    await doPlainCsvExport();
  });

  card.querySelector('#sv-export-encrypted').addEventListener('click', async () => {
    dialog.remove();
    await doEncryptedExport();
  });

  card.querySelector('#sv-export-cancel').addEventListener('click', () => {
    dialog.remove();
    showToast('Export cancelled', '');
  });

  // Close on background click
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) {
      dialog.remove();
      showToast('Export cancelled', '');
    }
  });
}

// ─── E15: Plain CSV export (with security warning shown above) ──────────

async function doPlainCsvExport() {
  // Bitwarden CSV format
  const rows = [['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp']];
  for (const e of state.vault) {
    if (e.deleted) continue;
    const type = e.type || 'login';
    const favorite = e.favorite ? '1' : '';
    if (type === 'login') {
      rows.push([e.folder || '', favorite, 'login', e.name || '', e.notes || '', '', '', e.url || '', e.user || '', e.pass || '', e.totp || '']);
    } else if (type === 'card') {
      // Bitwarden card type uses different columns; we'll map into notes for portability.
      const notes = `Cardholder: ${e.cardholder || ''}\nBrand: ${detectCardBrand(e.cardNumber || '')}\nExp: ${e.exp || ''}\nCVV: ${e.cvv || ''}\n${e.notes || ''}`;
      rows.push([e.folder || '', favorite, 'card', e.name || '', notes, '', '', '', '', e.cardNumber || '', '']);
    } else if (type === 'identity') {
      const notes = `Name: ${e.firstName || ''} ${e.lastName || ''}\nEmail: ${e.email || ''}\nPhone: ${e.phone || ''}\nAddress: ${e.address || ''}\nCity: ${e.city || ''}\nState: ${e.state || ''}\nPostal: ${e.postal || ''}\nCountry: ${e.country || ''}\nSSN: ${e.ssn || ''}\nPassport: ${e.passport || ''}\nLicense: ${e.license || ''}\n${e.notes || ''}`;
      rows.push([e.folder || '', favorite, 'identity', e.name || '', notes, '', '', '', '', '', '']);
    } else if (type === 'note') {
      rows.push([e.folder || '', favorite, 'securenote', e.name || '', e.notes || '', '', '', '', '', '', '']);
    }
  }
  const csv = rows.map(r => r.map(csvEscape).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = (state.fileName || 'vault').replace(/\.svlt$/i, '') + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  showToast('Exported plaintext CSV — DELETE this file after use!', 'warning');
}

// ─── E15: Encrypted .svlt export ──────────────────────────────────────
// Uses the vaultFileCrypto.encryptVaultFile function to produce an
// encrypted .svlt file (same format as the synced vault file). This file
// can be re-imported by any SecureVault instance (extension or Electron)
// using the master password. No plaintext is ever written to disk.

async function doEncryptedExport() {
  if (!state.sessionPassword) {
    showToast('Vault must be unlocked to export', 'error');
    return;
  }

  try {
    // Delegate encryption to background.js (which has the session password
    // and vaultFileCrypto.js imported). This avoids exposing the password
    // over IPC and uses the same encryption pipeline as routine vault saves.
    const resp = await sendBg({
      type: 'encrypt_vault',
      entries: state.vault.filter(e => !e.deleted)  // exclude trashed entries
    });

    if (!resp || !resp.ok) {
      showToast('Encryption failed: ' + (resp?.error || 'unknown error'), 'error');
      return;
    }

    // Convert base64 back to binary
    const binary = atob(resp.encryptedB64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (state.fileName || 'vault').replace(/\.svlt$/i, '') + '_export.svlt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    showToast('Exported encrypted .svlt file', 'success');
  } catch (e) {
    showToast('Export failed: ' + (e.message || e), 'error');
  }
}

function csvEscape(s) {
  const str = String(s);
  if (/[",\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

// ─── Folder datalist ──────────────────────────────────────────────────

function refreshFolderDatalist() {
  const folders = new Set();
  for (const e of state.vault) {
    if (e.folder) folders.add(e.folder);
  }
  const html = Array.from(folders).map(f => `<option value="${escapeAttr(f)}">`).join('');
  const dl1 = $('#folders-datalist');
  const dl2 = $('#folders-datalist-card');
  if (dl1) dl1.innerHTML = html;
  if (dl2) dl2.innerHTML = html;
}

function escapeAttr(s) {
  return String(s).replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

// ─── HIBP breach check (single password + vault health scan) ──────────
//
// All actual API work happens in background.js (via breachCheck.js, using
// the k-anonymity model). The window just sends a "check_pwned" message
// and renders the result badge.

function setBreachBadge(state_) {
  const badge = $('#breach-badge');
  if (!badge) return;
  badge.className = 'breach-badge';
  switch (state_.kind) {
    case 'checking':
      badge.classList.add('checking');
      badge.textContent = '⏳ Checking…';
      break;
    case 'breached':
      badge.classList.add('breached');
      badge.textContent = '⚠ Found in ' + Number(state_.count).toLocaleString() + ' breaches';
      break;
    case 'safe':
      badge.classList.add('safe');
      badge.textContent = '✓ Not found in any breach';
      break;
    case 'error':
      badge.classList.add('error');
      badge.textContent = '⚠ Could not check (offline?)';
      break;
    case 'disabled':
      badge.classList.add('error');
      badge.textContent = '⚠ Enable breach detection in Settings';
      break;
    case 'empty':
      badge.textContent = '';
      break;
  }
}

async function handleCheckPwned() {
  const input = document.querySelector('#fields-login [data-field="pass"]');
  const password = input ? input.value : '';
  if (!password) {
    setBreachBadge({ kind: 'empty' });
    return;
  }
  setBreachBadge({ kind: 'checking' });
  try {
    const resp = await sendBg({ type: 'check_pwned', password });
    if (!resp) {
      setBreachBadge({ kind: 'error' });
      return;
    }
    if (resp.error && /disabled/i.test(resp.error)) {
      setBreachBadge({ kind: 'disabled' });
      return;
    }
    if (resp.error) {
      setBreachBadge({ kind: 'error' });
      return;
    }
    if (resp.breached) {
      setBreachBadge({ kind: 'breached', count: resp.count || 0 });
    } else {
      setBreachBadge({ kind: 'safe' });
    }
  } catch (e) {
    setBreachBadge({ kind: 'error' });
  }
}

// ─── Vault-wide health scan ───────────────────────────────────────────
//
// Sends every (unique) password to background.js for batch HIBP checking.
// background.js streams `health_scan_progress` messages back; we render a
// progress modal and finally a results list.

function openHealthScanModal() {
  const modal = $('#health-scan-modal');
  if (!modal) return;
  $('#health-scan-title').textContent = '🛡 Scanning vault…';
  $('#health-scan-status').textContent = 'Preparing…';
  $('#health-scan-fill').style.width = '0%';
  $('#health-scan-results').innerHTML = '';
  $('#health-scan-dismiss').classList.add('hidden');
  modal.classList.remove('hidden');
}

function closeHealthScanModal() {
  const modal = $('#health-scan-modal');
  if (modal) modal.classList.add('hidden');
}

function updateHealthScanProgress(checked, total, site) {
  if (total <= 0) {
    $('#health-scan-fill').style.width = '100%';
    $('#health-scan-status').textContent = 'No passwords to check.';
    return;
  }
  const pct = Math.round((checked / total) * 100);
  $('#health-scan-fill').style.width = pct + '%';
  $('#health-scan-status').textContent = `Checking ${site}… (${checked}/${total})`;
}

function renderHealthScanResults(results) {
  const total = results.length;
  const breached = results.filter(r => r.breached);
  const errored = results.filter(r => r.error);

  $('#health-scan-title').textContent = breached.length > 0
    ? '🛡 Found ' + breached.length + ' breached password' + (breached.length === 1 ? '' : 's')
    : '🛡 No breaches found';
  $('#health-scan-status').textContent =
    `Checked ${total} password${total === 1 ? '' : 's'} · ` +
    `${breached.length} breached` +
    (errored.length ? ` · ${errored.length} error${errored.length === 1 ? '' : 's'}` : '');
  $('#health-scan-fill').style.width = '100%';

  const container = $('#health-scan-results');
  container.innerHTML = '';
  if (breached.length === 0) {
    container.appendChild(el('div', {
      style: 'padding:12px;text-align:center;color:var(--muted, #9ca3af);font-size:12px;',
      text: errored.length
        ? 'Some passwords could not be checked (network error?). Try again later.'
        : 'All checked passwords are safe.'
    }));
  } else {
    // Sort by breach count descending
    const sorted = breached.slice().sort((a, b) => (b.count || 0) - (a.count || 0));
    for (const item of sorted) {
      const row = el('div', { class: 'health-scan-result-item' });
      row.appendChild(el('span', { text: item.site }));
      row.appendChild(el('span', { text: Number(item.count || 0).toLocaleString() + '×' }));
      container.appendChild(row);
    }
  }

  $('#health-scan-dismiss').classList.remove('hidden');
}

async function handleHealthScan() {
  // Gather entries with passwords (de-duplicated by the background worker).
  const entries = state.vault.filter(e =>
    !e.deleted && (e.type === 'login' || !e.type) && (e.pass || e.password)
  ).map(e => ({
    site: e.name || e.site || e.url || 'Untitled',
    pass: e.pass || e.password
  }));

  if (entries.length === 0) {
    showToast('No login passwords to scan', 'error');
    return;
  }

  openHealthScanModal();

  try {
    const resp = await sendBg({ type: 'vault_health_scan', entries });
    if (!resp || !resp.ok) {
      $('#health-scan-title').textContent = '🛡 Scan failed';
      $('#health-scan-status').textContent = (resp && resp.error) || 'Unknown error';
      $('#health-scan-fill').style.width = '0%';
      $('#health-scan-dismiss').classList.remove('hidden');
      return;
    }
    renderHealthScanResults(resp.results || []);
  } catch (e) {
    $('#health-scan-title').textContent = '🛡 Scan failed';
    $('#health-scan-status').textContent = String(e && e.message || e);
    $('#health-scan-dismiss').classList.remove('hidden');
  }
}

// ─── Incoming messages from background ────────────────────────────────
//
// IMPORTANT: chrome.runtime.sendMessage from a content script is delivered
// to BOTH background.js AND this window. The first listener to call
// sendResponse() wins. We must ONLY respond to message types we own
// (locked, do_clipboard_write, do_clipboard_clear, window_action,
// health_scan_progress) — for anything else, return false synchronously so
// background's response is the one the sender receives.

const WINDOW_OWNED_TYPES = new Set([
  'locked',
  'do_clipboard_write',
  'do_clipboard_clear',
  'window_action',
  'health_scan_progress'
]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = message && message.type;
  // Not ours — let background handle it.
  if (!WINDOW_OWNED_TYPES.has(type)) {
    return false;
  }
  (async () => {
    try {
      if (type === 'locked') {
        // Auto-lock fired in background — sync UI locally only (do NOT
        // re-send `lock` to background; that would cause an infinite loop).
        handleLocalLock();
      } else if (type === 'do_clipboard_write') {
        // Background asks us to write to clipboard (e.g. from context menu).
        try {
          await navigator.clipboard.writeText(message.value || '');
          await sendBg({ type: 'copy_to_clipboard', value: message.value || '' });
        } catch (e) {
          // Fallback
          const ta = document.createElement('textarea');
          ta.value = message.value || '';
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand('copy'); } catch (_) {}
          document.body.removeChild(ta);
          await sendBg({ type: 'copy_to_clipboard', value: message.value || '' });
        }
      } else if (type === 'do_clipboard_clear') {
        try {
          await navigator.clipboard.writeText('');
        } catch (_) {}
      } else if (type === 'window_action') {
        // Background forwarded a pending action (e.g. add entry). Bitwarden-
        // style: prefill url + user + pass when sent from save-prompt or
        // inline generator "Save to SecureVault" action.
        const action = message.action || {};
        if (action.add === '1' || action.add === 1) {
          openAddModal({
            url: action.url || '',
            user: action.user || '',
            pass: action.pass || ''
          });
        }
      } else if (type === 'health_scan_progress') {
        // Streaming progress from background's vault_health_scan handler.
        if (typeof message.checked === 'number') {
          updateHealthScanProgress(message.checked, message.total, message.site || '');
        }
      }
      sendResponse({ ok: true });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
});

// ─── Event wiring ─────────────────────────────────────────────────────

function wireEvents() {
  // Lock screen
  $('#pick-file-btn').addEventListener('click', handlePickFile);
  $('#unlock-btn').addEventListener('click', handleUnlock);
  $('#resume-btn').addEventListener('click', handleResume);
  $('#lock-forget-btn').addEventListener('click', async () => {
    // "Forget session" — clear EVERYTHING including the vault blob from
    // local storage and the IDB file handle. This forces the full unlock
    // screen (file picker + password) on the next popup open.
    await clearSessionMeta();
    await clearVaultBlobLocal();
    await clearFileHandleFromIDB();
    state.encryptedBuffer = null;
    state.fileHandle = null;
    state.fileName = '';
    $('#lock-mode-open').classList.remove('hidden');
    $('#lock-mode-resume').classList.add('hidden');
    $('#master-pw').focus();
  });
  $('#master-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleUnlock(); });
  $('#resume-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleResume(); });

  // Visibility toggles
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.toggle-visibility');
    if (!btn) return;
    const targetId = btn.dataset.target;
    const field = btn.dataset.field;
    let input;
    if (targetId) input = $('#' + targetId);
    else if (field) input = document.querySelector(`[data-field="${field}"]`);
    if (input) {
      input.type = input.type === 'password' ? 'text' : 'password';
    }
  });

  // Pop out to a detached window (like Bitwarden's "Open in new window")
  $('#popout-btn').addEventListener('click', async () => {
    await sendBg({ type: 'open_window' });
    window.close();  // close the popup
  });

  // Header lock button
  $('#lock-now-btn').addEventListener('click', handleLockNow);

  // Tab navigation
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Vault toolbar
  $('#add-entry-btn').addEventListener('click', () => openAddModal());
  $('#empty-add-btn').addEventListener('click', () => openAddModal());
  $('#btn-health-scan').addEventListener('click', handleHealthScan);
  $('#search-input').addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderVault();
  });

  // Filter chips
  $$('#filter-chips .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      $$('#filter-chips .chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      state.currentFilter = chip.dataset.filter;
      renderVault();
    });
  });

  // Modal
  $('#modal-close').addEventListener('click', closeModal);
  $('#modal-cancel').addEventListener('click', closeModal);
  $('#modal-save').addEventListener('click', handleSaveEntry);
  $('#modal-delete').addEventListener('click', handleDeleteEntry);
  $('.modal-backdrop').addEventListener('click', closeModal);

  // Type selector
  $$('#entry-type .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => setEntryType(btn.dataset.type));
  });

  // Inline generate
  $('#gen-inline').addEventListener('click', async () => {
    const resp = await sendBg({
      type: 'generate_password',
      options: { mode: 'random', length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true }
    });
    if (resp && resp.ok) {
      const input = document.querySelector('#fields-login [data-field="pass"]');
      if (input) {
        input.value = resp.password;
        updateInlineStrength(resp.password);
      }
    }
  });

  // Password strength on input
  document.addEventListener('input', (e) => {
    if (e.target.matches('[data-field="pass"]')) {
      updateInlineStrength(e.target.value);
      // Invalidate any stale breach badge — the password changed.
      const badge = $('#breach-badge');
      if (badge && badge.textContent) {
        badge.textContent = '';
        badge.className = 'breach-badge';
      }
    }
    if (e.target.matches('[data-field="cardNumber"]')) {
      e.target.value = formatCardNumber(e.target.value);
      detectCardBrand(e.target.value);
    }
    if (e.target.matches('[data-field="exp"]')) {
      e.target.value = formatExpiry(e.target.value);
    }
    if (e.target.matches('[data-field="totp"]')) {
      startTotpPreview(e.target.value.trim());
    }
  });

  // TOTP copy button
  $('#totp-copy').addEventListener('click', async () => {
    const input = document.querySelector('#fields-login [data-field="totp"]');
    const sec = input ? input.value.trim() : '';
    if (!sec) {
      showToast('Enter a TOTP secret first', 'error');
      return;
    }
    const resp = await sendBg({ type: 'generate_totp', secret: sec });
    if (resp && resp.ok && resp.totp) {
      await copyToClipboard(resp.totp.code);
    } else {
      showToast('Invalid TOTP secret', 'error');
    }
  });

  // Breach check button (add/edit modal)
  $('#btn-check-pwned').addEventListener('click', handleCheckPwned);

  // Health scan modal dismiss button
  $('#health-scan-dismiss').addEventListener('click', closeHealthScanModal);

  // More menu
  $$('#more-menu button').forEach(btn => {
    btn.addEventListener('click', () => handleMoreAction(btn.dataset.action));
  });

  // Generator
  $('#gen-regenerate').addEventListener('click', regeneratePassword);
  $('#gen-copy').addEventListener('click', handleGenCopy);
  $$('#gen-mode .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#gen-mode .seg-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      $('#random-options').classList.toggle('hidden', btn.dataset.mode !== 'random');
      $('#passphrase-options').classList.toggle('hidden', btn.dataset.mode !== 'passphrase');
      regeneratePassword();
    });
  });
  $('#gen-length').addEventListener('input', (e) => {
    $('#gen-length-val').textContent = e.target.value;
    regeneratePassword();
  });
  $('#gen-wordcount').addEventListener('input', (e) => {
    $('#gen-wordcount-val').textContent = e.target.value;
    regeneratePassword();
  });
  ['gen-upper', 'gen-lower', 'gen-num', 'gen-sym', 'gen-avoid-ambig',
   'gen-capitalize', 'gen-include-num'].forEach(id => {
    $('#' + id).addEventListener('change', regeneratePassword);
  });
  $('#gen-separator').addEventListener('change', regeneratePassword);
  $('#clear-history').addEventListener('click', clearGenHistory);

  // Settings
  ['set-lock-timeout', 'set-clip-timeout', 'set-autofill', 'set-lockicon'].forEach(id => {
    $('#' + id).addEventListener('change', saveSettingsFromForm);
  });
  $('#setting-hibp').addEventListener('change', handleHibpToggle);
  $('#change-mp-btn').addEventListener('click', handleChangeMasterPassword);
  // v6.7 SYNC FIX: Auto-sync toggle. Persisted to chrome.storage.local
  // and re-applied on next popup open.
  $('#set-auto-sync').addEventListener('change', async (e) => {
    const enabled = e.target.checked;
    setAutoSyncEnabled(enabled);
    await saveAutoSyncPref(enabled);
    showToast(enabled ? 'Auto-sync enabled' : 'Auto-sync disabled', '');
  });
  $('#reload-file-btn').addEventListener('click', handleReloadFile);
  $('#export-csv-btn').addEventListener('click', handleExportCsv);
  $('#lock-now-settings-btn').addEventListener('click', handleLockNow);

  // Window blur → tell background to clear clipboard
  window.addEventListener('blur', () => {
    sendBg({ type: 'window_blur' });
  });

  // Escape closes modal / more menu / health scan modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!$('#entry-modal').classList.contains('hidden')) closeModal();
      const hsm = $('#health-scan-modal');
      if (hsm && !hsm.classList.contains('hidden') && !$('#health-scan-dismiss').classList.contains('hidden')) {
        closeHealthScanModal();
      }
      closeMoreMenu();
    }
  });

  // Tell background we're ready
  sendBg({ type: 'window_ready' });
}

// ─── Boot ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  wireEvents();
  renderGenHistory();
  await boot();
  // Cache settings (for breach-check row visibility in the entry modal)
  // and apply HIBP-dependent UI visibility (health-scan button, etc.).
  await refreshCachedSettings();
  if (state._cachedSettings) {
    applyHibpVisibility(!!state._cachedSettings.hibpCheckEnabled);
  }
  // Periodically refresh folder datalist
  refreshFolderDatalist();
  setInterval(refreshFolderDatalist, 5000);
});
