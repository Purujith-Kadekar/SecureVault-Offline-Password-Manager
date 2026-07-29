'use strict';
/**
 * renderer.js — SecureVault Electron premium dashboard UI logic.
 *
 * Runs in the sandboxed renderer process. All sensitive operations (crypto,
 * serial I/O, file I/O) go through window.vaultAPI → preload.js contextBridge
 * → main.js IPC handlers. This file only sees display-ready data.
 *
 * Responsibilities:
 *   - Screen routing (splash / device-connect / setup / lock / dashboard)
 *   - Device handshake flow (6-digit code, port picker)
 *   - SD-card unlock flow (PIN entry, create new vault)
 *   - Dashboard rendering (sidebar with types/folders/tags/favorites/trash,
 *     entry list with avatars + actions, search, sort)
 *   - Add/Edit modal for all 4 entry types (Login, Card, Identity, Note)
 *   - Settings modal (SD card, security, backups, extension sync, about)
 *   - Password generator modal (random + passphrase modes)
 *   - TOTP live preview, clipboard auto-clear, auto-lock timer
 *   - Toast notifications, context menu, keyboard shortcuts
 *   - CSV import/export, extension-sync (write .svlt + sync from .svlt)
 */

// ═══════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════
const AUTO_LOCK_DEFAULT_MIN = 5;
const PURGE_DAYS_DEFAULT = 30;
const CLIPBOARD_CLEAR_MS = 30000;       // 30s auto-clear for copied secrets
const TRASH_PURGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

const TYPE_LABELS = {
  login:    'Login',
  card:     'Card',
  identity: 'Identity',
  note:     'Secure Note',
};
const TYPE_ICONS = {
  login:    '🔐',
  card:     '💳',
  identity: '🪪',
  note:     '📝',
};

const STRENGTH_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#84cc16', '#10b981'];

// Card brand detection (BIN ranges — best-effort, not authoritative)
const CARD_BRANDS = [
  { name: 'Visa',       pattern: /^4/ },
  { name: 'Mastercard', pattern: /^(5[1-5]|2[2-7])/ },
  { name: 'Amex',       pattern: /^3[47]/ },
  { name: 'Discover',   pattern: /^6(?:011|5)/ },
  { name: 'JCB',        pattern: /^35/ },
  { name: 'Diners',     pattern: /^3[0689]/ },
];

// ═══════════════════════════════════════════════════════════════════════
//  State — only display-ready data, never keys or frame bytes
//  D18 FIX: Added _dirty flag, snapshot mechanism for undo, and
//  saveConfirmation before destructive operations.
// ═══════════════════════════════════════════════════════════════════════
const state = {
  mode: null,                 // 'device' | 'sdcard'
  sdRoot: null,               // SD card path (sdcard mode)
  // D11 FIX: sdPin removed — the PIN is never stored in the renderer process
  // anymore. JS strings can't be zeroed, so a compromised renderer could
  // extract the plaintext PIN from memory for the entire session duration.
  // Now the PIN is cached only in main.js as a Buffer that can be .fill(0)'d
  // after use, and vault:save uses the cached PIN from main instead of
  // receiving it over IPC.
  entries: [],                // decrypted entries (display-ready)
  _dirty: false,              // D18: dirty flag — set on any entry mutation
  _snapshot: null,            // D18: snapshot of modified entries before mutation (for undo)
  currentFilter: {            // active sidebar filter
    type: 'all',              // 'all' | 'login' | 'card' | 'identity' | 'note'
    folder: '',               // '' = No folder, else folder name
    tag: '',                  // '' = no tag filter, else tag name
    fav: false,               // favorites view
    trash: false,             // trash view
  },
  searchQuery: '',
  sort: 'name-asc',
  editingIndex: null,         // null = adding new entry, number = editing
  clipboardTimer: null,
  autoLockTimer: null,
  autoLockMinutes: AUTO_LOCK_DEFAULT_MIN,
  totpInterval: null,
  extSyncStatus: null,
  limits: null,
};

// ═══════════════════════════════════════════════════════════════════════
//  D18 FIX: State management helpers — dirty tracking, snapshots, undo
// ═══════════════════════════════════════════════════════════════════════
function markDirty() {
  state._dirty = true;
}

function clearDirty() {
  state._dirty = false;
  state._snapshot = null;
}

// D18: Save a snapshot of the current entries before a mutation.
// Used for undo on save failure.
function saveSnapshot() {
  state._snapshot = JSON.parse(JSON.stringify(state.entries));
}

// D18: Restore entries from the last snapshot (undo on save failure).
function restoreFromSnapshot() {
  if (state._snapshot) {
    state.entries = state._snapshot;
    state._snapshot = null;
    state._dirty = true; // still dirty — needs re-save
  }
}

// D18: Confirmation before destructive operations when dirty.
// Returns true if the user confirms or if state is not dirty.
function confirmIfDirty(message) {
  if (!state._dirty) return true;
  return confirm(message || 'You have unsaved changes. Continue?');
}

// ═══════════════════════════════════════════════════════════════════════
//  DOM helpers
// ═══════════════════════════════════════════════════════════════════════
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') {
      e.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v !== null && v !== undefined) {
      e.setAttribute(k, v);
    }
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return e;
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ═══════════════════════════════════════════════════════════════════════
//  Toast notifications (bottom-right, 3.5s auto-dismiss, color-coded)
// ═══════════════════════════════════════════════════════════════════════
function toast(message, type = 'info', durationMs = 3500) {
  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  const t = el('div', { class: `toast ${type}` },
    el('span', { class: 'toast-icon' }, icons[type] || 'ℹ'),
    el('span', { class: 'toast-msg' }, message)
  );
  $('#toast-container').appendChild(t);
  setTimeout(() => {
    t.classList.add('dismissing');
    setTimeout(() => t.remove(), 220);
  }, durationMs);
}

// ═══════════════════════════════════════════════════════════════════════
//  Screen routing
// ═══════════════════════════════════════════════════════════════════════
const SCREENS = ['screen-sdcard', 'screen-device-connect', 'screen-setup', 'screen-lock', 'screen-dashboard'];

function showScreen(name) {
  for (const s of SCREENS) {
    const e = document.getElementById(s);
    if (e) e.classList.toggle('hidden', s !== name);
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Sync pill / SD indicator helpers
// ═══════════════════════════════════════════════════════════════════════
function setSyncPill(state_, label) {
  const pill = $('#ext-sync-pill');
  pill.classList.remove('idle', 'syncing', 'synced', 'error');
  pill.classList.add(state_);
  if (label) $('.sync-label', pill).textContent = label;
}

function setSdIndicator(state_) {
  const ind = $('#sd-indicator');
  ind.classList.remove('connected', 'device', 'error');
  if (state_) ind.classList.add(state_);
}

// ═══════════════════════════════════════════════════════════════════════
//  Splash screen — mode chooser
// ═══════════════════════════════════════════════════════════════════════
async function initSplash() {
  showScreen('screen-sdcard');

  // Auto-detect any SD card with a vault.db on it — surface as a hint.
  try {
    const { all, withVault } = await vaultAPI.listRemovableVolumes();
    if (withVault.length === 1) {
      $('#sdcard-candidates').textContent = `Found vault.db on ${withVault[0]} — click "Read SD Card" to use it.`;
    } else if (withVault.length > 1) {
      $('#sdcard-candidates').textContent = `Found vault.db on ${withVault.length} drives — click "Read SD Card" to choose.`;
    } else if (all.length > 0) {
      $('#sdcard-candidates').textContent = `${all.length} removable drive(s) detected, but none has a vault.db yet.`;
    }
  } catch { /* ignore — user can still pick manually */ }

  // Restore last-used SD card path as a hint.
  const saved = await vaultAPI.getSavedSDCard();
  if (saved) {
    $('#sdcard-path-display').textContent = `Last used: ${saved}`;
  }
}

$('#btn-connect-device').addEventListener('click', () => {
  state.mode = 'device';
  setSdIndicator('device');
  showDeviceConnect();
});

$('#btn-pick-sdcard').addEventListener('click', async () => {
  state.mode = 'sdcard';
  setSdIndicator('connected');
  await pickOrUseSavedSdCard();
});

async function pickOrUseSavedSdCard() {
  // Try the saved path first — if it still has a vault.db, skip the picker.
  const saved = await vaultAPI.getSavedSDCard();
  if (saved) {
    const st = await vaultAPI.sdCardStatus(saved);
    if (st.exists) {
      state.sdRoot = saved;
      await vaultAPI.setSelectedSDCard(saved);
      return saved.startsWithVault ? showLockScreen(saved) : routeAfterSdCardPicked(saved, st);
    }
  }
  // Otherwise show the picker.
  const chosen = await vaultAPI.selectSDCard();
  if (!chosen) {
    // User canceled — go back to splash.
    state.mode = null;
    setSdIndicator(null);
    showScreen('screen-sdcard');
    return;
  }
  state.sdRoot = chosen;
  const st = await vaultAPI.sdCardStatus(chosen);
  routeAfterSdCardPicked(chosen, st);
}

function routeAfterSdCardPicked(sdRoot, st) {
  if (!st.exists) {
    $('#sdcard-error').textContent = `Path not found: ${sdRoot}`;
    return;
  }
  if (st.hasVault) {
    showLockScreen(sdRoot);
  } else {
    showSetupScreen(sdRoot);
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Device connect screen — 6-digit code entry
//  Port picker is optional (auto-detection is the default). If the HTML
//  has no #device-port / #btn-refresh-ports elements (the clean UI), we
//  skip the port picker entirely and let the main process auto-detect.
// ═══════════════════════════════════════════════════════════════════════
async function showDeviceConnect() {
  showScreen('screen-device-connect');
  $('#device-code').value = '';
  $('#device-connect-error').textContent = '';
  $('#device-connect-status').textContent = '';
  // Only refresh the port dropdown if it exists in the HTML.
  if ($('#device-port')) await refreshPorts();
  setTimeout(() => $('#device-code').focus(), 50);
}

async function refreshPorts() {
  const select = $('#device-port');
  if (!select) return;  // port picker not in the DOM — auto-detection mode
  select.innerHTML = '';
  const result = await vaultAPI.deviceListPorts();
  if (!result.ok) {
    $('#device-connect-status').textContent = 'Cannot list serial ports: ' + result.error;
    return;
  }
  const ports = result.ports || [];
  if (ports.length === 0) {
    select.appendChild(el('option', { value: '' }, 'No serial ports found'));
    return;
  }
  // Sort: ESP32-flagged ports first, then alphabetical.
  ports.sort((a, b) => (b.isEsp32 - a.isEsp32) || a.path.localeCompare(b.path));
  for (const p of ports) {
    const label = `${p.path} ${p.manufacturer ? '(' + p.manufacturer + ')' : ''}${p.isEsp32 ? ' ★ ESP32' : ''}`;
    select.appendChild(el('option', { value: p.path }, label));
  }
  // Auto-select the first ESP32-flagged port if any.
  const esp = ports.find(p => p.isEsp32);
  if (esp) select.value = esp.path;
}

// Only wire the refresh button if it exists.
const refreshPortsBtn = $('#btn-refresh-ports');
if (refreshPortsBtn) refreshPortsBtn.addEventListener('click', refreshPorts);

$('#device-code').addEventListener('input', (e) => {
  e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
});

$('#btn-device-connect').addEventListener('click', async () => {
  const code = $('#device-code').value.trim();
  if (code.length !== 6) {
    $('#device-connect-error').textContent = 'Enter the 6-digit code shown on the ESP32.';
    return;
  }
  // Port picker is optional — if absent, pass null and let main auto-detect.
  const portSelect = $('#device-port');
  const portPath = portSelect ? (portSelect.value || null) : null;
  $('#device-connect-error').textContent = '';
  $('#device-connect-status').textContent = 'Connecting…';
  $('#btn-device-connect').disabled = true;

  const result = await vaultAPI.deviceHandshake(code, portPath);
  $('#btn-device-connect').disabled = false;

  if (!result.ok) {
    $('#device-connect-error').textContent = result.error || 'Handshake failed.';
    $('#device-connect-status').textContent = '';
    setSdIndicator('error');
    return;
  }
  $('#device-connect-status').textContent = 'Connected! Loading vault…';
  setSdIndicator('device');
  await loadDeviceEntries();
});

$('#btn-device-back').addEventListener('click', () => {
  state.mode = null;
  setSdIndicator(null);
  initSplash();
});

$('#device-code').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#btn-device-connect').click();
});

// ═══════════════════════════════════════════════════════════════════════
//  Setup screen — create new vault on blank SD card
// ═══════════════════════════════════════════════════════════════════════
function showSetupScreen(sdRoot) {
  showScreen('screen-setup');
  $('#setup-pin').value = '';
  $('#setup-pin-confirm').value = '';
  $('#setup-error').textContent = '';
  $('#setup-strength-meter').classList.add('hidden');
  $('#lock-path-display').textContent = sdRoot;
  setTimeout(() => $('#setup-pin').focus(), 50);
}

$('#setup-pin').addEventListener('input', async () => {
  const pin = $('#setup-pin').value;
  if (!pin) {
    $('#setup-strength-meter').classList.add('hidden');
    return;
  }
  // PINs are usually short numeric — show strength only if it's a real password.
  if (pin.length >= 4) {
    const s = await vaultAPI.passwordStrength(pin);
    $('#setup-strength-meter').classList.remove('hidden');
    $('#setup-strength-fill').className = 'strength-fill score-' + s.score;
    $('#setup-strength-label').textContent = `${s.label} (${s.entropy} bits)`;
  }
});

$('#btn-create-vault').addEventListener('click', async () => {
  const pin = $('#setup-pin').value;
  const confirm = $('#setup-pin-confirm').value;
  if (!pin || pin.length < 4) {
    $('#setup-error').textContent = 'PIN must be at least 4 characters.';
    return;
  }
  if (pin !== confirm) {
    $('#setup-error').textContent = 'PINs do not match.';
    return;
  }
  $('#setup-error').textContent = '';
  const result = await vaultAPI.vaultCreateNew(state.sdRoot, pin);
  if (!result.success) {
    $('#setup-error').textContent = result.error;
    return;
  }
  // D11 FIX: PIN is no longer stored in the renderer. The main process caches
  // it securely (as a Buffer that can be .fill(0)'d). vaultCreateNew sends
  // the PIN to main, which caches it internally.
  state.entries = [];
  toast('Vault created', 'success');
  showDashboard();
});

$('#btn-setup-back').addEventListener('click', () => {
  state.mode = null;
  setSdIndicator(null);
  initSplash();
});

// ═══════════════════════════════════════════════════════════════════════
//  SD-card lock screen
// ═══════════════════════════════════════════════════════════════════════
function showLockScreen(sdRoot) {
  showScreen('screen-lock');
  $('#lock-pin').value = '';
  $('#lock-error').textContent = '';
  $('#lock-path-display').textContent = sdRoot;
  setTimeout(() => $('#lock-pin').focus(), 50);
}

$('#btn-unlock').addEventListener('click', async () => {
  const pin = $('#lock-pin').value;
  if (!pin) {
    $('#lock-error').textContent = 'Enter your PIN.';
    return;
  }
  $('#lock-error').textContent = '';
  const result = await vaultAPI.vaultUnlock(state.sdRoot, pin);
  if (!result.success) {
    $('#lock-error').textContent = result.error;
    if (result.code === 'WRONG_PIN') $('#lock-pin').select();
    return;
  }
  // D11 FIX: PIN is no longer stored in renderer. vault:unlock in main.js
  // caches the PIN in a Buffer that can be .fill(0)'d on lock/quit.
  // D9 FIX: If the vault was a v1 file (needsMigration), show a toast
  // informing the user that it will be upgraded to v2 on next save.
  // D18 FIX: Clear dirty state when vault is unlocked/reloaded.
  state.entries = (result.entries || []).map(normalizeEntryForUi);
  clearDirty();
  toast(`Unlocked ${state.entries.length} entries`, 'success');
  if (result.needsMigration) {
    toast('Vault upgraded: next save will use stronger encryption (600K iterations + HMAC)', 'info', 6000);
  }
  showDashboard();
});

$('#lock-pin').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#btn-unlock').click();
});

$('#btn-lock-change-card').addEventListener('click', () => {
  state.mode = null;
  state.sdRoot = null;
  // D11 FIX: sdPin no longer stored in renderer.
  state.entries = [];
  setSdIndicator(null);
  initSplash();
});

// ═══════════════════════════════════════════════════════════════════════
//  Device entries — load after handshake
// ═══════════════════════════════════════════════════════════════════════
async function loadDeviceEntries() {
  const result = await vaultAPI.deviceListEntries();
  if (!result.ok) {
    $('#device-connect-status').textContent = '';
    $('#device-connect-error').textContent = result.error || 'Failed to list entries.';
    setSdIndicator('error');
    return;
  }
  // Device entries are flat {index, site, user, pass, totp} — augment with
  // type from the device (default to 'login' for backward compat) and pull
  // URL from cache.
  const urlCacheResult = await vaultAPI.urlCacheGetAll();
  const urlCache = urlCacheResult.cache || {};

  // D3+D6 FIX: Preserve existing UUIDs and _version from current state when
  // re-loading device entries. Without this, every loadDeviceEntries() call
  // would assign fresh UUIDs to all entries, breaking the stable-identity
  // contract. Match by (site, user) pair to find existing entries and
  // preserve their `id` and `_version` fields.
  const existingById = new Map();
  for (const e of state.entries) {
    if (e.id) existingById.set((e.site || '').toLowerCase() + '|' + (e.user || '').toLowerCase(), e);
  }

  // D18 FIX: Clear dirty state on device entries reload.
  state.entries = (result.entries || []).map((e, i) => {
    const typeMap = { 0: 'login', 1: 'card', 2: 'identity', 3: 'note' };
    const typeStr = (typeof e.type === 'number') ? (typeMap[e.type] || 'login')
                  : (e.type || 'login');
    // Preserve existing UUID if the entry matches an existing one by (site, user).
    const matchKey = ((e.site || '')).toLowerCase() + '|' + ((e.user || '')).toLowerCase();
    const existingEntry = existingById.get(matchKey);
    const preservedId = existingEntry?.id || e.id;
    const preservedVersion = existingEntry?._version || e._version;
    return normalizeEntryForUi({
      ...e,
      type: typeStr,
      favorite: e.fav ? true : (e.favorite || false),
      deleted: e.del ? true : (e.deleted || false),
      url: urlCache[e.site] || '',
      index: typeof e.index === 'number' ? e.index : i,
      _source: 'device',
      id: preservedId,
      _version: preservedVersion || 0,
    });
  });
  clearDirty();
  $('#device-connect-status').textContent = '';
  showDashboard();
}

// ═══════════════════════════════════════════════════════════════════════
//  Entry normalization — make sure every entry has all the fields the UI
//  expects, regardless of source (device vs SD card vs CSV).
// ═══════════════════════════════════════════════════════════════════════
function normalizeEntryForUi(e) {
  // D12 FIX: Use the shared canonical normalizeEntry.js module as the base,
  // then add UI-only fields (_source, _index) ON TOP.
  // Since renderer.js runs in a sandboxed context (no Node require), we
  // inline the canonical normalization here, matching normalizeEntry.js
  // exactly. Any future changes to the canonical schema must be updated
  // in BOTH normalizeEntry.js AND this function.
  const type = ['login', 'card', 'identity', 'note'].includes(e.type) ? e.type : 'login';
  // D3+D6 FIX: Ensure every entry has a stable UUID `id`.
  const entryId = (e.id && typeof e.id === 'string') ? e.id : crypto.randomUUID();
  const isFav = !!(e.fav || e.favorite);
  const isDel = !!(e.del || e.deleted);

  // Canonical base (matches normalizeEntry.js)
  const base = {
    type,
    id:      entryId,
    _version: typeof e._version === 'number' ? e._version : 0,
    site:    String(e.site || e.name || ''),
    user:    String(e.user || e.login_username || ''),
    pass:    String(e.pass || e.login_password || ''),
    totp:    String(e.totp || e.login_totp || ''),
    url:     String(e.url || e.login_uri || ''),
    notes:   String(e.notes || ''),
    folder:  String(e.folder || ''),
    fav:     isFav ? 1 : 0,
    deleted: isDel,
    deletedAt: isDel ? (Number(e.deletedAt) || 0) : 0,
    created: Number(e.created) || 0,
    updated: Number(e.updated) || 0,
    // Card fields (canonical firmware-style names)
    cardholder:  String(e.cardholder || e.cardHolder || ''),
    cardNumber:  String(e.cardNumber || ''),
    cardBrand:   String(e.cardBrand || ''),
    exp:         String(e.exp || e.cardExpiry || ''),
    cvv:         String(e.cvv || e.cardCvv || ''),
    // Identity fields (canonical firmware-style names)
    firstName:  String(e.firstName || e.idFirstName || ''),
    lastName:   String(e.lastName || e.idLastName || ''),
    email:      String(e.email || e.idEmail || ''),
    phone:      String(e.phone || e.idPhone || ''),
    address:    String(e.address || e.idAddress || ''),
    city:       String(e.city || e.idCity || ''),
    state:      String(e.state || e.idState || ''),
    postal:     String(e.postal || e.idPostal || ''),
    country:    String(e.country || e.idCountry || ''),
    ssn:        String(e.ssn || e.idSsn || ''),
    passport:   String(e.passport || e.idPassport || ''),
    license:    String(e.license || e.idLicense || ''),
  };
  if (Array.isArray(e.tags)) base.tags = e.tags.map(String);

  // ── UI-only fields (added ON TOP of canonical base, per D12 FIX) ──
  base.cardHolder = String(e.cardHolder || e.cardholder || '');
  base.cardExpiry = String(e.cardExpiry || e.exp || '');
  base.cardCvv = String(e.cardCvv || e.cvv || '');
  base.idEmail = String(e.idEmail || e.email || '');
  base.idPhone = String(e.idPhone || e.phone || '');
  base.idAddress = String(e.idAddress || e.address || '');
  base.idFirstName = String(e.idFirstName || e.firstName || '');
  base.idLastName = String(e.idLastName || e.lastName || '');
  base.idCity = String(e.idCity || e.city || '');
  base.idState = String(e.idState || e.state || '');
  base.idPostal = String(e.idPostal || e.postal || '');
  base.idCountry = String(e.idCountry || e.country || '');
  base.idSsn = String(e.idSsn || e.ssn || '');
  base.idPassport = String(e.idPassport || e.passport || '');
  base.idLicense = String(e.idLicense || e.license || '');
  base.idUsername = String(e.idUsername || '');
  base._source = e._source || (state.mode === 'device' ? 'device' : 'sdcard');
  base._index = typeof e.index === 'number' ? e.index : (typeof e._index === 'number' ? e._index : null);

  return base;
}

// ═══════════════════════════════════════════════════════════════════════
//  Dashboard — render sidebar + entry list
// ═══════════════════════════════════════════════════════════════════════
function showDashboard() {
  showScreen('screen-dashboard');
  // v10.9 FIX: Call autoPurgeTrash() on dashboard show — it was defined
  // but never called, making the entire auto-purge feature dead code.
  // Trash entries older than 30 days are now actually purged on each
  // dashboard show, as the original comment intended.
  autoPurgeTrash();
  renderSidebar();
  renderEntryList();
  updateStatusbar();
  startAutoLockTimer();
  // Status pill reflects current extension-sync config.
  refreshExtSyncStatus();
}

function getActiveEntries() {
  // Filter out trash unless we're in trash view.
  let list = state.entries.filter(e => state.currentFilter.trash ? e.deleted : !e.deleted);

  if (state.currentFilter.trash) {
    // Trash view shows deleted entries only.
  } else if (state.currentFilter.type !== 'all') {
    list = list.filter(e => e.type === state.currentFilter.type);
  } else if (state.currentFilter.folder !== '') {
    list = list.filter(e => (e.folder || '') === state.currentFilter.folder);
  } else if (state.currentFilter.tag !== '') {
    list = list.filter(e => (e.tags || []).includes(state.currentFilter.tag));
  } else if (state.currentFilter.fav) {
    list = list.filter(e => e.fav);
  }

  // Search filter (case-insensitive across name, user, url, notes, tags)
  if (state.searchQuery) {
    const q = state.searchQuery.toLowerCase();
    list = list.filter(e => {
      const hay = [e.site, e.user, e.url, e.notes, e.folder, ...(e.tags || [])].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  // Sort
  switch (state.sort) {
    case 'name-asc':       list.sort((a, b) => (a.site || '').localeCompare(b.site || '')); break;
    case 'name-desc':      list.sort((a, b) => (b.site || '').localeCompare(a.site || '')); break;
    case 'updated-desc':   list.sort((a, b) => (b.updated || 0) - (a.updated || 0)); break;
    case 'created-desc':   list.sort((a, b) => (b.created || 0) - (a.created || 0)); break;
  }
  return list;
}

function renderSidebar() {
  // Type counts (exclude trash)
  const live = state.entries.filter(e => !e.deleted);
  const counts = {
    all:      live.length,
    login:    live.filter(e => e.type === 'login').length,
    card:     live.filter(e => e.type === 'card').length,
    identity: live.filter(e => e.type === 'identity').length,
    note:     live.filter(e => e.type === 'note').length,
    fav:      live.filter(e => e.fav).length,
    trash:    state.entries.filter(e => e.deleted).length,
  };
  $('#count-all').textContent = counts.all;
  $('#count-login').textContent = counts.login;
  $('#count-card').textContent = counts.card;
  $('#count-identity').textContent = counts.identity;
  $('#count-note').textContent = counts.note;
  $('#count-fav').textContent = counts.fav;
  $('#count-trash').textContent = counts.trash;

  // Folders (dynamic, from entries)
  const folderCounts = {};
  for (const e of live) {
    const f = e.folder || '';
    folderCounts[f] = (folderCounts[f] || 0) + 1;
  }
  const folderList = $('#folder-filter');
  folderList.innerHTML = '';
  // "No folder" first
  folderList.appendChild(el('li', {
    dataset: { folder: '' },
    class: state.currentFilter.folder === '' && !state.currentFilter.fav && !state.currentFilter.trash && state.currentFilter.type === 'all' && state.currentFilter.tag === '' ? 'active' : '',
    onclick: () => selectFilter({ folder: '', tag: '', fav: false, trash: false, type: 'all' }),
  },
    el('span', { class: 'nav-icon' }, '📁'),
    el('span', { class: 'nav-label' }, 'No folder'),
    el('span', { class: 'count' }, String(folderCounts[''] || 0))
  ));
  for (const f of Object.keys(folderCounts).sort()) {
    if (f === '') continue;
    folderList.appendChild(el('li', {
      dataset: { folder: f },
      class: state.currentFilter.folder === f ? 'active' : '',
      onclick: () => selectFilter({ folder: f, tag: '', fav: false, trash: false, type: 'all' }),
    },
      el('span', { class: 'nav-icon' }, '📁'),
      el('span', { class: 'nav-label' }, f),
      el('span', { class: 'count' }, String(folderCounts[f]))
    ));
  }

  // Tags (dynamic, from entries)
  const tagCounts = {};
  for (const e of live) {
    for (const t of (e.tags || [])) tagCounts[t] = (tagCounts[t] || 0) + 1;
  }
  const tagList = $('#tag-filter');
  tagList.innerHTML = '';
  const tagKeys = Object.keys(tagCounts).sort();
  if (tagKeys.length === 0) {
    tagList.appendChild(el('li', { class: 'muted small' }, 'No tags yet'));
  } else {
    for (const t of tagKeys) {
      tagList.appendChild(el('li', {
        class: state.currentFilter.tag === t ? 'active' : '',
        onclick: () => selectFilter({ tag: t, folder: '', fav: false, trash: false, type: 'all' }),
      },
        el('span', { class: 'nav-icon' }, '#'),
        el('span', { class: 'nav-label' }, t),
        el('span', { class: 'count' }, String(tagCounts[t]))
      ));
    }
  }
}

function selectFilter(patch) {
  // Only one sidebar filter is active at a time.
  state.currentFilter = { type: 'all', folder: '', tag: '', fav: false, trash: false, ...patch };
  // Update visual active state for type list.
  $$('#type-filter li').forEach(li => {
    li.classList.toggle('active', li.dataset.type === (patch.type || 'all'));
  });
  $$('#folder-filter li').forEach(li => {
    li.classList.toggle('active', li.dataset.folder === (patch.folder ?? ''));
  });
  $('#fav-nav').classList.toggle('active', !!patch.fav);
  $('#trash-nav').classList.toggle('active', !!patch.trash);
  // Toggle trash vs main view.
  $('#main-list').classList.toggle('hidden', !!patch.trash);
  $('#main-trash').classList.toggle('hidden', !patch.trash);
  renderEntryList();
  updateStatusbar();
}

// Type filter click handlers
$$('#type-filter li').forEach(li => {
  li.addEventListener('click', () => selectFilter({ type: li.dataset.type }));
});
$('#fav-nav').addEventListener('click', () => selectFilter({ fav: true }));
$('#trash-nav').addEventListener('click', () => selectFilter({ trash: true }));
$('#btn-exit-trash').addEventListener('click', () => selectFilter({ type: 'all' }));

$('#sort-select').addEventListener('change', (e) => {
  state.sort = e.target.value;
  renderEntryList();
});

function updateStatusbar() {
  const list = getActiveEntries();
  const filterName = currentFilterName();
  $('#current-filter-name').textContent = filterName;
  $('#current-filter-count').textContent = `${list.length} ${list.length === 1 ? 'item' : 'items'}`;
  $('#entry-count').textContent = `${state.entries.filter(e => !e.deleted).length} entries (${state.entries.filter(e => e.deleted).length} in trash)`;
}

function currentFilterName() {
  const f = state.currentFilter;
  if (f.trash) return '🗑 Trash';
  if (f.fav)   return '⭐ Favorites';
  if (f.tag)   return `#${f.tag}`;
  if (f.folder) return `📁 ${f.folder}`;
  if (f.type === 'all') return 'All Items';
  return `${TYPE_ICONS[f.type] || ''} ${TYPE_LABELS[f.type] || 'Items'}`;
}

// ═══════════════════════════════════════════════════════════════════════
//  Entry list rendering — cards with avatars + actions
// ═══════════════════════════════════════════════════════════════════════
function renderEntryList() {
  const isTrash = state.currentFilter.trash;
  const container = isTrash ? $('#trash-list') : $('#entry-list');
  const emptyState = isTrash ? $('#trash-empty-state') : $('#empty-state');
  container.innerHTML = '';

  const list = getActiveEntries();
  if (list.length === 0) {
    emptyState.classList.remove('hidden');
    if (!isTrash) {
      // Update empty state text for current filter
      const h3 = emptyState.querySelector('h3');
      const p = emptyState.querySelector('p');
      if (state.searchQuery) {
        h3.textContent = 'No matches';
        p.textContent = `No entries match "${state.searchQuery}".`;
      } else {
        h3.textContent = 'No entries yet';
        p.textContent = 'Add your first entry to get started.';
      }
    }
    return;
  }
  emptyState.classList.add('hidden');

  for (const entry of list) {
    container.appendChild(renderEntryRow(entry, isTrash));
  }
}

function renderEntryRow(entry, isTrash) {
  const initial = (entry.site || '?').charAt(0).toUpperCase();
  const subtitle = getEntrySubtitle(entry);

  const row = el('div', { class: 'entry-row', dataset: { site: entry.site } });

  // Avatar
  row.appendChild(el('div', { class: `entry-avatar type-${entry.type}` }, initial));

  // Main
  const main = el('div', { class: 'entry-main' });
  main.appendChild(el('div', { class: 'entry-name' }, entry.site || '(untitled)'));
  main.appendChild(el('div', { class: 'entry-subtitle' }, subtitle));
  row.appendChild(main);

  // Meta
  const meta = el('div', { class: 'entry-meta' });
  if (entry.totp && entry.type === 'login') {
    meta.appendChild(el('span', { class: 'entry-totp-badge' }, '2FA'));
  }
  if (entry.fav) {
    meta.appendChild(el('span', { class: 'entry-fav', title: 'Favorite' }, '⭐'));
  }
  if (entry.folder) {
    meta.appendChild(el('span', { class: 'entry-tag', title: 'Folder' }, entry.folder));
  }
  for (const t of (entry.tags || []).slice(0, 2)) {
    meta.appendChild(el('span', { class: 'entry-tag', title: 'Tag' }, '#' + t));
  }
  row.appendChild(meta);

  // Actions
  const actions = el('div', { class: 'entry-actions' });
  if (!isTrash) {
    if (entry.type === 'login') {
      actions.appendChild(el('button', {
        class: 'btn ghost tiny', title: 'Copy password',
        onclick: (e) => { e.stopPropagation(); copyPassword(entry); },
      }, '📋'));
    } else if (entry.type === 'card') {
      actions.appendChild(el('button', {
        class: 'btn ghost tiny', title: 'Reveal card number',
        onclick: (e) => { e.stopPropagation(); revealCardNumber(entry, row); },
      }, '👁'));
    }
    actions.appendChild(el('button', {
      class: 'btn ghost tiny', title: 'More',
      onclick: (e) => { e.stopPropagation(); openContextMenu(e, entry); },
    }, '⋮'));
  } else {
    // Trash view: Restore + Delete Permanently.
    // v6.2: Use explicit text labels (not just icons) so the user can
    // never confuse "Move to Trash" (vault view) with "Delete Permanently"
    // (trash view). Permanent delete is ONLY available in the trash view.
    actions.appendChild(el('button', {
      class: 'btn ghost tiny', title: 'Restore this entry to the vault',
      onclick: (e) => { e.stopPropagation(); restoreEntry(entry); },
    }, '↩ Restore'));
    actions.appendChild(el('button', {
      class: 'btn danger tiny', title: 'Permanently delete — cannot be undone',
      onclick: (e) => { e.stopPropagation(); deletePermanently(entry); },
    }, '🗑 Delete Permanently'));
  }
  row.appendChild(actions);

  // Click row → open edit modal (non-trash only)
  if (!isTrash) {
    row.addEventListener('click', () => openEditModal(entry));
    row.addEventListener('contextmenu', (e) => { e.preventDefault(); openContextMenu(e, entry); });
  }

  return row;
}

function getEntrySubtitle(entry) {
  switch (entry.type) {
    case 'login':
      return entry.user || '(no username)';
    case 'card':
      return formatCardNumberPreview(entry.cardNumber) || '(no number)';
    case 'identity':
      return entry.idEmail || entry.email || entry.idPhone || entry.phone || entry.user || '(no email)';
    case 'note':
      return (entry.notes || '').slice(0, 60) + ((entry.notes || '').length > 60 ? '…' : '') || '(empty)';
    default:
      return '';
  }
}

function formatCardNumberPreview(num) {
  if (!num) return '';
  // Show last 4 only — never the full PAN in the list view.
  const digits = String(num).replace(/\D/g, '');
  if (digits.length < 4) return '••••';
  return '•••• •••• •••• ' + digits.slice(-4);
}

function detectCardBrand(num) {
  const digits = String(num || '').replace(/\D/g, '');
  for (const b of CARD_BRANDS) {
    if (b.pattern.test(digits)) return b.name;
  }
  return '';
}

// ═══════════════════════════════════════════════════════════════════════
//  Context menu (right-click on entry row)
// ═══════════════════════════════════════════════════════════════════════
function openContextMenu(event, entry) {
  const menu = $('#ctx-menu');
  menu.innerHTML = '';

  const addItem = (label, onclick, opts = {}) => {
    menu.appendChild(el('div', {
      class: 'ctx-item' + (opts.danger ? ' danger' : ''),
      onclick: () => { closeContextMenu(); onclick(); },
    }, label));
  };
  const addSep = () => menu.appendChild(el('div', { class: 'ctx-sep' }));

  addItem('✏ Edit', () => openEditModal(entry));
  addItem('📋 Copy password', () => copyPassword(entry));
  if (entry.totp) addItem('⏱ Copy TOTP code', () => copyTotp(entry));
  if (entry.url)  addItem('🔗 Copy URL', () => copyText(entry.url, 'URL copied'));
  addSep();
  addItem(entry.fav ? '⭐ Remove favorite' : '⭐ Add favorite', () => toggleFavorite(entry));
  if (entry.folder) addItem('📁 Remove from folder', () => moveEntryToFolder(entry, ''));
  addSep();
  addItem('🗑 Move to trash', () => moveToTrash(entry), { danger: true });

  // Position
  const x = Math.min(event.clientX, window.innerWidth - 220);
  const y = Math.min(event.clientY, window.innerHeight - 300);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  menu.classList.remove('hidden');
}

function closeContextMenu() { $('#ctx-menu').classList.add('hidden'); }
document.addEventListener('click', closeContextMenu);
document.addEventListener('contextmenu', (e) => {
  if (!e.target.closest('.entry-row')) closeContextMenu();
});

// ═══════════════════════════════════════════════════════════════════════
//  Clipboard helpers (auto-clear after 30s)
// ═══════════════════════════════════════════════════════════════════════
async function copyText(text, toastMsg = 'Copied') {
  await vaultAPI.copyToClipboard(text);
  toast(toastMsg, 'success', 2000);
  // Auto-clear after 30s, but only if the clipboard still has what we put there.
  if (state.clipboardTimer) clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(async () => {
    const cleared = await vaultAPI.clearClipboardIfMatches(text);
    if (cleared) toast('Clipboard cleared', 'info', 1500);
  }, CLIPBOARD_CLEAR_MS);
}

async function copyPassword(entry) {
  if (!entry.pass) { toast('No password to copy', 'warning'); return; }
  await copyText(entry.pass, 'Password copied (30s)');
}

async function copyTotp(entry) {
  if (!entry.totp) { toast('No TOTP secret', 'warning'); return; }
  const r = await vaultAPI.totp(entry.totp);
  if (!r.ok) { toast('TOTP error: ' + r.error, 'error'); return; }
  await copyText(r.code, `TOTP ${r.code} copied (${r.secondsLeft}s left)`, 2000);
}

function revealCardNumber(entry, row) {
  // Toggle between masked and revealed on the subtitle line.
  const sub = row.querySelector('.entry-subtitle');
  if (sub.dataset.revealed === '1') {
    sub.textContent = formatCardNumberPreview(entry.cardNumber);
    sub.dataset.revealed = '0';
  } else {
    sub.textContent = entry.cardNumber || '';
    sub.dataset.revealed = '1';
    // Auto-hide after 10s
    setTimeout(() => {
      if (sub.dataset.revealed === '1') {
        sub.textContent = formatCardNumberPreview(entry.cardNumber);
        sub.dataset.revealed = '0';
      }
    }, 10000);
  }
}

async function toggleFavorite(entry) {
  entry.fav = entry.fav ? 0 : 1;
  entry.updated = Date.now();
  // D2 FIX: Increment _version on every edit for merge conflict resolution.
  entry._version = (entry._version || 0) + 1;
  entry._edited = true;
  // D18 FIX: Mark dirty and save snapshot before mutation.
  saveSnapshot();
  markDirty();
  await persistEntry(entry);
  clearDirty(); // persistEntry succeeded — clear dirty flag
  renderSidebar();
  renderEntryList();
  toast(entry.fav ? 'Added to favorites' : 'Removed from favorites', 'success', 1500);
}

async function moveEntryToFolder(entry, folder) {
  entry.folder = folder;
  entry.updated = Date.now();
  // D2 FIX: Increment _version on every edit.
  entry._version = (entry._version || 0) + 1;
  entry._edited = true;
  // D18 FIX: Mark dirty and save snapshot before mutation.
  saveSnapshot();
  markDirty();
  await persistEntry(entry);
  clearDirty();
  renderSidebar();
  renderEntryList();
}

async function moveToTrash(entry) {
  // Mark deleted locally — it disappears from the main list but stays in
  // state.entries until "Empty Trash" or "Delete Permanently" removes it
  // for good.
  entry.deleted = true;
  entry.deletedAt = Date.now();
  entry.updated = Date.now();
  // D2 FIX: Increment _version on every edit for merge conflict resolution.
  entry._version = (entry._version || 0) + 1;
  entry._edited = true;

  // Persist the deleted flag in BOTH modes. The device firmware round-trips
  // a `del` flag per entry (see persistEntry's deviceEntry payload) — the
  // previous code only pushed this to the SD card and silently skipped
  // device mode entirely, so on device the trash only existed in the
  // Electron app's in-memory state and reverted the moment you reconnected
  // or reloaded. Pass the entry's own index so this updates it in place
  // instead of being treated as a new entry (which duplicated it).
  //
  // v6.1: forceUpdate=true ensures this NEVER falls through to deviceAddEntry
  // even if _index is somehow null. Moving to trash must never create a
  // duplicate — if we can't find the device index, warn the user instead.
  const idx = state.entries.indexOf(entry);
  if (state.mode === 'device' && (idx < 0 || state.entries[idx]._index === null)) {
    toast('Cannot move to trash: entry has no device index. Re-sync from device and try again.', 'error', 4000);
    entry.deleted = false;
    entry.deletedAt = 0;
    return;
  }

  // v6.3: Stash the device index before persistEntry — persistEntry calls
  // loadDeviceEntries() on success, which rebuilds state.entries from
  // scratch and invalidates the `entry` reference's position in the array.
  const deviceIndex = state.entries[idx]._index;
  const expectedSite = entry.site;

  await persistEntry(entry, idx, /*forceUpdate*/ true);

  // v6.3 VERIFY: After persistEntry + loadDeviceEntries, find the entry
  // by its device index and confirm the del flag actually persisted on
  // the device. This catches the v6.2 silent-failure bug where the
  // update IPC returned ok but the del flag was squashed to 0 by
  // toDeviceEntry's missing-field check. Without this verification, the
  // toast said "Moved to trash" but the entry stayed in the vault.
  if (state.mode === 'device') {
    const verified = state.entries.find(e =>
      e._index === deviceIndex || (e.site === expectedSite)
    );
    if (!verified) {
      toast('Move to trash failed: entry not found after update. Re-sync from device.', 'error', 4000);
      return;
    }
    if (!verified.deleted) {
      // The device returned del=0 even though we sent del=1. This is the
      // signature of the v6.2 toDeviceEntry bug, or a firmware/SD issue.
      toast('Move to trash failed on device — del flag did not persist. Re-sync and try again.', 'error', 4500);
      // Restore local state to match device reality.
      verified.deleted = false;
      verified.deletedAt = 0;
      renderSidebar();
      renderEntryList();
      updateStatusbar();
      return;
    }
  }

  renderSidebar();
  renderEntryList();
  updateStatusbar();
  toast('Moved to trash', 'success', 1500);
}

async function restoreEntry(entry) {
  entry.deleted = false;
  entry.deletedAt = 0;
  entry.updated = Date.now();
  // D2 FIX: Increment _version on every edit for merge conflict resolution.
  entry._version = (entry._version || 0) + 1;
  entry._edited = true;
  // Pass the entry's own index — without it this is treated as a new
  // entry and duplicates it instead of updating in place.
  //
  // v6.1: forceUpdate=true — restoring from trash must never create a
  // duplicate either.
  const idx = state.entries.indexOf(entry);
  if (state.mode === 'device' && (idx < 0 || state.entries[idx]._index === null)) {
    toast('Cannot restore: entry has no device index. Re-sync from device and try again.', 'error', 4000);
    entry.deleted = true;
    return;
  }

  // v6.3: Stash index + site for post-update verification (same rationale
  // as moveToTrash).
  const deviceIndex = state.entries[idx]._index;
  const expectedSite = entry.site;

  await persistEntry(entry, idx, /*forceUpdate*/ true);

  // v6.3 VERIFY: Confirm the del flag was actually cleared on the device.
  if (state.mode === 'device') {
    const verified = state.entries.find(e =>
      e._index === deviceIndex || (e.site === expectedSite)
    );
    if (!verified) {
      toast('Restore failed: entry not found after update. Re-sync from device.', 'error', 4000);
      return;
    }
    if (verified.deleted) {
      toast('Restore failed on device — del flag did not clear. Re-sync and try again.', 'error', 4500);
      verified.deleted = true;
      renderSidebar();
      renderEntryList();
      updateStatusbar();
      return;
    }
  }

  renderSidebar();
  renderEntryList();
  updateStatusbar();
  toast('Restored from trash', 'success', 1500);
}

async function deletePermanently(entry) {
  // D18 FIX: Confirm before destructive operation.
  if (!confirmIfDirty(`Permanently delete "${entry.site}"? This cannot be undone. You have unsaved changes that will be lost.`)) {
    if (state._dirty) toast('Operation cancelled — you have unsaved changes.', 'warning', 2500);
    return;
  }
  if (!confirm(`Permanently delete "${entry.site}"? This cannot be undone.`)) return;
  const idx = state.entries.indexOf(entry);
  if (idx < 0) return;

  // Physically delete from device or SD card FIRST (before mutating local
  // state), so a failure doesn't leave the UI showing an entry that's
  // still on the device.
  if (state.mode === 'device' && entry._index !== null) {
    const r = await vaultAPI.deviceDeleteEntry(entry._index);
    if (!r || !r.ok) {
      toast('Device delete failed: ' + (r ? r.error : 'no response'), 'error', 3500);
      // Re-sync to make sure local state matches device reality.
      await loadDeviceEntries();
      return;
    }
    // v6.2: Re-fetch from device so all remaining entries get their
    // fresh (post-shift) _index values. Without this, the renderer's
    // in-memory _index for every entry AFTER the deleted one is stale
    // by 1, and the next delete/move-to-trash would target the wrong
    // entry — the root cause of the "same entry appears in trash AND
    // vault" duplicate bug.
    await loadDeviceEntries();
  } else if (state.mode === 'sdcard') {
    // SD card mode: remove from local state then re-save the whole file.
    // D18 FIX: Save snapshot before mutation, restore on failure.
    saveSnapshot();
    markDirty();
    state.entries.splice(idx, 1);
    const r = await vaultAPI.vaultSave(state.sdRoot, entriesForFirmware(state.entries));
    if (!r.success) { toast('Save failed: ' + r.error, 'error'); restoreFromSnapshot(); return; }
    clearDirty();
    renderSidebar();
    renderEntryList();
    updateStatusbar();
  }
  toast('Entry deleted', 'success', 1500);
}

$('#btn-empty-trash').addEventListener('click', async () => {
  const trashEntries = state.entries.filter(e => e.deleted);
  if (trashEntries.length === 0) { toast('Trash is already empty', 'info'); return; }
  if (!confirm(`Permanently delete ${trashEntries.length} entries from trash?`)) return;

  // v6.2 INDEX-SHIFT FIX: The firmware's deleteEntry(idx) does an in-memory
  // memmove that shifts all entries AFTER idx down by 1. So if we delete
  // index 2 then index 3, the second delete fails (entry 3 became entry 2
  // after the first delete, so index 3 is now out of range) — leaving the
  // entry on the device. The UI then reloads from device and the "deleted"
  // entry reappears.
  //
  // Fix: sort by _index DESCENDING and delete highest first. Deleting
  // index N never invalidates indices < N, so this is safe for batch
  // deletion without re-fetching the list between each call.
  if (state.mode === 'device') {
    const sorted = [...trashEntries].sort((a, b) => {
      const ai = (typeof a._index === 'number') ? a._index : -1;
      const bi = (typeof b._index === 'number') ? b._index : -1;
      return bi - ai;  // descending
    });
    let okCount = 0;
    let failCount = 0;
    for (const entry of sorted) {
      if (entry._index === null) { failCount++; continue; }
      const r = await vaultAPI.deviceDeleteEntry(entry._index);
      if (r && r.ok) okCount++; else failCount++;
    }
    if (failCount > 0) {
      toast(`Deleted ${okCount}, ${failCount} failed. Re-syncing from device...`, 'warning', 3500);
    }
  }

  // Remove trashed entries from local state
  state.entries = state.entries.filter(e => !e.deleted);

  // In SD card mode, save the updated state
  if (state.mode === 'sdcard') {
    // D18 FIX: Save snapshot before mutation, restore on failure.
    saveSnapshot();
    markDirty();
    const r = await vaultAPI.vaultSave(state.sdRoot, entriesForFirmware(state.entries));
    if (!r.success) { toast('Save failed: ' + r.error, 'error'); restoreFromSnapshot(); return; }
    clearDirty();
  }

  // v6.2: In device mode, ALWAYS re-fetch from device after Empty Trash
  // to guarantee the local state matches what's actually on the SD card.
  // The per-delete loop above is correct (descending order), but a final
  // sync is the safety net for any edge case (e.g., delete failed silently
  // due to a flaky USB connection).
  if (state.mode === 'device') {
    await loadDeviceEntries();
  } else {
    renderSidebar();
    renderEntryList();
    updateStatusbar();
  }

  toast('Trash emptied', 'success', 1500);
});

// ═══════════════════════════════════════════════════════════════════════
//  Add/Edit modal — all 4 entry types
// ═══════════════════════════════════════════════════════════════════════
$('#btn-add-entry').addEventListener('click', () => openEditModal(null));
$('#btn-empty-add').addEventListener('click', () => openEditModal(null));

function openEditModal(entry) {
  state.editingIndex = entry ? state.entries.indexOf(entry) : null;
  const isEdit = !!entry;

  $('#modal-title').textContent = isEdit ? 'Edit Entry' : 'Add Entry';
  $('#btn-modal-delete').classList.toggle('hidden', !isEdit);

  // Reset all fields
  $$('[data-type-fields]').forEach(f => f.classList.add('hidden'));
  $$('#type-segmented .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.type === 'login'));

  // Default to login for new entries
  const e = entry ? { ...entry } : { type: 'login', fav: 0, tags: [], folder: '' };

  // Set type selector
  setModalType(e.type || 'login');

  // Populate login fields
  $('#field-site').value  = e.site || '';
  $('#field-url').value   = e.url || '';
  $('#field-user').value  = e.user || '';
  $('#field-pass').value  = e.pass || '';
  $('#field-totp').value  = e.totp || '';
  $('#field-notes').value = e.notes || '';

  // Card fields — check both renderer-style (cardHolder, cardExpiry, cardCvv)
  // and firmware-style (cardholder, exp, cvv) field names.
  $('#field-card-name').value    = (e.type === 'card' ? e.site : '') || '';
  $('#field-card-holder').value  = e.cardHolder || e.cardholder || '';
  $('#field-card-number').value  = e.cardNumber || '';
  $('#field-card-expiry').value  = e.cardExpiry || e.exp || '';
  $('#field-card-cvv').value     = e.cardCvv || e.cvv || '';
  $('#field-card-notes').value   = (e.type === 'card' ? e.notes : '') || '';
  $('#card-brand-display').textContent = e.cardBrand || detectCardBrand(e.cardNumber);

  // Identity fields — check both renderer-style (idFirstName) and firmware-style
  // (firstName) field names. Entries loaded from the device use firstName/lastName
  // etc. (from the firmware's SV_WRITE_ENTRY_TO_JSON), while entries created
  // locally use idFirstName/idLastName (from collectEntryFromForm). Both must
  // work so editing an existing identity entry doesn't show blank fields.
  $('#field-id-name').value     = (e.type === 'identity' ? e.site : '') || '';
  $('#field-id-first').value    = e.idFirstName || e.firstName || '';
  $('#field-id-last').value     = e.idLastName  || e.lastName  || '';
  $('#field-id-email').value    = e.idEmail     || e.email     || '';
  $('#field-id-phone').value    = e.idPhone     || e.phone     || '';
  $('#field-id-address').value  = e.idAddress   || e.address   || '';
  $('#field-id-city').value     = e.idCity      || e.city      || '';
  $('#field-id-state').value    = e.idState     || e.state     || '';
  $('#field-id-postal').value   = e.idPostal    || e.postal    || '';
  $('#field-id-country').value  = e.idCountry   || e.country   || '';
  $('#field-id-ssn').value      = e.idSsn       || e.ssn       || '';
  $('#field-id-passport').value = e.idPassport  || e.passport  || '';
  $('#field-id-license').value  = e.idLicense   || e.license   || '';
  $('#field-id-notes').value    = (e.type === 'identity' ? e.notes : '') || '';

  // Note fields
  $('#field-note-title').value   = (e.type === 'note' ? e.site : '') || '';
  $('#field-note-content').value = (e.type === 'note' ? e.notes : '') || '';

  // Shared
  $('#field-folder').value  = e.folder || '';
  $('#field-tags').value    = (e.tags || []).join(', ');
  $('#field-favorite').checked = !!e.fav;

  // Populate folder datalist
  const folders = new Set();
  for (const ent of state.entries) if (ent.folder) folders.add(ent.folder);
  const dl = $('#folder-datalist');
  dl.innerHTML = '';
  for (const f of folders) dl.appendChild(el('option', { value: f }));

  // Reset strength meter
  updateStrengthMeter();

  // Show modal
  $('#modal-backdrop').classList.remove('hidden');
  setTimeout(() => focusFirstModalField(e.type || 'login'), 50);

  // Breach check row — only show when HIBP is enabled. Also clear any stale
  // badge from a previous open / password. Done AFTER the modal is shown so
  // the user sees the row appear asynchronously (the IPC round-trip is fast
  // but non-zero); the form is usable immediately either way.
  vaultAPI.getHibpEnabled().then((s) => {
    $('#breach-check-row').classList.toggle('hidden', !s.enabled);
  }).catch(() => { $('#breach-check-row').classList.add('hidden'); });
  const _bb = $('#breach-badge');
  _bb.className = 'breach-badge';
  _bb.textContent = '';
}

function focusFirstModalField(type) {
  const map = {
    login:    '#field-site',
    card:     '#field-card-name',
    identity: '#field-id-name',
    note:     '#field-note-title',
  };
  const el_ = $(map[type] || '#field-site');
  if (el_) el_.focus();
}

function setModalType(type) {
  $$('#type-segmented .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.type === type));
  $$('[data-type-fields]').forEach(f => {
    f.classList.toggle('hidden', f.dataset.typeFields !== type);
  });
}

$$('#type-segmented .seg-btn').forEach(btn => {
  btn.addEventListener('click', () => setModalType(btn.dataset.type));
});

$('#btn-modal-close').addEventListener('click', closeModal);
$('#btn-modal-cancel').addEventListener('click', closeModal);
$('#modal-backdrop').addEventListener('click', (e) => {
  if (e.target.id === 'modal-backdrop') closeModal();
});

function closeModal() {
  $('#modal-backdrop').classList.add('hidden');
  state.editingIndex = null;
  stopTotpPreview();
}

// ── Password show/hide + strength meter ──
$('#btn-toggle-pass').addEventListener('click', () => {
  const f = $('#field-pass');
  f.type = f.type === 'password' ? 'text' : 'password';
});

$('#field-pass').addEventListener('input', updateStrengthMeter);
// Clear any stale breach-check badge as soon as the user edits the password
// — the previously-checked result no longer applies to the new value.
$('#field-pass').addEventListener('input', () => {
  const badge = $('#breach-badge');
  badge.className = 'breach-badge';
  badge.textContent = '';
});

async function updateStrengthMeter() {
  const pwd = $('#field-pass').value;
  if (!pwd) {
    $('#strength-fill').className = 'strength-fill';
    $('#strength-label').textContent = '';
    return;
  }
  const s = await vaultAPI.passwordStrength(pwd);
  $('#strength-fill').className = 'strength-fill score-' + s.score;
  $('#strength-label').textContent = `${s.label} (${s.entropy} bits)`;
}

// ── Password generator button → opens generator modal ──
$('#btn-generate-pass').addEventListener('click', () => openGenerator('login'));

// ── TOTP live preview ──
$('#field-totp').addEventListener('input', () => {
  const secret = $('#field-totp').value.trim();
  if (!secret) {
    $('#totp-preview').classList.add('hidden');
    stopTotpPreview();
    return;
  }
  $('#totp-preview').classList.remove('hidden');
  startTotpPreview(secret);
});

async function startTotpPreview(secret) {
  stopTotpPreview();
  const update = async () => {
    const r = await vaultAPI.totp(secret);
    if (!r.ok) {
      $('#totp-code').textContent = '------';
      $('#totp-seconds').textContent = 'invalid';
      $('#totp-bar').style.width = '0%';
      return;
    }
    $('#totp-code').textContent = r.code;
    $('#totp-seconds').textContent = r.secondsLeft + 's';
    $('#totp-bar').style.width = (r.secondsLeft / 30 * 100) + '%';
    $('#totp-bar').style.background = r.secondsLeft <= 5 ? 'var(--danger)' : 'var(--success)';
  };
  await update();
  state.totpInterval = setInterval(update, 1000);
}

function stopTotpPreview() {
  if (state.totpInterval) {
    clearInterval(state.totpInterval);
    state.totpInterval = null;
  }
}

$('#btn-copy-totp').addEventListener('click', async () => {
  const secret = $('#field-totp').value.trim();
  if (!secret) return;
  const r = await vaultAPI.totp(secret);
  if (!r.ok) { toast('TOTP error: ' + r.error, 'error'); return; }
  await copyText(r.code, `TOTP ${r.code} copied`, 2000);
});

// ── Card number auto-format + brand detection ──
$('#field-card-number').addEventListener('input', (e) => {
  let digits = e.target.value.replace(/\D/g, '').slice(0, 19);
  // Group in 4s
  const grouped = digits.match(/.{1,4}/g);
  e.target.value = grouped ? grouped.join(' ') : '';
  $('#card-brand-display').textContent = detectCardBrand(digits);
});

$('#field-card-expiry').addEventListener('input', (e) => {
  let digits = e.target.value.replace(/\D/g, '').slice(0, 4);
  if (digits.length >= 3) digits = digits.slice(0, 2) + '/' + digits.slice(2);
  e.target.value = digits;
});

$('#btn-toggle-cvv').addEventListener('click', () => {
  const f = $('#field-card-cvv');
  f.type = f.type === 'password' ? 'text' : 'password';
});

// ═══════════════════════════════════════════════════════════════════════
//  Save entry — collect form data, persist via device or SD card
// ═══════════════════════════════════════════════════════════════════════
$('#btn-modal-save').addEventListener('click', async () => {
  const type = $('#type-segmented .seg-btn.active').dataset.type;
  const entry = collectEntryFromForm(type);
  if (!entry) return;  // collectEntryFromForm shows its own error toast

  entry.updated = Date.now();
  if (state.editingIndex === null) entry.created = Date.now();
  // D2 FIX: Increment _version on every edit so merge logic can use the
  // version counter instead of timestamps (which are unreliable for
  // device-sourced entries that all get Date.now() at sync time).
  if (state.editingIndex !== null) {
    entry._version = (state.entries[state.editingIndex]._version || 0) + 1;
    // Preserve the existing UUID if editing — never change an entry's id.
    entry.id = state.entries[state.editingIndex].id || entry.id;
  } else {
    entry._version = 1;
  }
  entry._edited = true;  // D2: flag that this entry was explicitly edited on this side

  await persistEntry(entry, state.editingIndex);
  closeModal();
  renderSidebar();
  renderEntryList();
  updateStatusbar();
  toast(state.editingIndex === null ? 'Entry added' : 'Entry updated', 'success', 1500);
});

$('#btn-modal-delete').addEventListener('click', async () => {
  if (state.editingIndex === null) return;
  const entry = state.entries[state.editingIndex];
  if (!entry) return;
  if (!confirm(`Move "${entry.site}" to trash?\n\nYou can restore it from the Trash later, or delete it permanently from there.`)) return;
  await moveToTrash(entry);
  closeModal();
});

function collectEntryFromForm(type) {
  const now = Date.now();
  const base = {
    type,
    fav: $('#field-favorite').checked ? 1 : 0,
    folder: $('#field-folder').value.trim().slice(0, 23),
    tags: $('#field-tags').value.split(',').map(s => s.trim()).filter(Boolean).slice(0, 32),
    updated: now,
  };
  // Preserve created/deleted timestamps if editing
  if (state.editingIndex !== null && state.entries[state.editingIndex]) {
    const orig = state.entries[state.editingIndex];
    base.created = orig.created || now;
    base.deleted = orig.deleted;
    base.deletedAt = orig.deletedAt;
    base._source = orig._source;
    base._index = orig._index;
  } else {
    base.created = now;
    base.deleted = false;
    base.deletedAt = 0;
  }

  if (type === 'login') {
    const site = $('#field-site').value.trim();
    if (!site) { toast('Site name is required', 'warning'); return null; }
    return {
      ...base,
      site: site.slice(0, 31),
      url: $('#field-url').value.trim().slice(0, 63),
      user: $('#field-user').value.slice(0, 47),
      pass: $('#field-pass').value.slice(0, 47),
      totp: $('#field-totp').value.trim().slice(0, 31).toUpperCase(),
      notes: $('#field-notes').value.slice(0, 159),
    };
  }
  if (type === 'card') {
    const name = $('#field-card-name').value.trim();
    if (!name) { toast('Card name is required', 'warning'); return null; }
    return {
      ...base,
      site: name.slice(0, 31),
      user: '', pass: '', totp: '',  // firmware-visible fields
      // Both Electron-internal (cardHolder) and firmware-canonical
      // (cardholder) names -- same reason as identity below: vaultCrypto.js
      // and the firmware only ever read the plain names, so without this
      // the cardholder/exp/cvv silently don't round-trip through a save+
      // reload in SD-card file mode (they're never dropped in device mode
      // because persistEntry()'s device branch re-derives them from
      // cardHolder directly, but the file-saved copy has no such repair
      // step on the way back in).
      cardHolder: $('#field-card-holder').value.slice(0, 31),
      cardholder: $('#field-card-holder').value.slice(0, 31),
      cardNumber: $('#field-card-number').value.replace(/\s/g, '').slice(0, 23),
      cardBrand: detectCardBrand($('#field-card-number').value),
      cardExpiry: $('#field-card-expiry').value.slice(0, 7),
      exp:        $('#field-card-expiry').value.slice(0, 7),
      cardCvv: $('#field-card-cvv').value.slice(0, 4),
      cvv:     $('#field-card-cvv').value.slice(0, 4),
      notes: $('#field-card-notes').value.slice(0, 159),
    };
  }
  if (type === 'identity') {
    const name = $('#field-id-name').value.trim();
    if (!name) { toast('Identity name is required', 'warning'); return null; }
    return {
      ...base,
      site: name.slice(0, 31),
      user: '', pass: '', totp: '',
      // v12.0: Include BOTH firmware-style (firstName) and Electron-style
      // (idFirstName) field names so toDeviceEntry() finds them either way
      firstName:   $('#field-id-first').value.trim().slice(0, 23),
      lastName:    $('#field-id-last').value.trim().slice(0, 23),
      idFirstName: $('#field-id-first').value.trim().slice(0, 23),
      idLastName:  $('#field-id-last').value.trim().slice(0, 23),
      email:       $('#field-id-email').value.slice(0, 47),
      idEmail:     $('#field-id-email').value.slice(0, 47),
      phone:       $('#field-id-phone').value.slice(0, 19),
      idPhone:     $('#field-id-phone').value.slice(0, 19),
      address:     $('#field-id-address').value.slice(0, 47),
      idAddress:   $('#field-id-address').value.slice(0, 47),
      city:        $('#field-id-city').value.trim().slice(0, 23),
      idCity:      $('#field-id-city').value.trim().slice(0, 23),
      state:       $('#field-id-state').value.trim().slice(0, 23),
      idState:     $('#field-id-state').value.trim().slice(0, 23),
      postal:      $('#field-id-postal').value.trim().slice(0, 11),
      idPostal:    $('#field-id-postal').value.trim().slice(0, 11),
      country:     $('#field-id-country').value.trim().slice(0, 23),
      idCountry:   $('#field-id-country').value.trim().slice(0, 23),
      ssn:         $('#field-id-ssn').value.slice(0, 15),
      idSsn:       $('#field-id-ssn').value.slice(0, 15),
      passport:    $('#field-id-passport').value.slice(0, 23),
      idPassport:  $('#field-id-passport').value.slice(0, 23),
      license:     $('#field-id-license').value.slice(0, 23),
      idLicense:   $('#field-id-license').value.slice(0, 23),
      notes:       $('#field-id-notes').value.slice(0, 159),
    };
  }
  if (type === 'note') {
    const title = $('#field-note-title').value.trim();
    if (!title) { toast('Title is required', 'warning'); return null; }
    return {
      ...base,
      site: title.slice(0, 31),
      user: '', pass: '', totp: '',
      notes: $('#field-note-content').value.slice(0, 159),
    };
  }
  return null;
}

/**
 * Persist an entry — to the ESP32 (if in device mode) or to vault.db (if in
 * SD card mode). For device mode, the firmware only accepts {site, user,
 * pass, totp} — extended fields (notes, folder, tags, card*, id*) are
 * desktop-only and NOT pushed to the device. They live only in the .svlt
 * file that's auto-written for the browser extension.
 *
 * For SD card mode, the full extended entry is saved to vault.db.
 */
// Prepare entries for SD-card-file persistence. Two things happen here:
//
// 1. Normalize fav/del (see below).
// 2. Strip the Electron-UI-only duplicate keys (cardHolder, cardExpiry,
//    cardCvv, idFirstName, idLastName, idEmail, idPhone, idAddress,
//    idCity, idState, idPostal, idCountry, idSsn, idPassport, idLicense,
//    idUsername) before writing to vault.db. Those exist so the UI's own
//    internal state (see normalizeEntryForUi) works regardless of which
//    naming convention a field arrived under -- but the firmware and
//    vaultCrypto.js's normalizeEntry() only ever read the plain names
//    (cardholder, exp, cvv, firstName, ...), so writing both to disk is
//    redundant bloat in every saved record, not something either reader
//    needs. This matters because vault.db is the same file the firmware
//    itself reads if the SD card is later inserted into the device.
//
// NOTE: `type` stays a STRING here ('login'/'card'/'identity'/'note') on
// purpose. This function used to coerce it to a number, which made every
// non-login entry fail vaultCrypto.js's validateEntries() (it requires a
// string) — see audit §4.5. Do not reintroduce a string->number
// conversion for `type` in this function.
const ELECTRON_ONLY_DUP_KEYS = [
  'cardHolder', 'cardExpiry', 'cardCvv',
  'idFirstName', 'idLastName', 'idEmail', 'idPhone', 'idAddress',
  'idCity', 'idState', 'idPostal', 'idCountry', 'idSsn', 'idPassport',
  'idLicense', 'idUsername',
  // D2: _edited is renderer-internal bookkeeping (not stored in vault.db
  // or .svlt — it's only used for merge conflict resolution within the
  // same session).
  '_edited',
];

/**
 * v6.4 SYNC FIX: Synthesize a stable id for entries that don't have one.
 * The browser extension requires `id` for edit/delete/trash/restore — without
 * it, every entry synced from the SD-card path is a read-only ghost in the
 * extension. We use a deterministic hash of (type + site + user) so the same
 * logical entry produces the same id across re-saves (the extension uses id
 * to match edit operations; an unstable id would break edit/delete after a
 * re-sync).
 *
 * This runs both in the renderer and the main process — the algorithm MUST
 * stay identical on both sides. Do not change one without changing the other.
 */
// D3+D6 FIX: Replaced synthesizeEntryId (which hashed type|site|user into a
// deterministic FNV-like ID) with crypto.randomUUID(). The old approach had
// two critical bugs:
//   1. Two accounts on the same site with the same user would synthesize the
//      SAME ID, causing them to merge/overwrite during sync.
//   2. If an entry's site or user was edited, its synthesized ID changed,
//      making it appear as a new entry during merge (old ID stays in the
//      map as a stale orphan, new ID creates a duplicate).
// crypto.randomUUID() provides truly unique, stable IDs — each entry gets
// one UUID on creation that never changes regardless of field edits.
// The function is kept as a thin wrapper for backward compat and to ensure
// existing entries with a proper `id` field keep it.
function synthesizeEntryId(e) {
  if (e.id && typeof e.id === 'string') return e.id;
  // New entries without an id get a fresh UUID. This is stable across edits
  // (the UUID is assigned once and never changes).
  return crypto.randomUUID();
}

function entriesForFirmware(entries) {
  return entries.map((e, i) => {
    // v6.4 SYNC FIX: Emit BOTH naming conventions for fav/del so every
    // downstream reader (firmware wants fav/del numerics; extension wants
    // favorite/deleted booleans) sees a consistent, correctly-typed value.
    // Previously only fav/del (numeric) were emitted; favorite (boolean)
    // was missing → the extension's Favorites filter silently showed 0
    // entries even when the user had favorites flagged in Electron.
    const isFav = !!(e.fav || e.favorite);
    const isDel = !!(e.del || e.deleted);
    const now = Date.now();

    const out = {
      ...e,
      // Firmware-style numerics (0/1)
      fav: isFav ? 1 : 0,
      del: isDel ? 1 : 0,
      // Extension-style booleans — these MUST be present so the extension's
      // filters (which check `entry.favorite` and `entry.deleted`) work.
      favorite: isFav,
      deleted: isDel,

      // Extension identity + display fields. The extension uses `name` as
      // the entry title and `id` for edit/delete/trash. SD-card-sourced
      // entries have `site` but not `name`, and never have `id` — so
      // synthesize them here so the extension sees a complete record.
      id: synthesizeEntryId(e),
      name: e.name || e.site || '',

      // Timestamps — the extension sorts by `updated`. normalizeEntryForUi
      // already sets these, but older vault.db files may not have them.
      created: Number(e.created) || now,
      updated: Number(e.updated) || now,
      deletedAt: isDel ? (Number(e.deletedAt) || now) : 0,
    };

    for (const k of ELECTRON_ONLY_DUP_KEYS) delete out[k];
    // Never leak renderer-internal bookkeeping fields into the .svlt file.
    delete out._source;
    delete out._index;
    // D2: _version is NOT deleted here — it needs to round-trip through
    // vault.db and .svlt for merge conflict resolution. _edited IS deleted
    // (added to ELECTRON_ONLY_DUP_KEYS above) because it's session-only.
    return out;
  });
}

async function persistEntry(entry, editIndex = null, forceUpdate = false) {
  const isEdit = editIndex !== null && editIndex >= 0 && editIndex < state.entries.length;

  if (state.mode === 'device') {
    // Device firmware sees the full entry schema: site, user, pass, totp,
    // type, fav, del, PLUS per-type extra fields (notes, folder, card*,
    // identity*). The old code only sent {site,user,pass,totp,type,fav,del}
    // which meant all identity/card/note data was silently dropped on
    // device — the entry appeared as a login with empty extras.
    const typeNum = { login: 0, card: 1, identity: 2, note: 3 }[entry.type] || 0;
    const deviceEntry = {
      site: entry.site,
      user: entry.user || '',
      pass: entry.pass || '',
      totp: entry.totp || '',
      type: typeNum,
      fav: entry.fav ? 1 : 0,
      // v6.3 FIX: Send BOTH `del` (numeric, what the firmware reads via
      // SV_READ_ENTRY_FROM_JSON) AND `deleted` (boolean, what main.js's
      // toDeviceEntry() reads). The previous version only sent `del`,
      // but main.js re-transforms this object through toDeviceEntry()
      // which used to read only `deleted` — causing the del flag to be
      // silently reset to 0 (the "Move to Trash silently fails" bug).
      // Sending both makes the round-trip resilient even if only one
      // naming convention is checked downstream.
      del: entry.deleted ? 1 : 0,
      deleted: entry.deleted ? true : false,
      favorite: entry.fav ? true : false,
      // Shared extras (all types)
      notes:  entry.notes || '',
      folder: entry.folder || '',
    };

    // LOGIN extras
    if (typeNum === 0) {
      deviceEntry.url = entry.url || '';
    }

    // CARD extras
    if (typeNum === 1) {
      deviceEntry.cardholder = entry.cardHolder || '';
      deviceEntry.cardNumber = entry.cardNumber || '';
      deviceEntry.exp        = entry.cardExpiry || '';
      deviceEntry.cvv        = entry.cardCvv || '';
    }

    // IDENTITY extras — map Electron internal field names (idEmail, etc.)
    // to firmware field names (email, firstName, etc.) that the firmware's
    // SV_READ_ENTRY_FROM_JSON macro expects.
    if (typeNum === 2) {
      deviceEntry.firstName = entry.idFirstName || '';
      deviceEntry.lastName  = entry.idLastName  || '';
      deviceEntry.email     = entry.idEmail     || '';
      deviceEntry.phone     = entry.idPhone     || '';
      deviceEntry.address   = entry.idAddress   || '';
      deviceEntry.city      = entry.idCity      || '';
      deviceEntry.state     = entry.idState     || '';
      deviceEntry.postal    = entry.idPostal    || '';
      deviceEntry.country   = entry.idCountry   || '';
      deviceEntry.ssn       = entry.idSsn       || '';
      deviceEntry.passport  = entry.idPassport  || '';
      deviceEntry.license   = entry.idLicense   || '';
    }

    // v6.1: Decide update vs add. forceUpdate=true means the caller
    // (moveToTrash/restoreEntry) is modifying an existing entry and must
    // NEVER fall through to deviceAddEntry (which would duplicate it).
    // If forceUpdate is set but we don't have a valid _index, that's a
    // bug — refuse rather than silently duplicate.
    const hasValidIndex = isEdit && state.entries[editIndex]._index !== null;
    if (forceUpdate && !hasValidIndex) {
      toast('Internal error: cannot update entry without a device index. Re-sync from device.', 'error', 4000);
      return;
    }

    if (hasValidIndex) {
      const r = await vaultAPI.deviceUpdateEntry(state.entries[editIndex]._index, deviceEntry);
      if (!r.ok) { toast('Device update failed: ' + r.error, 'error'); return; }
      // Re-fetch the full device list to get fresh indices.
      await loadDeviceEntries();
    } else {
      const r = await vaultAPI.deviceAddEntry(deviceEntry);
      if (!r.ok) { toast('Device add failed: ' + r.error, 'error'); return; }
      await loadDeviceEntries();
    }

    // Cache URL → site-name mapping for the extension .svlt file.
    if (entry.url) await vaultAPI.urlCacheSet(entry.site, entry.user || '', entry.url); // D13 FIX: pass (site, user, url)

    // The device list reload already auto-wrote the .svlt file (in main.js).
  } else if (state.mode === 'sdcard') {
    if (isEdit) {
      state.entries[editIndex] = entry;
    } else {
      state.entries.push(entry);
    }
    const r = await vaultAPI.vaultSave(state.sdRoot, entriesForFirmware(state.entries));
    if (!r.success) {
      toast('Save failed: ' + r.error, 'error');
      // D18 FIX: Restore from snapshot on save failure instead of
      // incomplete rollback (old code couldn't fully roll back edits).
      restoreFromSnapshot();
      return;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Password Generator modal — random + passphrase modes
// ═══════════════════════════════════════════════════════════════════════
let genMode = 'random';
let genTargetField = null;  // where to inject the generated password

function openGenerator(targetType = 'login') {
  $('#gen-backdrop').classList.remove('hidden');
  genTargetField = targetType === 'login' ? $('#field-pass') : null;
  setGenMode('random');
  refreshGenerator();
  setTimeout(() => $('#btn-gen-use').focus(), 50);
}

function setGenMode(mode) {
  genMode = mode;
  $$('.gen-mode-tabs .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.genMode === mode));
  $$('[data-gen-fields]').forEach(f => f.classList.toggle('hidden', f.dataset.genFields !== mode));
}

$$('.gen-mode-tabs .seg-btn').forEach(btn => {
  btn.addEventListener('click', () => { setGenMode(btn.dataset.genMode); refreshGenerator(); });
});

$('#btn-gen-close').addEventListener('click', () => $('#gen-backdrop').classList.add('hidden'));
$('#btn-gen-refresh').addEventListener('click', refreshGenerator);
$('#gen-backdrop').addEventListener('click', (e) => {
  if (e.target.id === 'gen-backdrop') $('#gen-backdrop').classList.add('hidden');
});

// Sliders update their labels + regenerate live
$('#gen-length').addEventListener('input', (e) => {
  $('#gen-length-val').textContent = e.target.value;
  refreshGenerator();
});
$('#gen-wordcount').addEventListener('input', (e) => {
  $('#gen-wordcount-val').textContent = e.target.value;
  refreshGenerator();
});
['gen-uppercase', 'gen-lowercase', 'gen-numbers', 'gen-symbols', 'gen-avoid-ambiguous',
 'gen-capitalize', 'gen-include-number'].forEach(id => {
  $('#' + id).addEventListener('change', refreshGenerator);
});
$('#gen-separator').addEventListener('input', refreshGenerator);

async function refreshGenerator() {
  const options = genMode === 'passphrase' ? {
    passphrase: true,
    wordCount: parseInt($('#gen-wordcount').value, 10),
    separator: $('#gen-separator').value || '-',
    capitalize: $('#gen-capitalize').checked,
    includeNumber: $('#gen-include-number').checked,
  } : {
    length: parseInt($('#gen-length').value, 10),
    uppercase: $('#gen-uppercase').checked,
    lowercase: $('#gen-lowercase').checked,
    numbers: $('#gen-numbers').checked,
    symbols: $('#gen-symbols').checked,
    avoidAmbiguous: $('#gen-avoid-ambiguous').checked,
  };
  const r = await vaultAPI.generatePassword(options);
  if (!r.ok) { toast('Generator error: ' + r.error, 'error'); return; }
  $('#gen-output').value = r.password;
  // Update strength meter
  const s = await vaultAPI.passwordStrength(r.password);
  $('#gen-strength-fill').className = 'strength-fill score-' + s.score;
  $('#gen-strength-label').textContent = `${s.label} (${s.entropy} bits)`;
}

$('#btn-gen-copy').addEventListener('click', () => {
  const pwd = $('#gen-output').value;
  if (pwd) copyText(pwd, 'Password copied (30s)');
});

$('#btn-gen-use').addEventListener('click', () => {
  const pwd = $('#gen-output').value;
  if (!pwd) return;
  if (genTargetField) {
    genTargetField.value = pwd;
    updateStrengthMeter();
  } else {
    // No target field — just copy to clipboard.
    copyText(pwd, 'Password copied (30s)');
  }
  $('#gen-backdrop').classList.add('hidden');
});

// ═══════════════════════════════════════════════════════════════════════
//  Settings modal
// ═══════════════════════════════════════════════════════════════════════
$('#btn-settings').addEventListener('click', openSettings);
$('#btn-settings-close').addEventListener('click', () => $('#settings-backdrop').classList.add('hidden'));
$('#btn-settings-done').addEventListener('click', () => $('#settings-backdrop').classList.add('hidden'));
$('#settings-backdrop').addEventListener('click', (e) => {
  if (e.target.id === 'settings-backdrop') $('#settings-backdrop').classList.add('hidden');
});

// v6.2: The "Remove selftest-* entries" maintenance button was REMOVED.
// Reason: it was buggy (index-shift on sequential deletes left entries
// behind on the device) AND it was a band-aid for the real problem —
// the Python selftest script leaves entries behind when interrupted.
//
// The correct way to remove unwanted entries is to use the normal UI:
//   • To remove an entry from the vault: open it → "Move to Trash"
//   • To remove it permanently: go to Trash → "Delete Permanently"
//   • To clear all trashed entries at once: Trash view → "Empty Trash"
//
// The Empty Trash button now correctly handles index-shift by sorting
// the trash entries by descending _index before issuing DELETE requests,
// so deleting entry at index N doesn't invalidate the indices of entries
// at indices < N (which the firmware preserves after a hard delete).

async function openSettings() {
  // SD card path
  const savedSd = await vaultAPI.getSavedSDCard();
  $('#settings-sdcard-path').value = savedSd || '(not set)';

  // Backups
  if (state.sdRoot) {
    const backups = await vaultAPI.vaultListBackups(state.sdRoot);
    const list = $('#settings-backup-list');
    list.innerHTML = '';
    if (backups.length === 0) {
      list.appendChild(el('li', {}, el('span', { class: 'muted' }, 'No backups yet')));
    } else {
      for (const b of backups) {
        const date = new Date(b.mtime).toLocaleString();
        list.appendChild(el('li', {},
          el('span', {}, `${b.filename}  (${(b.size / 1024).toFixed(1)} KB, ${date})`),
          el('button', {
            class: 'restore-btn',
            onclick: async () => {
              if (!confirm('Restore this backup? Current vault.db will be safety-copied first.')) return;
              const r = await vaultAPI.vaultRestoreBackup(state.sdRoot, b.filename);
              if (r.success) toast('Backup restored — re-unlock to load it', 'success');
              else toast('Restore failed: ' + r.error, 'error');
            },
          }, 'Restore')
        ));
      }
    }
  }

  // Extension sync
  await refreshExtSyncStatus();
  const status = state.extSyncStatus || {};
  $('#extsync-enabled').checked = !!status.enabled;
  $('#extsync-filepath').value = status.filePath || '';
  $('#extsync-auto-sync').checked = !!status.autoWriteOnSync;
  $('#extsync-auto-edit').checked = !!status.autoWriteOnEdit;
  $('#extsync-password-status').textContent = status.hasPassword
    ? '✓ Master password is set (stored in OS keychain)'
    : '✗ No master password set — set one below to enable .svlt writes';
  $('#extsync-safestorage-status').textContent = status.safeStorageAvailable
    ? '✓ OS keychain available (safeStorage)'
    : '✗ OS keychain unavailable — master password cannot be persisted';

  // Breach detection (HIBP) — off by default. The toggle controls both the
  // per-entry "Check for breaches" button and the vault-wide health scan.
  let hibpEnabled = false;
  try {
    const hibpStatus = await vaultAPI.getHibpEnabled();
    hibpEnabled = !!hibpStatus.enabled;
  } catch { /* non-fatal */ }
  $('#settings-hibp').checked = hibpEnabled;
  $('#btn-health-scan').disabled = !hibpEnabled;
  $('#health-scan-result').textContent = '';

  $('#settings-backdrop').classList.remove('hidden');
}

$('#btn-settings-pick-sdcard').addEventListener('click', async () => {
  const chosen = await vaultAPI.selectSDCard();
  if (chosen) {
    state.sdRoot = chosen;
    $('#settings-sdcard-path').value = chosen;
    toast('SD card path updated', 'success', 1500);
  }
});

$('#btn-change-pin').addEventListener('click', async () => {
  const oldPin = $('#settings-old-pin').value;
  const newPin = $('#settings-new-pin').value;
  const confirmPin = $('#settings-new-pin-confirm').value;
  if (!oldPin || !newPin) { toast('Fill in current and new PIN', 'warning'); return; }
  if (newPin !== confirmPin) { toast('New PINs do not match', 'warning'); return; }
  if (newPin.length < 4) { toast('New PIN must be at least 4 characters', 'warning'); return; }
  if (!state.sdRoot) { toast('No SD card selected', 'warning'); return; }
  const r = await vaultAPI.vaultChangePin(state.sdRoot, oldPin, newPin);
  if (!r.success) { toast(r.error || 'PIN change failed', 'error'); return; }
  // D11 FIX: PIN is no longer stored in renderer. main.js's vaultChangePin
  // handler updates the cached PIN in the main process (as a Buffer).
  $('#settings-old-pin').value = '';
  $('#settings-new-pin').value = '';
  $('#settings-new-pin-confirm').value = '';
  toast('Master PIN changed', 'success');
});

// ── Extension sync settings handlers ──
$('#extsync-enabled').addEventListener('change', async (e) => {
  await vaultAPI.extSyncSetEnabled(e.target.checked);
  toast(e.target.checked ? 'Extension sync enabled' : 'Extension sync disabled', 'success', 1500);
  await refreshExtSyncStatus();
});

$('#btn-extsync-pick').addEventListener('click', async () => {
  const r = await vaultAPI.extSyncPickFilePath();
  if (r.ok) {
    $('#extsync-filepath').value = r.path;
    toast('File path set: ' + r.path, 'success', 2000);
    await refreshExtSyncStatus();
  } else if (!r.canceled) {
    toast('Pick failed: ' + r.error, 'error');
  }
});

$('#btn-extsync-set-password').addEventListener('click', async () => {
  const pw = $('#extsync-new-password').value;
  if (!pw || pw.length < 8) { toast('Password must be at least 8 characters', 'warning'); return; }
  const r = await vaultAPI.extSyncSetPassword(pw);
  if (!r.ok) { toast(r.error, 'error'); return; }
  $('#extsync-new-password').value = '';
  toast('Master password set', 'success');
  await refreshExtSyncStatus();
  openSettings(); // refresh the password-status line
});

$('#btn-extsync-change-password').addEventListener('click', async () => {
  const newPw = $('#extsync-new-password').value;
  if (!newPw || newPw.length < 8) { toast('New password must be at least 8 characters', 'warning'); return; }
  // D20 FIX: Replace prompt() with themed modal dialog for password verification.
  const oldPw = await showPasswordVerifyModal('Enter the CURRENT master password to verify:');
  if (oldPw === null) return;  // user cancelled
  const r = await vaultAPI.extSyncChangePassword(oldPw, newPw);
  if (!r.ok) { toast(r.error, 'error'); return; }
  $('#extsync-new-password').value = '';
  toast('Password changed — ' + r.note, 'success', 3500);
  await refreshExtSyncStatus();
});

$('#btn-extsync-clear-password').addEventListener('click', async () => {
  if (!confirm('Clear the stored master password? You will need to re-enter it before the next .svlt write.')) return;
  await vaultAPI.extSyncClearPassword();
  toast('Master password cleared', 'success', 1500);
  await refreshExtSyncStatus();
  openSettings();
});

$('#extsync-auto-sync').addEventListener('change', async (e) => {
  await vaultAPI.extSyncSetAutoWrite(e.target.checked, $('#extsync-auto-edit').checked);
});
$('#extsync-auto-edit').addEventListener('change', async (e) => {
  await vaultAPI.extSyncSetAutoWrite($('#extsync-auto-sync').checked, e.target.checked);
});

$('#btn-extsync-write-now').addEventListener('click', async () => {
  setSyncPill('syncing', 'Writing…');
  const r = await vaultAPI.extSyncWriteNow();
  if (r.ok) {
    toast(`.svlt written from ${r.source}`, 'success');
    setSyncPill('synced', 'Ext: synced');
  } else {
    toast(r.error, 'error');
    setSyncPill('error', 'Ext: error');
  }
});

$('#btn-extsync-sync-from-file').addEventListener('click', async () => {
  setSyncPill('syncing', 'Syncing from file…');
  const r = await vaultAPI.extSyncSyncFromFile();
  if (r.ok) {
    toast(`Synced from file: ${r.added} added, ${r.skipped} skipped, ${r.failed} failed`, 'success', 4500);
    setSyncPill('synced', 'Ext: synced');
    // Reload device entries to reflect the newly-added entries.
    if (state.mode === 'device') await loadDeviceEntries();
  } else {
    toast(r.error, 'error');
    setSyncPill('error', 'Ext: error');
  }
});

async function refreshExtSyncStatus() {
  const status = await vaultAPI.extSyncGetStatus();
  state.extSyncStatus = status;
  if (!status.enabled) {
    setSyncPill('idle', 'Ext: off');
  } else if (!status.filePath || !status.hasPassword) {
    setSyncPill('error', 'Ext: not configured');
  } else {
    setSyncPill('synced', 'Ext: ready');
  }
  $('#ext-sync-info').textContent = status.filePath
    ? `→ ${status.filePath}`
    : '';
}

// ═══════════════════════════════════════════════════════════════════════
//  Breach detection (HIBP Pwned Passwords, k-anonymity model)
//
//  OFF BY DEFAULT: every call to checkPwned / vaultHealthScan is gated
//  behind hibpCheckEnabled in the main process. The settings toggle here
//  just persists that flag; the main process enforces the gate.
// ═══════════════════════════════════════════════════════════════════════
$('#settings-hibp').addEventListener('change', async (e) => {
  await vaultAPI.setHibpEnabled(e.target.checked);
  $('#btn-health-scan').disabled = !e.target.checked;
  // Show/hide the topbar health scan button too.
  $('#btn-topbar-health-scan').classList.toggle('hidden', !e.target.checked);
  if (e.target.checked) {
    toast('Breach detection enabled. Uses k-anonymity — only a 5-char hash prefix is sent.', 'success', 4000);
  } else {
    toast('Breach detection disabled. Cache cleared.', 'info', 2000);
  }
});

// Single-password breach check inside the Add/Edit modal.
$('#btn-check-pwned').addEventListener('click', async () => {
  const pw = $('#field-pass').value;
  if (!pw) return;
  const badge = $('#breach-badge');
  badge.className = 'breach-badge checking';
  badge.textContent = 'Checking...';
  const result = await vaultAPI.checkPwned(pw);
  if (result.error) {
    badge.className = 'breach-badge error';
    badge.textContent = '⚠ ' + result.error;
  } else if (result.breached) {
    badge.className = 'breach-badge breached';
    badge.textContent = '⚠ Found in ' + result.count.toLocaleString() + ' breaches';
  } else {
    badge.className = 'breach-badge safe';
    badge.textContent = '✓ Not found in any breach';
  }
});

// Vault-wide health scan — shared by the Settings button and the topbar
// shortcut button. Streams progress via the health-scan:progress IPC event.
async function runVaultHealthScan(resultEl, btn) {
  if (!state.entries || state.entries.length === 0) {
    resultEl.innerHTML = '<span class="muted">No entries to scan.</span>';
    return;
  }
  const prevText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '🛡 Scanning...';
  resultEl.innerHTML = '<div class="health-scan-progress-bar"><div class="health-scan-progress-fill" style="width:0%"></div></div>';

  let progressFill = resultEl.querySelector('.health-scan-progress-fill');

  const progressUnsub = vaultAPI.onHealthScanProgress((data) => {
    const pct = data.total > 0 ? (data.checked / data.total * 100) : 0;
    resultEl.innerHTML =
      '<div class="health-scan-progress-bar"><div class="health-scan-progress-fill" style="width:' + pct + '%"></div></div>' +
      '<p class="muted small">Checking "' + escapeHtml(data.site) + '"... (' + data.checked + '/' + data.total + ')</p>';
    progressFill = resultEl.querySelector('.health-scan-progress-fill');
  });

  // D19 FIX: Send only entry IDs, not full entries with plaintext passwords.
  const entryIds = state.entries.map(e => e.id);
  const result = await vaultAPI.vaultHealthScan(entryIds);
  if (progressUnsub) progressUnsub();

  btn.disabled = false;
  btn.textContent = prevText;

  if (!result.ok) {
    resultEl.innerHTML = '<span class="error">' + escapeHtml(result.error || 'Scan failed') + '</span>';
    return;
  }

  const breached = result.results.filter(r => r.breached);
  if (breached.length === 0) {
    resultEl.innerHTML = '<span style="color:var(--success);">✓ All clear! No breached passwords found in ' + result.results.length + ' entries.</span>';
  } else {
    let html = '<span style="color:var(--danger);">⚠ Found ' + breached.length + ' breached password(s) out of ' + result.results.length + ' checked:</span><div style="margin-top:8px;">';
    for (const r of breached) {
      html += '<div class="health-scan-result-item"><span>' + escapeHtml(r.site) + '</span><span>' + (r.count || 0).toLocaleString() + ' breaches</span></div>';
    }
    html += '</div>';
    resultEl.innerHTML = html;
  }
}

// Settings modal "Scan vault for breaches" button.
$('#btn-health-scan').addEventListener('click', () => {
  runVaultHealthScan($('#health-scan-result'), $('#btn-health-scan'));
});

// Topbar shortcut — kicks off the same scan, surfaces results as a toast
// (since the topbar has no inline result panel) and opens Settings so the
// user can see the full breakdown.
$('#btn-topbar-health-scan').addEventListener('click', async () => {
  if (!state.entries || state.entries.length === 0) {
    toast('No entries to scan', 'warning', 1500);
    return;
  }
  toast('Breach scan started — see Settings for progress', 'info', 2500);
  await openSettings();
  // Defer so the Settings modal is visible before we kick off.
  setTimeout(() => runVaultHealthScan($('#health-scan-result'), $('#btn-health-scan')), 100);
});

// ═══════════════════════════════════════════════════════════════════════
//  Topbar buttons — sync, CSV, lock
// ═══════════════════════════════════════════════════════════════════════
$('#btn-ext-sync-now').addEventListener('click', () => $('#btn-extsync-write-now').click());
$('#btn-ext-sync-from-file').addEventListener('click', () => $('#btn-extsync-sync-from-file').click());

$('#btn-csv-export').addEventListener('click', async () => {
  // Export only non-trashed entries.
  const live = state.entries.filter(e => !e.deleted);
  if (live.length === 0) { toast('No entries to export', 'warning'); return; }
  const r = await vaultAPI.csvExport(live);
  if (r.ok) toast(`Exported ${r.count} entries to ${r.path}`, 'success', 3500);
  else if (!r.canceled) toast('Export failed: ' + r.error, 'error');
});

$('#btn-csv-import').addEventListener('click', async () => {
  const r = await vaultAPI.csvImport();
  if (!r.ok) {
    if (!r.canceled) toast('Import failed: ' + r.error, 'error');
    return;
  }
  // Merge imported entries into the current vault.
  const imported = r.entries.map(normalizeEntryForUi);
  // Track where the imports start so we can push only the new ones to the device.
  const importStartIdx = state.entries.length;
  let added = 0;
  for (const entry of imported) {
    // De-dupe by (site, user) pair (case-insensitive) — fixes D3+D6.
    const exists = state.entries.some(e =>
      (e.site || '').toLowerCase() === (entry.site || '').toLowerCase() &&
      (e.user || '').toLowerCase() === (entry.user || '').toLowerCase() &&
      !e.deleted
    );
    if (!exists) {
      // Assign a UUID to new entries — fixes D3+D6.
      if (!entry.id) entry.id = crypto.randomUUID();
      state.entries.push(entry);
      added++;
    }
  }
  if (state.mode === 'sdcard') {
    const sr = await vaultAPI.vaultSave(state.sdRoot, entriesForFirmware(state.entries));
    if (!sr.success) { toast('Save failed: ' + sr.error, 'error'); return; }
  } else if (state.mode === 'device') {
    // D1 FIX: Push each newly imported entry to the device, otherwise they
    // vanish on disconnect/reload because the device never received them.
    for (const entry of state.entries.slice(importStartIdx)) {
      const typeNum = { login: 0, card: 1, identity: 2, note: 3 }[entry.type] || 0;
      const deviceEntry = {
        site: entry.site,
        user: entry.user || '',
        pass: entry.pass || '',
        totp: entry.totp || '',
        type: typeNum,
        fav: entry.fav ? 1 : 0,
        del: entry.deleted ? 1 : 0,
        deleted: entry.deleted ? true : false,
        notes: entry.notes || '',
        folder: entry.folder || '',
      };
      if (typeNum === 0) deviceEntry.url = entry.url || '';
      if (typeNum === 1) {
        deviceEntry.cardholder = entry.cardHolder || '';
        deviceEntry.cardNumber = entry.cardNumber || '';
        deviceEntry.exp = entry.cardExpiry || '';
        deviceEntry.cvv = entry.cardCvv || '';
      }
      if (typeNum === 2) {
        deviceEntry.firstName = entry.idFirstName || '';
        deviceEntry.lastName = entry.idLastName || '';
        deviceEntry.email = entry.idEmail || '';
        deviceEntry.phone = entry.idPhone || '';
        deviceEntry.address = entry.idAddress || '';
        deviceEntry.city = entry.idCity || '';
        deviceEntry.state = entry.idState || '';
        deviceEntry.postal = entry.idPostal || '';
        deviceEntry.country = entry.idCountry || '';
        deviceEntry.ssn = entry.idSsn || '';
        deviceEntry.passport = entry.idPassport || '';
        deviceEntry.license = entry.idLicense || '';
      }
      await vaultAPI.deviceAddEntry(deviceEntry);
    }
    // Re-fetch the full device list to refresh indices.
    await loadDeviceEntries();
  }
  renderSidebar();
  renderEntryList();
  updateStatusbar();
  toast(`Imported ${added} entries (${imported.length - added} duplicates skipped)`, 'success', 3500);
});

$('#btn-lock-now').addEventListener('click', lockAll);

async function lockAll() {
  stopTotpPreview();
  if (state.clipboardTimer) {
    clearTimeout(state.clipboardTimer);
    await vaultAPI.clearClipboardIfMatches(''); // best-effort clear
    state.clipboardTimer = null;
  }
  // Tear down the device session if any.
  if (state.mode === 'device') {
    await vaultAPI.deviceLock();
  }
  // Wipe in-memory state.
  state.entries = [];
  // D18 FIX: Clear dirty state and snapshot on lock.
  clearDirty();
  // D11 FIX: sdPin removed from renderer state. The main process zeros its
  // cached PIN Buffer on lock/quit — the renderer never had it.
  state.editingIndex = null;
  state.searchQuery = '';
  $('#search-box').value = '';
  setSdIndicator(null);
  setSyncPill('idle', 'Ext: idle');
  stopAutoLockTimer();
  initSplash();
}

// ═══════════════════════════════════════════════════════════════════════
//  Search
// ═══════════════════════════════════════════════════════════════════════
$('#search-box').addEventListener('input', (e) => {
  state.searchQuery = e.target.value.trim();
  renderEntryList();
  updateStatusbar();
});

// ═══════════════════════════════════════════════════════════════════════
//  Auto-lock timer — fires after `state.autoLockMinutes` of inactivity
// ═══════════════════════════════════════════════════════════════════════
let lastActivity = Date.now();
['click', 'keydown', 'mousemove'].forEach(ev => {
  document.addEventListener(ev, () => { lastActivity = Date.now(); });
});

function startAutoLockTimer() {
  stopAutoLockTimer();
  state.autoLockTimer = setInterval(() => {
    if (state.autoLockMinutes <= 0) return;
    const idle = (Date.now() - lastActivity) / 60000;
    if (idle >= state.autoLockMinutes) {
      toast('Auto-locking due to inactivity', 'info', 1500);
      lockAll();
    }
  }, 15000);
}

function stopAutoLockTimer() {
  if (state.autoLockTimer) {
    clearInterval(state.autoLockTimer);
    state.autoLockTimer = null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Trash auto-purge — runs once on dashboard show, purges entries older
//  than PURGE_DAYS_DEFAULT (30 days).
// ═══════════════════════════════════════════════════════════════════════
function autoPurgeTrash() {
  const cutoff = Date.now() - TRASH_PURGE_MS;
  const before = state.entries.length;
  state.entries = state.entries.filter(e => !(e.deleted && e.deletedAt && e.deletedAt < cutoff));
  const purged = before - state.entries.length;
  if (purged > 0) {
    toast(`Auto-purged ${purged} old trash entries`, 'info', 2500);
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Main-process push events
// ═══════════════════════════════════════════════════════════════════════

// v6: Handle device disconnect (ESP32 crash, USB unplug, keepalive failure).
// Without this, the renderer never knows the session is gone — the user
// keeps clicking buttons and gets cryptic errors on every action.
vaultAPI.onDeviceDisconnected((payload) => {
  const reason = payload && payload.reason ? payload.reason : 'unknown';
  // Don't show a toast if the user explicitly locked — that's expected.
  if (reason === 'user_lock') return;
  let msg;
  if (reason === 'port_closed') {
    msg = 'Device disconnected (USB lost). The ESP32 may have rebooted or been unplugged.';
  } else if (reason === 'keepalive_failed') {
    msg = 'Device stopped responding to keepalive pings.';
  } else if (reason && reason.startsWith('serial_error')) {
    msg = 'Serial port error: ' + reason;
  } else if (reason === 'client_timeout') {
    msg = 'Session timed out due to inactivity.';
  } else {
    msg = 'Device session ended: ' + reason;
  }
  toast(msg, 'warning', 4500);
  // If we're in device mode, return to splash so the user can reconnect.
  if (state.mode === 'device') {
    lockAll();
  }
});

vaultAPI.onAutoDetected(async (payload) => {
  // Only auto-route if we're on the splash screen.
  if (!$('#screen-sdcard').classList.contains('hidden')) {
    if (payload.multiple) {
      $('#sdcard-candidates').textContent = `Multiple SD cards detected — click "Read SD Card" to choose.`;
    } else {
      $('#sdcard-candidates').textContent = `SD card auto-detected: ${payload.path}`;
      // Auto-route: set as selected and go to lock screen.
      state.sdRoot = payload.path;
      await vaultAPI.setSelectedSDCard(payload.path);
      state.mode = 'sdcard';
      setSdIndicator('connected');
      showLockScreen(payload.path);
    }
  }
});

vaultAPI.onSdCardRemoved((payload) => {
  toast(`SD card removed: ${payload.path}`, 'warning', 3000);
  if (state.mode === 'sdcard') {
    lockAll();
  }
});

vaultAPI.onForceLock(() => {
  // Window minimize/blur/close — wipe state and return to splash.
  if (state.mode) lockAll();
});

vaultAPI.onWindowBlur(() => {
  // On blur, just clear the clipboard if it has a secret — don't full-lock.
  if (state.clipboardTimer) {
    clearTimeout(state.clipboardTimer);
    state.clipboardTimer = null;
  }
});

vaultAPI.onExtSyncWritten((payload) => {
  setSyncPill('synced', `Ext: ${payload.count} entries`);
  toast(`Synced ${payload.count} entries to ${payload.path}`, 'success', 2500);
  $('#ext-sync-info').textContent = `→ ${payload.path} (${payload.bytes} bytes)`;
});

vaultAPI.onExtSyncError((msg) => {
  setSyncPill('error', 'Ext: error');
  toast('Extension sync error: ' + msg, 'error', 4500);
});

// ═══════════════════════════════════════════════════════════════════════
//  Keyboard shortcuts
// ═══════════════════════════════════════════════════════════════════════
document.addEventListener('keydown', (e) => {
  // Ctrl+F → focus search
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault();
    $('#search-box').focus();
    return;
  }
  // Ctrl+L → lock
  if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
    e.preventDefault();
    lockAll();
    return;
  }
  // Ctrl+N → new entry
  if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
    e.preventDefault();
    if (!$('#screen-dashboard').classList.contains('hidden')) openEditModal(null);
    return;
  }
  // Esc → close any open modal / clear search
  if (e.key === 'Escape') {
    if (!$('#modal-backdrop').classList.contains('hidden')) { closeModal(); return; }
    if (!$('#settings-backdrop').classList.contains('hidden')) { $('#settings-backdrop').classList.add('hidden'); return; }
    if (!$('#gen-backdrop').classList.contains('hidden')) { $('#gen-backdrop').classList.add('hidden'); return; }
    if (state.searchQuery) {
      state.searchQuery = '';
      $('#search-box').value = '';
      renderEntryList();
      updateStatusbar();
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════
//  Init
// ═══════════════════════════════════════════════════════════════════════
(async function init() {
  // Load entry field limits for client-side validation hints.
  try {
    state.limits = await vaultAPI.getLimits();
  } catch { /* non-fatal */ }

  // Show the topbar breach-scan shortcut only if HIBP is enabled in config.
  try {
    const hibpStatus = await vaultAPI.getHibpEnabled();
    $('#btn-topbar-health-scan').classList.toggle('hidden', !hibpStatus.enabled);
  } catch { /* non-fatal — keep button hidden by default */ }

  await initSplash();

  // If the device is already connected (e.g. hot reload), skip to dashboard.
  try {
    const connected = await vaultAPI.deviceIsConnected();
    if (connected) {
      state.mode = 'device';
      setSdIndicator('device');
      await loadDeviceEntries();
    }
  } catch { /* not connected — fine */ }
})();

// ═══════════════════════════════════════════════════════════════════════
//  D20 FIX: Themed modal dialog for password verification
//  Replaces browser prompt() with a custom modal that matches the app's
//  dark premium theme. Features: password masking, show/hide toggle,
//  Cancel and Verify buttons, themed styling.
// ═══════════════════════════════════════════════════════════════════════
function showPasswordVerifyModal(promptText) {
  return new Promise((resolve) => {
    // Create modal backdrop
    const backdrop = document.createElement('div');
    backdrop.id = 'pw-verify-backdrop';
    backdrop.className = 'modal-backdrop';

    // Create modal card
    const card = document.createElement('div');
    card.className = 'modal-card pw-verify-card';
    card.innerHTML = `
      <div class="modal-header">
        <h3 class="modal-title">🔒 Password Verification</h3>
      </div>
      <div class="modal-body">
        <p class="pw-verify-prompt">${escapeHtml(promptText)}</p>
        <div class="pw-verify-input-group">
          <input type="password" id="pw-verify-input" class="input" placeholder="Enter current password" autocomplete="off" />
          <button id="pw-verify-toggle" class="btn ghost tiny" title="Show/hide password">👁</button>
        </div>
      </div>
      <div class="modal-footer">
        <button id="pw-verify-cancel" class="btn ghost">Cancel</button>
        <button id="pw-verify-ok" class="btn primary">Verify</button>
      </div>
    `;

    backdrop.appendChild(card);
    document.body.appendChild(backdrop);

    const input = card.querySelector('#pw-verify-input');
    const toggleBtn = card.querySelector('#pw-verify-toggle');
    const cancelBtn = card.querySelector('#pw-verify-cancel');
    const okBtn = card.querySelector('#pw-verify-ok');

    // Show/hide toggle
    toggleBtn.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      toggleBtn.textContent = isPassword ? '🔒' : '👁';
    });

    // Cancel
    cancelBtn.addEventListener('click', () => {
      backdrop.remove();
      resolve(null);
    });

    // Verify
    okBtn.addEventListener('click', () => {
      const value = input.value;
      backdrop.remove();
      resolve(value || null);
    });

    // Enter key = Verify
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        okBtn.click();
      }
      if (e.key === 'Escape') {
        cancelBtn.click();
      }
    });

    // Click backdrop = Cancel
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cancelBtn.click();
    });

    // Focus input
    setTimeout(() => input.focus(), 50);
  });
}
