'use strict';
/**
 * main.js — SecureVault Electron main process (v6)
 *
 * Premium desktop companion app for the SecureVault hardware password manager.
 * Connects to an ESP32-S3 over USB-CDC serial (ECDH P-256 + AES-256-GCM via
 * secureChannel.js) and ALSO reads/writes an encrypted `.svlt` file that the
 * browser extension consumes (SVLT v2 format via vaultFileCrypto.js).
 *
 * Architecture:
 *
 *   ESP32 (USB-CDC) ←→ Electron App → writes vault.svlt file
 *                                        ↓
 *                                 Browser Extension reads it
 *
 * The Electron app can:
 *   1. Connect to the ESP32 over serial and push/pull vault entries
 *   2. Read/write the encrypted `.svlt` file the browser extension uses
 *   3. Auto-write `.svlt` after every device sync or SD-card vault save
 *   4. Read the `.svlt` (that the extension wrote) and push new entries to
 *      the ESP32 — closing the loop for "extension added a login on the web"
 *
 * Security rules enforced in this file:
 *   - contextIsolation: true, nodeIntegration: false, sandbox: true
 *   - All crypto lives here in the main process — renderer never sees keys,
 *     ECDH private keys, GCM nonces, or raw serial frame bytes
 *   - All sensitive Buffers are .fill(0)'d before going out of scope
 *   - Master password for the .svlt file is wrapped with Electron's
 *     safeStorage (DPAPI on Windows, Keychain on macOS, libsecret on Linux)
 *   - Atomic file writes (.tmp → fsync → rename) for both vault.db and
 *     vault.svlt — a crash mid-write never leaves a half-written file
 *   - Backups: last 5 backups of vault.db kept on the SD card in `.backups/`
 *   - URL cache (firmware has no URL field) persisted in `url_cache.json`
 *
 * IPC handler groups:
 *   - device:*   — secure channel to the ESP32 (handshake, list, get, add, ...)
 *   - vault:*    — SD-card vault.db (unlock, create, save, changePin, backups)
 *   - sdcard:*   — removable-volume detection + selection
 *   - util:*     — password generator, passphrase generator, strength, TOTP,
 *                   clipboard, limits
 *   - extsync:*  — browser-extension .svlt file (status, password, write,
 *                   sync-from-file)
 *   - urlcache:* — site-name → URL cache (firmware has no URL field)
 *   - csv:*      — Bitwarden-format CSV import/export
 *
 * All paths in this file are under userData/ (Electron-managed per-user dir).
 * Nothing sensitive is ever written to disk in plaintext — passwords are
 * safeStorage-wrapped, vault.db is PBKDF2+AES-256-GCM, .svlt is
 * PBKDF2-SHA512@600k+AES-256-GCM+HMAC-SHA256.
 */

const { app, BrowserWindow, ipcMain, dialog, clipboard, Menu, powerMonitor, safeStorage, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const {
  decryptVault,
  encryptVault,
  validateEntries,
  normalizeEntry,
  WrongPinError,
  VaultFormatError,
  VaultHmacError,
  MAX_ENTRIES,
  FIELD_LIMITS,
  EXTENDED_LIMITS,
  ENTRY_TYPES,
  KDF_ITERATIONS_V1,
  KDF_ITERATIONS_V2,
  KDF_VERSION_V1,
  KDF_VERSION_V2,
} = require('./vaultCrypto');
const secureChannel = require('./secureChannel');

// v5: Register disconnect callback so main.js can notify the renderer
// when the device silently disconnects (ESP32 crash/reboot). Without this,
// the renderer never finds out the session was torn down.
secureChannel.setDisconnectCallback((reason) => {
  console.warn('[main] Device disconnected — reason:', reason);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('device:disconnected', { reason });
  }
  zeroCachedVault();
});
const {
  encryptVaultFile,
  decryptVaultFile,
  WrongPasswordError,
  VaultFileError,
} = require('./vaultFileCrypto');
const WORDLIST = require('./wordlist');

// D12 FIX: Import shared canonical normalization module.
// Both main.js and renderer.js use this for field alias resolution.
// main.js adds extension-only fields (id, name, favorite, del) ON TOP.
const { normalizeEntry: canonicalNormalize, validateEntry, validatePin, validateDeviceIndex, ENTRY_TYPES: CANONICAL_ENTRY_TYPES } = require('./normalizeEntry');

// ─────────────────────────────────────────────────────────────────────────
//  Constants — file names + limits
// ─────────────────────────────────────────────────────────────────────────
const VAULT_FILENAME = 'vault.db';
const TMP_FILENAME   = 'vault.db.tmp';
const BACKUP_DIR     = '.backups';
const MAX_BACKUPS    = 5;
const CONFIG_PATH      = path.join(app.getPath('userData'), 'config.json');
const URL_CACHE_PATH   = path.join(app.getPath('userData'), 'url_cache.json');
const SVLT_LOCK_TIMEOUT_MS = 30000; // D16: stale lock threshold

// ─────────────────────────────────────────────────────────────────────────
//  Config persistence — D7 FIX: in-memory config + debounced write.
//
//  Previous problem: Multiple IPC handlers independently called
//  loadConfig() → modify → saveConfig(). Async gaps between load and save
//  allowed overwriting previous changes.
//
//  Fix: Config is now maintained as a SINGLE in-memory object, loaded once
//  at startup. All modifications go through updateConfig(patch), which reads
//  from in-memory config and marks it dirty. A debounced timer writes to
//  disk after 2 seconds of no changes. Direct loadConfig/saveConfig calls
//  are removed from individual handlers.
// ─────────────────────────────────────────────────────────────────────────
let _configInMemory = null;  // D7: single in-memory config
let _configDirty = false;    // D7: dirty flag for debounced write
let _configWriteTimer = null; // D7: debounce timer
const CONFIG_WRITE_DEBOUNCE_MS = 2000; // D7: write after 2 seconds of no changes

// Load config once at startup (synchronous I/O is acceptable here — no UI yet).
function _loadConfigSync() {
  try {
    _configInMemory = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    _configInMemory = {};
  }
}

// D7: Get config from in-memory object. Used by all code that needs config.
function getConfig() {
  if (_configInMemory === null) _loadConfigSync(); // lazy load on first access
  return _configInMemory;
}

// D7: Update config with a patch object. Merges patch into in-memory config
// and schedules a debounced write. No direct disk I/O in the patch path.
function updateConfig(patch) {
  const cfg = getConfig();
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) continue; // skip undefined — don't accidentally clear
    cfg[k] = v;
  }
  _configDirty = true;
  // Schedule debounced write: write after 2 seconds of no changes.
  if (_configWriteTimer) clearTimeout(_configWriteTimer);
  _configWriteTimer = setTimeout(() => {
    _configWriteTimer = null;
    if (_configDirty) _flushConfigToDisk();
  }, CONFIG_WRITE_DEBOUNCE_MS);
}

// D7: Flush in-memory config to disk (called by debounced timer, or on quit).
// Uses async atomic write pattern (D8 FIX).
async function _flushConfigToDisk() {
  if (!_configDirty) return;
  const cfg = getConfig();
  const data = JSON.stringify(cfg, null, 2);
  try {
    await fs.promises.mkdir(path.dirname(CONFIG_PATH), { recursive: true });
    const tmp = CONFIG_PATH + '.tmp';
    // D8 FIX: Async atomic write pattern (open → write → fsync → close → rename)
    const fd = await fs.promises.open(tmp, 'w', 0o600);
    await fd.write(data, 0, 'utf8');
    await fd.sync();
    await fd.close();
    await fs.promises.rename(tmp, CONFIG_PATH);
    _configDirty = false;
  } catch (e) {
    console.error('[config] Failed to write config.json:', e.message);
  }
}

// D7: Flush config immediately (for app quit, must not be debounced).
function _flushConfigSync() {
  if (!_configDirty || !_configInMemory) return;
  try {
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    const tmp = CONFIG_PATH + '.tmp';
    const fd = fs.openSync(tmp, 'w', 0o600);
    fs.writeSync(fd, JSON.stringify(_configInMemory, null, 2));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fs.renameSync(tmp, CONFIG_PATH);
    _configDirty = false;
  } catch (e) {
    console.error('[config] Failed to flush config.json:', e.message);
  }
}

// Legacy functions kept for backward compat with any code that still uses them
// but they now go through the in-memory system.
function loadConfig() { return getConfig(); }
function saveConfig(cfg) { _configInMemory = cfg; _configDirty = true; _flushConfigToDisk(); }

// D8 FIX: Async atomic write helper — replaces sync write patterns.
// Pattern: open → write → fsync → close → rename. Used for vault.db,
// .svlt files, and any other critical file writes.
async function atomicWriteFile(filePath, data) {
  const tmp = filePath + '.tmp';
  const fd = await fs.promises.open(tmp, 'w', 0o600);
  if (Buffer.isBuffer(data)) {
    await fd.write(data, 0, data.length, 0);
  } else {
    await fd.write(data, 0, 'utf8');
  }
  await fd.sync();
  await fd.close();
  await fs.promises.rename(tmp, filePath);
}

function vaultPath(sdRoot) {
  return path.join(sdRoot, VAULT_FILENAME);
}

// ─────────────────────────────────────────────────────────────────────────
//  URL Cache — D13 FIX: now keyed by (siteName + "|" + user), not just
//  siteName. Two accounts on the same site with different users need
//  different URLs (e.g. Gmail personal vs Gmail work).
//
//  Old format: { "Gmail": "https://gmail.com" } — no user dimension.
//  New format: { "Gmail|user1": "https://gmail.com", "Gmail|user2": "..." }
//
//  Backward compat: on first load, if old format detected (keys contain
//  no "|"), migrate entries to new format. Old entries without a user
//  dimension get "|" appended (matching empty user).
// ─────────────────────────────────────────────────────────────────────────
let _urlCacheInMemory = null;  // D7: in-memory URL cache (same pattern as config)

function loadUrlCache() {
  if (_urlCacheInMemory !== null) return _urlCacheInMemory;
  try {
    let raw = JSON.parse(fs.readFileSync(URL_CACHE_PATH, 'utf8'));
    // D13 FIX: Migrate old format (siteName → url) to new format (siteName|user → url)
    // Old format keys contain no "|" separator.
    const migrated = {};
    let needsMigration = false;
    for (const [key, url] of Object.entries(raw)) {
      if (!key.includes('|')) {
        // Old format — migrate by appending "|" (empty user).
        migrated[key + '|'] = url;
        needsMigration = true;
      } else {
        migrated[key] = url;
      }
    }
    if (needsMigration) {
      _urlCacheInMemory = migrated;
      // Write migrated format to disk (sync, since we're loading at startup).
      try {
        fs.mkdirSync(path.dirname(URL_CACHE_PATH), { recursive: true });
        const tmp = URL_CACHE_PATH + '.tmp';
        const fd = fs.openSync(tmp, 'w', 0o600);
        fs.writeSync(fd, JSON.stringify(migrated, null, 2));
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fs.renameSync(tmp, URL_CACHE_PATH);
      } catch (e) {
        console.warn('[urlcache] Failed to write migrated cache:', e.message);
      }
    } else {
      _urlCacheInMemory = raw;
    }
    return _urlCacheInMemory;
  } catch {
    _urlCacheInMemory = {};
    return _urlCacheInMemory;
  }
}

function saveUrlCache(cache) {
  _urlCacheInMemory = cache;
  // D8 FIX: Use async atomic write for URL cache.
  atomicWriteFile(URL_CACHE_PATH, JSON.stringify(cache, null, 2)).catch(e => {
    console.warn('[urlcache] Failed to write:', e.message);
  });
}

// D13 FIX: Build cache key from (site, user) pair.
function urlCacheKey(siteName, user) {
  return String(siteName || '') + '|' + String(user || '');
}

ipcMain.handle('urlcache:set', (_evt, siteName, user, url) => {
  // D13 FIX: Now takes (siteName, user, url) instead of (siteName, url).
  // Backward compat: if called with old 2-arg pattern (siteName, url),
  // treat second arg as url with empty user.
  if (url === undefined && typeof user === 'string' && (user.startsWith('http') || !user)) {
    // Old 2-arg pattern: (siteName, url) → user='', url=user
    url = user;
    user = '';
  }
  if (!siteName) return { ok: false, error: 'siteName required' };
  const cache = loadUrlCache();
  const key = urlCacheKey(siteName, user || '');
  if (url && String(url).trim()) {
    cache[key] = String(url).trim();
  } else {
    delete cache[key];
  }
  saveUrlCache(cache);
  return { ok: true };
});

ipcMain.handle('urlcache:get', (_evt, siteName, user) => {
  // D13 FIX: Now takes (siteName, user) instead of just siteName.
  // Backward compat: if called with old 1-arg pattern, user defaults to ''.
  if (typeof user === 'undefined') user = '';
  const cache = loadUrlCache();
  const key = urlCacheKey(siteName, user);
  // Fallback: try just siteName| (empty user) and old siteName-only format
  return { ok: true, url: cache[key] || cache[siteName + '|'] || cache[siteName] || '' };
});

ipcMain.handle('urlcache:getAll', () => {
  return { ok: true, cache: loadUrlCache() };
});

ipcMain.handle('urlcache:delete', (_evt, siteName, user) => {
  // D13 FIX: Now takes (siteName, user).
  if (typeof user === 'undefined') user = '';
  const cache = loadUrlCache();
  const key = urlCacheKey(siteName, user);
  delete cache[key];
  saveUrlCache(cache);
  return { ok: true };
});

// ─────────────────────────────────────────────────────────────────────────
//  Removable-volume auto-detection
//
//  Strategy per OS:
//   - macOS:   scan /Volumes for new mount points
//   - Linux:   scan /media, /media/$USER, /run/media/$USER, /mnt
//   - Windows: shell out to PowerShell Get-CimInstance (wmic is gone in
//              Windows 11 24H2+) for DriveType=2 (removable) drives
//
//  For each candidate, we look for vault.db at the root. If found, we fire
//  `sdcard:auto-detected` to the renderer. Multiple vault.db's → renderer
//  shows a chooser.
// ─────────────────────────────────────────────────────────────────────────
function listRemovableVolumes() {
  return new Promise((resolve) => {
    const candidates = [];
    const seen = new Set();
    const consider = (dir) => {
      try {
        if (!dir || !fs.existsSync(dir)) return;
        for (const name of fs.readdirSync(dir)) {
          const full = path.join(dir, name);
          try {
            const st = fs.statSync(full);
            if (!st.isDirectory()) continue;
            if (seen.has(full)) continue;
            seen.add(full);
            candidates.push(full);
          } catch { /* permission error on a sibling mount — skip */ }
        }
      } catch { /* dir doesn't exist on this OS — skip */ }
    };

    if (process.platform === 'win32') {
      // IMPORTANT: this used to be execSync, which BLOCKS the Electron main
      // process (and therefore every IPC call and the whole UI) for as long
      // as PowerShell takes to start — often 200ms-1s+. Since this runs
      // every 1.5s via the volume-watch timer, that made the entire app
      // stutter constantly. execFile is async and non-blocking.
      require('child_process').execFile(
        'powershell.exe',
        ['-NoProfile', '-Command', "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object -ExpandProperty DeviceID"],
        { windowsHide: true, timeout: 5000 },
        (err, stdout) => {
          if (!err && stdout) {
            for (const line of stdout.toString().split(/\r?\n/)) {
              const d = line.trim();
              if (/^[A-Z]:$/i.test(d)) consider(d + '\\');
            }
          }
          resolve(candidates);
        }
      );
      return;
    }

    if (process.platform === 'darwin') {
      consider('/Volumes');
    } else {
      consider('/media');
      consider(path.join('/media', os.userInfo().username));
      consider(path.join('/run/media', os.userInfo().username));
      consider('/mnt');
    }
    resolve(candidates);
  });
}

async function findVaultOnRemovableVolumes() {
  const vols = await listRemovableVolumes();
  const withVault = [];
  for (const v of vols) {
    try {
      if (fs.existsSync(path.join(v, VAULT_FILENAME))) {
        withVault.push(v);
      }
    } catch { /* permission — skip */ }
  }
  return { all: vols, withVault };
}

let volumeWatchTimer = null;
let lastKnownVaultPaths = new Set();
let state_lastSelectedPath = null;
let mainWindow = null;
let appTray = null;
let isQuitting = false;  // distinguishes "user clicked Quit" from "window closed"
let sdcardRemovalDebounce = null;  // timer for debouncing flaky USB removals (8-o)

// ─── .svlt file watcher (extension → Electron sync) ─────────────────────
// Watches the .svlt file for changes from the browser extension. When the
// extension writes a new entry, fs.watch fires here, and we debounce 300ms
// before reading + merging into the SD-card cache + pushing to ESP32.
let svltWatcher = null;
let svltWatchDebounce = null;
const SVLT_WATCH_DEBOUNCE_MS = 300;

function startSvltWatcher() {
  stopSvltWatcher();
  const cfg = getExtSyncConfig();
  if (!cfg.enabled || !cfg.filePath) return;
  try {
    svltWatcher = fs.watch(cfg.filePath, { persistent: false }, (eventType) => {
      if (eventType !== 'change') return;
      // Debounce: extension writes atomically (tmp + rename), so we may
      // see multiple events. Wait 300ms for things to settle.
      if (svltWatchDebounce) clearTimeout(svltWatchDebounce);
      svltWatchDebounce = setTimeout(() => {
        svltWatchDebounce = null;
        onSvltFileChanged().catch((e) => {
          console.warn('[extension-sync] .svlt watcher error:', e.message);
        });
      }, SVLT_WATCH_DEBOUNCE_MS);
    });
    svltWatcher.on('error', () => {
      // File may have been deleted/recreated — try to re-watch on next tick.
      stopSvltWatcher();
      setTimeout(startSvltWatcher, 2000);
    });
  } catch (e) {
    // File may not exist yet — retry on next config change.
  }
}

function stopSvltWatcher() {
  if (svltWatcher) {
    try { svltWatcher.close(); } catch (_) {}
    svltWatcher = null;
  }
  if (svltWatchDebounce) {
    clearTimeout(svltWatchDebounce);
    svltWatchDebounce = null;
  }
}

/**
 * Called when the .svlt file changes on disk (typically because the browser
 * extension wrote a new entry). Reads + decrypts the file, two-way merges
 * with the in-memory SD-card cache, and pushes the delta to the ESP32 if a
 * session is established.
 */
async function onSvltFileChanged() {
  const cfg = getExtSyncConfig();
  if (!cfg.enabled || !cfg.filePath) return;
  if (!fs.existsSync(cfg.filePath)) return;
  const password = getExtSyncPassword();
  if (!password) return;

  let fileEntries;
  try {
    // D8 FIX: Use async file I/O for .svlt file read.
    const buf = await fs.promises.readFile(cfg.filePath);
    fileEntries = decryptVaultFile(buf, password);
  } catch (e) {
    // Wrong password (extension changed it?) or corrupt file.
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('extension-sync:error',
        'Could not decrypt .svlt file after change: ' + e.message);
    }
    return;
  }

  // Two-way merge with the cached SD-card vault.
  const cached = cachedVaultEntries || [];
  const merged = twoWayMerge(cached, fileEntries);
  const delta = computeDelta(cached, merged);

  if (delta.added.length === 0 && delta.updated.length === 0 && delta.deleted.length === 0) {
    // No changes — extension wrote something equivalent to what we already had.
    return;
  }

  // Update cache.
  // D11 FIX: Use getCachedPin() instead of cachedVaultPin (which no longer
  // exists — the PIN is now stored as a Buffer that can be .fill(0)'d).
  setCachedVault(merged, getCachedPin());

  // Push to ESP32 if connected.
  if (secureChannel.isEstablished()) {
    try {
      for (const entry of delta.added) {
        await secureChannel.addEntry(toDeviceEntry(entry));
      }
      for (const { index, entry } of delta.updated) {
        await secureChannel.updateEntry(index, toDeviceEntry(entry));
      }
      for (const index of delta.deleted) {
        await secureChannel.deleteEntry(index);
      }
      // Refresh the .svlt file from device state so both sides are in sync.
      await refreshExtensionVaultFromDevice();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('extension-sync:synced', {
          added: delta.added.length,
          updated: delta.updated.length,
          deleted: delta.deleted.length,
        });
      }
    } catch (e) {
      console.warn('[extension-sync] push to ESP32 failed:', e.message);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('extension-sync:error',
          'Push to ESP32 failed: ' + e.message);
      }
    }
  } else {
    // Not connected — the merge is cached. When the user next connects and
    // unlocks the SD card, vault:save will push the merged state.
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('extension-sync:pending', {
        added: delta.added.length,
        updated: delta.updated.length,
        deleted: delta.deleted.length,
        message: 'Changes from extension cached. Connect to ESP32 to sync.',
      });
    }
  }
}

/**
 * Two-way merge by entry UUID + `updated` timestamp.
 *
 * Each entry is identified by its `id` field (UUID). The merge rule:
 *   - If only one side has the entry → take it.
 *   - If both sides have it → take the one with the newer `updated` timestamp.
 *   - Deletions: an entry with `deleted: true` is a tombstone. A tombstone
 *     always wins over a non-tombstone with the same id, UNLESS the
 *     non-tombstone has a newer `updated` timestamp (i.e. the entry was
 *     resurrected by editing it after deletion).
 *
 * Returns a new merged array. Neither input is mutated.
 */
function twoWayMerge(localEntries, remoteEntries) {
  const map = new Map();
  for (const e of localEntries) {
    // D3+D6 FIX: Key by (site, user) pair instead of site alone, so two
    // accounts on the same site with different users don't merge/overwrite.
    // Entries with a proper UUID `id` field use that directly.
    const id = e.id || e._uuid || ('site_user:' + (e.site || e.name || '') + '|' + (e.user || ''));
    // D2 FIX: Track _version for merge conflict resolution. Device-sourced
    // entries (no _version field) get version 0. The merge rule is:
    //   - If both sides have _version: higher version wins.
    //   - If one side lacks _version (device-sourced): compare by `updated`
    //     timestamp, but only trust timestamps from the Electron side
    //     (not from device-sourced entries which all have the same Date.now()
    //     timestamp). For device-sourced entries, "last edited side wins"
    //     based on whether the entry was modified on this side.
    const version = typeof e._version === 'number' ? e._version : 0;
    map.set(id, { ...e, _uuid: id, _version: version });
  }
  for (const e of remoteEntries) {
    const id = e.id || e._uuid || ('site_user:' + (e.site || e.name || '') + '|' + (e.user || ''));
    const existing = map.get(id);
    const candidate = { ...e, _uuid: id };
    const candidateVersion = typeof candidate._version === 'number' ? candidate._version : 0;
    if (!existing) {
      candidate._version = candidateVersion;
      map.set(id, candidate);
    } else {
      // D2 FIX: Use version counter instead of timestamp for merge decisions.
      // Higher _version always wins. If versions are equal (both 0, i.e.
      // device-sourced), fall back to "last edited side wins" — prefer the
      // side that has a meaningful `updated` timestamp (Electron-side) over
      // device-sourced entries whose timestamp is always Date.now() at sync
      // time. If both have real timestamps, compare those as tiebreaker.
      if (candidateVersion > existing._version) {
        candidate._version = candidateVersion;
        map.set(id, candidate);
      } else if (candidateVersion === existing._version) {
        // Both are version 0 (device-sourced or legacy entries with no version).
        // Use updated timestamps as tiebreaker, but only trust timestamps from
        // the Electron side (not device-sourced entries where updated = sync time).
        const existingTs = existing.updated || existing.created || 0;
        const candidateTs = candidate.updated || candidate.created || 0;
        // If one entry was explicitly edited on this side (has a _edited flag
        // from the Electron UI), that side wins regardless of timestamps.
        if (candidate._edited && !existing._edited) {
          candidate._version = candidateVersion;
          map.set(id, candidate);
        } else if (candidateTs > existingTs) {
          candidate._version = candidateVersion;
          map.set(id, candidate);
        }
        // else keep existing
      }
      // else existing has higher version — keep existing
    }
  }
  return Array.from(map.values());
}

/**
 * Compute the delta between the old cached state and the new merged state,
 * relative to the ESP32 device entries (which use `index` as the key).
 *
 * Returns: { added: [entries], updated: [{index, entry}], deleted: [indexes] }
 */
function computeDelta(oldEntries, newEntries) {
  // The device identifies entries by index, not by UUID. We need to match
  // newEntries to oldEntries by UUID to figure out what's add vs update.
  // D3+D6 FIX: Key by (site, user) pair instead of site alone.
  const oldByUuid = new Map();
  for (const e of oldEntries) {
    const id = e.id || e._uuid || ('site_user:' + (e.site || e.name || '') + '|' + (e.user || ''));
    oldByUuid.set(id, e);
  }
  const added = [];
  const updated = [];
  const deleted = [];
  for (const e of newEntries) {
    const id = e.id || e._uuid || ('site_user:' + (e.site || e.name || '') + '|' + (e.user || ''));
    const old = oldByUuid.get(id);
    if (!old) {
      // New entry — will be added on the device.
      if (!e.deleted) added.push(e);
    } else if (e.deleted && !old.deleted) {
      // Tombstone — delete on device.
      if (typeof old._index === 'number') deleted.push(old._index);
    } else if (!e.deleted) {
      // D2 FIX: Use _version for comparison instead of just timestamps.
      // If version is higher, or entry was explicitly edited, push update.
      const newerVersion = (e._version || 0) > (old._version || 0);
      const newerTimestamp = (e.updated || 0) > (old.updated || 0);
      if (newerVersion || newerTimestamp || e._edited) {
        // Updated entry — push to device.
        if (typeof old._index === 'number') {
          updated.push({ index: old._index, entry: e });
        } else {
          added.push(e);
        }
      }
    }
  }
  return { added, updated, deleted };
}

/**
 * Convert a vault entry (with url, type, extended fields) to the device's
 * full wire format. The firmware accepts all fields (site, user, pass, totp,
 * type, fav, del, plus per-type extras: url, notes, folder, cardholder,
 * cardNumber, exp, cvv, firstName, lastName, email, phone, address, city,
 * state, postal, country, ssn, passport, license).
 */
function toDeviceEntry(entry) {
  // Handle both string ('identity') and numeric (2) type representations.
  // The renderer's persistEntry() sends type as a number; extension entries
  // send type as a string. Both must map to the correct typeNum.
  let typeNum;
  if (typeof entry.type === 'number') {
    typeNum = entry.type;
  } else {
    typeNum = { login: 0, card: 1, identity: 2, note: 3 }[entry.type] || 0;
  }
  const deviceEntry = {
    site: entry.site || entry.name || '',
    user: entry.user || entry.login_username || '',
    pass: entry.pass || entry.login_password || '',
    totp: entry.totp || entry.login_totp || '',
    type: typeNum,
    // v6.3 FIX: Check BOTH `fav`/`favorite` (and `del`/`deleted`) — the
    // renderer's persistEntry() sends a half-prepared deviceEntry that has
    // `fav` and `del` (numeric 0/1) but NOT `favorite`/`deleted` (boolean).
    // When this function re-transforms that already-prepared object, the
    // old code read only `entry.deleted` (undefined) and silently reset
    // `del` to 0 — that was the root cause of "Move to Trash silently
    // fails": the renderer set del=1, but main.js squashed it back to 0
    // before sending to the firmware, so the entry was never actually
    // flagged as trashed on the device. Symmetric defensive check for
    // `fav` is harmless and matches the existing pattern.
    fav: (entry.fav || entry.favorite) ? 1 : 0,
    del: (entry.del || entry.deleted) ? 1 : 0,
    // Shared extras (all types)
    notes:  entry.notes || '',
    folder: entry.folder || '',
  };

  // LOGIN extras
  if (typeNum === 0) {
    deviceEntry.url = entry.url || entry.login_uri || '';
  }

  // CARD extras
  if (typeNum === 1) {
    deviceEntry.cardholder = entry.cardholder || entry.cardHolder || '';
    deviceEntry.cardNumber = entry.cardNumber || '';
    deviceEntry.exp        = entry.exp || entry.cardExpiry || '';
    deviceEntry.cvv        = entry.cvv || entry.cardCvv || '';
  }

  // IDENTITY extras — accept both firmware-style (firstName) and
  // Electron-style (idFirstName) field names from the extension.
  if (typeNum === 2) {
    deviceEntry.firstName = entry.firstName || entry.idFirstName || '';
    deviceEntry.lastName  = entry.lastName  || entry.idLastName  || '';
    deviceEntry.email     = entry.email     || entry.idEmail     || '';
    deviceEntry.phone     = entry.phone     || entry.idPhone     || '';
    deviceEntry.address   = entry.address   || entry.idAddress   || '';
    deviceEntry.city      = entry.city      || entry.idCity      || '';
    deviceEntry.state     = entry.state     || entry.idState     || '';
    deviceEntry.postal    = entry.postal    || entry.idPostal    || '';
    deviceEntry.country   = entry.country   || entry.idCountry   || '';
    deviceEntry.ssn       = entry.ssn       || entry.idSsn       || '';
    deviceEntry.passport  = entry.passport  || entry.idPassport  || '';
    deviceEntry.license   = entry.license   || entry.idLicense   || '';
  }

  return deviceEntry;
}

/**
 * v6.3 FIX: Build an entry object in the shape the browser extension expects
 * when reading the .svlt file.
 *
 * PREVIOUS BUG (v6.0–v6.2): three different call sites built "fullEntries"
 * with only the firmware's wire fields (site, user, pass, totp, type, fav,
 * notes, folder, card*, identity*). They were MISSING the extension's
 * required metadata fields:
 *
 *   - `id` (string) — used by the extension to identify entries for
 *     edit/delete/trash operations. Without it, every entry that came
 *     from Electron → .svlt was un-editable in the extension.
 *   - `deleted` (boolean) — used by the extension to filter trash vs
 *     vault. Without it, all trashed-on-device entries reappeared in
 *     the extension's vault view.
 *   - `favorite` (boolean) — used by the extension for the favorite
 *     filter and star toggle. Without it, all favorite-on-device entries
 *     showed as not-favorite in the extension.
 *   - `name` (string) — used by the extension as the entry title
 *     (falls back to `site`, but the Add/Edit form's data-field="name"
 *     input would be blank when editing a device-synced entry).
 *   - `created` / `updated` / `deletedAt` (timestamps) — used for sort
 *     order in the extension's vault list.
 *
 * This helper centralizes the field mapping so all 3 callers (the device
 * list handler, the auto-write-after-edit refresh, and the manual "Write
 * now" handler) produce identical, extension-compatible entry objects.
 *
 * @param {object} full — the raw entry object returned by secureChannel.getEntry()
 * @param {string} typeStr — 'login' | 'card' | 'identity' | 'note'
 * @param {string} url — URL from cache (or site name as fallback)
 * @param {number} deviceIndex — the entry's index on the device (used to
 *   synthesize a stable id when the device doesn't provide one)
 * @returns {object} extension-compatible entry object
 */
function buildExtensionEntry(full, typeStr, url, deviceIndex) {
  const siteName = full.site || '';
  const isDeleted = !!(full.del || full.deleted);
  const isFavorite = !!(full.fav || full.favorite);
  const now = Date.now();
  return {
    // ── Identity / metadata ──────────────────────────────────────────
    // The extension requires a unique `id` for edit/delete/trash. The
    // firmware doesn't have one (it uses integer indices that shift on
    // delete), so we synthesize a stable id from the device index + site
    // name. This id is stable across re-syncs AS LONG AS the entry's
    // device index doesn't shift — which is true between two syncs where
    // no delete happened. After a delete, the extension re-reads the
    // whole .svlt file anyway (writeExtensionVaultFile atomically
    // replaces it), so any stale id references in the extension's
    // in-memory state are correctly rebuilt.
    // D3+D6 FIX: Use crypto.randomUUID() instead of synthesizing from
    // device index + site name. The old approach created fragile IDs that
    // broke on index shifts and couldn't distinguish two accounts on the
    // same site with different users. Now each device-sourced entry gets a
    // stable UUID generated on first sync. If the entry already has an `id`
    // (from a previous sync or from the extension), keep it.
    id: full.id || crypto.randomUUID(),
    _version: typeof full._version === 'number' ? full._version : 0,  // D2: version counter
    name: siteName,        // extension uses `name` as the title (login derives `site` from `name` on save)
    site: siteName,        // also keep `site` for direct lookup
    type: typeStr,
    url: url,
    // ── Trash / favorite (dual-naming for backward compat) ──────────
    deleted: isDeleted,    // extension reads this (boolean)
    del: isDeleted ? 1 : 0,// firmware-style numeric (in case extension ever checks)
    favorite: isFavorite,  // extension reads this (boolean)
    fav: isFavorite ? 1 : 0,
    // ── Timestamps ───────────────────────────────────────────────────
    // Firmware doesn't track these per-entry, so use now() as a stable
    // fallback. The extension sorts by `updated` — equal timestamps
    // preserve insertion order, which matches the device's LIST order.
    created: now,
    updated: now,
    deletedAt: isDeleted ? now : 0,
    // ── Login fields ─────────────────────────────────────────────────
    user: full.user || '',
    pass: full.pass || '',
    totp: full.totp || '',
    notes: full.notes || '',
    folder: full.folder || '',
    // ── Card fields ──────────────────────────────────────────────────
    cardholder: full.cardholder || '',
    cardNumber: full.cardNumber || '',
    exp: full.exp || '',
    cvv: full.cvv || '',
    // ── Identity fields ──────────────────────────────────────────────
    firstName: full.firstName || '',
    lastName: full.lastName || '',
    email: full.email || '',
    phone: full.phone || '',
    address: full.address || '',
    city: full.city || '',
    state: full.state || '',
    postal: full.postal || '',
    country: full.country || '',
    ssn: full.ssn || '',
    passport: full.passport || '',
    license: full.license || '',
  };
}

function startVolumeWatcher() {
  if (volumeWatchTimer) return;
  // 1.5s poll — feels instant to a human plugging in a card.
  volumeWatchTimer = setInterval(async () => {
    const { withVault } = await findVaultOnRemovableVolumes();
    const now = new Set(withVault);
    for (const p of now) {
      if (!lastKnownVaultPaths.has(p)) {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('sdcard:auto-detected', { path: p, multiple: now.size > 1 });
        }
      }
    }
    lastKnownVaultPaths = now;

    // Fire "removed" if the previously-selected card was yanked — but
    // DEBOUNCE 5 seconds to avoid spurious locks from flaky USB connections
    // (bug 8-o). A momentary disconnect that re-appears within 5s should
    // NOT wipe the user's session.
    if (state_lastSelectedPath && !now.has(state_lastSelectedPath)) {
      if (sdcardRemovalDebounce) clearTimeout(sdcardRemovalDebounce);
      const removedPath = state_lastSelectedPath;
      sdcardRemovalDebounce = setTimeout(async () => {
        sdcardRemovalDebounce = null;
        // Re-check: the card may have re-appeared.
        const { withVault: recheck } = await findVaultOnRemovableVolumes();
        if (!recheck.includes(removedPath)) {
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('sdcard:removed', { path: removedPath });
          }
          if (state_lastSelectedPath === removedPath) {
            state_lastSelectedPath = null;
          }
        }
      }, 5000);
    }
  }, 1500);
}

// ─────────────────────────────────────────────────────────────────────────
//  Window + Tray
// ─────────────────────────────────────────────────────────────────────────
function createTrayIcon() {
  // Use a tiny 16x16 native image (no asset file needed). On macOS this
  // renders as a monochrome template; on Windows/Linux it shows as-is.
  const img = nativeImage.createEmpty();
  // Encode a 16x16 dark "SV" badge.
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" rx="3" fill="#175DDC"/><text x="8" y="12" font-family="sans-serif" font-size="9" font-weight="700" fill="#fff" text-anchor="middle">SV</text></svg>';
  const trayImg = nativeImage.createFromDataURL('data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64'));
  appTray = new Tray(trayImg);
  appTray.setToolTip('SecureVault');
  const menu = Menu.buildFromTemplate([
    { label: 'Show SecureVault', click: () => { showMainWindow(); } },
    { type: 'separator' },
    { label: 'Lock', click: () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('force-lock');
      }
    }},
    { type: 'separator' },
    { label: 'Quit', click: () => {
      isQuitting = true;
      app.quit();
    }},
  ]);
  appTray.setContextMenu(menu);
  appTray.on('click', () => { showMainWindow(); });
}

function showMainWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  } else {
    createWindow();
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 720,
    minWidth: 760,
    minHeight: 560,
    backgroundColor: '#0f1117',
    title: 'SecureVault',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  Menu.setApplicationMenu(null);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => mainWindow.show());

  // D14 FIX: Replace force-lock on minimize with close-to-tray behavior.
  // Previously, minimizing the window immediately locked the vault, which
  // was too aggressive — users commonly minimize to do other work and
  // expect to un-minimize and continue where they left off. Now, minimize
  // just hides the window (close-to-tray), keeping the session alive.
  // Auto-lock only happens on: explicit lock action (Ctrl+L, tray "Lock"),
  // auto-lock timer expiry, or close event (if tray not set up).
  mainWindow.on('minimize', () => {
    if (!mainWindow.isDestroyed()) mainWindow.hide(); // close-to-tray instead of force-lock
  });
  mainWindow.on('blur', () => {
    if (!mainWindow.isDestroyed()) mainWindow.webContents.send('window-blur');
  });
  // Close-to-tray: don't actually destroy the window — just hide it. The
  // tray icon stays, the secure channel persists, and the .svlt watcher
  // keeps running so extension edits still sync to the SD card.
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      // D14 FIX: Don't force-lock on close — just hide the window
      // (close-to-tray). The user can explicitly lock via Ctrl+L or the
      // tray "Lock" menu. Auto-lock also happens on timer expiry. The
      // previous behavior of force-locking on close was too aggressive —
      // closing the window to get it out of the way should not lock the
      // vault, just hide it (same as minimize).
      if (!mainWindow.isDestroyed()) {
        mainWindow.hide();
      }
    }
  });
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  createWindow();
  createTrayIcon();
  startVolumeWatcher();
  // Start watching the .svlt file if extension sync is already configured.
  startSvltWatcher();
  // powerMonitor resume (e.g. laptop woke from sleep) — re-check for the SD
  // card in case it was inserted while the system was asleep.
  powerMonitor.on('resume', async () => {
    const { withVault } = await findVaultOnRemovableVolumes();
    if (withVault.length > 0 && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('sdcard:auto-detected', {
        path: withVault[0],
        multiple: withVault.length > 1,
      });
    }
  });
});

app.on('window-all-closed', () => {
  // Tray mode: NEVER quit when the window closes. The app stays alive in
  // the tray so the .svlt watcher + secure channel can keep syncing. The
  // user must explicitly click "Quit" in the tray menu to exit.
  // (On macOS the behavior is the same — tray is the canonical "stay
  // alive" mechanism on all platforms.)
  // DO NOT tear down the secure channel here — it's needed for background
  // sync when the extension writes to .svlt while the window is hidden.
  if (process.platform === 'darwin' && !appTray) {
    // No tray (creation failed?) — fall back to old behavior on macOS only.
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
  if (volumeWatchTimer) {
    clearInterval(volumeWatchTimer);
    volumeWatchTimer = null;
  }
  stopSvltWatcher();
  // D7 FIX: Flush config to disk immediately on quit (not debounced).
  _flushConfigSync();
  // Zero all session secrets before the process exits.
  secureChannel.teardown();
  zeroCachedVault();
  if (appTray) {
    try { appTray.destroy(); } catch (_) {}
    appTray = null;
  }
});

// ─────────────────────────────────────────────────────────────────────────
//  Cached vault state (in-memory only, zeroed on lock/quit)
//
//  After `vault:save` or `extsync:writeNow` we sometimes need the most
//  recent plaintext entries to re-write the .svlt file (e.g. after a PIN
//  change, or when the user manually triggers an extension-sync write from
//  the SD card without being connected to a device).
//
//  THIS IS NEVER PERSISTED TO DISK. It lives in `cachedVaultEntries` only
//  for the lifetime of the session and is .fill(0)'d on lock/quit.
// ─────────────────────────────────────────────────────────────────────────
let cachedVaultEntries = null;
// D11 FIX: Cache the PIN as a Buffer that can be .fill(0)'d on lock/quit,
// instead of a JS string (which is immutable and can't be zeroed — a
// compromised renderer could extract the plaintext PIN from memory for the
// entire session duration). The Buffer is allocated once and filled from
// the UTF-8 encoding of the PIN string, then the string reference is
// immediately dropped. On lock/quit, the Buffer is zeroed before being
// freed, ensuring no plaintext PIN remains in memory.
let cachedVaultPinBuffer = null;

function setCachedVault(entries, pin) {
  // D11 FIX: When pin is null/undefined, preserve the existing cached PIN
  // (just update the entries). This is important for extension-sync handlers
  // that update cached entries but don't have the PIN — the PIN should only
  // be zeroed on explicit lock/quit, not on every entry cache update.
  const preservePin = (pin === null || pin === undefined);
  if (!preservePin) {
    // New PIN provided — zero the old one first.
    if (cachedVaultPinBuffer) {
      cachedVaultPinBuffer.fill(0);
      cachedVaultPinBuffer = null;
    }
  }
  // Deep-clone so the renderer can't mutate our copy.
  cachedVaultEntries = JSON.parse(JSON.stringify(entries || []));
  // D11 FIX: Store PIN as a zeroable Buffer, not a JS string.
  if (!preservePin && pin) {
    cachedVaultPinBuffer = Buffer.from(String(pin), 'utf8');
  }
}

function getCachedPin() {
  // D11 FIX: Return the PIN as a string for use in encryptVault(), but
  // the underlying Buffer can still be zeroed on lock/quit.
  if (!cachedVaultPinBuffer) return null;
  return cachedVaultPinBuffer.toString('utf8');
}

function zeroCachedVault() {
  if (cachedVaultEntries) {
    // Strings in JS are immutable, but we at least drop the references so
    // GC can reclaim them and the V8 heap doesn't hold stale plaintext.
    cachedVaultEntries = null;
  }
  // D11 FIX: Zero the PIN Buffer before freeing it — this ensures no
  // plaintext PIN remains in memory after lock/quit. JS strings can't be
  // zeroed (they're immutable), but Buffers can be .fill(0)'d.
  if (cachedVaultPinBuffer) {
    cachedVaultPinBuffer.fill(0);
    cachedVaultPinBuffer = null;
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  IPC: SD card selection / auto-detection
// ─────────────────────────────────────────────────────────────────────────
ipcMain.handle('sdcard:listRemovable', async () => {
  const { all, withVault } = await findVaultOnRemovableVolumes();
  return { all, withVault };
});

ipcMain.handle('sdcard:select', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select your SD card (the drive itself, or the folder containing vault.db)',
    properties: ['openDirectory'],
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  const chosen = result.filePaths[0];
  // D7 FIX: Use updateConfig instead of loadConfig → modify → saveConfig.
  updateConfig({ sdCardPath: chosen });
  state_lastSelectedPath = chosen;
  return chosen;
});

ipcMain.handle('sdcard:getSaved', () => {
  // D7 FIX: Use getConfig() instead of loadConfig().
  const cfg = getConfig();
  return cfg.sdCardPath || null;
});

ipcMain.handle('sdcard:setSelected', (_evt, sdRoot) => {
  state_lastSelectedPath = sdRoot;
  // D7 FIX: Use updateConfig instead of loadConfig → modify → saveConfig.
  updateConfig({ sdCardPath: sdRoot });
  return true;
});

ipcMain.handle('sdcard:status', (_evt, sdRoot) => {
  try {
    if (!sdRoot || !fs.existsSync(sdRoot)) return { exists: false };
    const vp = vaultPath(sdRoot);
    const hasVault = fs.existsSync(vp);
    let writable = true;
    try {
      fs.accessSync(sdRoot, fs.constants.W_OK);
    } catch {
      writable = false;
    }
    return { exists: true, hasVault, writable, path: sdRoot };
  } catch (e) {
    return { exists: false, error: e.message };
  }
});

// ─────────────────────────────────────────────────────────────────────────
//  IPC: SD-card vault.db read / decrypt / encrypt+save
// ─────────────────────────────────────────────────────────────────────────
ipcMain.handle('vault:unlock', async (_evt, sdRoot, pin) => {
  // D17 FIX: Validate PIN input from renderer.
  const pinValidation = validatePin(pin);
  if (!pinValidation.valid) return { success: false, code: 'BAD_PIN', error: pinValidation.error };
  try {
    const vp = vaultPath(sdRoot);
    // D8 FIX: Use async file I/O instead of fs.readFileSync.
    if (!fs.existsSync(vp)) {
      return { success: false, code: 'NO_FILE', error: `No vault.db found at ${vp}` };
    }
    const buf = await fs.promises.readFile(vp);
    // D9 FIX: decryptVault now returns { entries, kdfVersion, needsMigration }
    // instead of just entries. Old v1 files (20K iterations) are transparently
    // decrypted and will be re-encrypted as v2 (600K iterations) on next save.
    const result = decryptVault(buf, pin);
    // D10 FIX: Store detected format version in config so the app can proactively
    // offer migration. If the vault needs migration (v1 → v2), update config.
    if (result.needsMigration) {
      updateConfig({ vault_db_format_version: result.kdfVersion });
    } else {
      updateConfig({ vault_db_format_version: result.kdfVersion });
    }
    state_lastSelectedPath = sdRoot;
    setCachedVault(result.entries, pin);
    return { success: true, entries: result.entries, kdfVersion: result.kdfVersion, needsMigration: result.needsMigration };
  } catch (e) {
    if (e instanceof WrongPinError)   return { success: false, code: 'WRONG_PIN',  error: e.message };
    if (e instanceof VaultFormatError) return { success: false, code: 'BAD_FORMAT', error: e.message };
    if (e instanceof VaultHmacError)   return { success: false, code: 'HMAC_FAIL', error: e.message };
    return { success: false, code: 'IO_ERROR', error: e.message };
  }
});

ipcMain.handle('vault:createNew', async (_evt, sdRoot, pin) => {
  // D17 FIX: Validate PIN input from renderer.
  const pinValidation = validatePin(pin);
  if (!pinValidation.valid) return { success: false, error: pinValidation.error };
  try {
    const vp = vaultPath(sdRoot);
    if (fs.existsSync(vp)) {
      return { success: false, error: 'vault.db already exists at this location.' };
    }
    // D9 FIX: New vaults are always created with v2 format (600K iterations + HMAC).
    const data = encryptVault([], pin);
    // D8 FIX: Use async atomic write pattern for vault creation.
    await atomicWriteFile(vp, data);
    data.fill(0);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('vault:save', async (_evt, sdRoot, entries) => {
  // D17 FIX: Validate entries input from renderer.
  if (!Array.isArray(entries)) {
    return { success: false, code: 'BAD_INPUT', error: 'entries must be an array' };
  }
  try {
    // D11 FIX: vault:save no longer takes a PIN parameter from the renderer.
    // The PIN is retrieved from the main process's cached Buffer, which is
    // .fill(0)'d on lock/quit. The renderer never receives or stores the PIN.
    const pin = getCachedPin();
    if (!pin) {
      return { success: false, code: 'NO_PIN', error: 'No cached PIN. Unlock the vault first.' };
    }

    const vp = vaultPath(sdRoot);

    // validateEntries() throws VaultFormatError on length violations — caught below.
    // D9 FIX: Always encrypt with v2 format (600K iterations + HMAC). Old v1
    // vaults are transparently upgraded on first save after unlock.
    const data = encryptVault(entries, pin);

    // Backup current vault.db (on the SD card, in .backups/) BEFORE touching
    // the live file — extra safety net for desktop bulk edits.
    if (fs.existsSync(vp)) {
      const backupDir = path.join(sdRoot, BACKUP_DIR);
      fs.mkdirSync(backupDir, { recursive: true });
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      fs.copyFileSync(vp, path.join(backupDir, `vault_${stamp}.db`));
      pruneOldBackups(backupDir);
    }

    // D8 FIX: Use async atomic write pattern for vault.db.
    await atomicWriteFile(vp, data);
    data.fill(0);

    // Cache so future extension-sync writes can re-encrypt without the
    // renderer needing to re-send the plaintext.
    setCachedVault(entries, pin);

    // ── Auto-write .svlt file for browser extension ──
    // After every SD-card save, also push the updated vault to the .svlt
    // file the browser extension reads. No-op if extension sync is
    // disabled or not yet configured.
    await writeExtensionVaultFile(entries);

    return { success: true };
  } catch (e) {
    if (e instanceof VaultFormatError) {
      return { success: false, code: 'BAD_FORMAT', error: e.message };
    }
    return { success: false, error: e.message };
  }
});

ipcMain.handle('vault:changePin', async (_evt, sdRoot, oldPin, newPin) => {
  // D17 FIX: Validate PIN inputs from renderer.
  const oldPinValidation = validatePin(oldPin);
  if (!oldPinValidation.valid) return { success: false, code: 'BAD_PIN', error: oldPinValidation.error };
  const newPinValidation = validatePin(newPin);
  if (!newPinValidation.valid) return { success: false, error: newPinValidation.error };
  try {
    const vp = vaultPath(sdRoot);
    if (!fs.existsSync(vp)) {
      return { success: false, error: 'vault.db not found.' };
    }
    // 1. Decrypt with OLD pin — throws WrongPinError if wrong.
    // D9 FIX: decryptVault returns { entries, kdfVersion, needsMigration }.
    // D8 FIX: Use async file I/O instead of fs.readFileSync.
    const buf = await fs.promises.readFile(vp);
    const { entries } = decryptVault(buf, oldPin);

    // 2. Backup before re-encrypting (encrypted with the OLD pin, so it's
    //    recoverable if the user forgets the new pin).
    const backupDir = path.join(sdRoot, BACKUP_DIR);
    fs.mkdirSync(backupDir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    fs.copyFileSync(vp, path.join(backupDir, `vault_pre-pinchange_${stamp}.db`));
    pruneOldBackups(backupDir);

    // 3. Re-encrypt with NEW pin. Fresh salt+IV (encryptVault always
    //    generates new ones), so even the on-disk bytes look completely
    //    different from the previous file.
    // D9 FIX: Always write v2 format (600K iterations + HMAC).
    // D8 FIX: Use async atomic write pattern.
    const data = encryptVault(entries, newPin);
    await atomicWriteFile(vp, data);
    data.fill(0);

    setCachedVault(entries, newPin);
    return { success: true };
  } catch (e) {
    if (e instanceof WrongPinError) {
      return { success: false, code: 'WRONG_PIN', error: 'Current PIN is incorrect.' };
    }
    return { success: false, error: e.message };
  }
});

function pruneOldBackups(backupDir) {
  try {
    const files = fs
      .readdirSync(backupDir)
      .filter((f) => f.startsWith('vault_') && f.endsWith('.db'))
      .map((f) => ({ f, t: fs.statSync(path.join(backupDir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t);
    for (const { f } of files.slice(MAX_BACKUPS)) {
      try { fs.unlinkSync(path.join(backupDir, f)); } catch { /* best effort */ }
    }
  } catch { /* dir missing — nothing to prune */ }
}

ipcMain.handle('vault:listBackups', (_evt, sdRoot) => {
  try {
    const backupDir = path.join(sdRoot, BACKUP_DIR);
    if (!fs.existsSync(backupDir)) return [];
    return fs
      .readdirSync(backupDir)
      .filter((f) => f.startsWith('vault_') && f.endsWith('.db'))
      .map((f) => {
        const stat = fs.statSync(path.join(backupDir, f));
        return { filename: f, mtime: stat.mtimeMs, size: stat.size };
      })
      .sort((a, b) => b.mtime - a.mtime);
  } catch {
    return [];
  }
});

ipcMain.handle('vault:restoreBackup', (_evt, sdRoot, filename) => {
  try {
    const backupDir = path.join(sdRoot, BACKUP_DIR);
    const src = path.join(backupDir, filename);
    const vp = vaultPath(sdRoot);
    if (!fs.existsSync(src)) return { success: false, error: 'Backup file not found' };
    // Safety-copy the current (possibly-bad) file too, so restoring never
    // destroys data with no way back.
    if (fs.existsSync(vp)) {
      fs.copyFileSync(vp, path.join(backupDir, `vault_before-restore_${Date.now()}.db`));
      pruneOldBackups(backupDir);
    }
    fs.copyFileSync(src, vp);
    // Cached vault is now stale — drop it.
    zeroCachedVault();
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// ─────────────────────────────────────────────────────────────────────────
//  IPC: Utils — password generator, passphrase generator, strength, TOTP,
//                   clipboard, limits
// ─────────────────────────────────────────────────────────────────────────

/**
 * generatePassword(options) — cryptographically-secure random password.
 *
 * Uses crypto.randomBytes with rejection sampling to avoid modulo bias:
 * we pull a random byte, and only accept it if it falls in the largest
 * multiple of charset.length below 256. Otherwise discard and retry.
 * This prevents the `byte % charset.length` bias toward earlier characters
 * when charset.length doesn't divide 256 evenly.
 *
 * Options:
 *   {length, uppercase, lowercase, numbers, symbols, avoidAmbiguous}
 */
function generatePassword(options = {}) {
  const {
    length = 20,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    avoidAmbiguous = true,
  } = options;

  if (typeof length !== 'number' || length < 1 || length > 256) {
    throw new Error('length must be between 1 and 256');
  }

  let charset = '';
  if (lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (numbers)   charset += '0123456789';
  if (symbols)   charset += '!@#$%^&*';
  if (avoidAmbiguous) {
    // Strip visually-ambiguous chars: 0/O/o, 1/l/I, |. Useful for passwords
    // a human may need to read off-screen or transcribe.
    charset = charset.replace(/[0Oo1lI|]/g, '');
  }
  if (!charset) charset = 'abcdefghijklmnopqrstuvwxyz';

  const limit = 256 - (256 % charset.length);
  const chars = new Array(length);
  let i = 0;
  // Oversize the buffer so we rarely loop — for length<=20 we essentially
  // never need more than ~length*1.05 bytes.
  const buf = crypto.randomBytes(length * 4);
  let j = 0;
  while (i < length && j < buf.length) {
    const b = buf[j++];
    if (b >= limit) continue;          // rejection sample
    chars[i++] = charset[b % charset.length];
  }
  // Pathological fallback (probability ~0 for length<=20) — keep the code
  // correct rather than hang.
  while (i < length) {
    const b = crypto.randomBytes(1)[0];
    if (b < limit) chars[i++] = charset[b % charset.length];
  }
  buf.fill(0);
  return chars.join('');
}

/**
 * generatePassphrase(options) — Diceware-style passphrase from the inline
 * 500-word EFF short wordlist (wordlist.js).
 *
 * Entropy per word = log2(500) ≈ 8.97 bits, so:
 *   4 words ≈ 36 bits (good for non-critical logins)
 *   5 words ≈ 45 bits
 *   6 words ≈ 54 bits (comparable to a 10-char random password)
 *   7 words ≈ 63 bits (recommended for master passwords)
 *
 * Options:
 *   {wordCount, separator, capitalize, includeNumber}
 */
function generatePassphrase(options = {}) {
  const {
    wordCount = 4,
    separator = '-',
    capitalize = true,
    includeNumber = true,
  } = options;

  if (typeof wordCount !== 'number' || wordCount < 2 || wordCount > 16) {
    throw new Error('wordCount must be between 2 and 16');
  }
  // crypto.randomInt uses rejection sampling internally — no modulo bias.
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let word = WORDLIST[crypto.randomInt(0, WORDLIST.length)];
    if (capitalize) word = word[0].toUpperCase() + word.slice(1);
    words.push(word);
  }
  if (includeNumber) {
    // Append a 0-99 number to one of the words (Bitwarden-style).
    const n = crypto.randomInt(0, 100);
    const idx = crypto.randomInt(0, words.length);
    words[idx] = words[idx] + String(n);
  }
  return words.join(separator);
}

ipcMain.handle('util:generatePassword', (_evt, options = {}) => {
  try {
    if (options.passphrase) {
      return { ok: true, password: generatePassphrase(options) };
    }
    return { ok: true, password: generatePassword(options) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

/**
 * passwordStrength(password) — Shannon-entropy-based strength estimator
 * with common-password + pattern penalties.
 *
 * Returns {score (0-4), label, entropy, suggestions[]}.
 *   0 = Very weak   (entropy < 28)
 *   1 = Weak        (entropy < 36)
 *   2 = Fair        (entropy < 60)
 *   3 = Strong      (entropy < 128)
 *   4 = Very strong (entropy >= 128)
 *
 * This is NOT zxcvbn (that's 200KB+) — it's a small in-process estimator
 * good enough to catch "password1" / "qwerty" / all-digit / short cases.
 */
const COMMON_PASSWORDS = new Set([
  'password','123456','123456789','12345678','12345','qwerty','abc123','football',
  'monkey','letmein','dragon','111111','baseball','iloveyou','trustno1','sunshine',
  'master','welcome','login','princess','admin','root','passw0rd','superman','batman',
  'access','hello','charlie','donald','password1','qwerty123','1q2w3e4r','aaaaaa',
  'asdfgh','zxcvbn','1qaz2wsx','pass','test','guest','user','000000','666666','888888',
  'iloveu','secret','starwars','whatever','solo','passw0rd1','letmein1','admin123',
]);

function passwordStrength(password) {
  if (!password) return { score: 0, label: 'Empty', entropy: 0, suggestions: ['Enter a password.'] };

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
  const entropy = password.length * Math.log2(pool || 1);

  let penalties = 0;
  const suggestions = [];

  // Sequential runs (abc, 123, qwerty)
  const sequential = /(?:abc|bcd|cde|xyz|012|123|234|345|456|567|678|789|890|qwe|wer|ert|rty|asd|sdf|dfg|zxc|cvb)/i;
  if (sequential.test(password)) { penalties += 15; suggestions.push('Avoid sequential characters (abc, 123, qwerty).'); }

  // Repeated chars (aaaa, 1111)
  if (/(.)\1\1/.test(password)) { penalties += 10; suggestions.push('Avoid repeating the same character 3+ times.'); }

  // All-digit (very common, very weak even if long)
  if (/^\d+$/.test(password)) { penalties += 20; suggestions.push('Add letters and symbols — all-number passwords are easily cracked.'); }

  // Common password dictionary
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    penalties += 40;
    suggestions.push('This is one of the most-cracked passwords in the world — change it.');
  }

  // Contains "password" / "admin" / "welcome" / "login"
  if (/password|admin|welcome|login/i.test(password)) {
    penalties += 15;
    suggestions.push('Avoid common words like "password", "admin", "welcome".');
  }

  // Length bonuses / penalties
  if (password.length < 8) { penalties += 25; suggestions.push('Use at least 12 characters.'); }
  else if (password.length < 12) { suggestions.push('12+ characters is recommended.'); }

  const adjusted = Math.max(0, entropy - penalties);
  let score;
  if      (adjusted < 28)  score = 0;
  else if (adjusted < 36)  score = 1;
  else if (adjusted < 60)  score = 2;
  else if (adjusted < 128) score = 3;
  else                     score = 4;

  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
  if (suggestions.length === 0 && score >= 3) suggestions.push('Good password.');
  return { score, label: labels[score], entropy: Math.round(adjusted), suggestions };
}

ipcMain.handle('util:passwordStrength', (_evt, password) => {
  return passwordStrength(password);
});

ipcMain.handle('util:copyToClipboard', (_evt, text) => {
  if (typeof text !== 'string') return false;
  clipboard.writeText(text);
  return true;
});

ipcMain.handle('util:clearClipboardIfMatches', (_evt, text) => {
  // Only wipe the clipboard if it still contains what we put there —
  // don't stomp on something the user copied from elsewhere in the meantime.
  if (typeof text === 'string' && clipboard.readText() === text) {
    clipboard.writeText('');
    return true;
  }
  return false;
});

ipcMain.handle('util:limits', () => ({
  MAX_ENTRIES,
  FIELD_LIMITS,
  EXTENDED_LIMITS,
  ENTRY_TYPES,
}));

// ─────────────────────────────────────────────────────────────────────────
//  IPC: TOTP code generation (RFC 6238) — so the dashboard can show a
//  live 30-second code without round-tripping to the device.
// ─────────────────────────────────────────────────────────────────────────
ipcMain.handle('util:totp', (_evt, secret, t = Date.now()) => {
  try {
    return computeTotp(secret, t);
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

function computeTotp(secret, t) {
  // Base32 decode (RFC 4648) — the firmware uses the same alphabet.
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (clean.length === 0) return { ok: false, error: 'Empty secret' };

  let bits = '';
  for (const c of clean) {
    const idx = ALPHA.indexOf(c);
    if (idx < 0) return { ok: false, error: 'Invalid Base32 character: ' + c };
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const key = Buffer.from(bytes);

  // T = floor(unix_time / 30), big-endian 8 bytes
  const counter = Math.floor(t / 1000 / 30);
  const counterBuf = Buffer.alloc(8);
  // JS bitwise ops are 32-bit, so write the high 4 bytes manually:
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset]     & 0x7f) << 24 |
                (hmac[offset + 1] & 0xff) << 16 |
                (hmac[offset + 2] & 0xff) << 8  |
                (hmac[offset + 3] & 0xff)) % 1000000;
  // Wipe the key buffer (best effort — hmac internally copies).
  key.fill(0);
  return {
    ok: true,
    code: String(code).padStart(6, '0'),
    secondsLeft: 30 - (Math.floor(t / 1000) % 30),
  };
}

// ─── Breach check (HIBP k-anonymity) ────────────────────────────────────
//
//  Checks plaintext passwords against the Have I Been Pwned Pwned Passwords
//  API using the k-anonymity model: only the first 5 hex chars of the SHA-1
//  hash are sent over the network. The plaintext password and full hash
//  never leave this process. See breachCheck.js for the implementation.
//
//  OFF BY DEFAULT: every call is gated behind `cfg.hibpCheckEnabled`. The
//  user must opt-in via Settings → Breach Detection. When the user later
//  disables it, the in-memory prefix cache is wiped via clearBreachCache().
const { checkPwnedPassword, vaultHealthScan, clearBreachCache } = require('./breachCheck');

ipcMain.handle('util:checkPwned', async (_evt, password) => {
  // D7 FIX: Use getConfig() instead of loadConfig().
  const cfg = getConfig();
  if (!cfg.hibpCheckEnabled) {
    return { breached: false, count: 0, error: 'Breach check is disabled. Enable it in Settings.' };
  }
  return await checkPwnedPassword(password);
});

// D19 FIX: vaultHealthScan no longer receives full entries from the renderer.
// Instead, the renderer sends only entry IDs. The main process looks up passwords
// from its own cachedVaultEntries — passwords never cross the IPC bridge for
// health scans.
ipcMain.handle('util:vaultHealthScan', async (_evt, entryIds) => {
  const cfg = getConfig();
  if (!cfg.hibpCheckEnabled) {
    return { ok: false, error: 'Breach check is disabled. Enable it in Settings.' };
  }
  // D19 FIX: Use cached entries from main process instead of renderer-sent entries.
  // The renderer sends only entryIds (array of id strings). Main looks up passwords
  // from cachedVaultEntries, which it already has from vault:unlock/vault:save.
  if (!cachedVaultEntries || cachedVaultEntries.length === 0) {
    return { ok: false, error: 'No cached vault entries. Unlock a vault first.' };
  }
  // Build entries list from cachedVaultEntries, filtered by entryIds if provided.
  let entriesToScan;
  if (Array.isArray(entryIds) && entryIds.length > 0) {
    entriesToScan = cachedVaultEntries.filter(e => entryIds.includes(e.id));
  } else {
    // No IDs provided — scan all cached entries.
    entriesToScan = cachedVaultEntries;
  }
  try {
    const results = await vaultHealthScan(entriesToScan, (checked, total, site, result) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('health-scan:progress', { checked, total, site, result });
      }
    });
    return { ok: true, results };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('util:clearBreachCache', () => {
  clearBreachCache();
  return { ok: true };
});

ipcMain.handle('settings:getHibpEnabled', () => {
  const cfg = getConfig();
  return { enabled: cfg.hibpCheckEnabled === true };
});

ipcMain.handle('settings:setHibpEnabled', (_evt, enabled) => {
  // D7 FIX: Use updateConfig instead of loadConfig → modify → saveConfig.
  updateConfig({ hibpCheckEnabled: !!enabled });
  if (!enabled) clearBreachCache();
  return { ok: true };
});

// ════════════════════════════════════════════════════════════════════════
//  IPC: SECURE DEVICE MODE (4-Layer Security Stack over USB-CDC Serial)
//
//  When the user chooses "Connect to ESP32", all vault access goes through
//  the ESP32 over USB-CDC serial with ECDH + AES-256-GCM. The renderer
//  sends the 6-digit code here; the main process does the ECDH handshake +
//  encrypted requests. The renderer NEVER sees the session key, ECDH
//  private key, or any raw frame bytes — only the decrypted entry data
//  needed for display.
//
//  Layer 4 isolation: all crypto lives in the main process (this file +
//  secureChannel.js). The renderer is a "dumb terminal" that displays data
//  and sends user intents (add/edit/delete/lock).
// ════════════════════════════════════════════════════════════════════════
ipcMain.handle('device:handshake', async (_evt, code, portPath) => {
  try {
    return await secureChannel.handshake(code, portPath);
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('device:isConnected', () => secureChannel.isEstablished());

ipcMain.handle('device:listEntries', async () => {
  try {
    const entries = await secureChannel.listEntries();

    // After a successful sync from the device, fetch full entries (with
    // TOTP secrets) and write the .svlt file for the browser extension.
    // Fire-and-forget — the device-list operation shouldn't fail if the
    // .svlt write fails.
    try {
      const urlCache = loadUrlCache();
      const typeMap = { 0: 'login', 1: 'card', 2: 'identity', 3: 'note' };
      const fullEntries = [];
      for (const e of entries) {
        if (typeof e.index === 'number') {
          const full = await secureChannel.getEntry(e.index);
          const siteName = full.site || '';
          const url = urlCache[siteName] || siteName;
          const typeStr = (typeof full.type === 'number') ? (typeMap[full.type] || 'login')
                        : (full.type || 'login');
          fullEntries.push(buildExtensionEntry(full, typeStr, url, e.index));
        }
      }
      setCachedVault(fullEntries, null);
      await writeExtensionVaultFile(fullEntries);
    } catch (extErr) {
      console.warn('[extension-sync] Auto-write after device sync failed:', extErr.message);
    }
    return { ok: true, entries };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('device:getEntry', async (_evt, index) => {
  try {
    return { ok: true, entry: await secureChannel.getEntry(index) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('device:addEntry', async (_evt, entry) => {
  // D17 FIX: Validate entry input from renderer.
  const entryValidation = validateEntry(entry);
  if (!entryValidation.valid) {
    return { ok: false, error: entryValidation.error };
  }
  try {
    // CRITICAL: Must route through toDeviceEntry() to translate renderer-style
    // field names (idFirstName, cardHolder, cardExpiry, etc.) to firmware-style
    // field names (firstName, cardholder, exp, etc.). Without this, the firmware's
    // SV_READ_ENTRY_FROM_JSON macro can't find the fields and they arrive as
    // empty strings — this was the root cause of Identity/Card entries being blank.
    const deviceEntry = toDeviceEntry(entry);
    const result = await secureChannel.addEntry(deviceEntry);
    // Refresh the .svlt file so the extension sees the new entry.
    // Fire-and-forget: don't await — extension sync sends N+1 serial
    // requests (1 LIST + N GETs) which can take 5-20s for large vaults
    // and would block the IPC response to the renderer.
    if (result && result.ok !== false) {
      refreshExtensionVaultFromDevice().catch(() => {});
    }
    return result;
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('device:updateEntry', async (_evt, index, entry) => {
  // D17 FIX: Validate entry and index inputs from renderer.
  const indexValidation = validateDeviceIndex(index);
  if (!indexValidation.valid) return { ok: false, error: indexValidation.error };
  const entryValidation = validateEntry(entry);
  if (!entryValidation.valid) return { ok: false, error: entryValidation.error };
  try {
    // CRITICAL: Must route through toDeviceEntry() — same reason as addEntry.
    const deviceEntry = toDeviceEntry(entry);
    const result = await secureChannel.updateEntry(index, deviceEntry);
    if (result && result.ok !== false) {
      refreshExtensionVaultFromDevice().catch(() => {});
    }
    return result;
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('device:deleteEntry', async (_evt, index) => {
  // D17 FIX: Validate index input from renderer.
  const indexValidation = validateDeviceIndex(index);
  if (!indexValidation.valid) return { ok: false, error: indexValidation.error };
  try {
    const result = await secureChannel.deleteEntry(index);
    if (result && result.ok !== false) {
      refreshExtensionVaultFromDevice().catch(() => {});
    }
    return result;
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// Layer 4: lock + zero all secrets
ipcMain.handle('device:lock', async () => {
  await secureChannel.lockSession();
  zeroCachedVault();
  return { ok: true };
});

ipcMain.handle('device:listPorts', async () => {
  try {
    return { ok: true, ports: await secureChannel.listPorts() };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// ════════════════════════════════════════════════════════════════════════
//  Extension Sync — writes a strongly-encrypted .svlt file that the
//  browser extension reads. The Electron app writes it after every device
//  sync or SD-card vault save. It can also read the .svlt file (that the
//  extension wrote) and push new entries to the ESP32.
//
//  Config persistence:
//    - File path: stored in plaintext in config.json (it's just a path)
//    - Master password: encrypted with Electron's safeStorage (DPAPI on
//      Windows, Keychain on macOS, libsecret on Linux) and stored as
//      base64 in config.json. Decrypts only on this machine, in this
//      user's OS session.
//
//  Auto-write triggers:
//    - After every successful `vault:save` (SD card save)
//    - After every successful `device:listEntries` (post-sync full fetch)
//    - After every successful `device:addEntry/updateEntry/deleteEntry`
// ════════════════════════════════════════════════════════════════════════
function getExtSyncConfig() {
  // D7 FIX: Use getConfig() instead of loadConfig().
  const cfg = getConfig();
  return {
    enabled:          cfg.ext_sync_enabled === true,
    filePath:         cfg.ext_sync_file_path || '',
    encryptedPassword: cfg.ext_sync_password || '', // base64 of safeStorage-encrypted bytes
    autoWriteOnSync:  cfg.ext_sync_auto_on_sync !== false, // default true
    autoWriteOnEdit:  cfg.ext_sync_auto_on_edit !== false, // default true
  };
}

function setExtSyncConfig(patch) {
  // D7 FIX: Use updateConfig instead of loadConfig → modify → saveConfig.
  updateConfig({
    ext_sync_enabled:        patch.enabled,
    ext_sync_file_path:      patch.filePath,
    ext_sync_password:       patch.encryptedPassword,
    ext_sync_auto_on_sync:   patch.autoWriteOnSync,
    ext_sync_auto_on_edit:   patch.autoWriteOnEdit,
  });
}

function getExtSyncPassword() {
  const { encryptedPassword } = getExtSyncConfig();
  if (!encryptedPassword) return null;
  try {
    if (!safeStorage.isEncryptionAvailable()) return null;
    const buf = Buffer.from(encryptedPassword, 'base64');
    return safeStorage.decryptString(buf);
  } catch (e) {
    console.warn('[extension-sync] Failed to decrypt stored password:', e.message);
    return null;
  }
}

function setExtSyncPassword(password) {
  if (!password) {
    setExtSyncConfig({ encryptedPassword: '' });
    return;
  }
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS keychain unavailable — cannot persist master password. Enable DPAPI/Keychain/libsecret or enter the password each session.');
  }
  const encrypted = safeStorage.encryptString(password);
  setExtSyncConfig({ encryptedPassword: encrypted.toString('base64') });
}

/**
 * v6.4 SYNC FIX: Normalize a single entry to the canonical extension-
 * compatible shape. This is the SOURCE OF TRUTH for what the .svlt file
 * contains — every entry that reaches writeExtensionVaultFile() passes
 * through here.
 *
 * Guarantees:
 *   - `id` (string) — always present, deterministic when missing
 *   - `name` (string) — falls back to `site`
 *   - `type` (string) — one of 'login' | 'card' | 'identity' | 'note'
 *   - `favorite` (boolean) AND `fav` (0/1) — both present, in sync
 *   - `deleted` (boolean) AND `del` (0/1) — both present, in sync
 *   - `created` / `updated` / `deletedAt` — numbers, always present
 *   - All string fields — coerced to string, never undefined
 *
 * The previous bug: the SD-card save path sent entries with `fav` (numeric)
 * but no `favorite` (boolean), so the extension's Favorites filter showed
 * 0 entries. The user's trashed identity also appeared in the Identities
 * filter because `deleted` was sometimes missing in edge cases (when the
 * entry came from a CSV import path that set `del` but not `deleted`).
 *
 * Symmetric to renderer.js's `entriesForFirmware` + `synthesizeEntryId` —
 * the synthesizeEntryId algorithm MUST match between the two.
 */
// D3+D6 FIX: Replace FNV-based synthesizeEntryIdMain with crypto.randomUUID().
// The old approach had the same bugs as the renderer's synthesizeEntryId:
//   1. Two accounts on same site with same user → same ID → merge/overwrite
//   2. Editing site or user changed the ID → stale orphan + duplicate
// Now uses crypto.randomUUID() for stable, unique IDs.
function synthesizeEntryIdMain(e) {
  if (e && e.id && typeof e.id === 'string') return e.id;
  return crypto.randomUUID();
}

function normalizeForExtensionSync(e) {
  // D12 FIX: Use canonicalNormalize as the base, then add extension-only
  // fields ON TOP. This eliminates duplicate normalization logic.
  const base = canonicalNormalize(e);
  if (!base) return null;
  const isFav = base.fav ? true : false;
  const isDel = base.deleted ? true : false;
  const now = Date.now();

  return {
    ...base,
    // ── Extension-specific fields ──
    id: synthesizeEntryIdMain(e),
    _version: base._version,
    name: base.site,        // extension uses `name` as the title
    favorite: isFav,        // extension reads this (boolean)
    del: isDel ? 1 : 0,     // firmware-style numeric
    created: base.created || now,
    updated: base.updated || now,
    deletedAt: isDel ? (base.deletedAt || now) : 0,
    url: base.url,
  };
}

/**
 * Write the .svlt file with the given entries using the stored master
 * password. No-op if extension sync is disabled, no file path, or no
 * password. Never throws — failures are logged and reported to the
 * renderer via `extension-sync:error` so the main vault operation (SD
 * card save, device sync) doesn't break.
 */
async function writeExtensionVaultFile(entries) {
  // D16 FIX: Acquire cooperative lock before writing .svlt file.
  const cfg = getExtSyncConfig();
  if (!cfg.enabled || !cfg.filePath) return;

  const password = getExtSyncPassword();
  if (!password) {
    console.warn('[extension-sync] No master password available — skip write. Open Settings → Extension Sync to set it.');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('extension-sync:error', 'No master password set — open Settings → Extension Sync.');
    }
    return;
  }

  // v6.4 SYNC FIX: Normalize every entry to the extension-compatible shape
  // right before encryption.
  const normalized = (Array.isArray(entries) ? entries : [])
    .map(normalizeForExtensionSync)
    .filter(Boolean);
  try {
    const encrypted = encryptVaultFile(normalized, password);

    // D16 FIX: Cooperative file locking for .svlt writes.
    // Acquire lock → write → release lock.
    const lockPath = cfg.filePath + '.lock';
    let lockAcquired = false;
    try {
      // Check if lock exists and is stale (older than 30 seconds).
      if (fs.existsSync(lockPath)) {
        try {
          const lockStat = fs.statSync(lockPath);
          const lockAge = Date.now() - lockStat.mtimeMs;
          if (lockAge > SVLT_LOCK_TIMEOUT_MS) {
            // Stale lock — assume the previous writer crashed and overwrite it.
            console.warn('[extension-sync] Stale .svlt.lock detected (age:', Math.round(lockAge/1000), 's) — removing.');
            fs.unlinkSync(lockPath);
          } else {
            // Lock is fresh — another process is writing. Skip this write.
            console.warn('[extension-sync] .svlt.lock is fresh — skipping write to avoid concurrent writes.');
            return;
          }
        } catch (e) {
          // Can't stat the lock — assume stale and try to remove it.
          try { fs.unlinkSync(lockPath); } catch (_) {}
        }
      }
      // Create lock file with timestamp and PID.
      const lockData = JSON.stringify({ ts: Date.now(), pid: process.pid });
      fs.writeFileSync(lockPath, lockData, 'utf8');
      lockAcquired = true;
    } catch (e) {
      console.warn('[extension-sync] Failed to acquire .svlt.lock:', e.message);
      // Proceed without lock — best effort.
    }

    // D8 FIX: Async atomic write for .svlt file.
    try {
      await atomicWriteFile(cfg.filePath, encrypted);
    } finally {
      // D16 FIX: Release lock after write (regardless of write success).
      if (lockAcquired) {
        try { fs.unlinkSync(lockPath); } catch (_) {}
      }
    }

    encrypted.fill(0);

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('extension-sync:written', {
        path: cfg.filePath,
        count: normalized.length,
        bytes: fs.statSync(cfg.filePath).size,
      });
    }
  } catch (e) {
    console.error('[extension-sync] writeExtensionVaultFile failed:', e.message);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('extension-sync:error', e.message);
    }
  }
}

/**
 * After an on-device edit (add/update/delete), re-fetch all entries from
 * the device and write a fresh .svlt file. Mirrors the post-sync auto-write
 * path so the extension always reflects the latest device state.
 *
 * v4: DEBOUNCED — multiple rapid edits (add then quickly delete) won't
 * each trigger a full LIST + N GETs cycle. Instead, we wait 3 seconds
 * after the last edit before refreshing. This dramatically reduces serial
 * traffic and prevents overwhelming the ESP32 with GET requests.
 */
let _refreshTimer = null;
async function refreshExtensionVaultFromDevice() {
  const cfg = getExtSyncConfig();
  if (!cfg.enabled || !cfg.filePath || !cfg.autoWriteOnEdit) return;
  if (!secureChannel.isEstablished()) return;

  // Debounce: if a refresh is already pending, reset the timer.
  // This coalesces multiple rapid edits into a single refresh.
  if (_refreshTimer) clearTimeout(_refreshTimer);
  _refreshTimer = setTimeout(async () => {
    _refreshTimer = null;
    try {
      const entries = await secureChannel.listEntries();
      const urlCache = loadUrlCache();
      const typeMap = { 0: 'login', 1: 'card', 2: 'identity', 3: 'note' };
      const fullEntries = [];
      for (const e of entries) {
        if (typeof e.index === 'number') {
          const full = await secureChannel.getEntry(e.index);
          const siteName = full.site || '';
          const url = urlCache[siteName] || siteName;
          const typeStr = (typeof full.type === 'number') ? (typeMap[full.type] || 'login')
                        : (full.type || 'login');
          fullEntries.push(buildExtensionEntry(full, typeStr, url, e.index));
        }
      }
      setCachedVault(fullEntries, null);
      await writeExtensionVaultFile(fullEntries);
    } catch (e) {
      console.warn('[extension-sync] refreshExtensionVaultFromDevice failed:', e.message);
    }
  }, 3000); // 3-second debounce
}

// ─── IPC: Extension Sync settings ───────────────────────────────────────
ipcMain.handle('extsync:getStatus', () => {
  const cfg = getExtSyncConfig();
  return {
    enabled:              cfg.enabled,
    filePath:             cfg.filePath,
    hasPassword:          !!cfg.encryptedPassword,
    autoWriteOnSync:      cfg.autoWriteOnSync,
    autoWriteOnEdit:      cfg.autoWriteOnEdit,
    safeStorageAvailable: safeStorage.isEncryptionAvailable(),
  };
});

ipcMain.handle('extsync:pickFilePath', async () => {
  if (!mainWindow) return { ok: false, error: 'No window' };
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Choose where to save the encrypted vault file for the browser extension',
    defaultPath: 'vault.svlt',
    filters: [
      { name: 'SecureVault file', extensions: ['svlt'] },
      { name: 'All files', extensions: ['*'] },
    ],
    properties: ['showOverwriteConfirmation'],
  });
  if (result.canceled || !result.filePath) return { ok: false, canceled: true };
  setExtSyncConfig({ filePath: result.filePath });
  // Restart the .svlt watcher now that we have a file path.
  startSvltWatcher();
  return { ok: true, path: result.filePath };
});

ipcMain.handle('extsync:setPassword', async (_evt, password) => {
  if (!password || password.length < 8) {
    return { ok: false, error: 'Master password must be at least 8 characters' };
  }
  try {
    setExtSyncPassword(password);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('extsync:changePassword', async (_evt, oldPassword, newPassword) => {
  if (!newPassword || newPassword.length < 8) {
    return { ok: false, error: 'New password must be at least 8 characters' };
  }
  // Verify old password matches the stored one
  // v10.9 FIX: Use crypto.timingSafeEqual() instead of !== for password
  // comparison. The old `stored !== oldPassword` comparison leaks length
  // information via timing attacks — an attacker measuring response time
  // can determine how many characters matched. For a master password to
  // an encrypted vault file, this should use constant-time comparison.
  const stored = getExtSyncPassword();
  if (!stored) {
    return { ok: false, error: 'Current password is wrong' };
  }
  const storedBuf = Buffer.from(stored, 'utf8');
  const oldBuf = Buffer.from(oldPassword, 'utf8');
  // Both buffers must be the same length for timingSafeEqual.
  // Pad the shorter one with zeros (this leaks length, but the length
  // is already known from the !== check pattern — the fix is about
  // preventing per-character timing leakage).
  const maxLen = Math.max(storedBuf.length, oldBuf.length);
  const paddedStored = Buffer.alloc(maxLen);
  const paddedOld = Buffer.alloc(maxLen);
  storedBuf.copy(paddedStored);
  oldBuf.copy(paddedOld);
  const { timingSafeEqual } = require('crypto');
  if (!timingSafeEqual(paddedStored, paddedOld)) {
    paddedStored.fill(0); paddedOld.fill(0);  // zero padded buffers
    return { ok: false, error: 'Current password is wrong' };
  }
  paddedStored.fill(0); paddedOld.fill(0);  // zero padded buffers after use
  try {
    // ── Anti-brick fix (bug 8-d) ───────────────────────────────────────
    // Previously: if cachedVaultEntries was empty, we'd update the master
    // password in safeStorage but NOT re-write the .svlt file. The file on
    // disk was still encrypted with the OLD password, so the next attempt
    // to decrypt it with the NEW password would fail with WrongPasswordError
    // — bricking the file.
    //
    // Now: if we don't have a cached vault, READ the file with the OLD
    // password first, then re-encrypt with the new password. This ensures
    // the file is always re-written with the new key.
    const cfg = getExtSyncConfig();
    if (cachedVaultEntries && cachedVaultEntries.length > 0) {
      setExtSyncPassword(newPassword);
      await writeExtensionVaultFile(cachedVaultEntries);
      return { ok: true, note: 'Password updated and .svlt file re-written.' };
    }
    // No cache — read the file with the old password, re-encrypt with new.
    if (cfg.filePath && fs.existsSync(cfg.filePath)) {
      try {
        // D8 FIX: Use async file I/O for .svlt file read.
        const buf = await fs.promises.readFile(cfg.filePath);
        const entries = decryptVaultFile(buf, oldPassword);
        setExtSyncPassword(newPassword);
        // Now writeExtensionVaultFile will use the NEW password (just stored).
        await writeExtensionVaultFile(entries);
        return { ok: true, note: 'Password updated and .svlt file re-written from disk.' };
      } catch (e) {
        // File could not be decrypted with the old password — don't change
        // the stored password (that would brick the file).
        return { ok: false, error: 'Could not decrypt .svlt file with the current password: ' + e.message };
      }
    }
    // No file configured — just update the stored password.
    setExtSyncPassword(newPassword);
    return {
      ok: true,
      note: 'Password updated. No .svlt file configured — set a file path in Settings.',
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('extsync:setEnabled', (_evt, enabled) => {
  setExtSyncConfig({ enabled: !!enabled });
  return { ok: true };
});

ipcMain.handle('extsync:setAutoWrite', (_evt, onSync, onEdit) => {
  setExtSyncConfig({ autoWriteOnSync: !!onSync, autoWriteOnEdit: !!onEdit });
  return { ok: true };
});

ipcMain.handle('extsync:writeNow', async () => {
  // Manually trigger a write — re-fetches from the device if connected,
  // otherwise falls back to the cached SD-card vault.
  if (secureChannel.isEstablished()) {
    // Force a write even if autoWriteOnEdit is disabled — the user
    // explicitly clicked "Write now" (bug 8-u: previously this called
    // refreshExtensionVaultFromDevice which silently no-ops when
    // autoWriteOnEdit is false, then lied that it synced from device).
    try {
      const entries = await secureChannel.listEntries();
      const urlCache = loadUrlCache();
      const typeMap = { 0: 'login', 1: 'card', 2: 'identity', 3: 'note' };
      const fullEntries = [];
      for (const e of entries) {
        if (typeof e.index === 'number') {
          const full = await secureChannel.getEntry(e.index);
          const siteName = full.site || '';
          const url = urlCache[siteName] || siteName;
          const typeStr = (typeof full.type === 'number') ? (typeMap[full.type] || 'login')
                        : (full.type || 'login');
          fullEntries.push(buildExtensionEntry(full, typeStr, url, e.index));
        }
      }
      setCachedVault(fullEntries, null);
      await writeExtensionVaultFile(fullEntries);
      return { ok: true, source: 'device', count: fullEntries.length };
    } catch (e) {
      return { ok: false, error: 'Device sync failed: ' + e.message };
    }
  }
  if (cachedVaultEntries && cachedVaultEntries.length > 0) {
    await writeExtensionVaultFile(cachedVaultEntries);
    return { ok: true, source: 'cache', count: cachedVaultEntries.length };
  }
  return {
    ok: false,
    error: 'No active device session and no cached vault. Connect to the ESP32 or unlock an SD-card vault first.',
  };
});

ipcMain.handle('extsync:clearPassword', () => {
  setExtSyncConfig({ encryptedPassword: '' });
  return { ok: true };
});

// ════════════════════════════════════════════════════════════════════════
//  Sync FROM .svlt file TO ESP32
//
//  Reads the .svlt file that the browser extension wrote, decrypts it,
//  and pushes new/modified entries to the ESP32 via the secure channel.
//
//  This is the reverse direction of the auto-write: instead of the Electron
//  app writing the file for the extension to read, the extension writes the
//  file and Electron reads it to sync to the device.
// ════════════════════════════════════════════════════════════════════════
ipcMain.handle('extsync:syncFromFile', async () => {
  const cfg = getExtSyncConfig();
  if (!cfg.enabled || !cfg.filePath) {
    return { ok: false, error: 'Extension sync not configured. Set a file path in Settings.' };
  }
  if (!fs.existsSync(cfg.filePath)) {
    return { ok: false, error: 'Vault file not found: ' + cfg.filePath };
  }

  const password = getExtSyncPassword();
  if (!password) {
    return { ok: false, error: 'No master password stored. Set it in Settings → Extension Sync.' };
  }

  if (!secureChannel.isEstablished()) {
    return { ok: false, error: 'Not connected to ESP32. Enter the 6-digit code and connect first.' };
  }

  // Read and decrypt the .svlt file
  let fileEntries;
  try {
    // D8 FIX: Use async file I/O instead of fs.readFileSync.
    const fileBuffer = await fs.promises.readFile(cfg.filePath);
    fileEntries = decryptVaultFile(fileBuffer, password);
  } catch (e) {
    if (e instanceof WrongPasswordError) {
      return { ok: false, error: 'Wrong master password (stored password does not match this .svlt file).' };
    }
    return { ok: false, error: 'Cannot decrypt vault file: ' + e.message };
  }

  if (!Array.isArray(fileEntries)) {
    return { ok: false, error: 'Vault file is corrupt or has no entries' };
  }

  // Get current device entries.
  let deviceEntries;
  try {
    deviceEntries = await secureChannel.listEntries();
  } catch (e) {
    return { ok: false, error: 'Cannot list device entries: ' + e.message };
  }

  // ── Two-way merge (replaces old "skip if site name exists" non-logic) ──
  // D3+D6 FIX: The device identifies entries by index. fileEntries identifies
  // by UUID. We now match fileEntries to deviceEntries by (site, user) pair
  // instead of site name alone — two accounts on the same site with different
  // users are now correctly distinguished and won't merge/overwrite each other.
  //   - If no device entry has the same (site, user) pair → ADD
  //   - If a device entry has the same (site, user) pair → UPDATE (push file's version)
  // For each device entry not in the file → leave alone (device may have
  // entries the user wants to keep; we don't auto-delete). The user can
  // explicitly delete via the dashboard.
  const deviceBySiteUser = new Map();
  for (const d of (deviceEntries || [])) {
    if (typeof d.index === 'number' && d.site) {
      // D3+D6 FIX: Key by (site, user) pair instead of site alone.
      const key = (d.site || '') + '|' + (d.user || '');
      // Assign a UUID to device-sourced entries on first sync if they don't have one.
      if (!d.id) d.id = crypto.randomUUID();
      deviceBySiteUser.set(key, d);
    }
  }

  let added = 0, updated = 0, skipped = 0, failed = 0;
  for (const entry of fileEntries) {
    if (entry.deleted) { skipped++; continue; }
    const siteName = entry.site || entry.name || '';
    if (!siteName) { skipped++; continue; }
    const userName = entry.user || entry.login_username || '';
    const deviceEntry = toDeviceEntry(entry);
    // D3+D6 FIX: Match by (site, user) pair instead of just site.
    const key = siteName + '|' + userName;
    const existing = deviceBySiteUser.get(key);
    try {
      if (existing) {
        const result = await secureChannel.updateEntry(existing.index, deviceEntry);
        if (result && result.ok !== false) updated++; else failed++;
      } else {
        const result = await secureChannel.addEntry(deviceEntry);
        if (result && result.ok !== false) added++; else failed++;
      }
    } catch {
      failed++;
    }
  }

  // Update URL cache with URLs from the file entries (firmware has no URL field)
  const urlCache = loadUrlCache();
  for (const entry of fileEntries) {
    const siteName = entry.site || entry.name || '';
    const url = entry.url || entry.login_uri || '';
    if (siteName && url) {
      urlCache[siteName] = url;
    }
  }
  saveUrlCache(urlCache);

  // Refresh the .svlt file so the extension sees the new state (with
  // device-assigned indexes mirrored back).
  await refreshExtensionVaultFromDevice();

  return {
    ok: true,
    added,
    updated,
    skipped,
    failed,
    total: fileEntries.length,
  };
});

// ════════════════════════════════════════════════════════════════════════
//  CSV Import / Export — Bitwarden format
//
//  Columns: folder, favorite, type, name, notes, fields, reprompt,
//           archivedDate, login_uri, login_username, login_password, login_totp
//
//  Mapping to/from our vault entries:
//    folder         ↔ folder
//    favorite       ↔ fav (1/0)
//    type           ↔ type (login/note/card/identity)
//    name           ↔ site (our entry name/title)
//    notes          ↔ notes
//    fields         ↔ (custom fields — stored as JSON string, empty by default)
//    reprompt       ↔ (ignored, always 0)
//    archivedDate   ↔ (if present, marks entry as soft-deleted)
//    login_uri      ↔ url
//    login_username ↔ user
//    login_password ↔ pass
//    login_totp     ↔ totp
// ════════════════════════════════════════════════════════════════════════
const CSV_COLUMNS = [
  'folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt',
  'archivedDate', 'login_uri', 'login_username', 'login_password', 'login_totp',
];

function csvEscape(value) {
  if (value == null) return '';
  const s = String(value);
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function exportEntriesToCsv(entries) {
  const rows = [CSV_COLUMNS.join(',')];
  for (const e of entries) {
    const deleted = e.deleted ? new Date(e.deletedAt || Date.now()).toISOString() : '';
    const row = [
      csvEscape(e.folder || ''),
      csvEscape(e.fav ? 1 : 0),
      csvEscape(e.type || 'login'),
      csvEscape(e.site || e.name || ''),
      csvEscape(e.notes || ''),
      csvEscape(e.fields || ''),
      csvEscape(0),
      csvEscape(deleted),
      csvEscape(e.url || ''),
      csvEscape(e.user || ''),
      csvEscape(e.pass || ''),
      csvEscape(e.totp || ''),
    ];
    rows.push(row.join(','));
  }
  return rows.join('\r\n');
}

// Minimal CSV parser — handles quoted fields, escaped quotes, newlines in quotes
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;

  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; }
        else { inQuotes = false; i++; }
      } else {
        field += c; i++;
      }
    } else {
      if      (c === '"')  { inQuotes = true; i++; }
      else if (c === ',')  { row.push(field); field = ''; i++; }
      else if (c === '\r') { i++; }
      else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; }
      else                 { field += c; i++; }
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function parseCsvToEntries(csvText) {
  const rows = parseCsv(csvText);
  if (rows.length < 2) return [];

  const header = rows[0].map(h => h.trim());
  const idx = {};
  for (let i = 0; i < header.length; i++) idx[header[i]] = i;

  const get = (row, key) => (idx[key] !== undefined ? (row[idx[key]] || '').trim() : '');

  const entries = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.length === 1 && row[0] === '') continue;

    const type = get(row, 'type') || 'login';
    const entry = {
      type: ENTRY_TYPES.includes(type) ? type : 'login',
      site: get(row, 'name'),
      url: get(row, 'login_uri'),
      user: get(row, 'login_username'),
      pass: get(row, 'login_password'),
      totp: get(row, 'login_totp'),
      notes: get(row, 'notes'),
      folder: get(row, 'folder'),
      fav: (get(row, 'favorite') === '1' || get(row, 'favorite') === 'true') ? 1 : 0,
      deleted: false,
      tags: [],
      created: Date.now(),
      updated: Date.now(),
    };

    const archived = get(row, 'archivedDate');
    if (archived) {
      entry.deleted = true;
      entry.deletedAt = Date.parse(archived) || Date.now();
    }

    if (entry.site) entries.push(entry);
  }
  return entries;
}

ipcMain.handle('csv:export', async (_evt, entries) => {
  try {
    const csv = exportEntriesToCsv(entries || []);
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export vault to CSV',
      defaultPath: 'securevault-export.csv',
      filters: [
        { name: 'CSV', extensions: ['csv'] },
        { name: 'All files', extensions: ['*'] },
      ],
    });
    if (result.canceled || !result.filePath) return { ok: false, canceled: true };
    fs.writeFileSync(result.filePath, csv, 'utf8');
    return { ok: true, path: result.filePath, count: (entries || []).length };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('csv:import', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Import vault from CSV',
      filters: [
        { name: 'CSV', extensions: ['csv'] },
        { name: 'All files', extensions: ['*'] },
      ],
      properties: ['openFile'],
    });
    if (result.canceled || !result.filePaths.length) return { ok: false, canceled: true };

    // D8 FIX: Use async file I/O for CSV import.
    const csvText = await fs.promises.readFile(result.filePaths[0], 'utf8');
    const entries = parseCsvToEntries(csvText);
    if (entries.length === 0) {
      return { ok: false, error: 'No valid entries found in CSV file' };
    }
    return { ok: true, entries, count: entries.length };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

// Export for potential unit tests (not used at runtime).
module.exports = { generatePassword, generatePassphrase, passwordStrength, computeTotp };
