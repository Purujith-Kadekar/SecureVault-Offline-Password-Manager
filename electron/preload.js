'use strict';
/**
 * preload.js — narrow contextBridge between the renderer (sandboxed UI) and
 * the main process (all crypto + serial I/O).
 *
 * Security: only these specific, narrow functions are exposed to the
 * renderer. The renderer never gets raw `require` / `fs` / `ipcRenderer`
 * access — contextIsolation: true + nodeIntegration: false + sandbox: true
 * (all set in main.js) enforces this.
 *
 * Every exposed method is a one-line wrapper around ipcRenderer.invoke()
 * or ipcRenderer.on() — no business logic here, just the bridge.
 *
 * D17 FIX: Added type checking wrappers for IPC calls — validates input
 * before sending to main process. D13 FIX: URL cache methods now accept
 * (siteName, user) pairs. D19 FIX: vaultHealthScan now sends entry IDs
 * instead of full entries.
 */

const { contextBridge, ipcRenderer } = require('electron');

// D17 FIX: Type checking wrappers — validate input before IPC calls.
// Prevents compromised renderer from injecting arbitrary data.
function assertString(val, name) {
  if (typeof val !== 'string') throw new TypeError(`${name} must be a string`);
}
function assertNonEmptyString(val, name) {
  if (typeof val !== 'string' || !val) throw new TypeError(`${name} must be a non-empty string`);
}
function assertObject(val, name) {
  if (!val || typeof val !== 'object') throw new TypeError(`${name} must be a non-null object`);
}
function assertInteger(val, name) {
  if (typeof val !== 'number' || !Number.isInteger(val)) throw new TypeError(`${name} must be an integer`);
}
function assertArray(val, name) {
  if (!Array.isArray(val)) throw new TypeError(`${name} must be an array`);
}

contextBridge.exposeInMainWorld('vaultAPI', {

  // ═══════════════════════════════════════════════════════════════════════
  //  SD card / removable volume detection
  // ═══════════════════════════════════════════════════════════════════════
  listRemovableVolumes: ()              => ipcRenderer.invoke('sdcard:listRemovable'),
  selectSDCard:         ()              => ipcRenderer.invoke('sdcard:select'),
  setSelectedSDCard:    (sdRoot)        => { assertString(sdRoot, 'sdRoot'); return ipcRenderer.invoke('sdcard:setSelected', sdRoot); },
  getSavedSDCard:       ()              => ipcRenderer.invoke('sdcard:getSaved'),
  sdCardStatus:         (sdRoot)        => { assertString(sdRoot, 'sdRoot'); return ipcRenderer.invoke('sdcard:status', sdRoot); },

  // ═══════════════════════════════════════════════════════════════════════
  //  Vault (SD-card vault.db) — unlock / create / save / changePin / backups
  // ═══════════════════════════════════════════════════════════════════════
  vaultUnlock:      (sdRoot, pin)       => { assertString(sdRoot, 'sdRoot'); assertString(pin, 'pin'); return ipcRenderer.invoke('vault:unlock', sdRoot, pin); },
  vaultCreateNew:   (sdRoot, pin)       => { assertString(sdRoot, 'sdRoot'); assertString(pin, 'pin'); return ipcRenderer.invoke('vault:createNew', sdRoot, pin); },
  vaultSave:        (sdRoot, entries)   => { assertString(sdRoot, 'sdRoot'); assertArray(entries, 'entries'); return ipcRenderer.invoke('vault:save', sdRoot, entries); },
  vaultChangePin:   (sdRoot, oldPin, newPin) => { assertString(sdRoot, 'sdRoot'); assertString(oldPin, 'oldPin'); assertString(newPin, 'newPin'); return ipcRenderer.invoke('vault:changePin', sdRoot, oldPin, newPin); },
  vaultListBackups: (sdRoot)            => { assertString(sdRoot, 'sdRoot'); return ipcRenderer.invoke('vault:listBackups', sdRoot); },
  vaultRestoreBackup: (sdRoot, filename) => { assertString(sdRoot, 'sdRoot'); assertString(filename, 'filename'); return ipcRenderer.invoke('vault:restoreBackup', sdRoot, filename); },

  // ═══════════════════════════════════════════════════════════════════════
  //  Utils — password / passphrase generator, strength, TOTP, clipboard
  // ═══════════════════════════════════════════════════════════════════════
  generatePassword:     (options)        => ipcRenderer.invoke('util:generatePassword', options),
  passwordStrength:     (password)       => { assertString(password, 'password'); return ipcRenderer.invoke('util:passwordStrength', password); },
  totp:                 (secret, t)      => { assertString(secret, 'secret'); return ipcRenderer.invoke('util:totp', secret, t); },
  copyToClipboard:      (text)           => { assertString(text, 'text'); return ipcRenderer.invoke('util:copyToClipboard', text); },
  clearClipboardIfMatches: (text)        => { assertString(text, 'text'); return ipcRenderer.invoke('util:clearClipboardIfMatches', text); },
  getLimits:            ()               => ipcRenderer.invoke('util:limits'),

  // ═══════════════════════════════════════════════════════════════════════
  //  Breach check (HIBP Pwned Passwords, k-anonymity model).
  // ═══════════════════════════════════════════════════════════════════════
  checkPwned:         (password)        => { assertString(password, 'password'); return ipcRenderer.invoke('util:checkPwned', password); },
  // D19 FIX: vaultHealthScan now sends entry IDs instead of full entries.
  // Passwords never cross the IPC bridge for health scans.
  vaultHealthScan:    (entryIds)        => { assertArray(entryIds, 'entryIds'); return ipcRenderer.invoke('util:vaultHealthScan', entryIds); },
  clearBreachCache:   ()                => ipcRenderer.invoke('util:clearBreachCache'),
  getHibpEnabled:     ()                => ipcRenderer.invoke('settings:getHibpEnabled'),
  setHibpEnabled:     (enabled)         => ipcRenderer.invoke('settings:setHibpEnabled', enabled),

  // ═══════════════════════════════════════════════════════════════════════
  //  Secure Device Mode (4-Layer Security Stack over USB-CDC Serial)
  // ═══════════════════════════════════════════════════════════════════════
  deviceListPorts:    ()                  => ipcRenderer.invoke('device:listPorts'),
  deviceHandshake:    (code, portPath)    => { assertString(code, 'code'); return ipcRenderer.invoke('device:handshake', code, portPath); },
  deviceIsConnected:  ()                  => ipcRenderer.invoke('device:isConnected'),
  deviceListEntries:  ()                  => ipcRenderer.invoke('device:listEntries'),
  deviceGetEntry:     (index)             => { assertInteger(index, 'index'); return ipcRenderer.invoke('device:getEntry', index); },
  // D17 FIX: Validate entry before sending to main process.
  deviceAddEntry:     (entry)             => { assertObject(entry, 'entry'); return ipcRenderer.invoke('device:addEntry', entry); },
  deviceUpdateEntry:  (index, entry)      => { assertInteger(index, 'index'); assertObject(entry, 'entry'); return ipcRenderer.invoke('device:updateEntry', index, entry); },
  deviceDeleteEntry:  (index)             => { assertInteger(index, 'index'); return ipcRenderer.invoke('device:deleteEntry', index); },
  deviceLock:         ()                  => ipcRenderer.invoke('device:lock'),

  // ═══════════════════════════════════════════════════════════════════════
  //  Extension Sync (.svlt file for the browser extension)
  // ═══════════════════════════════════════════════════════════════════════
  extSyncGetStatus:      ()                 => ipcRenderer.invoke('extsync:getStatus'),
  extSyncPickFilePath:   ()                 => ipcRenderer.invoke('extsync:pickFilePath'),
  extSyncSetPassword:    (password)         => { assertString(password, 'password'); return ipcRenderer.invoke('extsync:setPassword', password); },
  extSyncChangePassword: (oldPw, newPw)     => { assertString(oldPw, 'oldPw'); assertString(newPw, 'newPw'); return ipcRenderer.invoke('extsync:changePassword', oldPw, newPw); },
  extSyncSetEnabled:     (enabled)          => ipcRenderer.invoke('extsync:setEnabled', enabled),
  extSyncSetAutoWrite:   (onSync, onEdit)   => ipcRenderer.invoke('extsync:setAutoWrite', onSync, onEdit),
  extSyncWriteNow:       ()                 => ipcRenderer.invoke('extsync:writeNow'),
  extSyncClearPassword:  ()                 => ipcRenderer.invoke('extsync:clearPassword'),
  extSyncSyncFromFile:   ()                 => ipcRenderer.invoke('extsync:syncFromFile'),

  // ═══════════════════════════════════════════════════════════════════════
  //  CSV Import / Export (Bitwarden format)
  // ═══════════════════════════════════════════════════════════════════════
  csvExport: (entries) => { assertArray(entries, 'entries'); return ipcRenderer.invoke('csv:export', entries); },
  csvImport: ()         => ipcRenderer.invoke('csv:import'),

  // ═══════════════════════════════════════════════════════════════════════
  //  URL Cache — D13 FIX: now keyed by (siteName, user) pair.
  // Backward compat: urlCacheSet still works with 2 args (siteName, url)
  // by passing empty user.
  // ═══════════════════════════════════════════════════════════════════════
  urlCacheSet:   (siteName, userOrUrl, url) => {
    assertNonEmptyString(siteName, 'siteName');
    // D13 FIX: Support both old (siteName, url) and new (siteName, user, url) signatures.
    if (url === undefined) {
      // Old 2-arg pattern: (siteName, url) → user='', url=userOrUrl
      return ipcRenderer.invoke('urlcache:set', siteName, '', userOrUrl);
    }
    return ipcRenderer.invoke('urlcache:set', siteName, userOrUrl || '', url);
  },
  urlCacheGet:   (siteName, user) => {
    assertNonEmptyString(siteName, 'siteName');
    // D13 FIX: Support both old (siteName) and new (siteName, user) signatures.
    return ipcRenderer.invoke('urlcache:get', siteName, user || '');
  },
  urlCacheGetAll: ()              => ipcRenderer.invoke('urlcache:getAll'),
  urlCacheDelete: (siteName, user) => {
    assertNonEmptyString(siteName, 'siteName');
    // D13 FIX: Support both old (siteName) and new (siteName, user) signatures.
    return ipcRenderer.invoke('urlcache:delete', siteName, user || '');
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Main → renderer push events
  // ═══════════════════════════════════════════════════════════════════════

  onAutoDetected: (cb) => {
    const handler = (_event, payload) => cb(payload);
    ipcRenderer.on('sdcard:auto-detected', handler);
    return () => ipcRenderer.removeListener('sdcard:auto-detected', handler);
  },

  onSdCardRemoved: (cb) => {
    const handler = (_event, payload) => cb(payload);
    ipcRenderer.on('sdcard:removed', handler);
    return () => ipcRenderer.removeListener('sdcard:removed', handler);
  },

  onForceLock: (cb) => {
    const handler = () => cb();
    ipcRenderer.on('force-lock', handler);
    return () => ipcRenderer.removeListener('force-lock', handler);
  },
  onWindowBlur: (cb) => {
    const handler = () => cb();
    ipcRenderer.on('window-blur', handler);
    return () => ipcRenderer.removeListener('window-blur', handler);
  },

  onExtSyncWritten: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on('extension-sync:written', handler);
    return () => ipcRenderer.removeListener('extension-sync:written', handler);
  },

  onExtSyncError: (cb) => {
    const handler = (_e, msg) => cb(msg);
    ipcRenderer.on('extension-sync:error', handler);
    return () => ipcRenderer.removeListener('extension-sync:error', handler);
  },

  onExtSyncSynced: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on('extension-sync:synced', handler);
    return () => ipcRenderer.removeListener('extension-sync:synced', handler);
  },

  onExtSyncPending: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on('extension-sync:pending', handler);
    return () => ipcRenderer.removeListener('extension-sync:pending', handler);
  },

  onHealthScanProgress: (cb) => {
    const handler = (_e, data) => cb(data);
    ipcRenderer.on('health-scan:progress', handler);
    return () => ipcRenderer.removeListener('health-scan:progress', handler);
  },

  onDeviceDisconnected: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on('device:disconnected', handler);
    return () => ipcRenderer.removeListener('device:disconnected', handler);
  },

  // D10 FIX: vault migration notification — main process sends this when
  // it detects that the vault needs migration (v1 → v2).
  onVaultNeedsMigration: (cb) => {
    const handler = (_e, data) => cb(data);
    ipcRenderer.on('vault:needs-migration', handler);
    return () => ipcRenderer.removeListener('vault:needs-migration', handler);
  },
});
