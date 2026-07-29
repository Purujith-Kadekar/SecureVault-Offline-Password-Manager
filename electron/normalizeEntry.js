'use strict';
/**
 * normalizeEntry.js — CANONICAL entry normalization module (D12 FIX).
 *
 * Shared between main.js and renderer.js. This is the SINGLE source of truth
 * for entry field alias normalization (fav/favorite, del/deleted, cardholder/
 * cardHolder, etc.). Both main.js and renderer.js import this module and add
 * their own context-specific fields ON TOP of the canonical base.
 *
 * Canonical entry schema (what this module produces):
 *   {
 *     id, _version, type, site, user, pass, totp, url,
 *     notes, folder, tags,
 *     fav (0/1), deleted (boolean), deletedAt,
 *     created, updated,
 *     // Card fields (both naming conventions)
 *     cardholder, cardNumber, cardBrand, exp, cvv,
 *     // Identity fields (firmware-style names)
 *     firstName, lastName, email, phone, address,
 *     city, state, postal, country, ssn, passport, license,
 *   }
 *
 * Renderer adds ON TOP: _source, _index, cardHolder, cardExpiry, cardCvv,
 *                        idFirstName, idLastName, idEmail, ...
 * Main adds ON TOP: name, favorite (boolean), del (0/1)
 *
 * This replaces the 3 separate normalization functions:
 *   - vaultCrypto.normalizeEntry (crypto-level, minimal)
 *   - renderer.normalizeEntryForUi (UI-level, with _source/_index)
 *   - main.normalizeForExtensionSync (extension-level, with id/name)
 */

const ENTRY_TYPES = ['login', 'card', 'identity', 'note'];

/**
 * Canonical normalization — handles ALL field aliases.
 * This is the BASE that renderer.js and main.js extend.
 *
 * @param {object} e — raw entry from any source (device, SD card, extension, CSV)
 * @returns {object} — canonical base entry with all aliases resolved
 */
function normalizeEntry(e) {
  if (!e || typeof e !== 'object') return null;

  const type = ENTRY_TYPES.includes(e.type) ? e.type : 'login';

  const isFav = !!(e.fav || e.favorite);
  const isDel = !!(e.del || e.deleted);

  const out = {
    // ── Identity / metadata ──
    id:      (e.id && typeof e.id === 'string') ? String(e.id) : undefined,
    _version: typeof e._version === 'number' ? e._version : 0,

    // ── Core fields ──
    type,
    site:    String(e.site || e.name || ''),
    user:    String(e.user || e.login_username || ''),
    pass:    String(e.pass || e.login_password || ''),
    totp:    String(e.totp || e.login_totp || ''),
    url:     String(e.url || e.login_uri || ''),
    notes:   String(e.notes || ''),
    folder:  String(e.folder || ''),
    tags:    Array.isArray(e.tags) ? e.tags.map(String).filter(Boolean) : undefined,

    // ── Favorite / deleted (canonical: fav=0/1, deleted=boolean) ──
    fav:     isFav ? 1 : 0,
    deleted: isDel,
    deletedAt: isDel ? (Number(e.deletedAt) || 0) : 0,

    // ── Timestamps ──
    created: Number(e.created) || 0,
    updated: Number(e.updated) || 0,

    // ── Card fields (firmware-style canonical names) ──
    cardholder:  String(e.cardholder || e.cardHolder || ''),
    cardNumber:  String(e.cardNumber || ''),
    cardBrand:   String(e.cardBrand || ''),
    exp:         String(e.exp || e.cardExpiry || ''),
    cvv:         String(e.cvv || e.cardCvv || ''),
  };

  // ── Identity fields (firmware-style canonical names) ──
  out.firstName  = String(e.firstName || e.idFirstName || '');
  out.lastName   = String(e.lastName || e.idLastName || '');
  out.email      = String(e.email || e.idEmail || '');
  out.phone      = String(e.phone || e.idPhone || '');
  out.address    = String(e.address || e.idAddress || '');
  out.city       = String(e.city || e.idCity || '');
  out.state      = String(e.state || e.idState || '');
  out.postal     = String(e.postal || e.idPostal || '');
  out.country    = String(e.country || e.idCountry || '');
  out.ssn        = String(e.ssn || e.idSsn || '');
  out.passport   = String(e.passport || e.idPassport || '');
  out.license    = String(e.license || e.idLicense || '');

  // Remove undefined values (don't bloat JSON)
  for (const k of Object.keys(out)) {
    if (out[k] === undefined) delete out[k];
  }

  return out;
}

/**
 * Validate an entry from IPC input (D17 FIX).
 * Returns { valid: true } or { valid: false, error: string }.
 *
 * Checks: entries must be objects, pin must be string 4-8 chars,
 * indices must be integers 0-255, site must not be empty.
 */
function validateEntry(entry) {
  if (!entry || typeof entry !== 'object') {
    return { valid: false, error: 'Entry must be a non-null object' };
  }
  if (typeof entry.type !== 'undefined' && !ENTRY_TYPES.includes(entry.type) && typeof entry.type !== 'number') {
    return { valid: false, error: `Invalid entry type: ${entry.type}` };
  }
  const site = String(entry.site || entry.name || '');
  if (!site) {
    return { valid: false, error: 'Entry site/name cannot be empty' };
  }
  // Check core field lengths (firmware limits)
  if (Buffer.byteLength(site, 'utf8') > 31) {
    return { valid: false, error: 'Site name is too long (max 31 bytes)' };
  }
  if (entry.user && Buffer.byteLength(String(entry.user), 'utf8') > 47) {
    return { valid: false, error: 'Username is too long (max 47 bytes)' };
  }
  if (entry.pass && Buffer.byteLength(String(entry.pass), 'utf8') > 47) {
    return { valid: false, error: 'Password is too long (max 47 bytes)' };
  }
  if (entry.totp && Buffer.byteLength(String(entry.totp), 'utf8') > 31) {
    return { valid: false, error: 'TOTP secret is too long (max 31 bytes)' };
  }
  return { valid: true };
}

/**
 * Validate PIN: must be string, 4-8 characters.
 */
function validatePin(pin) {
  if (!pin || typeof pin !== 'string') {
    return { valid: false, error: 'PIN must be a string' };
  }
  if (pin.length < 4) {
    return { valid: false, error: 'PIN must be at least 4 characters' };
  }
  if (pin.length > 8) {
    return { valid: false, error: 'PIN must be at most 8 characters' };
  }
  return { valid: true };
}

/**
 * Validate device index: must be integer 0-255.
 */
function validateDeviceIndex(index) {
  if (typeof index !== 'number' || !Number.isInteger(index)) {
    return { valid: false, error: 'Device index must be an integer' };
  }
  if (index < 0 || index > 255) {
    return { valid: false, error: 'Device index must be between 0 and 255' };
  }
  return { valid: true };
}

module.exports = {
  normalizeEntry,
  validateEntry,
  validatePin,
  validateDeviceIndex,
  ENTRY_TYPES,
};
