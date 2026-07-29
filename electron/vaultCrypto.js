'use strict';
/**
 * vaultCrypto.js
 *
 * Reimplements, byte-for-byte, the "SVR1" on-disk record-oriented format
 * used by the ESP32 firmware (src/vault_manager.cpp + src/crypto_utils.cpp),
 * v10.0+. This is what /vault.db looks like when the SD card is read
 * directly (mounted on the PC) instead of through the device's serial
 * protocol.
 *
 * FORMAT VERSIONS:
 *
 *   Version 1 (legacy, firmware-compatible):
 *     [0..3]     magic "SVR1"
 *     [4]        format version (1)
 *     [5..20]    PBKDF2 salt                   (16 bytes)
 *     [21..24]   dataEnd   (uint32 BE)          -- end of the data area (bytes written)
 *     [25..26]   liveCount (uint16 BE)          -- informational only, not authoritative
 *     [27..]     ROW TABLE: exactly MAX_ENTRIES (256) fixed 37-byte rows, back to
 *                back. Row i is always at a FIXED file offset.
 *       each row:
 *         [0]      status      (0 = free, 1 = occupied)
 *         [1..4]   dataOffset  (uint32 BE -- offset into the data area below)
 *         [5..8]   dataLen     (uint32 BE -- ciphertext length, plaintext is the same)
 *         [9..20]  iv          (12 bytes -- GCM nonce, unique per record)
 *         [21..36] tag         (16 bytes -- GCM auth tag for this record)
 *     [27 + 256*37 ..]  DATA AREA: each occupied row's own AES-256-GCM
 *                ciphertext, one small JSON object per entry.
 *     KDF: PBKDF2-HMAC-SHA256, 20,000 iterations.
 *     NO overall HMAC — header and row table are unprotected.
 *
 *   Version 2 (D9 + D15 security fix, desktop-only):
 *     Same layout as v1, PLUS:
 *     - PBKDF2-HMAC-SHA256, 600,000 iterations (matching .svlt file's count).
 *     - 32-byte HMAC-SHA256 appended AFTER the data area, covering the
 *       header + row table (bytes [0 .. DB_DATA_OFFSET)).
 *     - HMAC key derived separately: HMAC-SHA256(pinDerivedKey, "vault-hmac-v1").
 *     - Version byte at [4] = 2 identifies this format.
 *     - IMPORTANT: Version 2 vault.db files CANNOT be read by the ESP32
 *       firmware (which expects 20K iterations). This is an accepted tradeoff:
 *       the desktop app reads old v1 files (written by the firmware) and
 *       re-encrypts them as v2 on the next save, upgrading security. The
 *       firmware can still write v1 files, and the desktop can read both.
 *
 * Key derivation:
 *   v1: PBKDF2-HMAC-SHA256, 20,000 iterations, 32-byte key.
 *   v2: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte key.
 *   Every record uses the SAME derived key with its OWN random IV.
 *
 * Per-entry plaintext is a single JSON OBJECT (not array element) with the
 * same field set VaultManager::_entryToJSON() emits on the firmware side:
 *   { "site","user","pass","totp","type","fav","del","url","notes",
 *     "folder","cardholder","cardNumber","exp","cvv","firstName",
 *     "lastName","email","phone","address","city","state","postal",
 *     "country","ssn","passport","license" }
 * The firmware's _jsonToEntry() reads each field with an `o["x"] | ""`-
 * style default and ignores unrecognized keys -- so desktop-only extras
 * (tags, cardBrand, created, updated, deletedAt, id, _version) can still
 * ride along in the JSON without breaking the firmware; they're just
 * dropped if the firmware itself later rewrites that specific entry.
 *
 * WHY THIS MODULE ALWAYS DOES A FULL REWRITE (no incremental patching):
 * the firmware's per-record incremental ADD/UPDATE/DELETE exist to avoid
 * PSRAM heap fragmentation on an embedded 8MB-PSRAM device building
 * megabyte-scale JSON strings. None of that applies to a desktop Node
 * process -- encryptVault() below simply re-encrypts every entry fresh
 * and writes a compact file with no dead space every time.
 */

const crypto = require('crypto');

const MAGIC = Buffer.from('SVR1', 'ascii');
const SALT_LEN = 16;
const IV_LEN = 12;   // GCM nonce
const TAG_LEN = 16;  // GCM auth tag
const KEY_LEN = 32;  // AES-256

// D9 FIX: KDF iterations and version tracking.
// Version 1 = 20,000 iterations (legacy, firmware-compatible).
// Version 2 = 600,000 iterations (desktop-only, matching .svlt file's count).
const FORMAT_V1 = 1;
const FORMAT_V2 = 2;
const KDF_ITERATIONS_V1 = 20000;
const KDF_ITERATIONS_V2 = 600000;
const KDF_VERSION_V1 = 1;  // maps to 20K iterations
const KDF_VERSION_V2 = 2;  // maps to 600K iterations
// Current default for NEW vaults written by the desktop app.
const KDF_ITERATIONS = KDF_ITERATIONS_V2;  // 600000

const HMAC_LEN = 32;  // SHA-256 HMAC length
const HMAC_KEY_INFO = Buffer.from('vault-hmac-v1', 'utf8');

const DB_ROW_LEN = 1 + 4 + 4 + IV_LEN + TAG_LEN; // 37 bytes/row
const DB_HEADER_LEN = MAGIC.length + 1 + SALT_LEN + 4 + 2; // 27 bytes

// Firmware caps at 64 entries and 32/48/48/32-byte fixed fields
// (site/user/pass/totp). We enforce the same limits on the 4 "firmware-
// visible" fields so a vault built on desktop never silently corrupts
// when read back on-device.
const MAX_ENTRIES = 256;

// Row table is always sized for MAX_ENTRIES rows regardless of how many
// are actually in use (matches the firmware's fixed-size row table) --
// this is what lets a single row be patched at a fixed file offset.
const DB_TABLE_OFFSET = DB_HEADER_LEN;
const DB_TABLE_LEN = MAX_ENTRIES * DB_ROW_LEN;
const DB_DATA_OFFSET = DB_TABLE_OFFSET + DB_TABLE_LEN;

const FIELD_LIMITS = { site: 31, user: 47, pass: 47, totp: 31 }; // -1 for NUL

// Desktop-only extended fields -- some ARE read by the firmware (see the
// top-of-file comment: notes, folder, type, fav/del, and the full
// card/identity field sets ARE part of the on-device schema and DO round-
// trip through the device), some are genuinely desktop-only and get
// dropped if the firmware ever rewrites that record (tags, cardBrand,
// created, updated, deletedAt, id, _version -- see top-of-file comment
// for the full list and why that's an accepted tradeoff).
const EXTENDED_LIMITS = {
  notes: 159,       // firmware char notes[160]
  folder: 23,       // firmware char folder[24]
  tag: 31,
  cardBrand: 31,
  cardNumber: 23,   // firmware char cardNumber[24]
  cvv: 4,           // firmware char cvv[5]
  exp: 7,           // firmware char exp[8]
  cardholder: 31,   // firmware char cardholder[32]
  url: 63,          // firmware char url[64]
  firstName: 23,    // firmware char firstName[24]
  lastName: 23,     // firmware char lastName[24]
  email: 47,        // firmware char email[48]
  phone: 19,        // firmware char phone[20]
  address: 47,      // firmware char address[48]
  city: 23,         // firmware char city[24]
  state: 23,        // firmware char state[24]
  postal: 11,       // firmware char postal[12]
  country: 23,      // firmware char country[24]
  ssn: 15,          // firmware char ssn[16]
  passport: 23,     // firmware char passport[24]
  license: 23,      // firmware char license[24]
};

const ENTRY_TYPES = ['login', 'note', 'card', 'identity'];

class VaultFormatError extends Error {}
class WrongPinError extends Error {}
class VaultHmacError extends Error {}

/**
 * Derive the encryption key from PIN + salt, using the specified iteration count.
 * D9 FIX: Now supports both 20K (v1/firmware) and 600K (v2/desktop) iterations.
 */
function deriveKey(pin, salt, iterations) {
  return crypto.pbkdf2Sync(String(pin), salt, iterations || KDF_ITERATIONS, KEY_LEN, 'sha256');
}

/**
 * D15 FIX: Derive the HMAC key from the PIN-derived encryption key.
 * The HMAC key is derived separately using HMAC-SHA256 with a fixed info
 * string, providing key separation (the encryption key and HMAC key are
 * cryptographically independent even though they share the same root).
 */
function deriveHmacKey(encKey) {
  return crypto.createHmac('sha256', encKey).update(HMAC_KEY_INFO).digest();
}

/**
 * D15 FIX: Compute HMAC-SHA256 over the header + row table (bytes
 * [0 .. DB_DATA_OFFSET)), using the HMAC key derived from the PIN.
 */
function computeHeaderHmac(encKey, headerAndTable) {
  const hmacKey = deriveHmacKey(encKey);
  try {
    return crypto.createHmac('sha256', hmacKey).update(headerAndTable).digest();
  } finally {
    hmacKey.fill(0);
  }
}

/**
 * Decrypt a vault.db buffer (as read straight off the SD card) with the
 * given PIN. Returns the parsed array of entries (with extended fields
 * preserved if present), in row-table order.
 *
 * D9 FIX: Detects format version (v1 = 20K iterations, v2 = 600K iterations)
 * and decrypts with the appropriate iteration count. Old v1 vaults are
 * transparently decrypted; the caller (main.js) can then save them as v2
 * on the next vault:save call, completing the migration.
 *
 * D15 FIX: For v2 files, verifies HMAC-SHA256 over the header + row table
 * before decrypting. If HMAC fails, rejects the file as corrupted/tampered.
 * v1 files have no HMAC (legacy, firmware-compatible).
 *
 * Throws WrongPinError if the PIN is wrong / file is corrupted (GCM tag
 * check fails on the first occupied row).
 * Throws VaultHmacError if the HMAC check fails (v2 files only).
 * Throws VaultFormatError if the header doesn't look like SVR1.
 */
function decryptVault(fileBuffer, pin) {
  const minSizeV1 = DB_DATA_OFFSET;
  const minSizeV2 = DB_DATA_OFFSET + HMAC_LEN;
  if (fileBuffer.length < minSizeV1) {
    throw new VaultFormatError('File is too short to be a valid vault.db');
  }

  const magic = fileBuffer.slice(0, 4);
  const formatVersion = fileBuffer[4];

  if (!magic.equals(MAGIC)) {
    throw new VaultFormatError(
      `Unrecognized vault.db header (expected SVR1, got "${magic.toString('latin1')}")`
    );
  }

  // D9 FIX: Determine KDF iterations based on format version.
  let iterations;
  if (formatVersion === FORMAT_V1) {
    iterations = KDF_ITERATIONS_V1;  // 20,000 (firmware-compatible)
  } else if (formatVersion === FORMAT_V2) {
    iterations = KDF_ITERATIONS_V2;  // 600,000 (desktop-only)
  } else {
    throw new VaultFormatError(
      `Unsupported vault.db format version ${formatVersion} (expected 1 or 2)`
    );
  }

  const salt = fileBuffer.slice(5, 5 + SALT_LEN);

  const key = deriveKey(pin, salt, iterations);

  try {
    // D15 FIX: For v2 files, verify HMAC over header + row table BEFORE
    // decrypting any records. The HMAC covers bytes [0 .. DB_DATA_OFFSET).
    if (formatVersion === FORMAT_V2) {
      if (fileBuffer.length < minSizeV2) {
        throw new VaultFormatError('v2 vault.db is too short (missing HMAC)');
      }
      const headerAndTable = fileBuffer.slice(0, DB_DATA_OFFSET);
      const storedHmac = fileBuffer.slice(fileBuffer.length - HMAC_LEN, fileBuffer.length);
      const computedHmac = computeHeaderHmac(key, headerAndTable);
      if (!crypto.timingSafeEqual(computedHmac, storedHmac)) {
        throw new VaultHmacError(
          'vault.db HMAC verification failed — file may be corrupted or tampered'
        );
      }
    }

    const entries = [];
    for (let slot = 0; slot < MAX_ENTRIES; slot++) {
      const rowOff = DB_TABLE_OFFSET + slot * DB_ROW_LEN;
      const status = fileBuffer[rowOff];
      if (status !== 1) continue; // free row -- nothing stored here

      const dataOffset = fileBuffer.readUInt32BE(rowOff + 1);
      const dataLen = fileBuffer.readUInt32BE(rowOff + 5);
      const iv = fileBuffer.slice(rowOff + 9, rowOff + 9 + IV_LEN);
      const tag = fileBuffer.slice(rowOff + 9 + IV_LEN, rowOff + 9 + IV_LEN + TAG_LEN);

      const cipherStart = DB_DATA_OFFSET + dataOffset;
      const cipherEnd = cipherStart + dataLen;
      // For v2 files, the HMAC occupies the last 32 bytes after the data area.
      const fileDataEnd = formatVersion === FORMAT_V2
        ? fileBuffer.length - HMAC_LEN
        : fileBuffer.length;
      if (cipherEnd > fileDataEnd) {
        throw new VaultFormatError(`Row ${slot}: record data extends past end of file (corrupt vault.db)`);
      }
      const ciphertext = fileBuffer.slice(cipherStart, cipherEnd);

      let plaintext;
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch (e) {
        // GCM tag mismatch => wrong PIN or corrupted/tampered file.
        throw new WrongPinError('Wrong PIN, or vault.db is corrupted/tampered');
      }

      let obj;
      try {
        obj = JSON.parse(plaintext.toString('utf8'));
      } catch (e) {
        throw new VaultFormatError(`Row ${slot}: decrypted data is not valid JSON (corrupted vault?)`);
      }
      entries.push(normalizeEntry(obj));
    }

    // D9 FIX: Return metadata indicating whether this was a v1 file (needs
    // migration to v2 on next save) or v2 (already upgraded).
    return {
      entries,
      kdfVersion: formatVersion,
      needsMigration: formatVersion === FORMAT_V1,
    };
  } finally {
    key.fill(0); // best-effort key wipe, mirrors secureZero() on-device
  }
}


function normalizeEntry(e) {
  const type = ENTRY_TYPES.includes(e.type) ? e.type : 'login';
  const out = {
    type,
    site: String(e.site ?? ''),
    user: String(e.user ?? ''),
    pass: String(e.pass ?? ''),
    totp: String(e.totp ?? ''),
  };
  // D3+D6 FIX: Preserve UUID id field if present.
  if (e.id != null && typeof e.id === 'string') out.id = String(e.id);
  // D2 FIX: Preserve _version field if present.
  if (e._version != null) out._version = Number(e._version) || 0;
  // Extended fields -- only copy through if present, validated on save.
  if (e.notes != null) out.notes = String(e.notes);
  if (e.folder != null) out.folder = String(e.folder);
  if (Array.isArray(e.tags)) out.tags = e.tags.map(String).filter(Boolean);
  if (e.fav != null) out.fav = e.fav ? 1 : 0;
  // Card fields
  if (type === 'card' || e.cardBrand != null) {
    if (e.cardBrand != null) out.cardBrand = String(e.cardBrand);
    if (e.cardNumber != null) out.cardNumber = String(e.cardNumber);
    if (e.cvv != null) out.cvv = String(e.cvv);
    if (e.exp != null) out.exp = String(e.exp);
    if (e.cardholder != null) out.cardholder = String(e.cardholder);
  }
  // Identity fields
  if (type === 'identity' || e.email != null) {
    if (e.firstName != null) out.firstName = String(e.firstName);
    if (e.lastName != null) out.lastName = String(e.lastName);
    if (e.email != null) out.email = String(e.email);
    if (e.phone != null) out.phone = String(e.phone);
    if (e.address != null) out.address = String(e.address);
    if (e.city != null) out.city = String(e.city);
    if (e.state != null) out.state = String(e.state);
    if (e.postal != null) out.postal = String(e.postal);
    if (e.country != null) out.country = String(e.country);
    if (e.ssn != null) out.ssn = String(e.ssn);
    if (e.passport != null) out.passport = String(e.passport);
    if (e.license != null) out.license = String(e.license);
  }
  // Soft-delete
  out.deleted = e.deleted ? true : false;
  if (e.deletedAt != null) out.deletedAt = Number(e.deletedAt) || 0;
  // Timestamps
  if (e.created != null) out.created = Number(e.created) || 0;
  if (e.updated != null) out.updated = Number(e.updated) || 0;
  return out;
}

/**
 * Encrypt an entries array into a fresh vault.db buffer, ready to write
 * to the SD card.
 *
 * D9 FIX: Always writes FORMAT_V2 (600K iterations) unless forceV1 is
 * explicitly set (used for firmware compatibility when the user wants the
 * ESP32 to be able to read the file directly). New vaults created by the
 * desktop app default to v2.
 *
 * D15 FIX: For v2 files, computes HMAC-SHA256 over the header + row table
 * and appends it after the data area. The HMAC key is derived from the
 * PIN-derived encryption key using HMAC-SHA256(encKey, "vault-hmac-v1"),
 * providing key separation.
 *
 * @param {Array} entries - entries to encrypt
 * @param {string} pin - vault PIN
 * @param {boolean} forceV1 - if true, write v1 format (20K iterations,
 *   no HMAC) for firmware compatibility. Default: false (write v2).
 */
function encryptVault(entries, pin, forceV1) {
  validateEntries(entries);

  // Strip undefined fields so we don't bloat the JSON.
  const clean = entries.map((e) => {
    const out = {};
    for (const [k, v] of Object.entries(e)) {
      if (v !== undefined) out[k] = v;
    }
    return out;
  });

  const useV2 = !forceV1;
  const formatVersion = useV2 ? FORMAT_V2 : FORMAT_V1;
  const iterations = useV2 ? KDF_ITERATIONS_V2 : KDF_ITERATIONS_V1;

  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveKey(pin, salt, iterations);

  let dataEnd = 0;
  const rows = []; // { dataOffset, dataLen, iv, tag, ciphertext }
  try {
    for (const e of clean) {
      const plaintext = Buffer.from(JSON.stringify(e), 'utf8');
      const iv = crypto.randomBytes(IV_LEN);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      rows.push({ dataOffset: dataEnd, dataLen: ciphertext.length, iv, tag, ciphertext });
      dataEnd += ciphertext.length;
    }
  } finally {
    // Don't fill key with 0 yet — we need it for HMAC computation for v2.
    // It will be zeroed after HMAC is computed below.
  }

  const header = Buffer.alloc(DB_HEADER_LEN);
  MAGIC.copy(header, 0);
  header[4] = formatVersion;  // D9 FIX: version byte now 1 or 2
  salt.copy(header, 5);
  header.writeUInt32BE(dataEnd, 5 + SALT_LEN);
  header.writeUInt16BE(clean.length, 5 + SALT_LEN + 4);

  // Zero-filled = every row defaults to status 0 (free); only the first
  // clean.length rows get marked occupied below.
  const table = Buffer.alloc(DB_TABLE_LEN);
  rows.forEach((row, i) => {
    const off = i * DB_ROW_LEN;
    table[off] = 1; // occupied
    table.writeUInt32BE(row.dataOffset, off + 1);
    table.writeUInt32BE(row.dataLen, off + 5);
    row.iv.copy(table, off + 9);
    row.tag.copy(table, off + 9 + IV_LEN);
  });

  const dataArea = Buffer.concat(rows.map((r) => r.ciphertext), dataEnd);

  // D15 FIX: For v2 files, compute HMAC-SHA256 over header + row table and
  // append it after the data area. This protects the file's structural
  // metadata (header + row table) from undetected corruption or tampering.
  // Per-entry GCM auth tags already protect each record's ciphertext, but
  // the header and row table were previously unprotected — an attacker
  // could swap rows, change offsets, or corrupt the salt without detection.
  if (useV2) {
    const headerAndTable = Buffer.concat([header, table]);
    const hmac = computeHeaderHmac(key, headerAndTable);
    key.fill(0);  // NOW zero the key after HMAC is computed
    return Buffer.concat([header, table, dataArea, hmac]);
  } else {
    key.fill(0);
    return Buffer.concat([header, table, dataArea]);
  }
}

/**
 * Validate entries against:
 *   - firmware's fixed-size buffer limits (site[32], user[48], pass[48],
 *     totp[32]) for the 4 always-present firmware-visible fields
 *   - desktop-only extended field limits (notes, card*, id*, folder, tag)
 */
function validateEntries(entries) {
  if (!Array.isArray(entries)) {
    throw new VaultFormatError('entries must be an array');
  }
  if (entries.length > MAX_ENTRIES) {
    throw new VaultFormatError(
      `Too many entries (${entries.length}). Max is ${MAX_ENTRIES}.`
    );
  }
  for (const [i, e] of entries.entries()) {
    // The 4 firmware-visible fields must always be present.
    for (const field of ['site', 'user', 'pass', 'totp']) {
      const val = String(e[field] ?? '');
      if (Buffer.byteLength(val, 'utf8') > FIELD_LIMITS[field]) {
        throw new VaultFormatError(
          `Entry #${i + 1} ("${e.site || '?'}"): ${field} is too long ` +
          `(max ${FIELD_LIMITS[field]} bytes, the ESP32's fixed-size buffer for this field).`
        );
      }
    }
    // 'site' is the entry's label/title for ALL types -- never empty.
    if (!String(e.site ?? '').length) {
      throw new VaultFormatError(`Entry #${i + 1}: site/title cannot be empty`);
    }

    // Validate type
    if (e.type && !ENTRY_TYPES.includes(e.type)) {
      throw new VaultFormatError(`Entry #${i + 1}: unknown type "${e.type}"`);
    }

    // Extended field limits
    if (e.notes && Buffer.byteLength(String(e.notes), 'utf8') > EXTENDED_LIMITS.notes) {
      throw new VaultFormatError(`Entry #${i + 1}: notes is too long (max ${EXTENDED_LIMITS.notes} bytes).`);
    }
    if (e.folder && Buffer.byteLength(String(e.folder), 'utf8') > EXTENDED_LIMITS.folder) {
      throw new VaultFormatError(`Entry #${i + 1}: folder name is too long (max ${EXTENDED_LIMITS.folder} bytes).`);
    }
    if (Array.isArray(e.tags)) {
      if (e.tags.length > 32) {
        throw new VaultFormatError(`Entry #${i + 1}: too many tags (max 32).`);
      }
      for (const t of e.tags) {
        if (Buffer.byteLength(String(t), 'utf8') > EXTENDED_LIMITS.tag) {
          throw new VaultFormatError(`Entry #${i + 1}: tag "${t}" is too long (max ${EXTENDED_LIMITS.tag} bytes).`);
        }
      }
    }

    // Login-specific
    if (e.type === 'login') {
      if (e.url && Buffer.byteLength(String(e.url), 'utf8') > EXTENDED_LIMITS.url) {
        throw new VaultFormatError(`Entry #${i + 1}: url is too long (max ${EXTENDED_LIMITS.url} bytes).`);
      }
    }
    // Card-specific
    if (e.type === 'card') {
      for (const f of ['cardBrand','cardNumber','cvv','exp','cardholder']) {
        if (e[f] && Buffer.byteLength(String(e[f]), 'utf8') > EXTENDED_LIMITS[f]) {
          throw new VaultFormatError(`Entry #${i + 1}: ${f} is too long (max ${EXTENDED_LIMITS[f]} bytes).`);
        }
      }
    }
    // Identity-specific
    if (e.type === 'identity') {
      for (const f of ['firstName','lastName','email','phone','address','city','state','postal','country','ssn','passport','license']) {
        if (e[f] && Buffer.byteLength(String(e[f]), 'utf8') > EXTENDED_LIMITS[f]) {
          throw new VaultFormatError(`Entry #${i + 1}: ${f} is too long (max ${EXTENDED_LIMITS[f]} bytes).`);
        }
      }
    }
  }
}

module.exports = {
  decryptVault,
  encryptVault,
  validateEntries,
  normalizeEntry,
  VaultFormatError,
  WrongPinError,
  VaultHmacError,
  HEADER_LEN: DB_HEADER_LEN,
  MAX_ENTRIES,
  FIELD_LIMITS,
  EXTENDED_LIMITS,
  ENTRY_TYPES,
  KDF_ITERATIONS,
  KDF_ITERATIONS_V1,
  KDF_ITERATIONS_V2,
  KDF_VERSION_V1,
  KDF_VERSION_V2,
  FORMAT_V1,
  FORMAT_V2,
};
