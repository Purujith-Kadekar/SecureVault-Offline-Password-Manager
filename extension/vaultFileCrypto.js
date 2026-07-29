/**
 * vaultFileCrypto.js — SVLT v2/v3 encryption + decryption via WebCrypto (browser side).
 *
 * Mirrors electron/vaultFileCrypto.js byte-for-byte. Both sides must agree on:
 *   - Magic "SVLT", version 2 (legacy) or version 3 (with data schema), KDF type 1 (PBKDF2-SHA512)
 *   - PBKDF2 iterations: 600,000
 *   - HKDF info: "SecureVault-v2"
 *   - AES-256-GCM with 96-bit nonces
 *   - Outer HMAC-SHA256 over header + vault ciphertext
 *
 * E12: Data schema versioning. The SVLT v3 format adds a 2-byte
 * DATA_SCHEMA_VERSION field in the header (after vaultCtLen). This
 * allows future schema migrations without breaking v2 compatibility:
 *   - v2 files (VERSION=2): no schema version in header → assumed schema 1
 *   - v3 files (VERSION=3): explicit DATA_SCHEMA_VERSION in header
 *   - On decrypt: if file schema > current DATA_SCHEMA_VERSION, warn the user
 *   - On encrypt: always write v3 format with current DATA_SCHEMA_VERSION
 *
 * Key handling rules:
 *   - PBKDF2-derived keys are non-extractable (extractable=false)
 *   - Plaintext Uint8Arrays are .fill(0)'d after use
 *   - CryptoKey objects are dropped by GC when references go out of scope
 */

const MAGIC = 'SVLT';                  // 4 bytes
const VERSION_V2 = 2;                  // Legacy format (no data schema field)
const VERSION_V3 = 3;                  // New format (includes DATA_SCHEMA_VERSION)
const DATA_SCHEMA_VERSION = 1;         // E12: Current data schema version
const DATA_SCHEMA_VERSION_LEN = 2;     // 2 bytes (Uint16) for schema version
const KDF_TYPE_PBKDF2_SHA512 = 1;      // 1 byte
const KDF_ITERATIONS = 600000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const DEK_LEN = 32;
const ENCRYPTED_DEK_LEN = DEK_LEN + TAG_LEN; // 48
const HMAC_LEN = 32;
const KEK_LEN = 32;
const HMAC_KEY_LEN = 32;
// v2 header: 4 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + ENCRYPTED_DEK_LEN + NONCE_LEN + 4 = 102
const HEADER_LEN_V2 = 4 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + ENCRYPTED_DEK_LEN + NONCE_LEN + 4;
// v3 header: v2 header + 2 bytes for DATA_SCHEMA_VERSION = 104
const HEADER_LEN_V3 = HEADER_LEN_V2 + DATA_SCHEMA_VERSION_LEN;
const HKDF_INFO = new Uint8Array([83, 101, 99, 117, 114, 101, 86, 97, 117, 108, 116, 45, 118, 50]); // "SecureVault-v2"

const _enc = new TextEncoder();
const _dec = new TextDecoder();

export class VaultFileError extends Error {}
export class WrongPasswordError extends Error {}

// E12: New error for when the file's data schema version is newer than
// what this code can handle. The user should upgrade the extension.
export class SchemaVersionTooNewError extends Error {
  constructor(fileSchemaVersion, supportedVersion) {
    super(
      `Data schema version ${fileSchemaVersion} is newer than supported version ${supportedVersion}. ` +
      `Please upgrade SecureVault to open this file.`
    );
    this.fileSchemaVersion = fileSchemaVersion;
    this.supportedVersion = supportedVersion;
  }
}

// ─── Key derivation ─────────────────────────────────────────────────────

async function deriveKeys(password, salt, iterations) {
  // 1. PBKDF2-SHA512 → 32-byte master key (non-extractable)
  const pwBytes = _enc.encode(password);
  let masterKeyMaterial;
  try {
    masterKeyMaterial = await crypto.subtle.importKey(
      'raw', pwBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey', 'deriveBits']
    );
  } finally {
    pwBytes.fill(0);
  }

  // Derive 64 raw bytes via PBKDF2-SHA512
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' },
    masterKeyMaterial,
    64 * 8  // 64 bytes = 512 bits
  );
  const derivedBytes = new Uint8Array(derivedBits);

  // First 32 bytes = master key for HKDF input
  const masterKey = derivedBytes.slice(0, 32);
  // We won't use the remaining 32 bytes — HKDF handles the key split below.
  // (This matches the Node side: PBKDF2 outputs 32 bytes there.)
  // To keep both sides identical, we only use the first 32 bytes.

  // 2. HKDF-SHA256 → 64 bytes split into KEK (32) + HMAC key (32)
  //    WebCrypto's HKDF requires importing the master key first.
  const hkdfInput = await crypto.subtle.importKey(
    'raw', masterKey,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  masterKey.fill(0);

  const hkdfOut = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    hkdfInput,
    (KEK_LEN + HMAC_KEY_LEN) * 8
  );
  const hkdfBytes = new Uint8Array(hkdfOut);

  const kekBytes = hkdfBytes.slice(0, KEK_LEN);
  const hmacKeyBytes = hkdfBytes.slice(KEK_LEN, KEK_LEN + HMAC_KEY_LEN);
  hkdfBytes.fill(0);

  // Wrap as non-extractable CryptoKeys
  const kek = await crypto.subtle.importKey(
    'raw', kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']  // Need both for decrypt AND encrypt operations
  );
  kekBytes.fill(0);

  const hmacKey = await crypto.subtle.importKey(
    'raw', hmacKeyBytes,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']  // Need both for encrypt (sign HMAC) AND decrypt (verify HMAC)
  );
  hmacKeyBytes.fill(0);

  return { kek, hmacKey };
}

// ─── Decrypt ────────────────────────────────────────────────────────────

/**
 * Decrypt an SVLT v2/v3 file ArrayBuffer.
 * E12: v2 files are assumed to have data schema version 1.
 * v3 files have an explicit schema version in the header.
 * If the schema version is newer than DATA_SCHEMA_VERSION, throws
 * SchemaVersionTooNewError. If it's older, applies migration
 * transformations (none yet — future work).
 *
 * @param {ArrayBuffer} fileBuffer
 * @param {string} password
 * @returns {Promise<{entries: Array, schemaVersion: number}>}
 */
export async function decryptVaultFile(fileBuffer, password) {
  const bytes = new Uint8Array(fileBuffer);
  // Minimum size check: v2 header (102) + HMAC (32) + GCM tag (16)
  if (bytes.length < HEADER_LEN_V2 + HMAC_LEN + TAG_LEN) {
    throw new VaultFileError('File is too short to be a valid SVLT vault');
  }

  // ── Parse header ────────────────────────────────────────────────
  let off = 0;
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]); off += 4;
  if (magic !== MAGIC) {
    throw new VaultFileError(`Bad magic (expected "SVLT", got "${magic}")`);
  }
  const fileVersion = bytes[off++]; // crypto format version (2 or 3)

  // E12: Determine header length and data schema version based on format version
  let headerLen;
  let fileSchemaVersion;
  if (fileVersion === VERSION_V2) {
    // Legacy v2 format: no schema version field → assume schema 1
    headerLen = HEADER_LEN_V2;
    fileSchemaVersion = 1;
  } else if (fileVersion === VERSION_V3) {
    // New v3 format: includes 2-byte DATA_SCHEMA_VERSION after vaultCtLen
    headerLen = HEADER_LEN_V3;
    // Schema version will be read after the rest of the header fields
  } else {
    throw new VaultFileError(`Unsupported crypto version ${fileVersion}`);
  }

  const kdfType = bytes[off++];
  if (kdfType !== KDF_TYPE_PBKDF2_SHA512) {
    throw new VaultFileError(`Unsupported KDF type ${kdfType}`);
  }
  const dv = new DataView(fileBuffer);
  const iterations = dv.getUint32(off); off += 4;
  if (iterations < 100000) {
    throw new VaultFileError(`KDF iterations too low (${iterations}) — refusing to decrypt weak file`);
  }
  const salt = bytes.slice(off, off + SALT_LEN); off += SALT_LEN;
  const dekNonce = bytes.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const encryptedDek = bytes.slice(off, off + ENCRYPTED_DEK_LEN); off += ENCRYPTED_DEK_LEN;
  const vaultNonce = bytes.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const vaultCtLen = dv.getUint32(off); off += 4;

  // E12: Read DATA_SCHEMA_VERSION for v3 format
  if (fileVersion === VERSION_V3) {
    fileSchemaVersion = dv.getUint16(off); off += 2;
  }

  if (off !== headerLen) {
    throw new VaultFileError('Header length mismatch');
  }

  // E12: Check data schema version
  if (fileSchemaVersion > DATA_SCHEMA_VERSION) {
    throw new SchemaVersionTooNewError(fileSchemaVersion, DATA_SCHEMA_VERSION);
  }
  // If fileSchemaVersion < DATA_SCHEMA_VERSION, apply migration
  // transformations. For now, no migrations are defined (they will
  // be added when the schema evolves). Old schemas are still readable
  // because normalizeEntry handles legacy field names.

  const vaultCiphertext = bytes.slice(headerLen, headerLen + vaultCtLen);
  const fileHmac = bytes.slice(bytes.length - HMAC_LEN);

  if (headerLen + vaultCtLen + HMAC_LEN !== bytes.length) {
    throw new VaultFileError('File length mismatch — truncated or corrupted');
  }

  // ── Derive keys ─────────────────────────────────────────────────
  const { kek, hmacKey } = await deriveKeys(password, salt, iterations);

  try {
    // ── 1. Verify outer HMAC FIRST (fast-fail on tampering) ────────
    const hmacPayload = bytes.slice(0, bytes.length - HMAC_LEN);
    const valid = await crypto.subtle.verify(
      { name: 'HMAC' },
      hmacKey,
      fileHmac,
      hmacPayload
    );
    if (!valid) {
      throw new WrongPasswordError('Wrong password, or file has been tampered with');
    }

    // ── 2. Decrypt DEK with KEK ────────────────────────────────────
    // WebCrypto's AES-GCM expects the auth tag appended to the ciphertext
    const dekCiphertextWithTag = encryptedDek; // already 48 bytes (32 + 16 tag)
    let dekBuffer;
    try {
      dekBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: dekNonce, tagLength: 128 },
        kek,
        dekCiphertextWithTag
      );
    } catch (e) {
      throw new WrongPasswordError('Wrong password, or DEK is corrupted');
    }
    const dek = new Uint8Array(dekBuffer);

    // Import DEK as AES-GCM key
    const dekKey = await crypto.subtle.importKey(
      'raw', dek,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    dek.fill(0);

    // ── 3. Decrypt vault with DEK ──────────────────────────────────
    let vaultJsonBuffer;
    try {
      vaultJsonBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: vaultNonce, tagLength: 128 },
        dekKey,
        vaultCiphertext  // includes 16-byte tag at end
      );
    } catch (e) {
      throw new VaultFileError('Vault ciphertext is corrupted (GCM tag mismatch)');
    }

    const vaultJsonBytes = new Uint8Array(vaultJsonBuffer);
    let entries;
    try {
      entries = JSON.parse(_dec.decode(vaultJsonBytes));
    } catch (e) {
      throw new VaultFileError('Decrypted data is not valid JSON');
    } finally {
      vaultJsonBytes.fill(0);
    }

    if (!Array.isArray(entries)) {
      throw new VaultFileError('Decrypted JSON is not an array');
    }

    // E12: Return entries along with the detected schema version
    // (useful for the UI to show migration notices or warnings)
    return { entries, schemaVersion: fileSchemaVersion };
  } finally {
    // CryptoKeys are non-extractable; they'll be GC'd when references drop.
    // No explicit fill needed — the underlying key material lives in the
    // browser's crypto runtime and is not exposed to JS.
  }
}

// ─── Encrypt (mirrors Node-side encryptVaultFile) ───────────────────────

export async function encryptVaultFile(entries, password) {
  if (!Array.isArray(entries)) throw new VaultFileError('entries must be an array');
  if (!password) throw new VaultFileError('password is required');

  // 1. Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));

  // 2. Derive KEK + HMAC key
  const { kek, hmacKey } = await deriveKeys(password, salt, KDF_ITERATIONS);

  let dekBytes = null;
  try {
    // 3. Generate random DEK
    dekBytes = crypto.getRandomValues(new Uint8Array(DEK_LEN));

    // 4. Encrypt DEK with KEK (AES-256-GCM)
    const dekNonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const encryptedDek = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: dekNonce, tagLength: 128 }, kek, dekBytes
    )); // 48 bytes (32 DEK + 16 tag)

    // 5. Encrypt vault JSON with DEK
    const vaultJson = _enc.encode(JSON.stringify(entries));
    const dekKey = await crypto.subtle.importKey(
      'raw', dekBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const vaultNonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const vaultCipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: vaultNonce, tagLength: 128 }, dekKey, vaultJson
    );
    const vaultCiphertext = new Uint8Array(vaultCipher);
    vaultJson.fill(0);

    // 6. Assemble header (104 bytes — v3 format with DATA_SCHEMA_VERSION)
    // E12: Always write v3 format (VERSION_V3 = 3) with DATA_SCHEMA_VERSION
    const header = new Uint8Array(HEADER_LEN_V3);
    let off = 0;
    header[0]=83; header[1]=86; header[2]=76; header[3]=84; off=4; // "SVLT"
    header[off++] = VERSION_V3;              // E12: Write v3 format version
    header[off++] = KDF_TYPE_PBKDF2_SHA512;
    const dv = new DataView(header.buffer);
    dv.setUint32(off, KDF_ITERATIONS); off += 4;
    header.set(salt, off); off += SALT_LEN;
    header.set(dekNonce, off); off += NONCE_LEN;
    header.set(encryptedDek, off); off += ENCRYPTED_DEK_LEN;
    header.set(vaultNonce, off); off += NONCE_LEN;
    dv.setUint32(off, vaultCiphertext.length); off += 4;
    dv.setUint16(off, DATA_SCHEMA_VERSION); off += 2;  // E12: Data schema version

    // 7. Compute outer HMAC over header + vault ciphertext
    const hmacPayload = new Uint8Array(header.length + vaultCiphertext.length);
    hmacPayload.set(header, 0);
    hmacPayload.set(vaultCiphertext, header.length);
    const hmacBuf = await crypto.subtle.sign({ name: 'HMAC' }, hmacKey, hmacPayload);
    const hmac = new Uint8Array(hmacBuf);

    // 8. Assemble final file: header + vault_ct + hmac
    const result = new Uint8Array(header.length + vaultCiphertext.length + hmac.length);
    result.set(header, 0);
    result.set(vaultCiphertext, header.length);
    result.set(hmac, header.length + vaultCiphertext.length);

    return result.buffer;
  } finally {
    if (dekBytes) dekBytes.fill(0);
  }
}

// ─── Format introspection (no decryption) ───────────────────────────────

export function peekFormat(fileBuffer) {
  const bytes = new Uint8Array(fileBuffer);
  if (bytes.length < 10) return null;
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  if (magic !== MAGIC) return null;
  const dv = new DataView(fileBuffer);
  const fileVersion = bytes[4];
  let schemaVersion = null;
  if (fileVersion === VERSION_V3 && bytes.length >= HEADER_LEN_V3) {
    // Schema version is at offset 102 (after vaultCtLen in v3 header)
    schemaVersion = dv.getUint16(HEADER_LEN_V2);  // right after the v2 header fields end
  } else if (fileVersion === VERSION_V2) {
    schemaVersion = 1; // assumed
  }
  return {
    magic,
    version: fileVersion,
    kdfType: bytes[5],
    iterations: dv.getUint32(6),
    schemaVersion,  // E12: data schema version (null if unknown format)
  };
}

// E12: Export DATA_SCHEMA_VERSION so other modules can check it
export { DATA_SCHEMA_VERSION, HEADER_LEN_V2, HEADER_LEN_V3, SchemaVersionTooNewError };
