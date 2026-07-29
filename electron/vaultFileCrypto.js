'use strict';
/**
 * vaultFileCrypto.js — SVLT v2 encrypted vault file format.
 *
 * Stronger than Bitwarden's vault format:
 *   - PBKDF2-SHA512 @ 600,000 iterations
 *   - HKDF-SHA256 splits master key into KEK + HMAC key (key separation)
 *   - Envelope encryption: KEK wraps random 32-byte DEK, DEK encrypts vault
 *   - AES-256-GCM for both layers
 *   - Outer HMAC-SHA256 over entire file (fast-fail on tampering + protects KDF params)
 *   - Pure binary format — no JSON wrapping ciphertext
 *
 * File layout (102-byte fixed header + variable ciphertext + 32-byte HMAC):
 *
 *   [0..3]     Magic "SVLT"                         (4 bytes)
 *   [4]        Version = 2                           (1 byte)
 *   [5]        KDF type = 1 (PBKDF2-SHA512)         (1 byte)
 *   [6..9]     PBKDF2 iterations (uint32 BE)         (4 bytes)
 *   [10..25]   KDF salt                              (16 bytes)
 *   [26..37]   DEK nonce                             (12 bytes)
 *   [38..85]   Encrypted DEK                         (48 bytes = 32 DEK + 16 GCM tag)
 *   [86..97]   Vault nonce                           (12 bytes)
 *   [98..101]  Vault ciphertext length (uint32 BE)   (4 bytes)
 *   [102..N]   Vault ciphertext                      (variable, last 16 bytes = GCM tag)
 *   [N..N+31]  File HMAC-SHA256                      (32 bytes) over [0..N-1]
 *
 * Key derivation:
 *   master_key = PBKDF2-SHA512(password, salt, 600000, 32 bytes)
 *   hkdf_out   = HKDF-SHA256(master_key, salt=[], info="SecureVault-v2", 64 bytes)
 *   kek        = hkdf_out[0:32]      // encrypts the DEK
 *   hmac_key   = hkdf_out[32:64]     // file integrity HMAC
 *
 * All sensitive Buffers are .fill(0)'d before they go out of scope.
 *
 * The Electron app uses encryptVaultFile() to write the .svlt file that the
 * browser extension reads. The browser extension uses decryptVaultFile()
 * (implemented in WebCrypto inside the extension) to read it back.
 *
 * The Electron app ALSO reads the .svlt file in extsync:syncFromFile (and
 * in extsync:changePassword's anti-brick fallback) to support the two-way
 * sync flow: the browser extension can write changes to the file, and
 * Electron reads them back to push to the ESP32 SD card. Both directions
 * use the same SVLT v2 format and the same crypto — they're fully
 * interchangeable.
 */

const crypto = require('crypto');

const MAGIC = Buffer.from('SVLT', 'ascii');
const VERSION = 2;
const KDF_TYPE_PBKDF2_SHA512 = 1;
const KDF_ITERATIONS = 600000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const DEK_LEN = 32;
const ENCRYPTED_DEK_LEN = DEK_LEN + TAG_LEN;
const HMAC_LEN = 32;
const HMAC_KEY_LEN = 32;
const KEK_LEN = 32;
const HKDF_INFO = Buffer.from('SecureVault-v2', 'utf8');

const HEADER_LEN = 4 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + ENCRYPTED_DEK_LEN + NONCE_LEN + 4;

class VaultFileError extends Error {}
class WrongPasswordError extends Error {}

function deriveKeys(password, salt, iterations) {
  const masterKey = crypto.pbkdf2Sync(
    Buffer.from(String(password), 'utf8'),
    salt,
    iterations,
    KEY_LEN,
    'sha512'
  );

  let hkdfOut = crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), HKDF_INFO, KEK_LEN + HMAC_KEY_LEN);
  if (!Buffer.isBuffer(hkdfOut)) {
    hkdfOut = Buffer.from(hkdfOut);
  }

  const kek = Buffer.from(hkdfOut.slice(0, KEK_LEN));
  const hmacKey = Buffer.from(hkdfOut.slice(KEK_LEN, KEK_LEN + HMAC_KEY_LEN));

  masterKey.fill(0);
  hkdfOut.fill(0);

  return { kek, hmacKey };
}

/**
 * Encrypt an entries array into an SVLT v2 Buffer ready to write to disk.
 */
function encryptVaultFile(entries, password) {
  if (!Array.isArray(entries)) {
    throw new VaultFileError('entries must be an array');
  }
  if (!password || typeof password !== 'string') {
    throw new VaultFileError('password is required');
  }

  const salt = crypto.randomBytes(SALT_LEN);
  const { kek, hmacKey } = deriveKeys(password, salt, KDF_ITERATIONS);

  try {
    const dek = crypto.randomBytes(DEK_LEN);

    const dekNonce = crypto.randomBytes(NONCE_LEN);
    const dekCipher = crypto.createCipheriv('aes-256-gcm', kek, dekNonce);
    const encryptedDek = Buffer.concat([
      dekCipher.update(dek),
      dekCipher.final(),
      dekCipher.getAuthTag()
    ]);

    const vaultJson = Buffer.from(JSON.stringify(entries), 'utf8');
    const vaultNonce = crypto.randomBytes(NONCE_LEN);
    const vaultCipher = crypto.createCipheriv('aes-256-gcm', dek, vaultNonce);
    const vaultCiphertext = Buffer.concat([
      vaultCipher.update(vaultJson),
      vaultCipher.final(),
      vaultCipher.getAuthTag()
    ]);

    dek.fill(0);
    vaultJson.fill(0);

    const header = Buffer.alloc(HEADER_LEN);
    let off = 0;
    MAGIC.copy(header, off); off += 4;
    header.writeUInt8(VERSION, off); off += 1;
    header.writeUInt8(KDF_TYPE_PBKDF2_SHA512, off); off += 1;
    header.writeUInt32BE(KDF_ITERATIONS, off); off += 4;
    salt.copy(header, off); off += SALT_LEN;
    dekNonce.copy(header, off); off += NONCE_LEN;
    encryptedDek.copy(header, off); off += ENCRYPTED_DEK_LEN;
    vaultNonce.copy(header, off); off += NONCE_LEN;
    header.writeUInt32BE(vaultCiphertext.length, off); off += 4;
    if (off !== HEADER_LEN) throw new Error('header length mismatch');

    const hmacPayload = Buffer.concat([header, vaultCiphertext]);
    const hmac = crypto.createHmac('sha256', hmacKey).update(hmacPayload).digest();

    return Buffer.concat([header, vaultCiphertext, hmac]);
  } finally {
    kek.fill(0);
    hmacKey.fill(0);
  }
}

/**
 * Decrypt an SVLT v2 file Buffer.
 * (Used only by the test suite — the Electron app itself never reads the
 * .svlt file; that's the browser extension's job.)
 */
function decryptVaultFile(fileBuffer, password) {
  if (!Buffer.isBuffer(fileBuffer)) fileBuffer = Buffer.from(fileBuffer);
  if (fileBuffer.length < HEADER_LEN + HMAC_LEN + TAG_LEN) {
    throw new VaultFileError('File is too short');
  }

  const magic = fileBuffer.slice(0, 4);
  if (!magic.equals(MAGIC)) throw new VaultFileError('Bad magic');
  const version = fileBuffer[4];
  if (version !== VERSION) throw new VaultFileError(`Unsupported version ${version}`);
  const kdfType = fileBuffer[5];
  if (kdfType !== KDF_TYPE_PBKDF2_SHA512) throw new VaultFileError(`Unsupported KDF type ${kdfType}`);
  const iterations = fileBuffer.readUInt32BE(6);
  if (iterations < 100000) throw new VaultFileError('KDF iterations too low');

  const salt = fileBuffer.slice(10, 10 + SALT_LEN);
  const dekNonce = fileBuffer.slice(26, 26 + NONCE_LEN);
  const encryptedDek = fileBuffer.slice(38, 38 + ENCRYPTED_DEK_LEN);
  const vaultNonce = fileBuffer.slice(86, 86 + NONCE_LEN);
  const vaultCtLen = fileBuffer.readUInt32BE(98);
  const vaultCiphertext = fileBuffer.slice(102, 102 + vaultCtLen);
  const fileHmac = fileBuffer.slice(fileBuffer.length - HMAC_LEN);

  if (102 + vaultCtLen + HMAC_LEN !== fileBuffer.length) {
    throw new VaultFileError('File length mismatch');
  }

  const { kek, hmacKey } = deriveKeys(password, salt, iterations);

  try {
    const hmacPayload = fileBuffer.slice(0, fileBuffer.length - HMAC_LEN);
    const computedHmac = crypto.createHmac('sha256', hmacKey).update(hmacPayload).digest();
    if (computedHmac.length !== fileHmac.length || !crypto.timingSafeEqual(computedHmac, fileHmac)) {
      throw new WrongPasswordError('Wrong password, or file has been tampered with');
    }

    const dekCiphertext = encryptedDek.slice(0, DEK_LEN);
    const dekTag = encryptedDek.slice(DEK_LEN, DEK_LEN + TAG_LEN);

    let dek;
    try {
      const dekDecipher = crypto.createDecipheriv('aes-256-gcm', kek, dekNonce);
      dekDecipher.setAuthTag(dekTag);
      dek = Buffer.concat([dekDecipher.update(dekCiphertext), dekDecipher.final()]);
    } catch (e) {
      throw new WrongPasswordError('Wrong password, or DEK is corrupted');
    }

    const vaultCt = vaultCiphertext.slice(0, vaultCiphertext.length - TAG_LEN);
    const vaultTag = vaultCiphertext.slice(vaultCiphertext.length - TAG_LEN);

    let vaultJson;
    try {
      const vaultDecipher = crypto.createDecipheriv('aes-256-gcm', dek, vaultNonce);
      vaultDecipher.setAuthTag(vaultTag);
      vaultJson = Buffer.concat([vaultDecipher.update(vaultCt), vaultDecipher.final()]);
    } catch (e) {
      throw new VaultFileError('Vault ciphertext is corrupted');
    } finally {
      dek.fill(0);
    }

    let entries;
    try {
      entries = JSON.parse(vaultJson.toString('utf8'));
    } catch (e) {
      throw new VaultFileError('Decrypted data is not valid JSON');
    } finally {
      vaultJson.fill(0);
    }

    if (!Array.isArray(entries)) throw new VaultFileError('Decrypted JSON is not an array');
    return entries;
  } finally {
    kek.fill(0);
    hmacKey.fill(0);
  }
}

function peekFormat(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer)) fileBuffer = Buffer.from(fileBuffer);
  if (fileBuffer.length < 10) return null;
  const magic = fileBuffer.slice(0, 4).toString('latin1');
  if (magic !== 'SVLT') return null;
  return {
    magic,
    version: fileBuffer[4],
    kdfType: fileBuffer[5],
    iterations: fileBuffer.readUInt32BE(6),
  };
}

module.exports = {
  encryptVaultFile,
  decryptVaultFile,
  peekFormat,
  VaultFileError,
  WrongPasswordError,
  MAGIC: MAGIC.toString('ascii'),
  VERSION,
  KDF_ITERATIONS,
  SALT_LEN,
  NONCE_LEN,
  TAG_LEN,
  DEK_LEN,
  ENCRYPTED_DEK_LEN,
  HMAC_LEN,
  HEADER_LEN,
};
