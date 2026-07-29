#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  crypto_utils.h — secure memory zeroing + PBKDF2-SHA256 + AES-256-GCM
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// Overwrites memory with zeros using a volatile pointer so the compiler
// cannot optimise it away. Use for PIN buffers, keys, secrets.
void secureZero(void* v, size_t n);

// PBKDF2-HMAC-SHA256. Used by duress_manager for duress PIN hashing.
// mbedtls_pkcs5 module may not be enabled in all ESP-IDF configs, so
// this is a hand-rolled implementation using mbedtls's SHA-256 directly.
void pbkdf2Sha256(const void* password, size_t passLen,
                  const void* salt, size_t saltLen,
                  uint32_t iterations,
                  void* out, size_t outLen);

// ─────────────────────────────────────────────────────────────────────────
//  AES-256-GCM vault encryption
// ─────────────────────────────────────────────────────────────────────────
// Sizes are fixed on purpose -- the on-disk vault format
// (VaultManager) embeds exactly these lengths in its file header.
#define VAULT_SALT_LEN       16   // PBKDF2 salt, stored alongside the ciphertext
#define VAULT_IV_LEN         12   // GCM nonce -- 96 bits, the recommended size
#define VAULT_TAG_LEN        16   // GCM authentication tag (128 bits)
#define VAULT_KEY_LEN        32   // AES-256 key
#define VAULT_KDF_ITERATIONS 2000  // v10.6: was 20000 — reduced 10x for ~10x faster
                                    // unlock (~0.3s on ESP32-S3 vs ~2-3s). Still
                                    // strong: combined with the 5-attempt PIN
                                    // lockout, brute force is infeasible.
#define VAULT_KDF_ITERATIONS_LEGACY 20000  // v10.5-and-earlier vaults. Used as a
                                            // fallback in _tryLoadFile when the
                                            // new (2000-iter) key fails to decrypt,
                                            // so existing vaults keep working.

// Fills buf with `n` cryptographically-strong random bytes from the
// ESP32's hardware RNG. Used for fresh salts/IVs on every save.
void secureRandom(uint8_t* buf, size_t n);

// Derives a 256-bit AES key from the vault PIN + a stored salt via
// PBKDF2-HMAC-SHA256 (VAULT_KDF_ITERATIONS rounds). keyOut32 must be
// VAULT_KEY_LEN (32) bytes.
void deriveVaultKey(const char* pin, const uint8_t* salt, size_t saltLen,
                    uint8_t* keyOut32);

// v10.6: Same as deriveVaultKey but takes an explicit iteration count.
// Used by the vault-load backward-compat path to retry with the legacy
// 20000-iteration count when a vault created by v10.5-or-earlier fails
// to decrypt with the new 2000-iteration key.
void deriveVaultKeyWithIters(const char* pin, const uint8_t* salt, size_t saltLen,
                             uint32_t iters, uint8_t* keyOut32);

// AES-256-GCM encrypt. `iv` must be VAULT_IV_LEN bytes and must never be
// reused with the same key. ciphertextOut must be `len` bytes; tagOut
// must be VAULT_TAG_LEN bytes. Returns true on success.
bool aesGcmEncrypt(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                    const uint8_t* plaintext, size_t len,
                    uint8_t* ciphertextOut, uint8_t* tagOut);

// AES-256-GCM authenticated decrypt. Verifies `tag` (VAULT_TAG_LEN bytes)
// as part of decryption -- returns false (and leaves plaintextOut
// contents undefined) if the tag doesn't match, which is what happens
// when the wrong PIN derives the wrong key. plaintextOut must be `len`
// bytes.
bool aesGcmDecrypt(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                    const uint8_t* ciphertext, size_t len,
                    const uint8_t* tag,
                    uint8_t* plaintextOut);

// ── AES-256-GCM with Additional Authenticated Data (AAD) ────────────────
// F5: Added for SecureLayerManager's web transport encryption.
// AAD is authenticated but NOT encrypted. The GCM tag covers both the
// plaintext and the AAD, so any modification of the AAD will cause the
// tag verification to fail. Used by SecureLayerManager to bind the
// counter value to the ciphertext, preventing counter-swap attacks.
bool aesGcmEncryptAad(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* plaintext, size_t len,
                       uint8_t* ciphertextOut, uint8_t* tagOut);

bool aesGcmDecryptAad(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* ciphertext, size_t len,
                       const uint8_t* tag,
                       uint8_t* plaintextOut);
