#include "crypto_utils.h"
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

void secureZero(void* v, size_t n) {
  volatile uint8_t* p = (volatile uint8_t*)v;
  while (n--) *p++ = 0;
}

// v9.20: Replaced the hand-rolled PBKDF2 with mbedtls_pkcs5_pbkdf2_hmac.
// The old code called mbedtls_sha256_starts/update/finish for every HMAC
// iteration (40,000 SHA-256 calls for 20k iterations), re-initializing
// the context each time. The library version uses streaming HMAC (one
// context init, reused across iterations) and benefits from the ESP32-S3's
// hardware SHA-256 accelerator — 3-5x faster.
//
// The hand-rolled version is kept below as a fallback in case
// CONFIG_MBEDTLS_PKCS5_C is not enabled in sdkconfig (it's on by
// default in ESP-IDF 5.x).
void pbkdf2Sha256(const void* password, size_t passLen,
                  const void* salt,     size_t saltLen,
                  uint32_t iterations,
                  void* out,           size_t outLen) {
  // Try the optimized library version first
  // v9.20: mbedtls 3.x (ESP-IDF 5.x) renamed this to _ext
  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mdInfo) {
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
      MBEDTLS_MD_SHA256,
      (const unsigned char*)password, passLen,
      (const unsigned char*)salt, saltLen,
      iterations,
      outLen,
      (unsigned char*)out
    );
    if (ret == 0) return;  // success
    // Fall through to hand-rolled version on failure
  }

  // ── Fallback: hand-rolled PBKDF2-HMAC-SHA256 ──────────────────────
  const uint8_t* pw = (const uint8_t*)password;
  const uint8_t* sl = (const uint8_t*)salt;
  uint8_t* dk = (uint8_t*)out;
  uint32_t blockNum = 1;

  while (outLen > 0) {
    uint8_t u[32], t[32];
    size_t msgLen = saltLen + 4;
    uint8_t msg[256];
    // v10.9 FIX: Buffer overflow guard — if saltLen > 252, the 4-byte
    // block counter written at msg[saltLen..saltLen+3] would exceed the
    // 256-byte msg buffer. The old code capped msgLen but still wrote
    // the block counter at the un-capped saltLen offset. Current vault
    // format uses 16-byte salts (safe), but the function signature
    // accepts arbitrary saltLen — a future caller could trigger the
    // overflow. Now we reject any saltLen that doesn't leave room for
    // the 4-byte block counter.
    if (saltLen + 4 > sizeof(msg)) {
      // Salt too long for the fallback path — can't safely compute.
      // Zero the output and return (the library path should have handled
      // this already, so hitting here means both paths failed).
      secureZero(dk, outLen);
      return;
    }
    memcpy(msg, sl, saltLen);
    msg[saltLen]     = (uint8_t)(blockNum >> 24);
    msg[saltLen + 1] = (uint8_t)(blockNum >> 16);
    msg[saltLen + 2] = (uint8_t)(blockNum >> 8);
    msg[saltLen + 3] = (uint8_t)(blockNum);

    uint8_t kx[64];  // v5.3: was 32 — BUFFER OVERFLOW! HMAC key is 64 bytes,
                      // passwords ≤64 bytes are zero-padded to 64. The old 32-byte
                      // buffer was overwritten by the memset at line 67, and the
                      // ipad/opad XOR loops read 64 bytes from a 32-byte buffer.
    if (passLen > 64) {
      mbedtls_sha256(pw, passLen, kx, 0);
      memset(kx + 32, 0, 32);  // hash output is 32B; pad rest to 64
    } else {
      memcpy(kx, pw, passLen);
      memset(kx + passLen, 0, 64 - passLen);
    }

    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) ipad[i] = kx[i] ^ 0x36;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, ipad, 64);
    mbedtls_sha256_update(&ctx, msg, msgLen);
    mbedtls_sha256_finish(&ctx, u);

    uint8_t opad[64];
    for (int i = 0; i < 64; i++) opad[i] = kx[i] ^ 0x5c;
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, opad, 64);
    mbedtls_sha256_update(&ctx, u, 32);
    mbedtls_sha256_finish(&ctx, u);

    memcpy(t, u, 32);

    for (uint32_t j = 1; j < iterations; j++) {
      mbedtls_sha256_starts(&ctx, 0);
      mbedtls_sha256_update(&ctx, ipad, 64);
      mbedtls_sha256_update(&ctx, u, 32);
      mbedtls_sha256_finish(&ctx, u);

      mbedtls_sha256_starts(&ctx, 0);
      mbedtls_sha256_update(&ctx, opad, 64);
      mbedtls_sha256_update(&ctx, u, 32);
      mbedtls_sha256_finish(&ctx, u);

      for (int k = 0; k < 32; k++) t[k] ^= u[k];
      // v5.3 FIX: vTaskDelay(1) instead of yield() — yield() only yields
      // to same-priority tasks. vTaskDelay(1) sleeps for 1 tick, allowing
      // the IDLE task (priority 0) to run and feed the Task WDT. This
      // prevents TWDT reset during PBKDF2 in the save task.
      //
      // v10.1 FIX: interval tightened from 0x3FF (every 1024 iters, ~19
      // yield points across 20000 iterations) to 0x7F (every 128 iters,
      // ~156 yield points). This PBKDF2 call runs on the SAME task that
      // owns the USB CDC serial port (no longer a background task as of
      // v5.4) — with only ~19 yield points, the FreeRTOS scheduler could
      // go 100ms+ without giving the CDC driver a chance to run, causing
      // the ESP32 to appear to "disconnect" if the host sent anything
      // (e.g. a keepalive PING) during that window. This is what made
      // the FIRST-EVER ADD (or first save after a fresh SD card, which is
      // the only time deriveVaultKey()/PBKDF2 actually runs — every
      // later save reuses the cached key) unreliable while UPDATE/DELETE
      // — which never hit this code path once the key is cached — kept
      // working. Total PBKDF2 wall-clock time is unaffected (the added
      // vTaskDelay(1) calls total under 200ms extra across the full
      // 20000-iteration derivation).
      if ((j & 0x7F) == 0) vTaskDelay(pdMS_TO_TICKS(1));
    }

    size_t copyLen = (outLen < 32) ? outLen : 32;
    memcpy(dk, t, copyLen);
    dk += copyLen;
    outLen -= copyLen;
    blockNum++;
  }
}

void secureRandom(uint8_t* buf, size_t n) {
  // esp_fill_random pulls from the ESP32's hardware RNG (seeded from RF/
  // thermal noise per the IDF docs) -- suitable for salts/IVs, which need
  // to be unpredictable and non-repeating but not kept secret themselves.
  esp_fill_random(buf, n);
}

void deriveVaultKey(const char* pin, const uint8_t* salt, size_t saltLen,
                    uint8_t* keyOut32) {
  pbkdf2Sha256(pin, strlen(pin), salt, saltLen, VAULT_KDF_ITERATIONS,
               keyOut32, VAULT_KEY_LEN);
}

// v10.6: Same as deriveVaultKey but with an explicit iteration count.
// Used only by the vault-load backward-compat path to retry decryption
// with the legacy 20000-iteration count when a v10.5-or-earlier vault
// fails to decrypt with the new 2000-iteration key.
void deriveVaultKeyWithIters(const char* pin, const uint8_t* salt, size_t saltLen,
                             uint32_t iters, uint8_t* keyOut32) {
  pbkdf2Sha256(pin, strlen(pin), salt, saltLen, iters,
               keyOut32, VAULT_KEY_LEN);
}

bool aesGcmEncrypt(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                    const uint8_t* plaintext, size_t len,
                    uint8_t* ciphertextOut, uint8_t* tagOut) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = false;
  do {
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key32, VAULT_KEY_LEN * 8) != 0) break;
    // v5.3: Yield before GCM to let IDLE feed TWDT (for large vaults,
    // this single call can take 200ms+ — cumulative with _toJSON it
    // can approach the 5s TWDT timeout)
    vTaskDelay(pdMS_TO_TICKS(1));
    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                   iv, ivLen, nullptr, 0,
                                   plaintext, ciphertextOut,
                                   VAULT_TAG_LEN, tagOut) != 0) break;
    ok = true;
  } while (0);
  mbedtls_gcm_free(&ctx);
  return ok;
}

bool aesGcmDecrypt(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                    const uint8_t* ciphertext, size_t len,
                    const uint8_t* tag,
                    uint8_t* plaintextOut) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = false;
  do {
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key32, VAULT_KEY_LEN * 8) != 0) break;
    // v10.7: Removed the vTaskDelay(1) that used to live here. This
    // function is called PER ENTRY from _loadRecordsFromOpenFile (up to
    // 256 times during one unlock), and the 1ms-per-call overhead added
    // up to 256ms of pure yield time to every unlock. With hardware AES
    // on the ESP32-S3, a single GCM decrypt of a ~150-500-byte record
    // takes only 1-3ms -- fast enough that the Task WDT (5s timeout) is
    // never at risk. The caller (_loadRecordsFromOpenFile) already yields
    // every 32 entries to feed the IDLE task, which is more than enough.
    //
    // The vTaskDelay(1) is KEPT in aesGcmEncrypt below because the save
    // path runs on the serial-protocol task with a smaller margin to the
    // TWDT timeout (cumulative with _toJSON + the write itself for very
    // large vaults). Decrypt is in the unlock hot path; encrypt is not.
    //
    // mbedtls_gcm_auth_decrypt verifies the tag itself and returns
    // MBEDTLS_ERR_GCM_AUTH_FAILED (nonzero) on mismatch -- this is what
    // catches a wrong PIN (wrong derived key) or a corrupted/tampered
    // vault file, instead of silently returning garbage plaintext.
    if (mbedtls_gcm_auth_decrypt(&ctx, len, iv, ivLen, nullptr, 0,
                                  tag, VAULT_TAG_LEN,
                                  ciphertext, plaintextOut) != 0) break;
    ok = true;
  } while (0);
  mbedtls_gcm_free(&ctx);
  return ok;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  F5: AES-256-GCM with Additional Authenticated Data (AAD)
// ═══════════════════════════════════════════════════════════════════════════════
//  These variants pass the AAD to mbedtls_gcm, which includes it in the
//  GHASH computation. The GCM auth tag then covers both the plaintext
//  and the AAD — any modification of either will cause tag verification
//  to fail. Used by SecureLayerManager to bind the message counter to
//  the ciphertext (preventing counter-swap replay attacks).
// ═══════════════════════════════════════════════════════════════════════════════
bool aesGcmEncryptAad(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* plaintext, size_t len,
                       uint8_t* ciphertextOut, uint8_t* tagOut) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = false;
  do {
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key32, VAULT_KEY_LEN * 8) != 0) break;
    vTaskDelay(pdMS_TO_TICKS(1));
    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                   iv, ivLen, aad, aadLen,
                                   plaintext, ciphertextOut,
                                   VAULT_TAG_LEN, tagOut) != 0) break;
    ok = true;
  } while (0);
  mbedtls_gcm_free(&ctx);
  return ok;
}

bool aesGcmDecryptAad(const uint8_t* key32, const uint8_t* iv, size_t ivLen,
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* ciphertext, size_t len,
                       const uint8_t* tag,
                       uint8_t* plaintextOut) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = false;
  do {
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key32, VAULT_KEY_LEN * 8) != 0) break;
    if (mbedtls_gcm_auth_decrypt(&ctx, len, iv, ivLen, aad, aadLen,
                                  tag, VAULT_TAG_LEN,
                                  ciphertext, plaintextOut) != 0) break;
    ok = true;
  } while (0);
  mbedtls_gcm_free(&ctx);
  return ok;
}