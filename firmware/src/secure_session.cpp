// ═══════════════════════════════════════════════════════════════════════════════
//  secure_session.cpp — implementation of the 4-Layer Security Stack
// ═══════════════════════════════════════════════════════════════════════════════
//
//  mbedtls 3.x compatibility note (ESP-IDF 5.x):
//  Both `mbedtls_ecp_keypair` AND `mbedtls_ecp_point` are opaque structs in
//  mbedtls 3.x — you cannot access .d, .Q, .X, .Y, .Z members directly.
//  This file uses ONLY the binary-serialization API:
//    - mbedtls_ecp_gen_keypair()          → generates d + Q into group
//    - mbedtls_mpi_write_binary(&d, ...)   → extract private scalar
//    - mbedtls_ecp_point_write_binary()    → extract public point (X.962)
//    - mbedtls_ecp_point_read_binary()     → parse peer's public point
//    - mbedtls_ecdh_compute_shared()       → ECDH shared secret
//  These functions are the stable public API across mbedtls 2.x and 3.x.
// ═══════════════════════════════════════════════════════════════════════════════
#include "secure_session.h"
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>     // mbedtls_ecdh_compute_shared
#include <mbedtls/bignum.h>   // mbedtls_mpi
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>       // mbedtls_md_hmac (one-shot HMAC)
#include <esp_random.h>
#include <string.h>

// Note: we intentionally do NOT use mbedtls_hkdf() — it's gated behind
// CONFIG_MBEDTLS_HKDF_C in ESP-IDF's sdkconfig, which isn't enabled by
// default and may not survive a clean rebuild. Instead, _deriveSessionKey()
// below implements HKDF-SHA256 (RFC 5869) manually using mbedtls_md_hmac(),
// which is ALWAYS compiled in (gated only by CONFIG_MBEDTLS_MD_C, which
// is force-on by other components that need SHA-256).

// ─────────────────────────────────────────────────────────────────────────
//  Constant-time memory compare (replacement for mbedtls_ct_memcmp which
//  isn't exposed in all ESP-IDF mbedtls builds). XORs each byte into an
//  accumulator — never branches on the secret data, so timing-analysis
//  attacks can't reveal byte-by-byte differences.
// ─────────────────────────────────────────────────────────────────────────
static int ct_memcmp(const void* a, const void* b, size_t n) {
  const volatile uint8_t* pa = (const volatile uint8_t*)a;
  const volatile uint8_t* pb = (const volatile uint8_t*)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) {
    diff |= (uint8_t)(pa[i] ^ pb[i]);
  }
  return diff ? 1 : 0;
}

// ─────────────────────────────────────────────────────────────────────────
//  Layer 1: 6-digit code generation
// ─────────────────────────────────────────────────────────────────────────
void SecureSession::generateCode() {
  // esp_random() returns a hardware RNG value (true entropy from the
  // ESP32's RF subsystem, validated at boot). Modulo 1,000,000 gives a
  // uniform 6-digit code (0..999999), formatted with leading zeros so
  // the code is always exactly 6 characters.
  uint32_t r = esp_random();
  snprintf(_code, SEC_CODE_BUF_LEN, "%06lu", (unsigned long)(r % 1000000));
  _state = SecState::CODE_SHOWN;
  _lastActivity = millis();

}

// ─────────────────────────────────────────────────────────────────────────
//  Layer 2: ECDH handshake
// ─────────────────────────────────────────────────────────────────────────
bool SecureSession::handleHello(const uint8_t* clientPubkey, size_t clientPubkeyLen,
                                const uint8_t* codeProof, size_t codeProofLen,
                                uint8_t* devicePubkeyOut, size_t devicePubkeyOutLen) {
  if (_state != SecState::CODE_SHOWN) {

    return false;
  }
  if (clientPubkeyLen != SEC_ECDH_PUBKEY_LEN || codeProofLen != 32 || devicePubkeyOutLen < SEC_ECDH_PUBKEY_LEN) {
    return false;
  }

  // ── Verify the 6-digit code proof ──────────────────────────────────
  // The client sends SHA-256(6-digit-code), NOT the raw code. Constant-time
  // compare prevents timing side-channels on the proof.
  uint8_t expectedProof[32];
  secSha256((const uint8_t*)_code, SEC_CODE_LEN, expectedProof);

  if (ct_memcmp(expectedProof, codeProof, 32) != 0) {

    secureZero(expectedProof, sizeof(expectedProof));
    return false;
  }
  secureZero(expectedProof, sizeof(expectedProof));

  _state = SecState::HANDSHAKING;

  // ── Generate device's ephemeral ECDH keypair ───────────────────────
  if (!_generateEcdhKeypair()) {

    _zeroAllSecrets();
    _state = SecState::EXPIRED;
    return false;
  }

  // ── Compute ECDH shared secret with client's public key ────────────
  if (!_computeSharedSecret(clientPubkey, clientPubkeyLen)) {

    _zeroAllSecrets();
    _state = SecState::EXPIRED;
    return false;
  }

  // ── Derive the 256-bit AES session key ─────────────────────────────
  // Key = HKDF-SHA256( ecdh_secret || code_proof,
  //                    salt = "SecureVault-v3",
  //                    info = "session-key", length = 32 )
  _deriveSessionKey(codeProof, codeProofLen);

  // Copy device public key to output (sent back to client in HELLO_ACK)
  memcpy(devicePubkeyOut, _devicePubKey, SEC_ECDH_PUBKEY_LEN);

  // Zero the ECDH private key + shared secret NOW — they're no longer
  // needed. Only the session key remains.
  secureZero(_devicePrivKey, sizeof(_devicePrivKey));
  secureZero(_sharedSecret, sizeof(_sharedSecret));

  // Zero the 6-digit code — it has served its purpose.
  secureZero(_code, sizeof(_code));

  _state = SecState::ESTABLISHED;
  _lastActivity = millis();

  return true;
}

bool SecureSession::_generateEcdhKeypair() {
  // HEAP-ALLOCATE all mbedtls contexts to avoid stack overflow on the
  // AsyncWebServer task (which has a small ~8KB stack). The entropy +
  // ctr_drbg contexts alone are ~400 bytes each, and the ECDH internal
  // bignum operations use another 2-4KB of stack. Heap allocation keeps
  // our stack footprint to <1KB.
  mbedtls_ecp_group* grp = new mbedtls_ecp_group;
  mbedtls_mpi* d = new mbedtls_mpi;
  mbedtls_ecp_point* Q = new mbedtls_ecp_point;
  mbedtls_entropy_context* entropy = new mbedtls_entropy_context;
  mbedtls_ctr_drbg_context* ctr_drbg = new mbedtls_ctr_drbg_context;
  bool ok = false;

  mbedtls_ecp_group_init(grp);
  mbedtls_mpi_init(d);
  mbedtls_ecp_point_init(Q);
  mbedtls_entropy_init(entropy);
  mbedtls_ctr_drbg_init(ctr_drbg);

  const char* pers = "SecureVault-ecdh-keygen";
  if (mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                             (const unsigned char*)pers, strlen(pers)) != 0) {

    goto cleanup;
  }

  // Load P-256 (secp256r1 / prime256v1)
  if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {

    goto cleanup;
  }

  // Generate keypair: d = private scalar, Q = public point.
  // This is the slowest step (~30-50ms on ESP32-S3 with hardware MPI).
  // yield() feeds the task watchdog so it doesn't trigger during the
  // blocking ECDH computation (same pattern as crypto_utils.cpp's PBKDF2).
  yield();
  if (mbedtls_ecp_gen_keypair(grp, d, Q, mbedtls_ctr_drbg_random, ctr_drbg) != 0) {

    goto cleanup;
  }
  yield();

  // Extract private key (32-byte scalar)
  if (mbedtls_mpi_write_binary(d, _devicePrivKey, SEC_ECDH_PRIVKEY_LEN) != 0) {

    goto cleanup;
  }

  // Extract public key in X.962 uncompressed format: 0x04 || X || Y
  {
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(grp, Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                        _devicePubKey, SEC_ECDH_PUBKEY_LEN) != 0 ||
        olen != SEC_ECDH_PUBKEY_LEN) {

      goto cleanup;
    }
  }

  ok = true;

cleanup:
  mbedtls_ecp_group_free(grp);
  mbedtls_mpi_free(d);
  mbedtls_ecp_point_free(Q);
  mbedtls_entropy_free(entropy);
  mbedtls_ctr_drbg_free(ctr_drbg);
  delete grp; delete d; delete Q; delete entropy; delete ctr_drbg;
  return ok;
}

bool SecureSession::_computeSharedSecret(const uint8_t* peerPubkey, size_t peerPubkeyLen) {
  // HEAP-ALLOCATE all mbedtls contexts (same reason as _generateEcdhKeypair).
  mbedtls_ecp_group* grp = new mbedtls_ecp_group;
  mbedtls_mpi* peerD = new mbedtls_mpi;
  mbedtls_ecp_point* peerQ = new mbedtls_ecp_point;
  mbedtls_mpi* sharedX = new mbedtls_mpi;
  mbedtls_entropy_context* entropy = new mbedtls_entropy_context;
  mbedtls_ctr_drbg_context* ctr_drbg = new mbedtls_ctr_drbg_context;
  bool ok = false;

  mbedtls_ecp_group_init(grp);
  mbedtls_mpi_init(peerD);
  mbedtls_ecp_point_init(peerQ);
  mbedtls_mpi_init(sharedX);
  mbedtls_entropy_init(entropy);
  mbedtls_ctr_drbg_init(ctr_drbg);

  if (mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                             (const unsigned char*)"SecureVault-ecdh-shared", 24) != 0) {
    goto cleanup;
  }

  if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto cleanup;

  // Parse peer's uncompressed public key (0x04 || X || Y) into an
  // mbedtls_ecp_point. mbedtls_ecp_point_read_binary handles the X/Y
  // assignment internally — we never touch opaque struct members.
  if (peerPubkeyLen != SEC_ECDH_PUBKEY_LEN || peerPubkey[0] != 0x04) {

    goto cleanup;
  }
  if (mbedtls_ecp_point_read_binary(grp, peerQ, peerPubkey, peerPubkeyLen) != 0) {

    goto cleanup;
  }

  // Validate the peer's public key is on the curve (prevents invalid-curve attacks)
  if (mbedtls_ecp_check_pubkey(grp, peerQ) != 0) {

    goto cleanup;
  }

  // Load our private key scalar
  if (mbedtls_mpi_read_binary(peerD, _devicePrivKey, SEC_ECDH_PRIVKEY_LEN) != 0) goto cleanup;

  // Compute shared secret = d * peerQ (the X-coordinate of the product point).
  // yield() before the slow ECDH computation to feed the watchdog.
  yield();
  if (mbedtls_ecdh_compute_shared(grp, sharedX, peerQ, peerD,
                                    mbedtls_ctr_drbg_random, ctr_drbg) != 0) {

    goto cleanup;
  }
  yield();

  // Write the shared secret (32 bytes, the X-coordinate)
  if (mbedtls_mpi_write_binary(sharedX, _sharedSecret, SEC_ECDH_SECRET_LEN) != 0) {

    goto cleanup;
  }

  ok = true;

cleanup:
  mbedtls_ecp_group_free(grp);
  mbedtls_mpi_free(peerD);
  mbedtls_ecp_point_free(peerQ);
  mbedtls_mpi_free(sharedX);
  mbedtls_entropy_free(entropy);
  mbedtls_ctr_drbg_free(ctr_drbg);
  delete grp; delete peerD; delete peerQ; delete sharedX; delete entropy; delete ctr_drbg;
  return ok;
}

void SecureSession::_deriveSessionKey(const uint8_t* codeProof, size_t codeProofLen) {
  // Manual HKDF-SHA256 (RFC 5869) implementation using mbedtls_md_hmac().
  //
  // We avoid mbedtls_hkdf() because it's gated behind CONFIG_MBEDTLS_HKDF_C
  // which isn't enabled in ESP-IDF's default sdkconfig. mbedtls_md_hmac()
  // (the one-shot HMAC function) is always available.
  //
  // HKDF-Extract(salt, IKM) -> PRK:
  //   PRK = HMAC-SHA256(salt, IKM)
  //
  // HKDF-Expand(PRK, info, L=32) -> OKM:
  //   T(1) = HMAC-SHA256(PRK, info || 0x01)
  //   OKM = T(1)   (since L == HashLen == 32, only one iteration)

  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  // Input material: ECDH shared secret (32) || code proof (32) = 64 bytes
  uint8_t ikm[SEC_ECDH_SECRET_LEN + 32];
  memcpy(ikm, _sharedSecret, SEC_ECDH_SECRET_LEN);
  size_t proofCopyLen = codeProofLen > 32 ? 32 : codeProofLen;
  memcpy(ikm + SEC_ECDH_SECRET_LEN, codeProof, proofCopyLen);

  // Salt = "SecureVault-v3" (14 bytes, no NUL)
  const uint8_t salt[] = "SecureVault-v3";
  size_t saltLen = sizeof(salt) - 1;

  // ── HKDF-Extract: PRK = HMAC-SHA256(salt, IKM) ─────────────────────
  uint8_t prk[32];  // SHA-256 output = 32 bytes
  mbedtls_md_hmac(mdInfo, salt, saltLen, ikm, sizeof(ikm), prk);
  secureZero(ikm, sizeof(ikm));

  // ── HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) ────────────
  // info = "session-key" (11 bytes, no NUL)
  const uint8_t info[] = "session-key";
  size_t infoLen = sizeof(info) - 1;

  // Build the expand input: info || counter(1 byte)
  uint8_t expandInput[32];  // info (11) + counter (1) = 12 bytes, but pad for safety
  memcpy(expandInput, info, infoLen);
  expandInput[infoLen] = 0x01;

  mbedtls_md_hmac(mdInfo, prk, 32, expandInput, infoLen + 1, _sessionKey);

  secureZero(prk, sizeof(prk));
  secureZero(expandInput, sizeof(expandInput));
}

// ─────────────────────────────────────────────────────────────────────────
//  Layer 3: AES-256-GCM frame encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────
bool SecureSession::encryptFrame(uint8_t msgType,
                                  const uint8_t* plaintext, size_t payloadLen,
                                  uint8_t* frameOut, size_t* frameOutLen) {
  if (_state != SecState::ESTABLISHED) {

    return false;
  }
  if (payloadLen > SEC_MAX_PAYLOAD) {
    return false;
  }
  if (!frameOut || !frameOutLen) return false;

  // ── Build frame header ─────────────────────────────────────────────
  // [0]   version = 1
  // [1]   msg_type
  // [2-3] payload_len (big-endian)
  // [4-15] nonce (12 bytes, fresh random per message)
  frameOut[0] = 1;
  frameOut[1] = msgType;
  frameOut[2] = (uint8_t)(payloadLen >> 8);
  frameOut[3] = (uint8_t)(payloadLen & 0xFF);

  // Fresh random nonce. With a 96-bit random nonce, the probability of
  // a nonce collision under the same key is negligible for any realistic
  // session length (birthday bound is 2^48 messages).
  uint8_t* nonce = frameOut + 4;
  secureRandom(nonce, SEC_NONCE_LEN);

  // ── AES-256-GCM encrypt ────────────────────────────────────────────
  // ciphertext is written immediately after the header (at offset 16),
  // tag is written after ciphertext (at offset 16 + payloadLen).
  uint8_t* ciphertext = frameOut + SEC_FRAME_HEADER_LEN;
  uint8_t* tag = frameOut + SEC_FRAME_HEADER_LEN + payloadLen;

  // Use the existing aesGcmEncrypt from crypto_utils — it's the same
  // mbedtls GCM implementation the vault itself uses, ensuring
  // consistent cipher behaviour across vault-at-rest and wire-encryption.
  bool ok = aesGcmEncrypt(_sessionKey, nonce, SEC_NONCE_LEN,
                          plaintext, payloadLen,
                          ciphertext, tag);

  if (!ok) {

    return false;
  }

  *frameOutLen = SEC_FRAME_HEADER_LEN + payloadLen + SEC_TAG_LEN;
  _lastActivity = millis();
  return true;
}

bool SecureSession::decryptFrame(const uint8_t* frame, size_t frameLen,
                                  uint8_t* msgTypeOut,
                                  uint8_t* plaintextOut, size_t* plaintextOutLen) {
  if (_state != SecState::ESTABLISHED) {
    return false;  // silently reject — don't leak session state to attacker
  }
  if (!frame || !msgTypeOut || !plaintextOut || !plaintextOutLen) return false;
  if (frameLen < SEC_FRAME_HEADER_LEN + SEC_TAG_LEN) {
    return false;  // too short to be a valid frame
  }

  // Parse header
  uint8_t version = frame[0];
  *msgTypeOut = frame[1];
  size_t payloadLen = ((size_t)frame[2] << 8) | frame[3];
  const uint8_t* nonce = frame + 4;

  if (version != 1) {

    return false;
  }
  if (payloadLen > SEC_MAX_PAYLOAD) {

    return false;
  }
  if (frameLen != SEC_FRAME_HEADER_LEN + payloadLen + SEC_TAG_LEN) {
    return false;
  }

  const uint8_t* ciphertext = frame + SEC_FRAME_HEADER_LEN;
  const uint8_t* tag = frame + SEC_FRAME_HEADER_LEN + payloadLen;

  // AES-256-GCM decrypt + auth-tag verify. Returns false if the tag
  // doesn't match (tampering, wrong key, corrupted frame).
  bool ok = aesGcmDecrypt(_sessionKey, nonce, SEC_NONCE_LEN,
                          ciphertext, payloadLen,
                          tag, plaintextOut);

  if (!ok) {

    return false;
  }

  *plaintextOutLen = payloadLen;
  _lastActivity = millis();
  return true;
}

// ─────────────────────────────────────────────────────────────────────────
//  Session management
// ─────────────────────────────────────────────────────────────────────────
void SecureSession::tick() {
  if (_state == SecState::ESTABLISHED || _state == SecState::CODE_SHOWN) {
    if (millis() - _lastActivity > SEC_SESSION_TIMEOUT_MS) {

      teardown();
    }
  }
}

void SecureSession::teardown() {
  _zeroAllSecrets();
  _state = SecState::EXPIRED;

}

void SecureSession::_zeroAllSecrets() {
  secureZero(_code, sizeof(_code));
  secureZero(_devicePrivKey, sizeof(_devicePrivKey));
  secureZero(_devicePubKey, sizeof(_devicePubKey));
  secureZero(_sharedSecret, sizeof(_sharedSecret));
  secureZero(_sessionKey, sizeof(_sessionKey));
}

// ─────────────────────────────────────────────────────────────────────────
//  Utility: SHA-256
// ─────────────────────────────────────────────────────────────────────────
void secSha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
  mbedtls_sha256(data, len, out32, 0);  // 0 = SHA-256 (not SHA-224)
}
