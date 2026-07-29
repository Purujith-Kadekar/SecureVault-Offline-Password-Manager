#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  web_crypto_utils.h — crypto helpers specific to the AP-mode web stack
// ═══════════════════════════════════════════════════════════════════════════════
//  These supplement crypto_utils.h (which has secureZero, secureRandom,
//  PBKDF2, AES-256-GCM, vault key derivation). The AP-mode web stack
//  additionally needs:
//
//    - Base64 encode/decode (for transporting ECDH pubkeys + AES-GCM
//      ciphertext + tags over HTTP JSON bodies)
//    - SHA-256 (for the 6-digit code proof + clientId fingerprint)
//    - HKDF-SHA256 (for deriving the AES session key from the ECDH
//      shared secret + the 6-digit code, matching SecureSession's
//      existing KDF on the serial side)
//    - HMAC-SHA256 (for CSRF token derivation from the session key)
//    - Device key derivation (mirrors SecureGen's DeviceStaticKey — a
//      deterministic key derived from chip MAC + flash identifiers,
//      used to wrap the ECDH handshake for opaque-to-sniffer key
//      exchange. NOT a true secret — see study_securegen_layers.md
//      caveat #6 — but provides defense-in-depth against passive
//      observers who don't have a same-model device to fingerprint.)
//
//  All implemented with mbedtls directly (already in REQUIRES).
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto_utils.h"  // secureZero, secureRandom, aesGcmEncrypt/Decrypt

// ── Base64 ────────────────────────────────────────────────────────────
// RFC 4648 standard alphabet, padded with '='. Output buffer must be
// at least 4*ceil(len/3) bytes. Returns the number of bytes written
// (excluding the null terminator) or 0 on failure (NULL inputs or
// outBuf too small).
size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t outCap);

// Inverse. *outLen receives the number of decoded bytes. Returns false
// on malformed input or outBuf too small.
bool base64Decode(const char* in, size_t inLen, uint8_t* out, size_t outCap, size_t* outLen);

// Convenience wrappers returning Arduino String (heap-allocated, use
// sparingly on hot paths — the raw C versions above are preferred
// inside HTTP handlers).
String base64EncodeStr(const uint8_t* in, size_t len);
String base64DecodeStr(const String& in);

// ── SHA-256 ───────────────────────────────────────────────────────────
void sha256(const uint8_t* data, size_t len, uint8_t out32[32]);

// Hex-encode a 32-byte SHA-256 digest into a 64-char null-terminated
// string (lowercase). out must be at least 65 bytes.
void sha256Hex(const uint8_t* data, size_t len, char out65[65]);

// ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────
// Extract+Expand. salt may be NULL/0 (treated as zeros per RFC).
// info may be NULL/0. outLen typically 32 (one AES-256 key) or 64
// (key + nonce). Returns true on success.
bool hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* out, size_t outLen);

// ── HMAC-SHA256 ───────────────────────────────────────────────────────
// Single-shot. out32 must be 32 bytes. Used for CSRF token derivation.
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t out32[32]);

// ── Device key derivation (deterministic, per-chip) ──────────────────
// NOT a secret in the cryptographic sense — derived from chip MAC +
// flash identifiers. Used as a wrapping key to make the ECDH handshake
// opaque to passive sniffers (an attacker needs a same-model device
// to derive a similar key — see study_securegen_layers.md caveat #6).
//
// Fills key32 with 32 bytes. Returns true on success.
bool deriveDeviceStaticKey(uint8_t key32[32]);

// ── Constant-time comparison ─────────────────────────────────────────
// Returns true if a and b have the same length AND all bytes match.
// Critical for session ID + CSRF token comparison — a naive memcmp
// leaks prefix length via timing.
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len);

// ── Hex encode/decode (for session IDs, CSRF tokens, clientId) ───────
// out must be 2*len+1 bytes. Lowercase.
void hexEncode(const uint8_t* in, size_t len, char* out);
// Inverse. Returns number of bytes decoded, or -1 on malformed input.
int hexDecode(const char* in, size_t inLen, uint8_t* out, size_t outCap);

// ── Random hex string generator ──────────────────────────────────────
// Fills out with 2*bytes hex chars + null terminator. out must be
// 2*bytes+1 bytes. Uses secureRandom() (hardware RNG).
void randomHex(size_t bytes, char* out);
