#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  secure_layer_manager.h — Layer 2: Transport Encryption (v5.5.0 — AES-256-GCM)
// ═══════════════════════════════════════════════════════════════════════════════
//  Author: Purujith Kadekar
//
//  v5.5.0 (F5: Crypto Unification): Replaced the HMAC-XOR stream cipher with
//  AES-256-GCM for the data encryption layer, unifying the crypto with
//  SecureSession (Serial/Dashboard mode) which already uses ECDH + AES-256-GCM.
//
//  The HMAC-based key exchange (challenge-response with 6-digit code as PSK)
//  is RETAINED — it works without WebCrypto (HTTP-only captive portal).
//  Only the data encryption layer was upgraded from XOR stream cipher to
//  AES-256-GCM.
//
//  Protocol (unchanged handshake, upgraded encryption):
//    1. Client: requests challenge → server sends serverNonce (16 bytes)
//    2. Client: codeProof = HMAC-SHA-256(code, serverNonce)
//    3. Client → POST /api/secure/hello {clientId, serverNonce, codeProof}
//    4. Server: verifies codeProof, derives encKey + macKey from code + serverNonce
//    5. Server → {ok, serverNonce, csrfToken, obfuscatedPaths, ...}
//    6. Client: derives the same encKey + macKey from code + serverNonce
//
//  Encryption (per request/response) — NEW: AES-256-GCM:
//    frame = { counter, iv: base64(12-byte-nonce), ct: base64(ciphertext), tag: base64(16-byte-auth-tag) }
//    nonce = 4 zero bytes || counter(8 bytes BE)   (unique per message, monotonically increasing)
//    ciphertext, tag = AES-256-GCM(encKey, nonce, plaintext, AAD=counter(8 bytes BE))
//
//  Security properties:
//    - Confidentiality: AES-256-GCM (standard authenticated encryption)
//    - Integrity: AES-256-GCM 16-byte auth tag (encrypt-then-MAC, built into GCM)
//    - Replay protection: per-session rxCounter/txCounter, reject counter <= rxCounter
//    - Key separation: encKey used for AES-GCM, macKey retained in session but
//      no longer used for per-frame MAC (GCM provides auth; macKey is kept for
//      potential future use and backward compat in session struct)
//    - Forward secrecy within session: serverNonce is random per session
//    - MITM resistance: the 6-digit code is the shared secret (PSK) — an attacker
//      who intercepts the handshake can't derive encKey/macKey without the code
//    - AAD binding: counter is included as Additional Authenticated Data, so
//      an attacker cannot change the counter without breaking the GCM tag
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <freertos/semphr.h>
#include <ESPAsyncWebServer.h>
#include "web_crypto_utils.h"

#define SL_MAX_SESSIONS  4
#define SL_SESSION_TTL_MS 300000UL

class SecureLayerManager {
public:
  static SecureLayerManager& getInstance();

  bool begin();
  void end();

  // F8: Initialization tracking. begin() sets _initialized = true.
  // If getInstance() is called before begin(), auto-initializes with warning.
  bool isInitialized() const { return _initialized; }

  // ── Key exchange (POST /api/secure/hello) — v5.4.7 challenge-response ──
  // Two-step handshake to prevent offline brute-force of the 6-digit code:
  //
  //   Step 1 (challenge): client sends {clientId} only.
  //     Server generates a random serverNonce, stores it in a pending-challenge
  //     map keyed by clientId, returns {serverNonce} to the client.
  //
  //   Step 2 (response): client computes codeProof = HMAC(code, serverNonce)
  //     and sends {clientId, serverNonce, codeProof}.
  //     Server looks up the pending challenge, verifies codeProof ==
  //     HMAC(storedCode, serverNonce), derives encKey + macKey from
  //     code + serverNonce, stores the session.
  //
  // This is unbruteforceable because:
  //   - The attacker sees serverNonce (random, 16 bytes) and codeProof (HMAC output)
  //   - To verify a code guess, they'd need to compute HMAC(guess, serverNonce)
  //     and compare — but HMAC-SHA-256 with a 6-byte key is still ~10⁶ operations
  //     PER GUESS, and each guess requires a full SHA-256 compression.
  //   - More importantly: the server can rate-limit step 2 (5 attempts/min per IP),
  //     making online brute-force infeasible.
  //   - The code never crosses the wire in any form — only an HMAC of it with a
  //     random nonce that changes every session.
  //
  // Step 1: generate a challenge. Returns the serverNonce (base64) for the client.
  // Stores the challenge in a pending-challenge map keyed by clientId.
  bool generateChallenge(const String& clientId, String& serverNonceB64Out);

  // Step 2: verify the response + establish the session.
  // Verifies codeProof == HMAC(code, serverNonce), derives encKey/macKey,
  // stores the session. Fills serverNonceB64Out again (so the client can
  // re-derive keys if it only kept the codeProof, not the nonce).
  bool establishSession(const String& clientId,
                        const String& serverNonceB64,
                        const String& codeProofHex);

  // ── Encrypt a plaintext response body ────────────────────────────
  String encryptResponseJSON(const String& clientId, const String& plaintext);

  // ── Decrypt an incoming request body ─────────────────────────────
  String decryptRequestStr(const String& clientId, const String& bodyJson);

  // ── Session queries ──────────────────────────────────────────────
  bool isSessionValid(const String& clientId);
  void invalidateSession(const String& clientId);
  int getActiveSessionCount();

  void tick();

private:
  SecureLayerManager() = default;
  SecureLayerManager(const SecureLayerManager&) = delete;
  SecureLayerManager& operator=(const SecureLayerManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;

  struct Session {
    bool active = false;
    char clientId[65] = {0};
    uint8_t encKey[32] = {0};
    uint8_t macKey[32] = {0};
    uint64_t rxCounter = 0;
    uint64_t txCounter = 1;
    unsigned long lastActivity = 0;
  };

  Session _sessions[SL_MAX_SESSIONS];
  SemaphoreHandle_t _mutex = nullptr;

  // v5.4.7: Pending challenges for the two-step handshake.
  // generateChallenge() stores a nonce here; establishSession() looks it up.
  struct Challenge {
    bool active = false;
    char clientId[65] = {0};
    uint8_t nonce[16] = {0};
    unsigned long createdAt = 0;
  };
  static const int SL_MAX_CHALLENGES = 4;
  Challenge _challenges[SL_MAX_CHALLENGES];

  Session* _findSession(const String& clientId);
  Session* _findFreeSlot();
  void _evictLRU();
  void _clearSession(Session& s);
  Challenge* _findChallenge(const String& clientId);
  Challenge* _findFreeChallengeSlot();
  void _clearChallenge(Challenge& c);

  // F5: AES-256-GCM encryption/decryption (replaces HMAC-XOR stream cipher).
  // Uses encKey as the AES-256 key, counter-derived nonce, and counter as AAD.
  // nonce = 4 zero bytes || counter(8 bytes BE) — unique per message.
  bool _aesGcmEncrypt(const uint8_t* encKey, uint64_t counter,
                      const uint8_t* plaintext, size_t ptLen,
                      uint8_t* ctOut, uint8_t* tagOut);
  bool _aesGcmDecrypt(const uint8_t* encKey, uint64_t counter,
                      const uint8_t* ciphertext, size_t ctLen,
                      const uint8_t* tag,
                      uint8_t* ptOut);

  // Build a 12-byte GCM nonce from the counter: 00 00 00 00 || counter(8 BE)
  void _buildGcmNonce(uint64_t counter, uint8_t nonce[12]);

  // Build 8-byte AAD from the counter (big-endian) for GCM authentication
  void _buildGcmAad(uint64_t counter, uint8_t aad[8]);
};

inline SecureLayerManager& secureLayer() { return SecureLayerManager::getInstance(); }
