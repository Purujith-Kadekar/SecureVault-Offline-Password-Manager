#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  secure_session.h — 4-Layer Security Stack for the SecureVault dashboard
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Layer 1 (Out-of-Band Physical Handshake):
//      On entering Dashboard Mode (after the vault PIN is verified on-device),
//      the ESP32 generates a cryptographically-random 6-digit code via
//      esp_random() and displays it on the TFT. The user types this code
//      into the Electron app. The code never crosses the wire in plaintext
//      -- it's only used as a Pre-Shared Key (PSK) mixed into the KDF.
//
//  Layer 2 (ECDH Session Key Exchange):
//      Both sides generate an ephemeral P-256 keypair. Public keys are
//      exchanged over the wire. Each side computes the ECDH shared secret
//      and derives the 256-bit AES session key via:
//          HKDF-SHA256( ecdh_secret || 6-digit-code, salt="SecureVault-v3",
//                       info="session-key", length=32 )
//      The 6-digit code acts as a PSK that an MITM doesn't know -- even
//      if an attacker intercepts both public keys and substitutes their
//      own, they can't derive the session key without the code.
//
//  Layer 3 (Authenticated Wire Encryption):
//      Every message after the handshake is AES-256-GCM encrypted with
//      the session key. Frame format:
//          [1B version][1B msg_type][2B payload_len BE][12B nonce]
//          [N B ciphertext][16B auth tag]
//      A fresh random nonce is generated per message (safe up to 2^32
//      messages per key, far beyond a dashboard session's lifetime).
//
//  Layer 4 (Process Isolation & Memory Zeroing):
//      The session key, ECDH private key, and 6-digit code live ONLY in
//      this module's static buffers inside the ESP32's main task. They
//      are zeroed with secureZero() (volatile-pointer memset, cannot be
//      optimised away) when:
//        - the session times out (60s inactivity),
//        - the user exits Dashboard Mode,
//        - auto-lock fires,
//        - or the device disconnects.
//      The web_manager never sees the raw session key -- it calls
//      SecureSession::decrypt() which returns the plaintext into a
//      caller-provided buffer, and the caller is responsible for
//      zeroing that buffer after use.
//
//  WHY P-256 (prime256v1 / secp256r1):
//      - mbedtls on ESP32 has hardware-accelerated P-256 (CONFIG_MBEDTLS_
//        HARDWARE_MPI + ECP), making keygen + ECDH ~50ms total.
//      - Node.js crypto.createECDH('prime256v1') is built in, no deps.
//      - Python cryptography.hazmat...ec.SECP256R1() is standard.
//      - Web Crypto API supports ECDH P-256 natively (browser extension).
//      All four sides speak the same curve with zero compatibility risk.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include "crypto_utils.h"

// ── Curve & key sizes ──────────────────────────────────────────────────
// P-256 public key (uncompressed, X.962 format): 0x04 || X(32) || Y(32) = 65 bytes
#define SEC_ECDH_PUBKEY_LEN  65
// P-256 private key (scalar): 32 bytes
#define SEC_ECDH_PRIVKEY_LEN 32
// ECDH shared secret (X-coordinate of the computed point): 32 bytes
#define SEC_ECDH_SECRET_LEN  32
// Final AES-256 session key: 32 bytes
#define SEC_SESSION_KEY_LEN  32

// 6-digit out-of-band code (ASCII "000000".."999999" + NUL = 7 bytes)
#define SEC_CODE_LEN  6
#define SEC_CODE_BUF_LEN (SEC_CODE_LEN + 1)

// AES-GCM nonce (96-bit, the NIST-recommended size for GCM)
#define SEC_NONCE_LEN 12
// AES-GCM auth tag (128-bit)
#define SEC_TAG_LEN   16

// Frame header: version(1) + msg_type(1) + payload_len(2) + nonce(12) = 16 bytes
#define SEC_FRAME_HEADER_LEN 16
// Max plaintext payload per frame (keeps total frame under 16KB for HTTP body limits)
#define SEC_MAX_PAYLOAD 8192
// Max total frame size (header + ciphertext + tag)
#define SEC_MAX_FRAME (SEC_FRAME_HEADER_LEN + SEC_MAX_PAYLOAD + SEC_TAG_LEN)

// Session inactivity timeout. 5 minutes — long enough for the user to
// read the vault, think about an edit, type it, and save without the
// session dying mid-operation. The old 60s was too short: the user
// would start editing an entry, take 60+ seconds, and the session would
// tear down before the save completed.
#define SEC_SESSION_TIMEOUT_MS 300000UL

// ── Message types ──────────────────────────────────────────────────────
enum SecMsgType : uint8_t {
  SEC_MSG_HELLO       = 0x01,  // Client → Device: { client_pubkey, code_hash }
  SEC_MSG_HELLO_ACK   = 0x02,  // Device → Client: { device_pubkey, ok }
  SEC_MSG_LIST        = 0x10,  // Client → Device: list entries
  SEC_MSG_LIST_RESP   = 0x11,  // Device → Client: { entries[] }
  SEC_MSG_GET         = 0x12,  // Client → Device: { index }
  SEC_MSG_GET_RESP    = 0x13,  // Device → Client: { entry }
  SEC_MSG_ADD         = 0x14,  // Client → Device: { entry }
  SEC_MSG_UPDATE      = 0x15,  // Client → Device: { index, entry }
  SEC_MSG_DELETE      = 0x16,  // Client → Device: { index }
  SEC_MSG_SAVE_OK     = 0x17,  // Device → Client: { ok, error? }
  SEC_MSG_LOCK        = 0x18,  // Client → Device: tear down session
  SEC_MSG_LOCKED      = 0x19,  // Device → Client: session torn down
  SEC_MSG_ERROR       = 0xFF,  // Device → Client: { error }
};

// ── Session state machine ──────────────────────────────────────────────
enum class SecState : uint8_t {
  IDLE,         // No session; 6-digit code not yet generated
  CODE_SHOWN,   // 6-digit code generated + displayed; waiting for HELLO
  HANDSHAKING,  // HELLO received, ECDH in progress
  ESTABLISHED,  // Session key derived; encrypted messages accepted
  EXPIRED,      // Timed out or locked; all keys zeroed
};

class SecureSession {
public:
  SecureSession() = default;

  // ── Layer 1: generate the 6-digit out-of-band code ──────────────────
  // Called by ui_screens.cpp when the user selects Dashboard Mode (after
  // PIN entry). Fills _code with a cryptographically-random 6-digit
  // string and transitions to CODE_SHOWN. The code is displayed on the
  // TFT and never transmitted over the wire.
  void generateCode();

  // Returns the current 6-digit code (null-terminated) or "" if no
  // session is active. Used by ui_screens.cpp to draw the code on screen.
  const char* code() const { return _code; }

  // ── Layer 2: ECDH handshake ────────────────────────────────────────
  // Called when a HELLO message arrives from the client. Verifies the
  // code proof, generates the device's ECDH keypair, computes the shared
  // secret with the client's public key, and derives the session key.
  //
  // clientPubkey: 65-byte uncompressed P-256 public key (0x04 || X || Y)
  // codeProof:    SHA-256( 6-digit-code ) — 32 bytes. The client sends
  //               this instead of the raw code so the code itself never
  //               crosses the wire, even during the handshake. An
  //               attacker who intercepts the handshake sees only the
  //               hash; the code itself is only on the TFT + the user's
  //               eyes → the Electron input field.
  //
  // devicePubkeyOut: filled with the device's 65-byte public key on
  //                  success (sent back to the client in HELLO_ACK).
  //
  // Returns true on success (code proof matches, ECDH succeeded, session
  // key derived). Returns false if the code proof doesn't match (wrong
  // 6-digit code) or ECDH fails (malformed client public key).
  bool handleHello(const uint8_t* clientPubkey, size_t clientPubkeyLen,
                   const uint8_t* codeProof, size_t codeProofLen,
                   uint8_t* devicePubkeyOut, size_t devicePubkeyOutLen);

  // ── Layer 3: frame encrypt/decrypt ──────────────────────────────────
  // encryptFrame: plaintext → AES-256-GCM → wire frame.
  //   msgType:   the SEC_MSG_* constant for this message
  //   plaintext: caller's plaintext payload (may be NULL if payloadLen==0)
  //   payloadLen: length of plaintext (0..SEC_MAX_PAYLOAD)
  //   frameOut:  caller-provided buffer, must be at least
  //              SEC_FRAME_HEADER_LEN + payloadLen + SEC_TAG_LEN bytes
  //   frameOutLen: filled with the actual frame length on success
  //   Returns true on success.
  bool encryptFrame(uint8_t msgType,
                    const uint8_t* plaintext, size_t payloadLen,
                    uint8_t* frameOut, size_t* frameOutLen);

  // decryptFrame: wire frame → AES-256-GCM verify + decrypt → plaintext.
  //   frame:     the raw bytes received from the wire
  //   frameLen:  length of frame
  //   msgTypeOut: filled with the message type from the frame header
  //   plaintextOut: caller-provided buffer, must be at least SEC_MAX_PAYLOAD
  //   plaintextOutLen: filled with the actual plaintext length on success
  //   Returns true if the GCM auth tag verifies AND the session is
  //   ESTABLISHED. Returns false on tag mismatch (tampering / wrong key),
  //   wrong session state, or malformed frame.
  bool decryptFrame(const uint8_t* frame, size_t frameLen,
                    uint8_t* msgTypeOut,
                    uint8_t* plaintextOut, size_t* plaintextOutLen);

  // ── Session management ──────────────────────────────────────────────
  SecState state() const { return _state; }
  bool isEstablished() const { return _state == SecState::ESTABLISHED; }

  // Called every loop() tick by web_manager. If the session has been
  // inactive for SEC_SESSION_TIMEOUT_MS, transitions to EXPIRED and
  // zeroes all keys.
  void tick();

  // Explicit teardown (user exits Dashboard Mode, auto-lock, or client
  // sends SEC_MSG_LOCK). Zeroes ALL secrets with secureZero().
  void teardown();

  // Activity timestamp (updated on every successful decrypt)
  void touch() { _lastActivity = millis(); }

private:
  volatile SecState _state = SecState::IDLE;

  // Layer 1 secret
  char _code[SEC_CODE_BUF_LEN] = {0};

  // Layer 2 secrets (zeroed after session key derivation)
  uint8_t _devicePrivKey[SEC_ECDH_PRIVKEY_LEN] = {0};
  uint8_t _devicePubKey[SEC_ECDH_PUBKEY_LEN] = {0};
  uint8_t _sharedSecret[SEC_ECDH_SECRET_LEN] = {0};

  // Layer 3 key (zeroed on teardown/expire)
  uint8_t _sessionKey[SEC_SESSION_KEY_LEN] = {0};

  unsigned long _lastActivity = 0;

  // Internal helpers
  bool _generateEcdhKeypair();
  bool _computeSharedSecret(const uint8_t* peerPubkey, size_t peerPubkeyLen);
  void _deriveSessionKey(const uint8_t* codeProof, size_t codeProofLen);
  void _zeroAllSecrets();
};

// ── Utility: SHA-256 (used for the 6-digit code proof) ─────────────────
// Implemented in secure_session.cpp using mbedtls.
void secSha256(const uint8_t* data, size_t len, uint8_t out32[32]);
