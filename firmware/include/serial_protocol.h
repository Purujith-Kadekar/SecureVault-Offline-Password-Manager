#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  serial_protocol.h — Secure vault access over USB CDC serial (NO HTTP)
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include "vault_manager.h"
#include "secure_session.h"
#include "session_context.h"  // F6: single authoritative PIN holder

class SerialProtocol {
public:
  SerialProtocol() = default;

  void begin(VaultManager& vault, SessionContext* sessionCtx);
  void end();

  void tick();

  void teardownSecureSession();

  // Regenerate the 6-digit code (for the "NEW CODE" button).
  void regenerateCode();

  // True if the ECDH handshake completed successfully.
  bool sessionEstablished() const { return _establishedFlag; }

  const char* code() const { return _session.code(); }

private:
  VaultManager* _vault = nullptr;
  SecureSession _session;
  SessionContext* _sessionCtx = nullptr;  // F6: read PIN from here, never store own copy

  // ── Serial receive state machine ───────────────────────────────────
  enum class RxState : uint8_t {
    SCAN_MAGIC,
    READ_LENGTH,
    READ_PAYLOAD,
  };
  RxState _rxState = RxState::SCAN_MAGIC;
  uint8_t _magicBuf[4] = {0};
  int _magicPos = 0;
  uint8_t _lenBuf[4] = {0};
  int _lenPos = 0;
  uint32_t _payloadLen = 0;
  uint8_t _payloadBuf[8192 + 256];
  int _payloadPos = 0;

  // ── Handshake task ─────────────────────────────────────────────────
  volatile bool _handshakeTaskRunning = false;
  volatile bool _establishedFlag = false;
  volatile bool _processingRequest = false;

  // Serial disconnect detection: if no data received for 30 seconds while
  // a session is established AND not processing a request, tear down the
  // session + generate a new code.
  unsigned long _lastSerialActivity = 0;
  static const unsigned long SERIAL_DISCONNECT_MS = 30000;

  static const uint8_t MAGIC[4];

  void processPayload();
  void handleHandshake(const uint8_t* data, size_t len);
  void handleSecureRequest(const uint8_t* frame, size_t frameLen);
  void handleReadRequest(uint8_t msgType, uint8_t* plaintext, size_t plaintextLen);
  void sendEncryptedResponse(uint8_t respMsgType, const char* jsonStr);
  void sendEncryptedResponseRaw(uint8_t respMsgType, const char* data, size_t len);
  void sendFrame(const uint8_t* data, size_t len);
  void sendJson(const char* json);

  static void handshakeTaskWrapper(void* arg);
};
