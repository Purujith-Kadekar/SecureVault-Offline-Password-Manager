// ═══════════════════════════════════════════════════════════════════════════════
//  serial_protocol.cpp — Secure vault access over USB CDC serial
// ═══════════════════════════════════════════════════════════════════════════════
#include "serial_protocol.h"
#include "vault_types.h"
#include <ArduinoJson.h>
#include <mbedtls/base64.h>
#include <string.h>
#include "crypto_buffer.h"  // cryptoAlloc/cryptoFree/largeAlloc/largeFree — unified DMA-safe allocator

// ── Per-request buffer allocation strategy ────────────────────────────
// This file uses two allocation classes from crypto_buffer.h:
//
//   cryptoAlloc()/cryptoFree() — for plaintext and respFrame, the direct
//     source/destination buffers for the ESP32-S3 AES-GCM hardware engine.
//     DMA requires internal SRAM (not PSRAM — cache/alignment incoherency),
//     and only cryptoAlloc() guarantees that. These MUST never be allocated
//     with new/malloc or largeAlloc().
//
//   largeAlloc()/largeFree() — for taskData (a plain memcpy'd JSON blob
//     that never touches the crypto engine) and the handshake task stack.
//     These are large (~8KB-24KB) non-crypto buffers that belong in PSRAM
//     to conserve scarce internal SRAM.

const uint8_t SerialProtocol::MAGIC[4] = {'S', 'V', '1', '3'};

// ── Per-type field round-trip helpers ─────────────────────────────────
// Centralize the wire-format handling of every entry field so the
// LIST / GET / ADD / UPDATE handlers can't drift apart. The wire
// format matches the browser extension's window.html schema exactly —
// empty strings for fields not relevant to the entry's type.

// Write all of an entry's fields into a JsonObject (used by LIST and GET).
#define SV_WRITE_ENTRY_TO_JSON(O, E) do {                                   \
  (O)["site"]        = (E).site;                                            \
  (O)["user"]        = (E).user;                                            \
  (O)["pass"]        = (E).pass;                                            \
  (O)["totp"]        = (E).totp;                                            \
  (O)["type"]        = vaultTypeToStr((E).type);                            \
  (O)["fav"]         = (E).favorite ? 1 : 0;                                \
  (O)["del"]         = (E).deleted ? 1 : 0;                                 \
  /* LOGIN extras */                                                        \
  (O)["url"]         = (E).url;                                             \
  (O)["notes"]       = (E).notes;                                           \
  (O)["folder"]      = (E).folder;                                          \
  /* CARD extras */                                                         \
  (O)["cardholder"]  = (E).cardholder;                                      \
  (O)["cardNumber"]  = (E).cardNumber;                                      \
  (O)["exp"]         = (E).exp;                                             \
  (O)["cvv"]         = (E).cvv;                                             \
  /* IDENTITY extras */                                                     \
  (O)["firstName"]   = (E).firstName;                                       \
  (O)["lastName"]    = (E).lastName;                                        \
  (O)["email"]       = (E).email;                                           \
  (O)["phone"]       = (E).phone;                                           \
  (O)["address"]     = (E).address;                                         \
  (O)["city"]        = (E).city;                                            \
  (O)["state"]       = (E).state;                                           \
  (O)["postal"]      = (E).postal;                                          \
  (O)["country"]     = (E).country;                                         \
  (O)["ssn"]         = (E).ssn;                                             \
  (O)["passport"]    = (E).passport;                                        \
  (O)["license"]     = (E).license;                                         \
} while (0)

// Helper to read type from a JSON value — handles both integer (0-3 from
// Electron) and string ("login","card","identity","note") representations.
template<typename T>
static inline uint8_t _svReadType(T& o) {
  JsonVariant tv = o["type"];
  if (tv.is<int>()) {
    int v = tv.as<int>();
    return (v >= 0 && v <= 3) ? (uint8_t)v : 0;
  }
  return vaultStrToType(tv | "login");
}

// Read all of an entry's fields out of a JsonObject (used by ADD and
// UPDATE). Missing fields default to empty strings — same as the
// vault_manager.cpp::_applyJSON path.
#define SV_READ_ENTRY_FROM_JSON(O, E) do {                                  \
  strlcpy((E).site,        (O)["site"]        | "", sizeof((E).site));      \
  strlcpy((E).user,        (O)["user"]        | "", sizeof((E).user));      \
  strlcpy((E).pass,        (O)["pass"]        | "", sizeof((E).pass));      \
  strlcpy((E).totp,        (O)["totp"]        | "", sizeof((E).totp));      \
  (E).type     = _svReadType(O);                                            \
  (E).favorite = (O)["fav"] | 0;                                            \
  (E).deleted  = (O)["del"] | 0;                                            \
  /* LOGIN extras */                                                        \
  strlcpy((E).url,        (O)["url"]         | "", sizeof((E).url));        \
  strlcpy((E).notes,      (O)["notes"]       | "", sizeof((E).notes));      \
  strlcpy((E).folder,     (O)["folder"]      | "", sizeof((E).folder));     \
  /* CARD extras */                                                         \
  strlcpy((E).cardholder, (O)["cardholder"]  | "", sizeof((E).cardholder)); \
  strlcpy((E).cardNumber, (O)["cardNumber"]  | "", sizeof((E).cardNumber)); \
  strlcpy((E).exp,        (O)["exp"]         | "", sizeof((E).exp));        \
  strlcpy((E).cvv,        (O)["cvv"]         | "", sizeof((E).cvv));        \
  /* IDENTITY extras */                                                     \
  strlcpy((E).firstName,  (O)["firstName"]   | "", sizeof((E).firstName));  \
  strlcpy((E).lastName,   (O)["lastName"]    | "", sizeof((E).lastName));   \
  strlcpy((E).email,      (O)["email"]       | "", sizeof((E).email));      \
  strlcpy((E).phone,      (O)["phone"]       | "", sizeof((E).phone));      \
  strlcpy((E).address,    (O)["address"]     | "", sizeof((E).address));    \
  strlcpy((E).city,       (O)["city"]        | "", sizeof((E).city));       \
  strlcpy((E).state,      (O)["state"]       | "", sizeof((E).state));      \
  strlcpy((E).postal,     (O)["postal"]      | "", sizeof((E).postal));     \
  strlcpy((E).country,    (O)["country"]     | "", sizeof((E).country));    \
  strlcpy((E).ssn,        (O)["ssn"]         | "", sizeof((E).ssn));        \
  strlcpy((E).passport,   (O)["passport"]    | "", sizeof((E).passport));   \
  strlcpy((E).license,    (O)["license"]     | "", sizeof((E).license));    \
} while (0)

// ─────────────────────────────────────────────────────────────────────────
//  Lifecycle
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::begin(VaultManager& vault, SessionContext* sessionCtx) {
  _vault = &vault;
  _sessionCtx = sessionCtx;
  // F6: PIN is read from SessionContext when needed, NOT stored locally.
  // The vault key is cached by VaultManager after beginWithPin() is called
  // during loadFromSD, so subsequent saveToSD calls use the cached key.
  // For mutations (add/update/delete), we read the PIN from _sessionCtx->pin()
  // at the time of the operation, ensuring we always get the current state.
  _session.generateCode();
  _rxState = RxState::SCAN_MAGIC;
  _magicPos = 0;
  _lenPos = 0;
  _payloadPos = 0;
  _lastSerialActivity = millis();
  _establishedFlag = false;
  _handshakeTaskRunning = false;
  _processingRequest = false;
}

void SerialProtocol::end() {
  while (_handshakeTaskRunning) { delay(10); }
  _session.teardown();
  _establishedFlag = false;
  _processingRequest = false;
  // F6: No local _pin to zero — SessionContext owns the PIN.
  // Just release the reference. VaultManager::clearCachedKey() is still
  // called to clear the derived key cache.
  _sessionCtx = nullptr;
  if (_vault) _vault->clearCachedKey();
  _vault = nullptr;
}

void SerialProtocol::teardownSecureSession() {
  while (_handshakeTaskRunning) { delay(10); }
  _session.teardown();
  _establishedFlag = false;
  if (_vault) _vault->clearCachedKey();
}

void SerialProtocol::regenerateCode() {
  while (_handshakeTaskRunning) { delay(10); }
  _session.teardown();
  _establishedFlag = false;
  _session.generateCode();
  _rxState = RxState::SCAN_MAGIC;
  _magicPos = 0;
  _lenPos = 0;
  _payloadPos = 0;
  _lastSerialActivity = millis();
}

// ─────────────────────────────────────────────────────────────────────────
//  Main tick — non-blocking serial receiver state machine
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::tick() {
  // Drive the session timeout (5 minutes inactivity)
  _session.tick();

  // CRITICAL: If the handshake task is running, DO NOT touch Serial.
  // The handshake task calls Serial.write() from its FreeRTOS task
  // context to send HELLO_ACK. Concurrent Serial access from tick()
  // corrupts the USB CDC driver state → device disconnects.
  if (_handshakeTaskRunning) {
    return;
  }

  // ── v10.3 RX STATE MACHINE WATCHDOG ─────────────────────────────────
  // If the state machine is stuck in READ_LENGTH or READ_PAYLOAD for more
  // than 5 seconds (meaning a partial frame was received and the rest was
  // lost — e.g., USB CDC RX buffer overflow dropped bytes mid-frame),
  // reset the state machine back to SCAN_MAGIC so the next frame can be
  // received instead of hanging forever waiting for bytes that will never
  // come. This is the safety net for the root-cause fix (larger RX buffer
  // in main.cpp); even with 8KB, a sufficiently corrupted stream could
  // still wedge the state machine without this guard.
  static unsigned long _rxStateEnterMs = 0;
  static RxState _lastRxState = RxState::SCAN_MAGIC;
  if (_rxState != _lastRxState) {
    _rxStateEnterMs = millis();
    _lastRxState = _rxState;
  } else if (_rxState != RxState::SCAN_MAGIC &&
             (millis() - _rxStateEnterMs > 5000)) {
    Serial.printf("[SerialProto] RX watchdog: stuck in state %d for %lu ms, resetting\n",
                  (int)_rxState, (unsigned long)(millis() - _rxStateEnterMs));
    Serial.flush();
    _rxState = RxState::SCAN_MAGIC;
    _magicPos = 0;
    _lenPos = 0;
    _payloadPos = 0;
    _payloadLen = 0;
    _rxStateEnterMs = millis();
    _lastRxState = _rxState;
  }

  // Serial disconnect detection: if no data for 30s while session is
  // established AND we're NOT currently processing a request, tear
  // down the session.
  if (_establishedFlag && !_processingRequest &&
      (millis() - _lastSerialActivity > SERIAL_DISCONNECT_MS)) {
    _session.teardown();
    _establishedFlag = false;
    _session.generateCode();
  }

  // Process all available bytes from Serial
  bool gotData = false;
  while (Serial.available() > 0) {
    gotData = true;
    uint8_t b = Serial.read();

    switch (_rxState) {
      case RxState::SCAN_MAGIC: {
        _magicBuf[_magicPos] = b;
        if (_magicBuf[_magicPos] == MAGIC[_magicPos]) {
          _magicPos++;
          if (_magicPos == 4) {
            _rxState = RxState::READ_LENGTH;
            _lenPos = 0;
          }
        } else {
          if (b == MAGIC[0]) {
            _magicBuf[0] = b;
            _magicPos = 1;
          } else {
            _magicPos = 0;
          }
        }
        break;
      }

      case RxState::READ_LENGTH: {
        _lenBuf[_lenPos++] = b;
        if (_lenPos == 4) {
          _payloadLen = ((uint32_t)_lenBuf[0]) |
                        ((uint32_t)_lenBuf[1] << 8) |
                        ((uint32_t)_lenBuf[2] << 16) |
                        ((uint32_t)_lenBuf[3] << 24);
          if (_payloadLen == 0 || _payloadLen > sizeof(_payloadBuf)) {
            Serial.printf("[SerialProto] RX bad payloadLen=%lu, resetting\n",
                          (unsigned long)_payloadLen);
            Serial.flush();
            _rxState = RxState::SCAN_MAGIC;
            _magicPos = 0;
          } else {
            _rxState = RxState::READ_PAYLOAD;
            _payloadPos = 0;
          }
        }
        break;
      }

      case RxState::READ_PAYLOAD: {
        _payloadBuf[_payloadPos++] = b;
        if ((uint32_t)_payloadPos == _payloadLen) {
          // v10.3: Log every complete frame with first byte + size, so we
          // can see exactly which frames make it through the RX path.
          Serial.printf("[SerialProto] RX payload complete: %lu bytes, firstByte=0x%02X\n",
                        (unsigned long)_payloadLen, _payloadBuf[0]);
          Serial.flush();
          processPayload();
          _rxState = RxState::SCAN_MAGIC;
          _magicPos = 0;
          _lenPos = 0;
          _payloadPos = 0;
        }
        break;
      }
    }
  }
  if (gotData) _lastSerialActivity = millis();
}

// ─────────────────────────────────────────────────────────────────────────
//  Frame dispatch
// ─────────────────────────────────────────────────────────────────────────
struct HandshakeTaskParam {
  SerialProtocol* self;
  uint8_t* data;
  size_t len;
};

void SerialProtocol::handshakeTaskWrapper(void* arg) {
  HandshakeTaskParam* p = (HandshakeTaskParam*)arg;
  SerialProtocol* self = p->self;
  uint8_t* data = p->data;
  size_t len = p->len;

  self->handleHandshake(data, len);

  // Set the volatile flag AFTER handleHandshake completes (which sends
  // the HELLO_ACK response via Serial.write). This ensures the ACK
  // frame is fully sent before the main loop resumes Serial processing.
  self->_establishedFlag = self->_session.isEstablished();

  // v5.3: Do NOT call loadFromSD() here. The vault is already loaded
  // from the UI path (user entered PIN → loadFromSD → key cached).
  // Calling loadFromSD() again in the handshake task does a second
  // PBKDF2 (3-5s), risks stack overflow in the handshake task, and
  // is unnecessary — the key should already be cached.
  if (self->_establishedFlag && self->_vault) {
    Serial.printf("[SerialProtocol] Handshake OK — vault has %d entries, key %s\n",
                  self->_vault->count(),
                  self->_vault->isKeyCached() ? "CACHED (fast saves)" : "NOT cached (saves will be slower)");
  }

  largeFree(data);
  delete p;

  self->_handshakeTaskRunning = false;

  vTaskDelay(pdMS_TO_TICKS(50));
  vTaskDelete(nullptr);
}

// NOTE: v5.4 removed SerialProtocol::saveTaskWrapper + SaveTaskParam.
// ADD/UPDATE/DELETE now run inline inside handleSecureRequest() on the
// serial-protocol task (same path as LIST/GET/LOCK). The background
// save task was the root cause of the "ADD disconnects" bug — see the
// comment block above the write-op branch in handleSecureRequest().

void SerialProtocol::processPayload() {
  if (_payloadLen == 0 || !_vault) return;

  if (_payloadBuf[0] == '{') {
    // JSON handshake
    if (_handshakeTaskRunning) {
      secureZero(_payloadBuf, _payloadLen);
      return;
    }

    uint8_t* taskData = (uint8_t*)largeAlloc(_payloadLen);
    if (!taskData) {
      secureZero(_payloadBuf, _payloadLen);
      sendJson("{\"ok\":false,\"error\":\"device low on memory — try again after reboot\"}");
      return;
    }
    memcpy(taskData, _payloadBuf, _payloadLen);
    secureZero(_payloadBuf, _payloadLen);

    HandshakeTaskParam* param = new HandshakeTaskParam{this, taskData, (size_t)_payloadLen};
    _handshakeTaskRunning = true;

    // v5.5: The handshake task's stack was the real remaining hog — 24576
    // bytes, and xTaskCreate() always places a dynamic task's stack on
    // internal SRAM (never PSRAM), regardless of MALLOC_CAP hints elsewhere.
    // sdkconfig already sets CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y,
    // which is exactly for this: xTaskCreateStatic() can be given a stack
    // buffer that lives in PSRAM. We allocate that buffer once (lazily) and
    // reuse it every handshake — _handshakeTaskRunning above already
    // guarantees these never overlap, so one persistent buffer is safe and
    // avoids alloc/free churn on every connect. The StaticTask_t control
    // block stays a plain static (compiler-placed in .bss, not the runtime
    // heap at all, so it doesn't compete with anything measured here).
    static StackType_t* s_handshakeStack = nullptr;
    static StaticTask_t s_handshakeTCB;
    if (!s_handshakeStack) {
      s_handshakeStack = (StackType_t*)largeAlloc(24576);
    }
    if (!s_handshakeStack) {
      largeFree(taskData);
      delete param;
      _handshakeTaskRunning = false;
      sendJson("{\"ok\":false,\"error\":\"device low on memory — try again after reboot\"}");
      return;
    }

    // With the stack (and plaintext/taskData/respFrame) off internal SRAM,
    // the actual remaining internal need per handshake is just the small
    // mbedtls ECDH contexts + JsonDocument parse — a few KB, not ~33KB.
    // 15000 keeps a wide safety margin over that while no longer rejecting
    // this board's normal idle baseline (~34.7KB, per [HeapMon]).
    uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < 15000) {
      Serial.printf("[SerialProtocol] Handshake REFUSED: low heap (%lu bytes)\n", freeHeap);
      largeFree(taskData);
      delete param;
      _handshakeTaskRunning = false;
      sendJson("{\"ok\":false,\"error\":\"device low on memory — try again after reboot\"}");
      return;
    }

    TaskHandle_t handle = xTaskCreateStatic(
      handshakeTaskWrapper,
      "sv_handshake",
      24576,  // 24KB stack — ECDH + base64 + JSON — now backed by PSRAM
      param,
      5,
      s_handshakeStack,
      &s_handshakeTCB
    );

    if (handle == nullptr) {
      largeFree(taskData);
      delete param;
      _handshakeTaskRunning = false;
      sendJson("{\"ok\":false,\"error\":\"internal: task creation failed\"}");
    }
  } else if (_payloadBuf[0] == 0x01) {
    // AES-GCM encrypted frame — process inline.
    // v5.4: ALL operations (read + write) run inline now — the old
    // background save task has been removed (see the comment block in
    // handleSecureRequest() for the root-cause explanation).
    _processingRequest = true;
    handleSecureRequest(_payloadBuf, _payloadLen);
    _processingRequest = false;
    secureZero(_payloadBuf, _payloadLen);
  } else {
    secureZero(_payloadBuf, _payloadLen);
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  Handshake handler (Layer 2: ECDH)
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::handleHandshake(const uint8_t* data, size_t len) {
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, data, len);
  if (err) {
    sendJson("{\"ok\":false,\"error\":\"bad JSON\"}");
    return;
  }

  String pubkeyB64 = doc["pubkey"] | "";
  String codeProofB64 = doc["codeProof"] | "";
  if (pubkeyB64.length() == 0 || codeProofB64.length() == 0) {
    sendJson("{\"ok\":false,\"error\":\"missing pubkey or codeProof\"}");
    return;
  }

  uint8_t clientPubkey[SEC_ECDH_PUBKEY_LEN];
  size_t clientPubkeyLen = 0;
  if (mbedtls_base64_decode(clientPubkey, sizeof(clientPubkey), &clientPubkeyLen,
                             (const unsigned char*)pubkeyB64.c_str(), pubkeyB64.length()) != 0 ||
      clientPubkeyLen != SEC_ECDH_PUBKEY_LEN) {
    sendJson("{\"ok\":false,\"error\":\"bad pubkey length\"}");
    return;
  }

  uint8_t codeProof[32];
  size_t codeProofLen = 0;
  if (mbedtls_base64_decode(codeProof, sizeof(codeProof), &codeProofLen,
                             (const unsigned char*)codeProofB64.c_str(), codeProofB64.length()) != 0 ||
      codeProofLen != 32) {
    sendJson("{\"ok\":false,\"error\":\"bad codeProof length\"}");
    return;
  }

  uint8_t devicePubkey[SEC_ECDH_PUBKEY_LEN];
  bool ok = _session.handleHello(clientPubkey, clientPubkeyLen,
                                  codeProof, 32,
                                  devicePubkey, sizeof(devicePubkey));

  if (ok) {
    unsigned char devicePubkeyB64[128];
    size_t b64Len = 0;
    mbedtls_base64_encode(devicePubkeyB64, sizeof(devicePubkeyB64), &b64Len,
                          devicePubkey, SEC_ECDH_PUBKEY_LEN);
    String resp = "{\"ok\":true,\"pubkey\":\"";
    resp += String((const char*)devicePubkeyB64).substring(0, b64Len);
    resp += "\"}";
    sendJson(resp.c_str());
  } else {
    sendJson("{\"ok\":false,\"error\":\"code proof mismatch or ECDH failed\"}");
  }

  secureZero(clientPubkey, sizeof(clientPubkey));
  secureZero(codeProof, sizeof(codeProof));
  secureZero(devicePubkey, sizeof(devicePubkey));
}

// ─────────────────────────────────────────────────────────────────────────
//  Secure request handler (Layer 3: AES-256-GCM decrypt → dispatch → encrypt)
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::handleSecureRequest(const uint8_t* frame, size_t frameLen) {
  uint8_t msgType = 0;
  uint8_t* plaintext = (uint8_t*)cryptoAlloc(SEC_MAX_PAYLOAD);
  size_t plaintextLen = 0;

  if (!plaintext) {
    sendJson("{\"ok\":false,\"error\":\"out of memory\"}");
    return;
  }

  if (!_session.decryptFrame(frame, frameLen, &msgType, plaintext, &plaintextLen)) {
    sendJson("{\"ok\":false,\"error\":\"decrypt failed\"}");
    cryptoFree(plaintext);
    return;
  }

  // PING — lightweight keepalive
  if (msgType == 0x20) {
    sendEncryptedResponse(0x21, "{\"ok\":true}");
    secureZero(plaintext, SEC_MAX_PAYLOAD);
    cryptoFree(plaintext);
    return;
  }

  // ── READ operations: process inline (fast, <50ms) ───────────────
  if (msgType == 0x10 || msgType == 0x12 || msgType == 0x18) {
    handleReadRequest(msgType, plaintext, plaintextLen);
    secureZero(plaintext, SEC_MAX_PAYLOAD);
    cryptoFree(plaintext);
    return;
  }

  // ── WRITE operations (ADD/UPDATE/DELETE): run INLINE ─────────────
  // v5.4 ROOT-CAUSE FIX for "ADD disconnects the device".
  //
  // History: v5.0–v5.3 ran these in a background FreeRTOS task (sv_save)
  // under the theory that it would keep the main loop responsive. In
  // practice it was the SOURCE of the disconnect, for two reasons:
  //
  //   1) UNSYNCHRONIZED CONCURRENCY. The save task's _toJSON() reads the
  //      vault's PSRAM arrays + mutates ArduinoJson/String on the shared
  //      heap, while the main loop (ui.tick() → vault.entryAt() →
  //      _buildViews(), and ble.update() → vault.entryAt()) reads+writes
  //      those SAME arrays with no mutex. ESP-IDF's malloc/realloc/free
  //      are NOT thread-safe across FreeRTOS tasks. Concurrent access
  //      corrupts either the heap metadata or the vault arrays → the
  //      USB CDC (HWCDC) driver, which also uses the heap, gets fed a
  //      garbage pointer and tears down the port. The OS then reports
  //      the COM device as gone, Electron's serialport fires 'close',
  //      and the user sees "disconnected" (5–30s after Save, no reboot,
  //      no panic). Five prior rounds of fixes (TWDT, priority 3→1,
  //      stack 24→28KB, ripping Serial.printf out of the task, etc.)
  //      treated symptoms of this corruption and could not fix it.
  //
  //   2) LIVENESS HOLE. If the task ever faulted or wedged, _saveTaskDone
  //      was never set, so tick() returned early FOREVER (line ~175) and
  //      the device silently stopped responding to Serial — a permanent
  //      hang that looked identical to #1.
  //
  // Fix: execute write ops INLINE on the serial-protocol task, exactly
  // like LIST/GET/LOCK already do (and those have always worked). This
  // eliminates the concurrency entirely. There is no cost:
  //   - The vault key is cached after loadFromSD(), so PBKDF2 is NOT
  //     re-run on save (the v5.3 key-caching fix already handles this).
  //   - _toJSON() and saveToSD() already yield (vTaskDelay) every 16
  //     entries and around each crypto/SD stage, so the IDLE task and
  //     the Task Watchdog are fed during the save.
  //   - The Electron client already blocks up to 90s on writes
  //     (secureChannel.js: secureRequest, isWriteOp path) and suppresses
  //     keepalive while a request is in flight (inFlight guard), so the
  //     ~1–3s the inline save takes is well within tolerance.
  if (msgType == 0x14 || msgType == 0x15 || msgType == 0x16) {
    // F6: PIN check — read from SessionContext, never from local copy.
    // The vault key cache + saveToSD both need the PIN.
    if (!_sessionCtx || !_sessionCtx->isSet()) {
      sendJson("{\"ok\":false,\"error\":\"no PIN available\"}");
      secureZero(plaintext, SEC_MAX_PAYLOAD);
      cryptoFree(plaintext);
      return;
    }

    // Parse the request inline (same logic the old task wrapper used).
    VaultEntryRW entry;
    memset(&entry, 0, sizeof(entry));
    int index = -1;
    bool paramOk = false;

    if (msgType == 0x14) {  // ADD
      JsonDocument doc;
      if (deserializeJson(doc, plaintext, plaintextLen) == DeserializationError::Ok) {
        SV_READ_ENTRY_FROM_JSON(doc, entry);
        if (strlen(entry.site) > 0) paramOk = true;
      }
    } else if (msgType == 0x15) {  // UPDATE
      JsonDocument doc;
      if (deserializeJson(doc, plaintext, plaintextLen) == DeserializationError::Ok) {
        index = doc["index"] | -1;
        JsonObject entryObj = doc["entry"].as<JsonObject>();
        if (index >= 0 && index < _vault->count() && !entryObj.isNull()) {
          SV_READ_ENTRY_FROM_JSON(entryObj, entry);
          paramOk = true;
        }
      }
    } else if (msgType == 0x16) {  // DELETE
      JsonDocument doc;
      if (deserializeJson(doc, plaintext, plaintextLen) == DeserializationError::Ok) {
        index = doc["index"] | -1;
        if (index >= 0 && index < _vault->count()) paramOk = true;
      }
    }

    // Free the plaintext buffer now that we've parsed it — saves heap
    // for _toJSON()'s ArduinoJson arena + String allocation.
    secureZero(plaintext, SEC_MAX_PAYLOAD);
    cryptoFree(plaintext);
    plaintext = nullptr;

    if (!paramOk) {
      sendEncryptedResponse(0xFF, "{\"ok\":false,\"error\":\"bad request data\"}");
      secureZero(&entry, sizeof(entry));
      return;
    }

    // Heap guard — _toJSON + AES-GCM need a contiguous heap chunk. If
    // the device is badly fragmented (long session, many entries), refuse
    // gracefully instead of letting malloc return null deep in saveToSD.
    uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < 30000) {
      Serial.printf("[SerialProtocol] Save REFUSED: low heap (%lu bytes)\n", freeHeap);
      char errBuf[96];
      snprintf(errBuf, sizeof(errBuf),
               "{\"ok\":false,\"error\":\"device low on memory (%lu bytes free) — reboot and try again\"}",
               (unsigned long)freeHeap);
      sendEncryptedResponse(0xFF, errBuf);
      secureZero(&entry, sizeof(entry));
      return;
    }

    // ── Run the mutation + save INLINE (no background task) ──────────
    // Single-threaded with ui.tick()/ble.update() → no heap/vault race.
    bool ok = false;
    unsigned long saveStart = millis();
    // F6: Read PIN from SessionContext for vault mutations.
    const char* pin = _sessionCtx->pin();
    if (msgType == 0x14) {
      ok = _vault->addEntry(entry, pin);
    } else if (msgType == 0x15) {
      ok = _vault->updateEntry(index, entry, pin);
    } else if (msgType == 0x16) {
      ok = _vault->deleteEntry(index, pin);
    }
    // Bounded safety net: a single save should take <5s with a cached key.
    // If it ever exceeds 30s, something is wrong with the SD card — log it
    // so it shows up next to the disconnect in the serial monitor. The save
    // has already completed either way (ok reflects the actual result).
    unsigned long saveMs = millis() - saveStart;
    if (saveMs > 30000) {
      Serial.printf("[SerialProtocol] WARNING: save took %lums (msgType=0x%02X) — SD card may be slow/failing\n",
                    (unsigned long)saveMs, msgType);
    }

    secureZero(&entry, sizeof(entry));

    // Send the encrypted SAVE_OK (0x17) back to Electron.
    JsonDocument rdoc;
    rdoc["ok"] = ok;
    const char* saveErr = _vault->lastSaveError();
    if (!ok && saveErr && saveErr[0] != '\0') {
      rdoc["error"] = saveErr;
    } else if (!ok) {
      rdoc["error"] = "save failed";
    }
    String out;
    serializeJson(rdoc, out);
    sendEncryptedResponseRaw(0x17, out.c_str(), out.length());
    return;
  }

  // Unknown message type
  secureZero(plaintext, SEC_MAX_PAYLOAD);
  cryptoFree(plaintext);
  sendJson("{\"ok\":false,\"error\":\"unknown message type\"}");
}

// ─────────────────────────────────────────────────────────────────────────
//  Handle read operations inline (LIST, GET, LOCK) — these are fast
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::handleReadRequest(uint8_t msgType, uint8_t* plaintext, size_t plaintextLen) {
  switch (msgType) {
    case 0x10: {  // LIST
      JsonDocument doc;
      doc["ok"] = true;  // v-fix: LIST never set this — Electron and any
                         // strict client treat a missing "ok" key as failure
                         // (secureChannel.js: `if (data.ok === undefined) data.ok = false`),
                         // so a perfectly valid LIST was always reported as failed.
      JsonArray entries = doc["entries"].to<JsonArray>();
      int n = _vault->count();
      for (int i = 0; i < n; i++) {
        VaultEntry e = _vault->entryAt(i);
        JsonObject o = entries.add<JsonObject>();
        o["index"] = i;
        o["site"]     = e.site;
        o["user"]     = e.user;
        o["totp_set"] = strlen(e.totp) > 0;
        o["type"]     = vaultTypeToStr(e.type);
        o["fav"]      = e.favorite ? 1 : 0;
        o["del"]      = e.deleted ? 1 : 0;
        if (e.cardholder[0])  o["cardholder"] = e.cardholder;
        if (e.email[0])       o["email"]      = e.email;
        if (e.firstName[0])   o["firstName"]  = e.firstName;
        if (e.lastName[0])    o["lastName"]   = e.lastName;
        if (e.notes[0]) {
          char notePreview[61];
          strncpy(notePreview, e.notes, 60);
          notePreview[60] = 0;
          o["notes"] = notePreview;
        }
      }
      String out;
      serializeJson(doc, out);
      size_t respLen = out.length();
      if (respLen > SEC_MAX_PAYLOAD) {
        sendEncryptedResponse(0xFF, "vault too large");
        return;
      }
      sendEncryptedResponseRaw(0x11, out.c_str(), respLen);
      return;
    }

    case 0x12: {  // GET
      JsonDocument doc;
      if (deserializeJson(doc, plaintext, plaintextLen) != DeserializationError::Ok) {
        sendEncryptedResponse(0xFF, "bad JSON");
        return;
      }
      int idx = doc["index"] | -1;
      if (idx < 0 || idx >= _vault->count()) {
        sendEncryptedResponse(0xFF, "index out of range");
        return;
      }
      VaultEntry e = _vault->entryAt(idx);
      JsonDocument rdoc;
      JsonObject rootObj = rdoc.to<JsonObject>();
      rootObj["ok"] = true;  // v-fix: same missing-"ok" bug as LIST above
      SV_WRITE_ENTRY_TO_JSON(rootObj, e);
      String out;
      serializeJson(rdoc, out);
      sendEncryptedResponseRaw(0x13, out.c_str(), out.length());
      return;
    }

    case 0x18: {  // LOCK
      // v5.5 FIX: Send the LOCKED (0x19) response as a proper encrypted
      // frame BEFORE tearing down the session. The previous order
      // (teardown → sendJson) caused sendEncryptedResponseRaw() to bail
      // out (because _session.isEstablished() was already false) and
      // fall through to sendJson(), which writes raw plaintext
      // "{\"ok\":true}" — the client reads '{' (0x7B = 123) as the
      // frame version byte and reports "bad frame version 123".
      sendEncryptedResponseRaw(0x19, "{\"ok\":true}", 12);
      // Give the USB CDC FIFO time to drain the encrypted frame before
      // we drop the session state. Without this, the host can see the
      // teardown before the response arrives and treat the link as dead.
      Serial.flush();
      delay(5);
      _session.teardown();
      _establishedFlag = false;
      if (_vault) _vault->clearCachedKey();
      // v10.4: Auto-regenerate a fresh 6-digit code immediately after
      // the client disconnects. The user should NOT have to manually
      // press "NEW CODE" after every normal disconnect — that button
      // is reserved for unseen scenarios (suspected shoulder-surfing,
      // code left on screen too long, etc.). The UI's
      // updateDashboardCodeScreen() detects the established→idle
      // transition and syncs the displayed code from _session.code().
      _session.generateCode();
      return;
    }

    default:
      sendEncryptedResponse(0xFF, "unknown read op");
      return;
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  Send save response (called from tick() when save task completes)
// ─────────────────────────────────────────────────────────────────────────
// NOTE: v5.4 removed sendSaveResponse(). The inline write path sends the
// SAVE_OK (0x17) response directly from handleSecureRequest(), so this
// function is no longer called.

// ─────────────────────────────────────────────────────────────────────────
//  Response helpers
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::sendEncryptedResponse(uint8_t respMsgType, const char* jsonStr) {
  sendEncryptedResponseRaw(respMsgType, jsonStr, strlen(jsonStr));
}

void SerialProtocol::sendEncryptedResponseRaw(uint8_t respMsgType, const char* data, size_t len) {
  if (!_session.isEstablished()) {
    sendJson("{\"ok\":false,\"error\":\"session expired\"}");
    return;
  }

  uint8_t* respFrame = (uint8_t*)cryptoAlloc(SEC_MAX_FRAME);
  if (!respFrame) {
    sendJson("{\"ok\":false,\"error\":\"out of memory\"}");
    return;
  }

  size_t respFrameLen = 0;
  if (_session.encryptFrame(respMsgType, (const uint8_t*)data, len, respFrame, &respFrameLen)) {
    sendFrame(respFrame, respFrameLen);
  } else {
    sendJson("{\"ok\":false,\"error\":\"encrypt failed\"}");
  }
  secureZero(respFrame, SEC_MAX_FRAME);
  cryptoFree(respFrame);
}

// ─────────────────────────────────────────────────────────────────────────
//  Frame sending
// ─────────────────────────────────────────────────────────────────────────
void SerialProtocol::sendFrame(const uint8_t* data, size_t len) {
  Serial.write(MAGIC, 4);
  uint8_t lenBytes[4] = {
    (uint8_t)(len & 0xFF),
    (uint8_t)((len >> 8) & 0xFF),
    (uint8_t)((len >> 16) & 0xFF),
    (uint8_t)((len >> 24) & 0xFF),
  };
  Serial.write(lenBytes, 4);
  Serial.write(data, len);
  Serial.flush();
}

void SerialProtocol::sendJson(const char* json) {
  sendFrame((const uint8_t*)json, strlen(json));
}
