// ═══════════════════════════════════════════════════════════════════════════════
//  web_auth_manager.cpp — Layer 1: Web Authentication & CSRF
// ═══════════════════════════════════════════════════════════════════════════════
#include "web_auth_manager.h"
#include <cstring>

WebAuthManager& WebAuthManager::getInstance() {
  static WebAuthManager instance;
  // F8: auto-initialize with warning if getInstance() called before begin()
  if (!instance._initialized) {
    Serial.println("[F8-WARN] WebAuthManager::getInstance() called before begin() — auto-initializing");
    instance.begin();
  }
  return instance;
}

bool WebAuthManager::begin() {
  if (_initialized) return true;  // idempotent
  if (!_mutex) {
    _mutex = xSemaphoreCreateMutex();
    if (!_mutex) return false;
  }
  // Clear any stale sessions from a previous AP run.
  if (xSemaphoreTake(_mutex, pdMS_TO_TICKS(100))) {
    for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
      _clearSession(_sessions[i]);
    }
    xSemaphoreGive(_mutex);
  }
  // Don't generate the code here — APModeManager calls generateCode()
  // explicitly so the code is fresh at the moment the user enters AP mode.
  _initialized = true;
  Serial.println("[F8] WebAuthManager::begin() — initialized");
  return true;
}

void WebAuthManager::end() {
  if (_mutex && xSemaphoreTake(_mutex, pdMS_TO_TICKS(100))) {
    for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
      _clearSession(_sessions[i]);
    }
    xSemaphoreGive(_mutex);
  }
  // Zero the code + proof.
  secureZero(_code, sizeof(_code));
  secureZero(_codeProofHex, sizeof(_codeProofHex));
  _codeSet = false;
}

void WebAuthManager::generateCode() {
  // esp_random() returns a uint32_t. Modulo 1,000,000 gives 0..999999.
  // Format as a zero-padded 6-digit string.
  uint32_t n = esp_random() % 1000000UL;
  snprintf(_code, sizeof(_code), "%06lu", (unsigned long)n);

  // Precompute the SHA-256 proof (hex) — clients send this instead of
  // the raw code so the code itself never crosses the wire, even during
  // the login request. Matches the existing serial-side SecureSession
  // pattern (see secure_session.h "code proof" comment).
  uint8_t proof[32];
  sha256((const uint8_t*)_code, 6, proof);
  hexEncode(proof, 32, _codeProofHex);
  _codeSet = true;
}

bool WebAuthManager::verifyCodeProof(const char* clientProofHex) const {
  if (!_codeSet || !clientProofHex) return false;
  if (strlen(clientProofHex) != WAUTH_CODE_PROOF_HEX_LEN) return false;
  // Constant-time compare — a naive strcmp would leak prefix length.
  return constantTimeEquals((const uint8_t*)clientProofHex,
                            (const uint8_t*)_codeProofHex,
                            WAUTH_CODE_PROOF_HEX_LEN);
}

bool WebAuthManager::login(char sessionIdOut[WAUTH_SESSION_ID_BUF_LEN],
                            char csrfTokenOut[WAUTH_CSRF_TOKEN_BUF_LEN]) {
  if (!_mutex) return false;
  if (!xSemaphoreTake(_mutex, pdMS_TO_TICKS(200))) return false;

  Session* slot = _findFreeSlot();
  if (!slot) {
    _evictLRU();
    slot = _findFreeSlot();
  }
  if (!slot) {
    xSemaphoreGive(_mutex);
    return false;
  }

  // 16-byte session ID, 32-byte CSRF token, both from secureRandom().
  uint8_t sidBin[16];
  uint8_t csrfBin[32];
  secureRandom(sidBin, sizeof(sidBin));
  secureRandom(csrfBin, sizeof(csrfBin));
  hexEncode(sidBin, sizeof(sidBin), sessionIdOut);
  hexEncode(csrfBin, sizeof(csrfBin), csrfTokenOut);

  // Copy into the slot.
  strncpy(slot->sessionId, sessionIdOut, WAUTH_SESSION_ID_HEX_LEN);
  slot->sessionId[WAUTH_SESSION_ID_HEX_LEN] = '\0';
  strncpy(slot->csrfToken, csrfTokenOut, WAUTH_CSRF_TOKEN_HEX_LEN);
  slot->csrfToken[WAUTH_CSRF_TOKEN_HEX_LEN] = '\0';
  slot->active = true;
  slot->lastActivity = millis();

  // Zero the local buffers — they held the raw random bytes.
  secureZero(sidBin, sizeof(sidBin));
  secureZero(csrfBin, sizeof(csrfBin));

  xSemaphoreGive(_mutex);
  return true;
}

bool WebAuthManager::extractSessionIdFromCookie(AsyncWebServerRequest* request,
                                                 char out[WAUTH_SESSION_ID_BUF_LEN]) {
  if (!request) return false;
  // AsyncWebServer returns "" (empty) if the header is absent.
  String cookie = request->header("Cookie");
  if (cookie.length() == 0) return false;

  // Look for "SecureVault=session=<32 hex chars>".
  // The "session=" prefix is intentional — it namespaces the session ID
  // within the cookie, allowing future additional cookie-scoped vars
  // (e.g. "theme=dark") without parsing ambiguity.
  const char* prefix = WAUTH_COOKIE_NAME "=session=";
  int prefixLen = strlen(prefix);
  int idx = cookie.indexOf(prefix);
  if (idx < 0) return false;
  int start = idx + prefixLen;
  int end = cookie.indexOf(';', start);
  if (end < 0) end = cookie.length();
  int sidLen = end - start;
  if (sidLen != WAUTH_SESSION_ID_HEX_LEN) return false;
  // Sanity-check: all hex.
  for (int i = 0; i < sidLen; i++) {
    char c = cookie[start + i];
    bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!isHex) return false;
  }
  cookie.substring(start, end).toCharArray(out, WAUTH_SESSION_ID_BUF_LEN);
  out[WAUTH_SESSION_ID_HEX_LEN] = '\0';
  return true;
}

WebAuthManager::Session* WebAuthManager::_findSessionByCookie(AsyncWebServerRequest* request) {
  char sid[WAUTH_SESSION_ID_BUF_LEN];
  if (!extractSessionIdFromCookie(request, sid)) return nullptr;
  return _findSessionById(sid);
}

WebAuthManager::Session* WebAuthManager::_findSessionById(const char* sessionId) {
  for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
    if (_sessions[i].active &&
        constantTimeEquals((const uint8_t*)_sessions[i].sessionId,
                           (const uint8_t*)sessionId,
                           WAUTH_SESSION_ID_HEX_LEN)) {
      return &_sessions[i];
    }
  }
  return nullptr;
}

WebAuthManager::Session* WebAuthManager::_findFreeSlot() {
  for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
    if (!_sessions[i].active) return &_sessions[i];
  }
  return nullptr;
}

void WebAuthManager::_evictLRU() {
  // Find the session with the oldest lastActivity and clear it.
  int oldestIdx = -1;
  unsigned long oldestTime = (unsigned long)-1;
  for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
    if (_sessions[i].active && _sessions[i].lastActivity < oldestTime) {
      oldestTime = _sessions[i].lastActivity;
      oldestIdx = i;
    }
  }
  if (oldestIdx >= 0) {
    _clearSession(_sessions[oldestIdx]);
  }
}

void WebAuthManager::_clearSession(Session& s) {
  secureZero(s.sessionId, sizeof(s.sessionId));
  secureZero(s.csrfToken, sizeof(s.csrfToken));
  s.active = false;
  s.lastActivity = 0;
}

bool WebAuthManager::isAuthenticated(AsyncWebServerRequest* request) {
  if (!_mutex || !request) return false;
  if (!xSemaphoreTake(_mutex, pdMS_TO_TICKS(100))) return false;

  Session* s = _findSessionByCookie(request);
  bool ok = false;
  if (s) {
    // TTL check.
    if (millis() - s->lastActivity < WAUTH_SESSION_TTL_MS) {
      s->lastActivity = millis();
      ok = true;
    } else {
      // Expired — clear it.
      _clearSession(*s);
    }
  }
  xSemaphoreGive(_mutex);
  return ok;
}

bool WebAuthManager::verifyCsrfToken(AsyncWebServerRequest* request) {
  if (!_mutex || !request) return false;
  // Note: AsyncWebServer does case-insensitive header lookup.
  String token = request->header("X-CSRF-Token");
  if (token.length() != WAUTH_CSRF_TOKEN_HEX_LEN) return false;

  if (!xSemaphoreTake(_mutex, pdMS_TO_TICKS(100))) return false;
  Session* s = _findSessionByCookie(request);
  bool ok = false;
  if (s) {
    ok = constantTimeEquals((const uint8_t*)token.c_str(),
                            (const uint8_t*)s->csrfToken,
                            WAUTH_CSRF_TOKEN_HEX_LEN);
  }
  xSemaphoreGive(_mutex);
  return ok;
}

void WebAuthManager::buildCookieHeader(const char* sessionId, char* out, size_t outCap) const {
  // Format: "SecureVault=session=<id>; HttpOnly; SameSite=Strict; Max-Age=300; Path=/"
  // No `Secure` flag — we're serving HTTP, not HTTPS, because the AP
  // has no certificate. The SecureLayer (Layer 2) provides the
  // end-to-end encryption that HTTPS would otherwise provide.
  snprintf(out, outCap,
           "%s=session=%s; HttpOnly; SameSite=Strict; Max-Age=%lu; Path=/",
           WAUTH_COOKIE_NAME, sessionId,
           (unsigned long)(WAUTH_SESSION_TTL_MS / 1000UL));
}

void WebAuthManager::logout(AsyncWebServerRequest* request) {
  if (!_mutex || !request) return;
  if (!xSemaphoreTake(_mutex, pdMS_TO_TICKS(100))) return;
  Session* s = _findSessionByCookie(request);
  if (s) _clearSession(*s);
  xSemaphoreGive(_mutex);
}

void WebAuthManager::tick() {
  if (!_mutex) return;
  if (!xSemaphoreTake(_mutex, pdMS_TO_TICKS(50))) return;
  unsigned long now = millis();
  for (int i = 0; i < WAUTH_MAX_SESSIONS; i++) {
    if (_sessions[i].active && (now - _sessions[i].lastActivity >= WAUTH_SESSION_TTL_MS)) {
      _clearSession(_sessions[i]);
    }
  }
  xSemaphoreGive(_mutex);
}
