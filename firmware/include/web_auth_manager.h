#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  web_auth_manager.h — Layer 1: Web Authentication & CSRF
// ═══════════════════════════════════════════════════════════════════════════════
//  Maps to SecureGen's WebAuth layer (security_model.md L3). Provides:
//
//    - Per-session 16-byte session ID (32 hex chars) + 32-byte CSRF token
//      (64 hex chars), both cryptographically random via secureRandom().
//    - In-RAM session map keyed by session ID, mutex-protected (fixes
//      the race condition documented in study_securegen_layers.md
//      caveat #1 — SecureGen omitted the mutex because AsyncWebServer
//      serializes callbacks on a single event loop, but adding a mutex
//      costs ~10 bytes/RAM-session and eliminates the latent bug).
//    - Session TTL: 5 minutes (matches SEC_SESSION_TIMEOUT_MS on the
//      serial side — consistent timeout across both network modes).
//    - Cookie helper: emits `SecureVault=session=<id>; HttpOnly;
//      SameSite=Strict; Max-Age=300` — HttpOnly blocks JS-side cookie
//      theft, SameSite=Strict blocks CSRF via cross-site navigation
//      (defense in depth on top of the explicit CSRF token).
//    - isAuthenticated(request): reads the Cookie header, extracts the
//      session= value, looks it up in the map, checks TTL. Used as the
//      first gate inside every protected handler.
//    - verifyCsrfToken(request): reads the X-CSRF-Token header,
//      constant-time-compares it to the session's stored CSRF token.
//      Required on every state-changing (POST/PUT/DELETE) endpoint.
//
//  Auth model in AP mode (locked-in by user clarification):
//    Layer 1 (network): WPA2 password — per-session random 8 chars,
//                       shown on the TFT. Gates who can even reach
//                       the HTTP server.
//    Layer 2 (out-of-band): 6-digit code — per-session random,
//                            shown on the TFT. Gates the ECDH
//                            handshake (acts as a PSK mixed into
//                            the KDF). Same pattern as the existing
//                            serial Dashboard Mode.
//    Layer 3 (this layer): WebAuth/CSRF — gates all post-handshake
//                           HTTP requests via session cookie + CSRF
//                           header.
//
//  Session lifecycle:
//    1. User joins the AP (WPA2 password from TFT).
//    2. Browser loads the captive portal page (HTTP GET /).
//    3. User enters the 6-digit code in the webapp.
//    4. Webapp POSTs /api/login with the code proof (SHA-256 of code).
//    5. WebAuthManager::login(codeProof) verifies the proof, mints a
//       new session (session ID + CSRF token), returns them to the
//       webapp. Session ID goes in a cookie; CSRF token goes in a
//       response header that the webapp stores in localStorage and
//       sends as X-CSRF-Token on subsequent requests.
//    6. The webapp immediately calls /api/secure/hello to do the ECDH
//       handshake (handled by SecureLayerManager — Layer 2). All
//       subsequent vault CRUD requests are ECDH-encrypted AND carry
//       the session cookie + CSRF header.
//    7. After 5 min of inactivity, the session expires. The webapp
//       shows the login screen again, asking for a fresh 6-digit code
//       (which is regenerated on the device whenever the AP session
//       is restarted OR explicitly via a "regenerate code" button).
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <freertos/semphr.h>
#include <ESPAsyncWebServer.h>
#include "web_crypto_utils.h"

// Session ID: 16 bytes = 32 hex chars + null = 33 bytes
#define WAUTH_SESSION_ID_HEX_LEN  32
#define WAUTH_SESSION_ID_BUF_LEN  (WAUTH_SESSION_ID_HEX_LEN + 1)
// CSRF token: 32 bytes = 64 hex chars + null = 65 bytes
#define WAUTH_CSRF_TOKEN_HEX_LEN  64
#define WAUTH_CSRF_TOKEN_BUF_LEN  (WAUTH_CSRF_TOKEN_HEX_LEN + 1)

// 6-digit code proof: SHA-256 of the 6-digit ASCII code = 32 bytes =
// 64 hex chars + null = 65 bytes
#define WAUTH_CODE_PROOF_HEX_LEN  64
#define WAUTH_CODE_PROOF_BUF_LEN  (WAUTH_CODE_PROOF_HEX_LEN + 1)

// Maximum simultaneous web sessions. AP mode is single-user (one phone
// at a time, enforced by softAP max_clients=1), so 4 is generous —
// allows for browser reconnects, accidental tab opens, etc. without
// thrashing. LRU-evicted when full.
#define WAUTH_MAX_SESSIONS 4

// Session TTL — 5 minutes of inactivity. Matches SEC_SESSION_TIMEOUT_MS
// on the serial side. Activity is tracked via touch(sessionId) called
// from isAuthenticated() on every successful auth check.
#define WAUTH_SESSION_TTL_MS 300000UL

// Cookie name. Short to keep the Cookie header small.
#define WAUTH_COOKIE_NAME "SecureVault"

class WebAuthManager {
public:
  static WebAuthManager& getInstance();

  // ── Initialization ────────────────────────────────────────────────
  // Seeds the in-RAM state. Must be called once before any other method.
  // Idempotent — safe to call again on AP restart.
  // F8: Sets _initialized = true. If getInstance() is called before
  // begin(), auto-initializes with warning.
  bool begin();

  // F8: Check whether begin() has been called.
  bool isInitialized() const { return _initialized; }

  // Tears down all sessions, zeroes the 6-digit code + proof. Called
  // when AP mode stops, so the next AP session starts with a fresh code.
  void end();

  // ── 6-digit code management (the out-of-band PSK) ─────────────────
  // Generates a fresh 6-digit code via secureRandom(). Called once at
  // AP start. The code is stored in RAM only — never persisted, never
  // logged. The proof (SHA-256 of the code) is computed once and
  // reused for all login attempts during this AP session.
  void generateCode();

  // Returns the current 6-digit code (null-terminated) or "" if no
  // session is active. Used by ui_screens.cpp to draw the code on
  // the TFT.
  const char* code() const { return _code; }

  // Constant-time comparison of a client-supplied proof against the
  // current session's proof. Returns true on match. Used by the
  // /api/login endpoint.
  bool verifyCodeProof(const char* clientProofHex) const;

  // ── Login flow ────────────────────────────────────────────────────
  // Called after verifyCodeProof() succeeds. Mints a new session,
  // fills sessionIdOut + csrfTokenOut with hex strings. Returns true
  // on success (false only if the session map is full AND LRU-eviction
  // fails, which shouldn't happen).
  bool login(char sessionIdOut[WAUTH_SESSION_ID_BUF_LEN],
             char csrfTokenOut[WAUTH_CSRF_TOKEN_BUF_LEN]);

  // ── Per-request gates (called from inside each HTTP handler) ──────
  // isAuthenticated: reads the Cookie header, extracts the session=...
  // value, looks it up, checks TTL. Side-effect: updates the session's
  // lastActivity timestamp on success.
  bool isAuthenticated(AsyncWebServerRequest* request);

  // verifyCsrfToken: reads X-CSRF-Token header, constant-time-compares
  // against the session's CSRF token. MUST be called AFTER
  // isAuthenticated() (it uses the request's resolved session).
  bool verifyCsrfToken(AsyncWebServerRequest* request);

  // Convenience: emits the Set-Cookie header value for a freshly-minted
  // session. Caller adds it to the response via request->response()->addHeader().
  // Format: "SecureVault=session=<id>; HttpOnly; SameSite=Strict; Max-Age=300; Path=/"
  void buildCookieHeader(const char* sessionId, char* out, size_t outCap) const;

  // Convenience: extracts the session ID from a request's Cookie header.
  // Returns true on success (false if no cookie or wrong name).
  static bool extractSessionIdFromCookie(AsyncWebServerRequest* request,
                                          char out[WAUTH_SESSION_ID_BUF_LEN]);

  // ── Teardown for a specific session (logout) ──────────────────────
  void logout(AsyncWebServerRequest* request);

  // ── Background tick (called from APModeManager::tick) ─────────────
  // Expires stale sessions. Cheap — O(WAUTH_MAX_SESSIONS).
  void tick();

private:
  WebAuthManager() = default;
  WebAuthManager(const WebAuthManager&) = delete;
  WebAuthManager& operator=(const WebAuthManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;

  struct Session {
    bool active = false;
    char sessionId[WAUTH_SESSION_ID_BUF_LEN] = {0};
    char csrfToken[WAUTH_CSRF_TOKEN_BUF_LEN] = {0};
    unsigned long lastActivity = 0;
  };

  Session _sessions[WAUTH_MAX_SESSIONS];
  SemaphoreHandle_t _mutex = nullptr;

  // The current 6-digit code + its SHA-256 proof. Both zeroed on end().
  char _code[7] = {0};                          // "000000".."999999" + NUL
  char _codeProofHex[WAUTH_CODE_PROOF_BUF_LEN] = {0};
  bool _codeSet = false;

  Session* _findSessionByCookie(AsyncWebServerRequest* request);
  Session* _findSessionById(const char* sessionId);
  Session* _findFreeSlot();
  void _evictLRU();
  void _clearSession(Session& s);
};

// ── C-style helpers (used by web_vault_server.cpp handlers) ─────────
inline WebAuthManager& webAuth() { return WebAuthManager::getInstance(); }
