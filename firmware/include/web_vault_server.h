#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  web_vault_server.h — AsyncWebServer + route handlers for AP-mode vault CRUD
//  Author: Purujith Kadekar
// ═══════════════════════════════════════════════════════════════════════════════
//  This is the integration point where all 6 layers come together:
//
//    Layer 1 (WebAuth/CSRF):  isAuthenticated() + verifyCsrfToken() on every
//                             state-changing endpoint.
//    Layer 2 (SecureLayer):   decryptRequest() on incoming bodies,
//                             encryptResponse() on outgoing bodies.
//    Layer 3 (URL obf):       dual-registration of real + obfuscated paths.
//    Layer 4 (Method tunnel): POST /api/tunnel dispatcher for PUT/DELETE.
//    Layer 5 (Traffic obf):   orthogonal — emits decoy UDPs, doesn't affect routes.
//    Layer 6 (Header obf):    getClientId() tries X-Client-ID, falls back to X-Req-UUID.
//
//  F13: Middleware Pipeline
//    All state-changing endpoints now go through applySecurityMiddleware(),
//    which automatically applies Layers 1, 2, and 6 before the handler runs.
//    This eliminates the possibility of forgetting a security check (especially
//    CSRF or decryption) in an individual handler. The middleware pipeline:
//      Step 1: Body size check (H8 fix — reject > 4KB)
//      Step 2: requestStarted() (C4 fix — track outstanding requests)
//      Step 3: Layer 1 — isAuthenticated() (401 if not)
//      Step 4: Layer 1 — verifyCsrfToken() (403 if bad)
//      Step 5: Layer 6 — getClientId() (400 if missing)
//      Step 6: Layer 2 — decryptRequestStr() (400 if failed)
//      Step 7: APModeManager::noteActivity() (idle timeout tracking)
//    On failure, the middleware sends the appropriate error response and
//    calls requestFinished(). On success, the handler gets the decrypted
//    body + clientId and just does business logic.
//
//  Routes registered (each on BOTH real + obfuscated path):
//    GET  /                         → captive portal page (HTML, not encrypted)
//    POST /api/login                → verify code proof, mint session+CSRF
//    POST /api/secure/hello         → challenge-response key exchange (Layer 2)
//    POST /api/vault/list           → list all entries (encrypted body)
//    POST /api/vault/add            → add new entry (encrypted body, tunneled PUT)
//    POST /api/vault/edit           → edit existing entry (encrypted body, tunneled PUT)
//    POST /api/vault/delete         → delete entry (encrypted body, tunneled DELETE)
//    POST /api/tunnel               → Layer 4 dispatcher (for legacy clients)
//    GET  /generate_204             → captive portal detection (Android)
//    GET  /hotspot-detect.html      → captive portal detection (Apple)
//    GET  /ncsi.txt                 → captive portal detection (Windows)
//    GET  /fwlink                   → captive portal detection (legacy MS)
//    404 handler                    → 302 redirect to /
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <ESPAsyncWebServer.h>
#include "vault_manager.h"
#include "vault_types.h"
#include "session_context.h"  // F6: single authoritative PIN holder

class WebVaultServer {
public:
  WebVaultServer() = default;
  ~WebVaultServer();

  // vault: the VaultManager instance (already loaded with the user's PIN)
  // sessionCtx: the SessionContext that holds the PIN (F6 fix — single
  //              authoritative copy). Read _sessionCtx->pin() when vault
  //              mutations need the PIN (add/update/delete).
  bool begin(VaultManager* vault, SessionContext* sessionCtx);

  void end();

  // v5.4.7: Called by each handler when a request starts/ends.
  // end() waits for all in-flight requests to complete before tearing down.
  void requestStarted() { _outstandingRequests++; }
  void requestFinished() { if(_outstandingRequests>0) _outstandingRequests--; }
  bool isBusy() const { return _outstandingRequests > 0; }

  // v5.4.7: H8 fix — maximum allowed HTTP body size (4 KB).
  // Prevents an attacker from OOMing the device with a huge POST body.
  static const size_t MAX_BODY_SIZE = 4096;

  // v5.4.7: H9 fix — rate limiting for /api/secure/hello (login attempts).
  // 5 attempts per 60 seconds per IP. Prevents online brute-force of the
  // 6-digit code (would take ~139 days at 5 attempts/min for 10^6 codes).
  bool isRateLimited(AsyncWebServerRequest* request);
  void recordFailedAttempt(const String& ip);
  void clearRateLimit(const String& ip);

  // ── F13: Middleware Pipeline ───────────────────────────────────────
  // Applies all security checks (Layers 1, 2, 6 + body size + activity
  // tracking) before the handler's business logic runs. Returns true on
  // success, fills clientId and decryptedBody. On failure, sends the
  // appropriate error response (encrypted if session exists, plaintext
  // otherwise), calls requestFinished(), and returns false.
  //
  // This replaces the old _gateStateChange() static helper, ensuring
  // every state-changing endpoint gets the same consistent security
  // treatment without any chance of forgetting a check.
  bool applySecurityMiddleware(AsyncWebServerRequest* request,
                                const String& body,
                                String& clientId,
                                String& decryptedBody);

  // ── Layer orchestration helpers (public — used by the middleware
  // pipeline + the per-endpoint handlers) ────────────────────────────
  // Reads clientId via Layer 6 (tries X-Client-ID, falls back to X-Req-UUID).
  String _getClientId(AsyncWebServerRequest* request) const;

  // Sends an encrypted JSON error response. Always uses Layer 2 if the
  // session is valid; falls back to plaintext HTTP error otherwise.
  void _sendError(AsyncWebServerRequest* request, int httpStatus, const char* message);

  // Sends an encrypted JSON success response. Falls back to plaintext
  // only if no secure session exists (used during /api/secure/hello
  // before the session is established).
  void _sendEncryptedJSON(AsyncWebServerRequest* request, const String& clientId, const String& plaintextJSON);

private:
  AsyncWebServer _server{80};
  // v5.4.9 FIX: removed unused AsyncEventSource _events — was declared
  // as "/events" but never used (no SSE endpoints). Each AsyncEventSource
  // allocates internal heap state (observer lists, buffers) that sits idle
  // for the entire AP-mode session. Removed to save ~256 bytes of heap.
  VaultManager* _vault = nullptr;
  SessionContext* _sessionCtx = nullptr;  // F6: read PIN from here, never store own copy
  bool _started = false;
  volatile int _outstandingRequests = 0;  // v5.4.7: C4 fix — prevents use-after-free

  // v5.4.7: H9 fix — per-IP rate limiting state for login attempts.
  struct RateLimitEntry {
    char ip[16] = {0};
    int attempts = 0;
    unsigned long windowStart = 0;
  };
  static const int RATE_LIMIT_MAX_ENTRIES = 4;
  RateLimitEntry _rateLimitTable[RATE_LIMIT_MAX_ENTRIES];
  static const int RATE_LIMIT_MAX_ATTEMPTS = 5;
  static const unsigned long RATE_LIMIT_WINDOW_MS = 60000;

  // ── Route registration helpers ───────────────────────────────────
  // Registers the same handler on BOTH the real path and the obfuscated
  // path (Layer 3). Returns true on success.
  bool _registerDual(const String& realPath, WebRequestMethodComposite method,
                     ArRequestHandlerFunction handler);
  // Same but with a body callback (for POST/PUT with bodies).
  bool _registerDualWithBody(const String& realPath, WebRequestMethodComposite method,
                              ArRequestHandlerFunction handler,
                              ArBodyHandlerFunction bodyHandler);

  // ── Captive portal routes ────────────────────────────────────────
  void _registerCaptivePortalRoutes();

  // ── The actual handlers (defined in web_vault_server.cpp) ────────
  void _handleRoot(AsyncWebServerRequest* request);
  void _handleLogin(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleSecureHello(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleVaultList(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleVaultAdd(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleVaultEdit(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleVaultDelete(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
  void _handleTunnel(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total);
};
