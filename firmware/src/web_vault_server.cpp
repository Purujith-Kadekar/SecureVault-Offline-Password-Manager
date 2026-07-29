// ═══════════════════════════════════════════════════════════════════════════════
//  web_vault_server.cpp — AsyncWebServer route handlers for AP-mode vault CRUD
// ═══════════════════════════════════════════════════════════════════════════════
#include "web_vault_server.h"
#include "ap_mode_manager.h"
#include "web_auth_manager.h"
#include "secure_layer_manager.h"
#include "url_obfuscation_manager.h"
#include "method_tunneling_manager.h"
#include "header_obfuscation_manager.h"
#include "web_crypto_utils.h"
#include "portal_html.h"
#include <ArduinoJson.h>
#include <cstring>

WebVaultServer::~WebVaultServer() {
  end();
}

bool WebVaultServer::begin(VaultManager* vault, SessionContext* sessionCtx) {
  if (!vault || !sessionCtx) return false;
  _vault = vault;
  // F6: Store SessionContext pointer — PIN is read from here when needed.
  // No local _pin copy anymore.
  _sessionCtx = sessionCtx;

  // ── Captive portal routes (no auth — these are how the phone's
  // captive-portal sheet detects "you're on a network that needs
  // sign-in" and pops the browser). All redirect to /.
  _registerCaptivePortalRoutes();

  // ── 404 handler → 302 redirect to / (captive portal behavior).
  _server.onNotFound([](AsyncWebServerRequest* req) {
    req->redirect("/");
  });

  // ── GET / → serve the captive portal page.
  // Not encrypted — the page itself is just HTML+JS. Encryption kicks
  // in once the user enters the 6-digit code and the ECDH handshake
  // completes (Layer 2). Until then there's no session key to encrypt
  // with, and the page contains no secrets.
  _server.on("/", HTTP_GET, [this](AsyncWebServerRequest* req) {
    _handleRoot(req);
  });

  // ── POST /api/login → verify code proof, mint session+CSRF.
  // This is the only POST that doesn't require Layer 1 (the user
  // hasn't logged in yet — they're logging in NOW). It DOES require
  // Layer 2's out-of-band code proof (SHA-256 of the 6-digit code).
  _server.on("/api/login", HTTP_POST,
    [](AsyncWebServerRequest* req) { /* main handler is empty — body handler does all the work */ },
    nullptr,
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleLogin(req, data, len, index, total);
    });

  // ── POST /api/secure/hello → ECDH key exchange.
  // Also pre-auth — this is where the ECDH session is established.
  // The code proof is verified inside SecureLayerManager::processKeyExchange.
  _server.on("/api/secure/hello", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    nullptr,
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleSecureHello(req, data, len, index, total);
    });

  // ── Vault CRUD endpoints.
  // Each is dual-registered on both the real path and the obfuscated
  // path (Layer 3). All require Layer 1 (auth+CSRF) + Layer 2 (encrypt).
  _registerDualWithBody("/api/vault/list", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleVaultList(req, data, len, index, total);
    });
  _registerDualWithBody("/api/vault/add", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleVaultAdd(req, data, len, index, total);
    });
  _registerDualWithBody("/api/vault/edit", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleVaultEdit(req, data, len, index, total);
    });
  _registerDualWithBody("/api/vault/delete", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleVaultDelete(req, data, len, index, total);
    });

  // ── Layer 4 tunnel dispatcher.
  // POST /api/tunnel handles all PUT/DELETE operations by reading the
  // X-Real-Method header (XOR-encrypted) and re-dispatching internally.
  _registerDualWithBody("/api/tunnel", HTTP_POST,
    [](AsyncWebServerRequest* req) {},
    [this](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
      _handleTunnel(req, data, len, index, total);
    });

  _server.begin();
  _started = true;
  return true;
}

void WebVaultServer::end() {
  if (!_started) return;
  // v5.4.7: C4 fix — wait for in-flight requests to complete before
  // tearing down. Prevents use-after-free if a handler is mid-execution
  // when end() is called. Timeout: 2 seconds max (don't block forever).
  unsigned long startWait = millis();
  while (_outstandingRequests > 0 && (millis() - startWait < 2000)) {
    delay(10);
  }
  _server.end();
  _started = false;
  // F6: No local _pin to zero — just release the SessionContext reference.
  _sessionCtx = nullptr;
  _vault = nullptr;
}

// ──────────────────────────────────────────────────────────────────────
// Route registration helpers
// ──────────────────────────────────────────────────────────────────────
bool WebVaultServer::_registerDual(const String& realPath, WebRequestMethodComposite method,
                                    ArRequestHandlerFunction handler) {
  _server.on(realPath.c_str(), method, handler);
  String obfPath = URLObfuscationManager::getInstance().obfuscateURL(realPath);
  if (obfPath.length() > 0) {
    _server.on(obfPath.c_str(), method, handler);
  }
  return true;
}

bool WebVaultServer::_registerDualWithBody(const String& realPath, WebRequestMethodComposite method,
                                            ArRequestHandlerFunction handler,
                                            ArBodyHandlerFunction bodyHandler) {
  _server.on(realPath.c_str(), method, handler, nullptr, bodyHandler);
  String obfPath = URLObfuscationManager::getInstance().obfuscateURL(realPath);
  if (obfPath.length() > 0) {
    _server.on(obfPath.c_str(), method, handler, nullptr, bodyHandler);
  }
  return true;
}

void WebVaultServer::_registerCaptivePortalRoutes() {
  // Android: GET /generate_204 expects HTTP 204 (no content). If it gets
  // anything else, the captive-portal sheet pops.
  _server.on("/generate_204", HTTP_GET, [](AsyncWebServerRequest* req) {
    req->redirect("/");
  });
  // Apple: GET /hotspot-detect.html expects "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>".
  // Anything else → captive portal sheet.
  _server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest* req) {
    req->redirect("/");
  });
  // Windows: GET /ncsi.txt expects "Microsoft NCSI".
  _server.on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest* req) {
    req->redirect("/");
  });
  // Legacy Microsoft: GET /fwlink.
  _server.on("/fwlink", HTTP_GET, [](AsyncWebServerRequest* req) {
    req->redirect("/");
  });
}

// ──────────────────────────────────────────────────────────────────────
// Layer orchestration helpers
// ──────────────────────────────────────────────────────────────────────
String WebVaultServer::_getClientId(AsyncWebServerRequest* request) const {
  return HeaderObfuscationManager::getInstance().getClientId(request);
}

void WebVaultServer::_sendError(AsyncWebServerRequest* request, int httpStatus, const char* message) {
  String cid = _getClientId(request);
  if (cid.length() > 0 && SecureLayerManager::getInstance().isSessionValid(cid)) {
    // Encrypted error.
    JsonDocument doc;
    doc["ok"] = false;
    doc["error"] = message;
    String body;
    serializeJson(doc, body);
    _sendEncryptedJSON(request, cid, body);
  } else {
    // Plaintext fallback (pre-handshake errors only).
    request->send(httpStatus, "application/json", String("{\"ok\":false,\"error\":\"") + message + "\"}");
  }
}

void WebVaultServer::_sendEncryptedJSON(AsyncWebServerRequest* request, const String& clientId, const String& plaintextJSON) {
  String encrypted = SecureLayerManager::getInstance().encryptResponseJSON(clientId, plaintextJSON);
  if (encrypted.length() == 0) {
    request->send(500, "application/json", "{\"ok\":false,\"error\":\"encryption_failed\"}");
    return;
  }
  AsyncWebServerResponse* response = request->beginResponse(200, "application/json", encrypted);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

// ──────────────────────────────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────────────────────────────
void WebVaultServer::_handleRoot(AsyncWebServerRequest* request) {
  // Serve the captive portal page from PROGMEM (portal_html.h).
  // Note: ESPAsyncWebServer 3.x deprecated beginResponse_P in favor of
  // beginResponse — both work, but the new API is recommended.
  AsyncWebServerResponse* response = request->beginResponse(200, "text/html",
    (const uint8_t*)PORTAL_HTML, PORTAL_HTML_LEN);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

void WebVaultServer::_handleLogin(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  // Only process when the full body has arrived.
  if (index + len < total) return;
  // v5.4.7: H8 fix — body size cap.
  if (len > MAX_BODY_SIZE) {
    request->send(413, "application/json", "{\"ok\":false,\"error\":\"body_too_large\"}");
    return;
  }

  // Parse JSON body: { "codeProof": "<64 hex chars>" }
  String body((const char*)data, len);
  JsonDocument doc;
  if (deserializeJson(doc, body) != DeserializationError::Ok) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad_json\"}");
    return;
  }
  String codeProofHex = doc["codeProof"] | "";
  if (codeProofHex.length() != WAUTH_CODE_PROOF_HEX_LEN) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad_code_proof_length\"}");
    return;
  }

  // Verify the code proof against the current AP session's code.
  if (!WebAuthManager::getInstance().verifyCodeProof(codeProofHex.c_str())) {
    request->send(403, "application/json", "{\"ok\":false,\"error\":\"code_mismatch\"}");
    return;
  }

  // Mint a new session.
  char sessionId[WAUTH_SESSION_ID_BUF_LEN];
  char csrfToken[WAUTH_CSRF_TOKEN_BUF_LEN];
  if (!WebAuthManager::getInstance().login(sessionId, csrfToken)) {
    request->send(500, "application/json", "{\"ok\":false,\"error\":\"session_create_failed\"}");
    return;
  }

  // Build the response. The Set-Cookie header carries the session ID;
  // the CSRF token is in the JSON body (the webapp stores it in
  // localStorage and sends it as X-CSRF-Token on subsequent requests).
  char cookieHeader[128];
  WebAuthManager::getInstance().buildCookieHeader(sessionId, cookieHeader, sizeof(cookieHeader));

  JsonDocument respDoc;
  respDoc["ok"] = true;
  respDoc["csrfToken"] = csrfToken;
  respDoc["tunnelingEnabled"] = true;
  // Tell the client which User-Agent-y headers to send (Layer 6).
  respDoc["fakeHeaders"] = HeaderObfuscationManager::getInstance().getFakeHeadersJSON();
  // Tell the client which obfuscated URL paths to use (Layer 3).
  respDoc["obfuscatedPaths"] = URLObfuscationManager::getInstance().getMappingsJSON();

  String responseBody;
  serializeJson(respDoc, responseBody);

  AsyncWebServerResponse* response = request->beginResponse(200, "application/json", responseBody);
  response->addHeader("Set-Cookie", cookieHeader);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

void WebVaultServer::_handleSecureHello(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;
  // v5.4.7: H8 fix — body size cap.
  if (len > MAX_BODY_SIZE) {
    request->send(413, "application/json", "{\"ok\":false,\"error\":\"body_too_large\"}");
    return;
  }

  // v5.4.7: Two-step challenge-response handshake.
  //
  // Step 1 (challenge): client sends {clientId} only.
  //   Server generates serverNonce, stores it as a pending challenge, returns it.
  //
  // Step 2 (response): client sends {clientId, serverNonce, codeProof} where
  //   codeProof = HMAC(code, serverNonce).
  //   Server verifies the challenge exists, verifies the codeProof, derives
  //   encKey/macKey, returns the session token.
  //
  // This prevents offline brute-force of the 6-digit code: an attacker who
  // captures the traffic sees serverNonce + codeProof, but can't verify a
  // code guess without computing HMAC(guess, serverNonce) for each of the
  // 10^6 possibilities — and the server rate-limits online attempts.
  String body((const char*)data, len);
  JsonDocument doc;
  if (deserializeJson(doc, body) != DeserializationError::Ok) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad_json\"}");
    return;
  }
  String clientId = doc["clientId"] | "";
  if (clientId.length() == 0 || clientId.length() > 64) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad_client_id\"}");
    return;
  }

  String serverNonce = doc["serverNonce"] | "";
  String codeProofHex = doc["codeProof"] | "";

  // Step 1: no serverNonce in the request → generate a challenge.
  if (serverNonce.length() == 0) {
    String challengeNonceB64;
    if (!SecureLayerManager::getInstance().generateChallenge(clientId, challengeNonceB64)) {
      request->send(500, "application/json", "{\"ok\":false,\"error\":\"challenge_failed\"}");
      return;
    }
    JsonDocument respDoc;
    respDoc["ok"] = true;
    respDoc["step"] = 1;
    respDoc["serverNonce"] = challengeNonceB64;
    String responseBody;
    serializeJson(respDoc, responseBody);
    request->send(200, "application/json", responseBody);
    return;
  }

  // Step 2: serverNonce + codeProof present → verify + establish session.
  if (codeProofHex.length() != WAUTH_CODE_PROOF_HEX_LEN) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad_code_proof\"}");
    return;
  }

  // v5.4.7: H9 fix — rate limit login attempts (5/min/IP).
  if (isRateLimited(request)) {
    request->send(429, "application/json", "{\"ok\":false,\"error\":\"rate_limited\"}");
    return;
  }

  if (!SecureLayerManager::getInstance().establishSession(clientId, serverNonce, codeProofHex)) {
    // Record the failed attempt for rate limiting.
    recordFailedAttempt(request->client()->remoteIP().toString());
    request->send(403, "application/json", "{\"ok\":false,\"error\":\"code_proof_mismatch\"}");
    return;
  }
  // Success — clear any rate-limit state for this IP.
  clearRateLimit(request->client()->remoteIP().toString());

  // Also mint a Layer 1 session (cookie + CSRF token) in the same response.
  char sessionId[WAUTH_SESSION_ID_BUF_LEN];
  char csrfToken[WAUTH_CSRF_TOKEN_BUF_LEN];
  if (!WebAuthManager::getInstance().login(sessionId, csrfToken)) {
    request->send(500, "application/json", "{\"ok\":false,\"error\":\"session_create_failed\"}");
    return;
  }

  char cookieHeader[128];
  WebAuthManager::getInstance().buildCookieHeader(sessionId, cookieHeader, sizeof(cookieHeader));

  JsonDocument respDoc;
  respDoc["ok"] = true;
  respDoc["step"] = 2;
  respDoc["serverNonce"] = serverNonce;  // echo back so client knows which nonce to use
  respDoc["csrfToken"] = csrfToken;
  respDoc["obfuscatedPaths"] = URLObfuscationManager::getInstance().getMappingsJSON();
  JsonArray tunneled = respDoc["tunneledEndpoints"].to<JsonArray>();
  tunneled.add("/api/vault/edit");
  tunneled.add("/api/vault/delete");
  respDoc["tunnelingEnabled"] = true;
  respDoc["obfuscatedClientIdHeader"] = HO_OBF_CLIENT_ID_HEADER;
  respDoc["obfuscatedSecureRequestHeader"] = HO_OBF_SECURE_REQUEST_HEADER;
  respDoc["fakeHeaders"] = HeaderObfuscationManager::getInstance().getFakeHeadersJSON();

  String responseBody;
  serializeJson(respDoc, responseBody);

  AsyncWebServerResponse* response = request->beginResponse(200, "application/json", responseBody);
  response->addHeader("Set-Cookie", cookieHeader);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

// ── Helper: parse a VaultEntryRW from a JSON object ─────────────────
// Used by _handleVaultAdd and _handleVaultEdit.
static bool _parseEntryFromJson(JsonObject obj, VaultEntryRW& e, int* idxOut = nullptr) {
  // Zero the struct first — stale fields from a previous entry at the
  // same stack location must never leak.
  memset(&e, 0, sizeof(e));
  e.type = vaultStrToType(obj["type"] | "login");
  e.favorite = obj["favorite"] | false;
  e.deleted = obj["deleted"] | false;
  if (idxOut) {
    *idxOut = obj["index"] | -1;
  }
  // Common fields.
  strncpy(e.site, obj["site"] | "", sizeof(e.site) - 1);
  strncpy(e.user, obj["user"] | "", sizeof(e.user) - 1);
  strncpy(e.pass, obj["pass"] | "", sizeof(e.pass) - 1);
  strncpy(e.totp, obj["totp"] | "", sizeof(e.totp) - 1);
  // LOGIN extras.
  strncpy(e.url,    obj["url"]    | "", sizeof(e.url) - 1);
  strncpy(e.notes,  obj["notes"]  | "", sizeof(e.notes) - 1);
  strncpy(e.folder, obj["folder"] | "", sizeof(e.folder) - 1);
  // CARD extras.
  strncpy(e.cardholder, obj["cardholder"] | "", sizeof(e.cardholder) - 1);
  strncpy(e.cardNumber, obj["cardNumber"] | "", sizeof(e.cardNumber) - 1);
  strncpy(e.exp,        obj["exp"]        | "", sizeof(e.exp) - 1);
  strncpy(e.cvv,        obj["cvv"]        | "", sizeof(e.cvv) - 1);
  // IDENTITY extras.
  strncpy(e.firstName, obj["firstName"] | "", sizeof(e.firstName) - 1);
  strncpy(e.lastName,  obj["lastName"]  | "", sizeof(e.lastName) - 1);
  strncpy(e.email,     obj["email"]     | "", sizeof(e.email) - 1);
  strncpy(e.phone,     obj["phone"]     | "", sizeof(e.phone) - 1);
  strncpy(e.address,   obj["address"]   | "", sizeof(e.address) - 1);
  strncpy(e.city,      obj["city"]      | "", sizeof(e.city) - 1);
  strncpy(e.state,     obj["state"]     | "", sizeof(e.state) - 1);
  strncpy(e.postal,    obj["postal"]    | "", sizeof(e.postal) - 1);
  strncpy(e.country,   obj["country"]   | "", sizeof(e.country) - 1);
  strncpy(e.ssn,       obj["ssn"]       | "", sizeof(e.ssn) - 1);
  strncpy(e.passport,  obj["passport"]  | "", sizeof(e.passport) - 1);
  strncpy(e.license,   obj["license"]   | "", sizeof(e.license) - 1);

  // Server-side mandatory field validation (from SecureKey pattern):
  // site is always required; user is required for login type.
  if (e.site[0] == '\0') return false;
  if (e.type == 0 && e.user[0] == '\0') return false;  // login needs a username
  return true;
}

// ── Helper: serialize one VaultEntry as a JSON object ───────────────
static void _serializeEntryToJson(const VaultEntry& e, JsonObject obj) {
  obj["type"] = vaultTypeToStr(e.type);
  obj["site"] = e.site ? e.site : "";
  obj["user"] = e.user ? e.user : "";
  obj["pass"] = e.pass ? e.pass : "";
  obj["totp"] = e.totp ? e.totp : "";
  obj["favorite"] = e.favorite;
  obj["deleted"] = e.deleted;
  obj["url"]      = e.url      ? e.url      : "";
  obj["notes"]    = e.notes    ? e.notes    : "";
  obj["folder"]   = e.folder   ? e.folder   : "";
  obj["cardholder"] = e.cardholder ? e.cardholder : "";
  obj["cardNumber"] = e.cardNumber ? e.cardNumber : "";
  obj["exp"] = e.exp ? e.exp : "";
  obj["cvv"] = e.cvv ? e.cvv : "";
  obj["firstName"] = e.firstName ? e.firstName : "";
  obj["lastName"]  = e.lastName  ? e.lastName  : "";
  obj["email"] = e.email ? e.email : "";
  obj["phone"] = e.phone ? e.phone : "";
  obj["address"] = e.address ? e.address : "";
  obj["city"] = e.city ? e.city : "";
  obj["state"] = e.state ? e.state : "";
  obj["postal"] = e.postal ? e.postal : "";
  obj["country"] = e.country ? e.country : "";
  obj["ssn"] = e.ssn ? e.ssn : "";
  obj["passport"] = e.passport ? e.passport : "";
  obj["license"] = e.license ? e.license : "";
}

// ═══════════════════════════════════════════════════════════════════════════════
//  F13: Middleware Pipeline — applies all security checks automatically
// ═══════════════════════════════════════════════════════════════════════════════
//  This replaces the old _gateStateChange() static helper. It's now a
//  member function that:
//    1. Enforces body size limit (H8 fix)
//    2. Tracks the request outstanding count (C4 fix)
//    3. Checks Layer 1: WebAuth isAuthenticated() → 401
//    4. Checks Layer 1: CSRF verifyCsrfToken() → 403
//    5. Checks Layer 6: getClientId() → 400
//    6. Checks Layer 2: decryptRequestStr() → 400
//    7. Notes AP-mode activity (idle timeout tracking)
//
//  On success, fills clientId + decryptedBody and returns true.
//  On failure, sends the appropriate error response, calls
//  requestFinished(), and returns false — the handler should just
//  return immediately.
//
//  The /api/login and /api/secure/hello endpoints are exempt — they're
//  pre-authentication (the user hasn't logged in yet / the session
//  hasn't been established).
// ═══════════════════════════════════════════════════════════════════════════════
bool WebVaultServer::applySecurityMiddleware(AsyncWebServerRequest* request,
                                              const String& body,
                                              String& clientId,
                                              String& decryptedBody) {
  // Step 1: Body size check (H8 fix — reject bodies larger than 4 KB).
  if (body.length() > MAX_BODY_SIZE) {
    _sendError(request, 413, "body_too_large");
    requestFinished();
    return false;
  }

  // Step 2: Track this request so end() won't delete the server mid-handler.
  requestStarted();

  // Step 3: Layer 1 — Authentication check.
  if (!WebAuthManager::getInstance().isAuthenticated(request)) {
    _sendError(request, 401, "unauthorized");
    requestFinished();
    return false;
  }

  // Step 4: Layer 1 — CSRF token verification.
  if (!WebAuthManager::getInstance().verifyCsrfToken(request)) {
    _sendError(request, 403, "csrf_mismatch");
    requestFinished();
    return false;
  }

  // Step 5: Layer 6 — Get client ID from obfuscated headers.
  clientId = _getClientId(request);
  if (clientId.length() == 0) {
    _sendError(request, 400, "missing_client_id");
    requestFinished();
    return false;
  }

  // Step 6: Layer 2 — Decrypt the request body using the secure session.
  decryptedBody = SecureLayerManager::getInstance().decryptRequestStr(clientId, body);
  if (decryptedBody.length() == 0 && request->method() == HTTP_POST) {
    _sendError(request, 400, "decrypt_failed");
    requestFinished();
    return false;
  }

  // Step 7: Note activity for AP-mode idle timeout tracking.
  APModeManager::getInstance().noteActivity();

  // Success — the handler now has clientId + decryptedBody.
  // requestFinished() must be called by the handler after it completes.
  return true;
}

void WebVaultServer::_handleVaultList(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;

  // F13: Middleware pipeline — applies all security checks automatically.
  String body((const char*)data, len);
  String cid, plaintext;
  if (!applySecurityMiddleware(request, body, cid, plaintext)) return;

  // Business logic: build the vault list as JSON.
  JsonDocument respDoc;
  respDoc["ok"] = true;
  JsonArray entries = respDoc["entries"].to<JsonArray>();
  int n = _vault->count();
  for (int i = 0; i < n; i++) {
    VaultEntry e = _vault->entryAt(i);
    if (e.deleted) continue;
    JsonObject obj = entries.add<JsonObject>();
    obj["index"] = i;
    _serializeEntryToJson(e, obj);
  }
  respDoc["count"] = n;

  String responseBody;
  serializeJson(respDoc, responseBody);
  _sendEncryptedJSON(request, cid, responseBody);
  requestFinished();  // v5.4.7: C4 fix
}

void WebVaultServer::_handleVaultAdd(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;
  String body((const char*)data, len);
  String cid, plaintext;
  if (!applySecurityMiddleware(request, body, cid, plaintext)) return;

  // Business logic: parse the entry from the decrypted JSON.
  JsonDocument doc;
  if (deserializeJson(doc, plaintext) != DeserializationError::Ok) {
    _sendError(request, 400, "bad_json");
    requestFinished();
    return;
  }
  VaultEntryRW e;
  if (!_parseEntryFromJson(doc.as<JsonObject>(), e)) {
    _sendError(request, 400, "missing_required_fields");
    requestFinished();
    return;
  }

  // F6: Add the entry using PIN from SessionContext.
  bool ok = _vault->addEntry(e, _sessionCtx->pin());
  if (!ok) {
    _sendError(request, 500, _vault->lastSaveError());
    requestFinished();
    return;
  }

  // Business logic: respond.
  JsonDocument respDoc;
  respDoc["ok"] = true;
  respDoc["count"] = _vault->count();
  String responseBody;
  serializeJson(respDoc, responseBody);
  _sendEncryptedJSON(request, cid, responseBody);
  requestFinished();  // v5.4.7: C4 fix
}

void WebVaultServer::_handleVaultEdit(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;
  String body((const char*)data, len);
  String cid, plaintext;
  if (!applySecurityMiddleware(request, body, cid, plaintext)) return;

  // Business logic: parse the entry.
  JsonDocument doc;
  if (deserializeJson(doc, plaintext) != DeserializationError::Ok) {
    _sendError(request, 400, "bad_json");
    requestFinished();
    return;
  }
  int idx = -1;
  VaultEntryRW e;
  if (!_parseEntryFromJson(doc.as<JsonObject>(), e, &idx)) {
    _sendError(request, 400, "missing_required_fields");
    requestFinished();
    return;
  }
  if (idx < 0 || idx >= _vault->count()) {
    _sendError(request, 400, "bad_index");
    requestFinished();
    return;
  }

  // F6: Update the entry using PIN from SessionContext.
  bool ok = _vault->updateEntry(idx, e, _sessionCtx->pin());
  if (!ok) {
    _sendError(request, 500, _vault->lastSaveError());
    requestFinished();
    return;
  }

  JsonDocument respDoc;
  respDoc["ok"] = true;
  String responseBody;
  serializeJson(respDoc, responseBody);
  _sendEncryptedJSON(request, cid, responseBody);
  requestFinished();  // v5.4.7: C4 fix
}

void WebVaultServer::_handleVaultDelete(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;
  String body((const char*)data, len);
  String cid, plaintext;
  if (!applySecurityMiddleware(request, body, cid, plaintext)) return;

  // Business logic: parse the delete request.
  JsonDocument doc;
  if (deserializeJson(doc, plaintext) != DeserializationError::Ok) {
    _sendError(request, 400, "bad_json");
    requestFinished();
    return;
  }
  int idx = doc["index"] | -1;
  if (idx < 0 || idx >= _vault->count()) {
    _sendError(request, 400, "bad_index");
    requestFinished();
    return;
  }

  // F6: Delete the entry using PIN from SessionContext.
  bool ok = _vault->deleteEntry(idx, _sessionCtx->pin());
  if (!ok) {
    _sendError(request, 500, _vault->lastSaveError());
    requestFinished();
    return;
  }

  JsonDocument respDoc;
  respDoc["ok"] = true;
  respDoc["count"] = _vault->count();
  String responseBody;
  serializeJson(respDoc, responseBody);
  _sendEncryptedJSON(request, cid, responseBody);
  requestFinished();  // v5.4.7: C4 fix
}

void WebVaultServer::_handleTunnel(AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index + len < total) return;

  // F13: Middleware pipeline.
  String body((const char*)data, len);
  String cid, plaintext;
  if (!applySecurityMiddleware(request, body, cid, plaintext)) return;

  // The decrypted body should be: { "endpoint": "/api/vault/edit", "data": <inner JSON> }
  JsonDocument doc;
  if (deserializeJson(doc, plaintext) != DeserializationError::Ok) {
    _sendError(request, 400, "bad_json");
    requestFinished();
    return;
  }
  String endpoint = doc["endpoint"] | "";
  if (endpoint.length() == 0) {
    _sendError(request, 400, "missing_endpoint");
    requestFinished();
    return;
  }

  // Layer 4: only allow tunneled endpoints.
  if (!MethodTunnelingManager::getInstance().shouldProcessTunneling(endpoint)) {
    _sendError(request, 403, "endpoint_not_tunneled");
    requestFinished();
    return;
  }

  // Verify the X-Real-Method header (XOR-encrypted) matches the expected
  // method for this endpoint.
  String realMethod = MethodTunnelingManager::getInstance().extractRealMethod(request, cid);
  if (realMethod.length() == 0) {
    _sendError(request, 400, "missing_real_method_header");
    requestFinished();
    return;
  }

  // Re-dispatch to the inner endpoint. The inner data is in doc["data"]
  // — re-serialize it and call the corresponding handler.
  // For simplicity (and because we already have all the layers verified),
  // we directly call the underlying vault operation here.
  JsonObject innerData = doc["data"].as<JsonObject>();

  if (endpoint == "/api/vault/edit") {
    if (realMethod != "PUT") {
      _sendError(request, 400, "method_mismatch");
      requestFinished();
      return;
    }
    int idx = -1;
    VaultEntryRW e;
    if (!_parseEntryFromJson(innerData, e, &idx)) {
      _sendError(request, 400, "missing_required_fields");
      requestFinished();
      return;
    }
    if (idx < 0 || idx >= _vault->count()) {
      _sendError(request, 400, "bad_index");
      requestFinished();
      return;
    }
    bool ok = _vault->updateEntry(idx, e, _sessionCtx->pin());
    if (!ok) {
      _sendError(request, 500, _vault->lastSaveError());
      requestFinished();
      return;
    }
    _sendEncryptedJSON(request, cid, "{\"ok\":true}");
    requestFinished();
    return;
  }
  if (endpoint == "/api/vault/delete") {
    if (realMethod != "DELETE") {
      _sendError(request, 400, "method_mismatch");
      requestFinished();
      return;
    }
    int idx = innerData["index"] | -1;
    if (idx < 0 || idx >= _vault->count()) {
      _sendError(request, 400, "bad_index");
      requestFinished();
      return;
    }
    bool ok = _vault->deleteEntry(idx, _sessionCtx->pin());
    if (!ok) {
      _sendError(request, 500, _vault->lastSaveError());
      requestFinished();
      return;
    }
    JsonDocument respDoc;
    respDoc["ok"] = true;
    respDoc["count"] = _vault->count();
    String responseBody;
    serializeJson(respDoc, responseBody);
    _sendEncryptedJSON(request, cid, responseBody);
    requestFinished();
    return;
  }

  _sendError(request, 404, "unknown_endpoint");
  requestFinished();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  v5.4.7: H9 fix — per-IP rate limiting for /api/secure/hello
// ═══════════════════════════════════════════════════════════════════════════════
bool WebVaultServer::isRateLimited(AsyncWebServerRequest* request) {
  if (!request) return false;
  String ip = request->client()->remoteIP().toString();
  unsigned long now = millis();

  for (int i = 0; i < RATE_LIMIT_MAX_ENTRIES; i++) {
    if (_rateLimitTable[i].ip[0] != '\0' && strcmp(_rateLimitTable[i].ip, ip.c_str()) == 0) {
      // Found this IP. Check if the window has expired.
      if (now - _rateLimitTable[i].windowStart > RATE_LIMIT_WINDOW_MS) {
        // Window expired — reset.
        _rateLimitTable[i].attempts = 0;
        _rateLimitTable[i].windowStart = now;
        return false;
      }
      // Window still active — check attempt count.
      return _rateLimitTable[i].attempts >= RATE_LIMIT_MAX_ATTEMPTS;
    }
  }
  // IP not in the table — not rate limited (first attempt).
  return false;
}

void WebVaultServer::recordFailedAttempt(const String& ip) {
  unsigned long now = millis();
  // Find existing entry or a free slot.
  for (int i = 0; i < RATE_LIMIT_MAX_ENTRIES; i++) {
    if (_rateLimitTable[i].ip[0] != '\0' && strcmp(_rateLimitTable[i].ip, ip.c_str()) == 0) {
      _rateLimitTable[i].attempts++;
      if (now - _rateLimitTable[i].windowStart > RATE_LIMIT_WINDOW_MS) {
        _rateLimitTable[i].windowStart = now;
        _rateLimitTable[i].attempts = 1;
      }
      return;
    }
  }
  // Find a free slot.
  for (int i = 0; i < RATE_LIMIT_MAX_ENTRIES; i++) {
    if (_rateLimitTable[i].ip[0] == '\0') {
      strncpy(_rateLimitTable[i].ip, ip.c_str(), sizeof(_rateLimitTable[i].ip) - 1);
      _rateLimitTable[i].attempts = 1;
      _rateLimitTable[i].windowStart = now;
      return;
    }
  }
  // Table full — evict the oldest entry (lowest windowStart).
  int oldestIdx = 0;
  unsigned long oldest = (unsigned long)-1;
  for (int i = 0; i < RATE_LIMIT_MAX_ENTRIES; i++) {
    if (_rateLimitTable[i].windowStart < oldest) {
      oldest = _rateLimitTable[i].windowStart;
      oldestIdx = i;
    }
  }
  memset(&_rateLimitTable[oldestIdx], 0, sizeof(RateLimitEntry));
  strncpy(_rateLimitTable[oldestIdx].ip, ip.c_str(), sizeof(_rateLimitTable[oldestIdx].ip) - 1);
  _rateLimitTable[oldestIdx].attempts = 1;
  _rateLimitTable[oldestIdx].windowStart = now;
}

void WebVaultServer::clearRateLimit(const String& ip) {
  for (int i = 0; i < RATE_LIMIT_MAX_ENTRIES; i++) {
    if (_rateLimitTable[i].ip[0] != '\0' && strcmp(_rateLimitTable[i].ip, ip.c_str()) == 0) {
      memset(&_rateLimitTable[i], 0, sizeof(RateLimitEntry));
      return;
    }
  }
}
