#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  header_obfuscation_manager.h — Layer 6: Header Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════
//  Maps to SecureGen's HeaderObfuscationManager (security_model.md L8).
//
//  Purpose:
//    - Renames 2 real headers (X-Client-ID → X-Req-UUID,
//      X-Secure-Request → X-Security-Level) so that header-based
//      scanner signatures don't match.
//    - Registers 5 fake decoy headers that the webapp sends with
//      random values on every request, so a sniffer can't tell which
//      headers are real.
//
//  Integration:
//    - Both real and obfuscated header names are accepted (clients
//      can use either). HeaderObfuscationIntegration::getClientId()
//      tries X-Client-ID first, falls back to X-Req-UUID.
//    - The fake headers are emitted by the webapp (see portal_html.h)
//      with random hex values on every request — they're not read by
//      the server, they're just noise.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <ESPAsyncWebServer.h>

// The real header names (used internally by Layers 2 + 4 to look up
// the clientId + secure-session flag).
#define HO_REAL_CLIENT_ID_HEADER     "X-Client-ID"
#define HO_REAL_SECURE_REQUEST_HEADER "X-Secure-Request"

// The obfuscated header names (what the webapp actually sends —
// scanner signatures look for the real names).
#define HO_OBF_CLIENT_ID_HEADER      "X-Req-UUID"
#define HO_OBF_SECURE_REQUEST_HEADER "X-Security-Level"

// Fake decoy headers. The webapp sends these with random hex values
// on every request. The server doesn't read them — they exist purely
// to add header-level noise.
#define HO_FAKE_HEADER_COUNT 5
extern const char* const HO_FAKE_HEADERS[HO_FAKE_HEADER_COUNT];

class HeaderObfuscationManager {
public:
  static HeaderObfuscationManager& getInstance();

  // F8: Sets _initialized = true. Idempotent (no state to initialize).
  bool begin();
  void end();

  // F8: Check whether begin() has been called.
  bool isInitialized() const { return _initialized; }

  // Returns the value of the client-ID header (tries real first, then
  // obfuscated). Returns "" if neither is present.
  String getClientId(AsyncWebServerRequest* request) const;

  // Returns true if the secure-request header is present (tries real
  // first, then obfuscated).
  bool isSecureRequest(AsyncWebServerRequest* request) const;

  // Returns the list of fake header names as a JSON array (used by
  // /api/secure/hello to tell the webapp which decoys to send).
  String getFakeHeadersJSON() const;

private:
  HeaderObfuscationManager() = default;
  HeaderObfuscationManager(const HeaderObfuscationManager&) = delete;
  HeaderObfuscationManager& operator=(const HeaderObfuscationManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;
};

inline HeaderObfuscationManager& headerObf() { return HeaderObfuscationManager::getInstance(); }
