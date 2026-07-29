#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  url_obfuscation_manager.h — Layer 3: URL Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════
//  Maps to SecureGen's URLObfuscationManager (security_model.md L5).
//
//  Purpose: maps real API paths (/api/vault/list, /api/vault/add, etc.)
//  to random 12-char hex paths (e.g. /x/abcdef123456) so that a passive
//  sniffer can't enumerate the API surface from captured traffic.
//
//  Simplification vs SecureGen:
//    SecureGen rotates the mappings every 30 reboots and persists them
//    to LittleFS. We don't — AP mode is ephemeral by design (user
//    enters AP mode, does a few CRUD ops, exits). The mappings are
//    regenerated every AP-mode start, which is strictly better than
//    SecureGen's 30-boot rotation for the AP use case.
//
//  Mapping algorithm:
//    obfuscatedPath = "/x/" + first 12 hex chars of SHA256(realPath + sessionIdSeed)
//    where sessionIdSeed is a 16-byte random value generated in begin().
//
//  Lookup is bidirectional:
//    - Forward: obfuscateURL("/api/vault/list") → "/x/abcdef123456"
//    - Reverse: deobfuscateURL("/x/abcdef123456") → "/api/vault/list"
//
//  Integration:
//    - WebVaultServer registers BOTH paths on each endpoint (the real
//      one for testing/debugging, the obfuscated one for production).
//    - The /api/secure/hello response includes an "obfuscatedPaths"
//      object telling the webapp which paths to use.
//    - Clients must use the obfuscated paths for state-changing ops;
//      using the real path returns 404 (treated as scanner probe).
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <ESPAsyncWebServer.h>

#define URL_OBF_PATH_LEN     12   // 12 hex chars after /x/
#define URL_OBF_PATH_BUF_LEN 16   // "/x/" + 12 + null
#define URL_OBF_MAX_ENDPOINTS 16  // vault/list, /add, /edit, /delete, /tunnel, etc.

class URLObfuscationManager {
public:
  static URLObfuscationManager& getInstance();

  // Generates a fresh session seed. Called at AP-mode start.
  // F8: Sets _initialized = true. Idempotent.
  bool begin();

  // F8: Check whether begin() has been called.
  bool isInitialized() const { return _initialized; }

  // Clears all mappings. Called at AP-mode stop.
  void end();

  // Registers a real path for obfuscation. Returns the obfuscated path.
  // Calling this twice with the same realPath returns the same mapping.
  String registerEndpoint(const String& realPath);

  // Forward: real → obfuscated. Returns "" if realPath wasn't registered.
  String obfuscateURL(const String& realPath) const;

  // Reverse: obfuscated → real. Returns "" if not found.
  String deobfuscateURL(const String& obfPath) const;

  // True if the path matches the /x/<12 hex> shape.
  bool isObfuscatedPath(const String& path) const;

  // Returns all registered mappings as a JSON object:
  //   { "/api/vault/list": "/x/abcdef123456", ... }
  // Used by /api/secure/hello to tell the client the obfuscated paths.
  String getMappingsJSON() const;

  int getMappingCount() const;

private:
  URLObfuscationManager() = default;
  URLObfuscationManager(const URLObfuscationManager&) = delete;
  URLObfuscationManager& operator=(const URLObfuscationManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;

  struct Mapping {
    bool active = false;
    String realPath;
    String obfPath;
  };

  Mapping _mappings[URL_OBF_MAX_ENDPOINTS];
  uint8_t _seed[16] = {0};
  bool _seedReady = false;

  void _generateObfPath(const String& realPath, char out[URL_OBF_PATH_BUF_LEN]) const;
};

inline URLObfuscationManager& urlObf() { return URLObfuscationManager::getInstance(); }
