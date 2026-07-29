#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  method_tunneling_manager.h — Layer 4: Method Tunneling
// ═══════════════════════════════════════════════════════════════════════════════
//  Maps to SecureGen's MethodTunnelingManager (security_model.md L6).
//
//  Purpose: tunnels all state-changing HTTP methods (PUT/DELETE) through
//  a single POST /api/tunnel endpoint, with the real method stored in
//  an XOR-encrypted X-Real-Method header. Defends against HTTP method
//  fingerprinting — every state-changing request looks like a POST to
//  /api/tunnel from the wire's perspective.
//
//  ⚠️ Faithful-port caveat (study_securegen_layers.md caveat #2):
//  SecureGen's actual implementation uses XOR with a deterministic key
//  derived from the public clientId — this is NOT cryptographic, just
//  obfuscation. We mirror the same construction to stay faithful to
//  the source. The cryptographic defense comes from Layer 2 (ECDH +
//  AES-256-GCM on the body), not from this layer. This layer's value
//  is purely traffic-pattern obfuscation: it makes every state-changing
//  request look identical on the wire (POST /api/tunnel, no method-
//  distinguishing URL or verb).
//
//  Endpoint whitelist: vault/edit (PUT), vault/delete (DELETE) — both
//  tunneled. vault/list (GET) and vault/add (POST) are NOT tunneled
//  (they're already POST-shaped and don't benefit from tunneling).
//
//  Header format:
//    X-Real-Method: <hex XOR of "PUT" or "DELETE" with MT_ESP32_<cid>_KEY>
//  Where the key is the first 32 chars of "MT_ESP32_" + clientId + "_METHOD_KEY".
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <ESPAsyncWebServer.h>

#define MT_MAX_TUNNELED_ENDPOINTS 8
#define MT_METHOD_HEADER_NAME "X-Real-Method"

class MethodTunnelingManager {
public:
  static MethodTunnelingManager& getInstance();

  // F8: Sets _initialized = true. Idempotent.
  bool begin();
  void end();

  // F8: Check whether begin() has been called.
  bool isInitialized() const { return _initialized; }

  // Returns true if the given real path is in the tunneled-endpoint whitelist.
  bool shouldProcessTunneling(const String& realPath) const;

  // Adds a real path to the whitelist. Called during server setup.
  void registerTunneledEndpoint(const String& realPath);

  // XOR-encrypt a method string ("PUT" / "DELETE") with the clientId-derived key.
  // Returns a hex string. Used by the client (the webapp) to build the header.
  String encryptMethodHeader(const String& method, const String& clientId) const;

  // Inverse — used by the /api/tunnel dispatcher to recover the real method.
  String decryptMethodHeader(const String& encryptedHex, const String& clientId) const;

  // Inspects a request: returns the real HTTP method if this is a tunneled
  // POST (has X-Real-Method header), or "" if not.
  String extractRealMethod(AsyncWebServerRequest* request, const String& clientId) const;

  // True if the request is a tunneled POST (HTTP_POST + has X-Real-Method header).
  bool isTunneledRequest(AsyncWebServerRequest* request) const;

  int getTunneledRequestCount() const { return _totalRequests; }

private:
  MethodTunnelingManager() = default;
  MethodTunnelingManager(const MethodTunnelingManager&) = delete;
  MethodTunnelingManager& operator=(const MethodTunnelingManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;

  String _endpoints[MT_MAX_TUNNELED_ENDPOINTS];
  int _endpointCount = 0;
  int _totalRequests = 0;

  // Derives the XOR key (mirrors SecureGen exactly):
  //   "MT_ESP32_" + clientId + "_METHOD_KEY", truncated/padded to 32 chars.
  String _deriveKey(const String& clientId) const;
};

inline MethodTunnelingManager& methodTunnel() { return MethodTunnelingManager::getInstance(); }
