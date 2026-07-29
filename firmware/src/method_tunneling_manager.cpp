// ═══════════════════════════════════════════════════════════════════════════════
//  method_tunneling_manager.cpp — Layer 4: Method Tunneling
// ═══════════════════════════════════════════════════════════════════════════════
#include "method_tunneling_manager.h"
#include "web_crypto_utils.h"
#include <cstring>

MethodTunnelingManager& MethodTunnelingManager::getInstance() {
  static MethodTunnelingManager instance;
  // F8: auto-initialize with warning if getInstance() called before begin()
  if (!instance._initialized) {
    Serial.println("[F8-WARN] MethodTunnelingManager::getInstance() called before begin() — auto-initializing");
    instance.begin();
  }
  return instance;
}

bool MethodTunnelingManager::begin() {
  if (_initialized) return true;  // idempotent
  _endpointCount = 0;
  _totalRequests = 0;
  _initialized = true;
  Serial.println("[F8] MethodTunnelingManager::begin() — initialized");
  return true;
}

void MethodTunnelingManager::end() {
  for (int i = 0; i < _endpointCount; i++) {
    _endpoints[i] = "";
  }
  _endpointCount = 0;
  _totalRequests = 0;
}

void MethodTunnelingManager::registerTunneledEndpoint(const String& realPath) {
  if (_endpointCount >= MT_MAX_TUNNELED_ENDPOINTS) return;
  // Don't double-register.
  for (int i = 0; i < _endpointCount; i++) {
    if (_endpoints[i] == realPath) return;
  }
  _endpoints[_endpointCount++] = realPath;
}

bool MethodTunnelingManager::shouldProcessTunneling(const String& realPath) const {
  for (int i = 0; i < _endpointCount; i++) {
    if (_endpoints[i] == realPath) return true;
  }
  return false;
}

String MethodTunnelingManager::_deriveKey(const String& clientId) const {
  // Mirrors SecureGen exactly: "MT_ESP32_<clientId>_METHOD_KEY", truncated/padded to 32 chars.
  String k = "MT_ESP32_" + clientId + "_METHOD_KEY";
  if (k.length() > 32) k = k.substring(0, 32);
  while (k.length() < 32) k += 'X';  // pad with X (matches SecureGen)
  return k;
}

String MethodTunnelingManager::encryptMethodHeader(const String& method, const String& clientId) const {
  String key = _deriveKey(clientId);
  // XOR each byte of `method` with the corresponding byte of `key`, then hex-encode.
  // NOTE: Arduino's Print.h #defines HEX as 16, so we use a different local name.
  String out;
  out.reserve(method.length() * 2);
  static const char HEX_CHARS[] = "0123456789abcdef";
  for (size_t i = 0; i < method.length(); i++) {
    uint8_t x = (uint8_t)method[i] ^ (uint8_t)key[i % key.length()];
    out += HEX_CHARS[(x >> 4) & 0x0F];
    out += HEX_CHARS[x & 0x0F];
  }
  return out;
}

String MethodTunnelingManager::decryptMethodHeader(const String& encryptedHex, const String& clientId) const {
  // Hex-decode then XOR with the key.
  if (encryptedHex.length() % 2 != 0) return "";
  size_t n = encryptedHex.length() / 2;
  if (n == 0 || n > 16) return "";  // methods are short ("PUT", "DELETE" = max 6 chars)
  String key = _deriveKey(clientId);
  String out;
  out.reserve(n);
  auto hexVal = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; i++) {
    int hi = hexVal(encryptedHex[2 * i]);
    int lo = hexVal(encryptedHex[2 * i + 1]);
    if (hi < 0 || lo < 0) return "";
    uint8_t b = (uint8_t)((hi << 4) | lo);
    b ^= (uint8_t)key[i % key.length()];
    out += (char)b;
  }
  return out;
}

String MethodTunnelingManager::extractRealMethod(AsyncWebServerRequest* request, const String& clientId) const {
  if (!isTunneledRequest(request)) return "";
  // AsyncWebServer does case-insensitive header lookup.
  String encHex = request->header(MT_METHOD_HEADER_NAME);
  if (encHex.length() == 0) return "";
  return decryptMethodHeader(encHex, clientId);
}

bool MethodTunnelingManager::isTunneledRequest(AsyncWebServerRequest* request) const {
  if (!request) return false;
  if (request->method() != HTTP_POST) return false;
  return request->header(MT_METHOD_HEADER_NAME).length() > 0;
}
