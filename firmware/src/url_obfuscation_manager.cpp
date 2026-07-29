// ═══════════════════════════════════════════════════════════════════════════════
//  url_obfuscation_manager.cpp — Layer 3: URL Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════
#include "url_obfuscation_manager.h"
#include "web_crypto_utils.h"
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <cstring>

URLObfuscationManager& URLObfuscationManager::getInstance() {
  static URLObfuscationManager instance;
  // F8: auto-initialize with warning if getInstance() called before begin()
  if (!instance._initialized) {
    Serial.println("[F8-WARN] URLObfuscationManager::getInstance() called before begin() — auto-initializing");
    instance.begin();
  }
  return instance;
}

bool URLObfuscationManager::begin() {
  if (_initialized) return true;  // idempotent
  // Fresh 16-byte seed every AP-mode start.
  secureRandom(_seed, sizeof(_seed));
  _seedReady = true;
  // Clear any stale mappings.
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    _mappings[i].active = false;
    _mappings[i].realPath = "";
    _mappings[i].obfPath = "";
  }
  _initialized = true;
  Serial.println("[F8] URLObfuscationManager::begin() — initialized");
  return true;
}

void URLObfuscationManager::end() {
  secureZero(_seed, sizeof(_seed));
  _seedReady = false;
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    _mappings[i].active = false;
    _mappings[i].realPath = "";
    _mappings[i].obfPath = "";
  }
}

void URLObfuscationManager::_generateObfPath(const String& realPath, char out[URL_OBF_PATH_BUF_LEN]) const {
  // SHA-256(realPath + seed + domainSeparator) → first 12 hex chars
  // after the "/x/" prefix.
  static const char DOMAIN[] = "SecureVault-URL-Obf-v1";

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const uint8_t*)realPath.c_str(), realPath.length());
  mbedtls_sha256_update(&ctx, _seed, sizeof(_seed));
  mbedtls_sha256_update(&ctx, (const uint8_t*)DOMAIN, sizeof(DOMAIN) - 1);
  uint8_t digest[32];
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);

  // Take the first 6 bytes → 12 hex chars.
  // NOTE: Arduino's Print.h #defines HEX as 16, so we use a different local name.
  static const char HEX_CHARS[] = "0123456789abcdef";
  out[0] = '/'; out[1] = 'x'; out[2] = '/';
  for (int i = 0; i < 6; i++) {
    out[3 + 2 * i]     = HEX_CHARS[(digest[i] >> 4) & 0x0F];
    out[3 + 2 * i + 1] = HEX_CHARS[digest[i] & 0x0F];
  }
  out[URL_OBF_PATH_BUF_LEN - 1] = '\0';

  secureZero(digest, sizeof(digest));
}

String URLObfuscationManager::registerEndpoint(const String& realPath) {
  if (!_seedReady) return "";

  // Check if already registered.
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (_mappings[i].active && _mappings[i].realPath == realPath) {
      return _mappings[i].obfPath;
    }
  }
  // Find a free slot.
  int slot = -1;
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (!_mappings[i].active) { slot = i; break; }
  }
  if (slot < 0) return "";

  char obf[URL_OBF_PATH_BUF_LEN];
  _generateObfPath(realPath, obf);
  _mappings[slot].active = true;
  _mappings[slot].realPath = realPath;
  _mappings[slot].obfPath = String(obf);
  return _mappings[slot].obfPath;
}

String URLObfuscationManager::obfuscateURL(const String& realPath) const {
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (_mappings[i].active && _mappings[i].realPath == realPath) {
      return _mappings[i].obfPath;
    }
  }
  return "";
}

String URLObfuscationManager::deobfuscateURL(const String& obfPath) const {
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (_mappings[i].active && _mappings[i].obfPath == obfPath) {
      return _mappings[i].realPath;
    }
  }
  return "";
}

bool URLObfuscationManager::isObfuscatedPath(const String& path) const {
  if (path.length() != URL_OBF_PATH_BUF_LEN - 1) return false;
  if (path.charAt(0) != '/' || path.charAt(1) != 'x' || path.charAt(2) != '/') return false;
  for (int i = 3; i < URL_OBF_PATH_BUF_LEN - 1; i++) {
    char c = path.charAt(i);
    bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!isHex) return false;
  }
  return true;
}

String URLObfuscationManager::getMappingsJSON() const {
  JsonDocument doc;
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (_mappings[i].active) {
      // Strip the leading /api/vault/ for the JSON key — the client
      // gets a clean name like "list", "add", etc.
      String key = _mappings[i].realPath;
      int prefixLen = strlen("/api/vault/");
      if (key.startsWith("/api/vault/")) {
        key = key.substring(prefixLen);
      } else if (key.startsWith("/api/")) {
        key = key.substring(strlen("/api/"));
      }
      doc[key] = _mappings[i].obfPath;
    }
  }
  String out;
  serializeJson(doc, out);
  return out;
}

int URLObfuscationManager::getMappingCount() const {
  int n = 0;
  for (int i = 0; i < URL_OBF_MAX_ENDPOINTS; i++) {
    if (_mappings[i].active) n++;
  }
  return n;
}
